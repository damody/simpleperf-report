use std::collections::{HashMap, HashSet};

use anyhow::Result;
use log::info;
use serde::Serialize;

use crate::ffi::ReportLib;
use crate::frame_graph::{
    self, FrameGraphEventInfo, ThreadSamples, TimedSample,
};
use crate::model::event_scope::{EventScope, EventScopeInfo};
use crate::model::sets::{FunctionSet, LibSet};

const MAX_CALLSTACK_LENGTH: usize = 750;

fn modify_text_for_html(text: &str) -> String {
    text.replace('<', "&lt;").replace('>', "&gt;")
}

/// Core data structure that reads perf.data and builds the hierarchy.
pub struct RecordData {
    pub meta_info: HashMap<String, String>,
    pub cmdline: String,
    pub arch: String,
    pub events: HashMap<String, EventScope>,
    pub libs: LibSet,
    pub functions: FunctionSet,
    pub total_samples: u64,
    /// Timed samples for frame graph: event_name → (pid, tid) → ThreadSamples.
    pub timed_samples: HashMap<String, HashMap<(u32, u32), ThreadSamples>>,
    /// Frame marker config: (thread_name_pattern, func_substring).
    pub frame_markers: Vec<(String, String)>,
    /// Whether frame graph analysis is enabled.
    pub frame_graph_enabled: bool,
}

impl RecordData {
    pub fn new() -> Self {
        Self {
            meta_info: HashMap::new(),
            cmdline: String::new(),
            arch: String::new(),
            events: HashMap::new(),
            libs: LibSet::new(),
            functions: FunctionSet::new(),
            total_samples: 0,
            timed_samples: HashMap::new(),
            frame_markers: Vec::new(),
            frame_graph_enabled: true,
        }
    }

    /// Load samples from an already-configured ReportLib (record file already set).
    pub fn load_record_file(&mut self, lib: &ReportLib) -> Result<()> {
        self.meta_info = lib.get_meta_info()?;
        self.cmdline = lib.get_record_cmd()?;
        self.arch = lib.get_arch()?;

        loop {
            let sample = match lib.get_next_sample() {
                Some(s) => s,
                None => break,
            };
            let raw_event = lib.get_event_of_current_sample();
            let symbol = lib.get_symbol_of_current_sample();
            let callchain = lib.get_callchain_of_current_sample();

            let event = self
                .events
                .entry(raw_event.name.clone())
                .or_insert_with(|| EventScope::new(raw_event.name.clone()));

            self.total_samples += 1;
            event.sample_count += 1;
            event.event_count += sample.period;

            let process = event.get_process(sample.pid);
            process.event_count += sample.period;

            let thread = process.get_thread(sample.tid, &sample.thread_comm);
            thread.event_count += sample.period;
            thread.sample_count += 1;

            // Build callstack
            let lib_id = match self.libs.get_lib_id(&symbol.dso_name) {
                Some(id) => id,
                None => {
                    let build_id = lib.get_build_id_for_path(&symbol.dso_name)?;
                    self.libs.add_lib(symbol.dso_name.clone(), build_id)
                }
            };
            let func_id = self.functions.get_func_id(
                lib_id,
                &symbol.symbol_name,
                symbol.symbol_addr,
                symbol.symbol_len,
            );
            let mut callstack = Vec::with_capacity(callchain.entries.len() + 1);
            callstack.push((lib_id, func_id, symbol.vaddr_in_file));

            for entry in &callchain.entries {
                let lib_id = match self.libs.get_lib_id(&entry.symbol.dso_name) {
                    Some(id) => id,
                    None => {
                        let build_id = lib.get_build_id_for_path(&entry.symbol.dso_name)?;
                        self.libs
                            .add_lib(entry.symbol.dso_name.clone(), build_id)
                    }
                };
                let func_id = self.functions.get_func_id(
                    lib_id,
                    &entry.symbol.symbol_name,
                    entry.symbol.symbol_addr,
                    entry.symbol.symbol_len,
                );
                callstack.push((lib_id, func_id, entry.symbol.vaddr_in_file));
            }

            if callstack.len() > MAX_CALLSTACK_LENGTH {
                callstack.truncate(MAX_CALLSTACK_LENGTH);
            }

            thread.add_callstack(sample.period, &callstack);

            // Collect timed samples for frame graph analysis.
            if self.frame_graph_enabled {
                let func_ids: Vec<i64> = callstack.iter().map(|&(_, fid, _)| fid).collect();
                let thread_samples = self
                    .timed_samples
                    .entry(raw_event.name.clone())
                    .or_default()
                    .entry((sample.pid, sample.tid))
                    .or_insert_with(|| {
                        ThreadSamples::new(sample.pid, sample.tid, sample.thread_comm.clone())
                    });
                let sample_type = if raw_event.name == "sched:sched_switch" {
                    frame_graph::SampleType::OffCpu
                } else {
                    frame_graph::SampleType::OnCpu
                };
                thread_samples.samples.push(TimedSample {
                    time: sample.time,
                    period: sample.period,
                    callstack_func_ids: func_ids,
                    sample_type,
                });
            }
        }

        // Update subtree event counts
        for event in self.events.values_mut() {
            for thread in event.threads_mut() {
                thread.update_subtree_event_count();
            }
        }

        info!("Loaded {} total samples so far", self.total_samples);
        Ok(())
    }

    /// Merge processes/threads by thread name.
    pub fn aggregate_by_thread_name(&mut self) {
        for event in self.events.values_mut() {
            let mut new_processes: HashMap<String, crate::model::ProcessScope> = HashMap::new();
            let old_processes: HashMap<u32, crate::model::ProcessScope> =
                std::mem::take(&mut event.processes);

            for (_, process) in old_processes {
                match new_processes.get_mut(&process.name) {
                    Some(existing) => existing.merge_by_thread_name(process),
                    None => {
                        new_processes.insert(process.name.clone(), process);
                    }
                }
            }
            event.processes = new_processes
                .into_values()
                .map(|p| (p.pid, p))
                .collect();
        }
    }

    /// Remove low-percent functions and callchain edges.
    pub fn limit_percents(&mut self, min_func_percent: f64, min_callchain_percent: f64) {
        let mut hit_func_ids: HashSet<i64> = HashSet::new();
        for event in self.events.values_mut() {
            let min_limit = event.event_count as f64 * min_func_percent * 0.01;
            let mut to_del_processes = Vec::new();
            for (&pid, process) in event.processes.iter_mut() {
                let mut to_del_threads = Vec::new();
                for (&tid, thread) in process.threads.iter_mut() {
                    if (thread.call_graph.subtree_event_count as f64) < min_limit {
                        to_del_threads.push(tid);
                    } else {
                        thread.limit_percents(min_limit, min_callchain_percent, &mut hit_func_ids);
                    }
                }
                for tid in to_del_threads {
                    process.threads.remove(&tid);
                }
                if process.threads.is_empty() {
                    to_del_processes.push(pid);
                }
            }
            for pid in to_del_processes {
                event.processes.remove(&pid);
            }
        }
        self.functions.trim_functions(&hit_func_ids);
    }

    /// Sort call graphs alphabetically by function name.
    pub fn sort_call_graph_by_function_name(&mut self) {
        let get_name = |func_id: i64| -> String { self.functions.get_func_name(func_id) };
        for event in self.events.values_mut() {
            for process in event.processes.values_mut() {
                for thread in process.threads.values_mut() {
                    thread.sort_call_graph_by_function_name(&get_name);
                }
            }
        }
    }

    /// Generate the complete record info JSON structure.
    pub fn gen_record_info(&self) -> RecordInfo {
        let timestamp = self.meta_info.get("timestamp");
        let record_time = if let Some(ts) = timestamp {
            if let Ok(secs) = ts.parse::<i64>() {
                chrono::DateTime::from_timestamp(secs, 0)
                    .map(|dt| {
                        dt.with_timezone(&chrono::Local)
                            .format("%Y-%m-%d (%A) %H:%M:%S")
                            .to_string()
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            }
        } else {
            chrono::Local::now()
                .format("%Y-%m-%d (%A) %H:%M:%S")
                .to_string()
        };

        let product_props = self.meta_info.get("product_props");
        let machine_type = if let Some(props) = product_props {
            let parts: Vec<&str> = props.splitn(3, ':').collect();
            if parts.len() == 3 {
                format!(
                    "{} ({}) by {}, arch {}",
                    parts[1], parts[2], parts[0], self.arch
                )
            } else {
                self.arch.clone()
            }
        } else {
            self.arch.clone()
        };

        let process_names = self.gen_process_names();
        let thread_names = self.gen_thread_names();
        let lib_list = self.gen_lib_list();
        let function_map = self.gen_function_map();
        let sample_info = self.gen_sample_info();
        let frame_graph_data = self.gen_frame_graph_data();

        RecordInfo {
            record_time,
            machine_type,
            android_version: self
                .meta_info
                .get("android_version")
                .cloned()
                .unwrap_or_default(),
            android_build_fingerprint: self
                .meta_info
                .get("android_build_fingerprint")
                .cloned()
                .unwrap_or_default(),
            kernel_version: self
                .meta_info
                .get("kernel_version")
                .cloned()
                .unwrap_or_default(),
            record_cmdline: self.cmdline.clone(),
            total_samples: self.total_samples,
            process_names,
            thread_names,
            lib_list,
            function_map,
            sample_info,
            source_files: Vec::new(),
            frame_graph_data,
        }
    }

    fn gen_process_names(&self) -> HashMap<u32, String> {
        let mut names = HashMap::new();
        for event in self.events.values() {
            for process in event.processes.values() {
                names.insert(process.pid, process.name.clone());
            }
        }
        names
    }

    fn gen_thread_names(&self) -> HashMap<u32, String> {
        let mut names = HashMap::new();
        for event in self.events.values() {
            for process in event.processes.values() {
                for thread in process.threads.values() {
                    names.insert(thread.tid, thread.name.clone());
                }
            }
        }
        names
    }

    fn gen_lib_list(&self) -> Vec<String> {
        self.libs
            .libs()
            .iter()
            .map(|lib| modify_text_for_html(&lib.name))
            .collect()
    }

    fn gen_function_map(&self) -> HashMap<i64, FuncData> {
        let mut map = HashMap::new();
        for func_id in self.functions.sorted_func_ids() {
            if let Some(function) = self.functions.get_func(func_id) {
                map.insert(
                    func_id,
                    FuncData {
                        l: function.lib_id,
                        f: modify_text_for_html(&function.func_name),
                    },
                );
            }
        }
        map
    }

    fn gen_sample_info(&self) -> Vec<EventScopeInfo> {
        self.events.values().map(|e| e.get_sample_info()).collect()
    }

    /// Generate frame graph data from collected timed samples.
    pub fn gen_frame_graph_data(&self) -> Vec<FrameGraphEventInfo> {
        if !self.frame_graph_enabled {
            return Vec::new();
        }

        let markers = if self.frame_markers.is_empty() {
            frame_graph::DEFAULT_MARKERS
                .iter()
                .map(|&(a, b)| (a.to_string(), b.to_string()))
                .collect::<Vec<_>>()
        } else {
            self.frame_markers.clone()
        };

        let get_name = |func_id: i64| -> String { self.functions.get_func_name(func_id) };
        let all_func_ids = self.functions.all_func_ids();

        // Check if both cpu-cycles and sched:sched_switch are present.
        let has_cpu_cycles = self.timed_samples.contains_key("cpu-cycles");
        let has_sched_switch = self.timed_samples.contains_key("sched:sched_switch");

        let mut result = Vec::new();

        if has_cpu_cycles && has_sched_switch {
            // Generate combined wall-clock frame graph.
            let combined = self.gen_combined_frame_graph(&markers, &get_name, &all_func_ids);
            if let Some(event_info) = combined {
                result.push(event_info);
            }
        }

        // Per-event frame graphs: use unified RHI boundaries.
        // All marker configs share the same func_substr, so resolve once.
        let marker_func_substr = &markers[0].1;
        let marker_fid =
            frame_graph::find_marker_func_id(&all_func_ids, marker_func_substr, &get_name);

        for (event_name, threads_map) in &self.timed_samples {
            let marker_fid = match marker_fid {
                Some(fid) => fid,
                None => continue,
            };

            // Find the RHI thread and compute global frame boundaries from it.
            let rhi_boundaries = {
                let rhi_thread = threads_map
                    .values()
                    .find(|ts| ts.thread_name.contains("RHIThread"));
                match rhi_thread {
                    Some(ts) => {
                        let mut sorted: Vec<TimedSample> = ts
                            .samples
                            .iter()
                            .map(|s| TimedSample {
                                time: s.time,
                                period: s.period,
                                callstack_func_ids: s.callstack_func_ids.clone(),
                                sample_type: s.sample_type.clone(),
                            })
                            .collect();
                        sorted.sort_by_key(|s| s.time);
                        frame_graph::compute_frame_boundaries(&sorted, marker_fid)
                    }
                    None => continue,
                }
            };
            if rhi_boundaries.is_empty() {
                continue;
            }

            let mut threads_info = Vec::new();

            for ((_pid, _tid), thread_samples) in threads_map {
                // Check if this thread matches any marker pattern.
                let matched = markers
                    .iter()
                    .any(|(pattern, _)| thread_samples.thread_name.contains(pattern.as_str()));
                if !matched {
                    continue;
                }

                let mut sorted_samples: Vec<TimedSample> = thread_samples
                    .samples
                    .iter()
                    .map(|s| TimedSample {
                        time: s.time,
                        period: s.period,
                        callstack_func_ids: s.callstack_func_ids.clone(),
                        sample_type: s.sample_type.clone(),
                    })
                    .collect();
                sorted_samples.sort_by_key(|s| s.time);

                let frames = frame_graph::analyze_frames_with_boundaries(
                    &sorted_samples,
                    &rhi_boundaries,
                );

                let marker_name = get_name(marker_fid);
                info!(
                    "FrameGraph: {} thread '{}' marker '{}' => {} frames",
                    event_name,
                    thread_samples.thread_name,
                    marker_name,
                    frames.len()
                );

                threads_info.push(frame_graph::FrameGraphThreadInfo {
                    pid: thread_samples.pid,
                    tid: thread_samples.tid,
                    thread_name: thread_samples.thread_name.clone(),
                    marker_func: marker_name,
                    marker_func_id: marker_fid,
                    frames,
                });
            }

            if !threads_info.is_empty() {
                result.push(FrameGraphEventInfo {
                    event_name: event_name.clone(),
                    threads: threads_info,
                });
            }
        }

        result
    }

    /// Generate a combined cpu-cycles + sched:sched_switch frame graph with wall-clock timing.
    ///
    /// Uses unified RHI boundaries: frame boundaries are computed from the RHI thread's
    /// merged samples and applied to all matched threads.
    fn gen_combined_frame_graph<F>(
        &self,
        markers: &[(String, String)],
        get_name: &F,
        all_func_ids: &[i64],
    ) -> Option<FrameGraphEventInfo>
    where
        F: Fn(i64) -> String,
    {
        let cpu_threads = self.timed_samples.get("cpu-cycles")?;
        let sched_threads = self.timed_samples.get("sched:sched_switch")?;

        // All markers share the same func_substr.
        let marker_func_substr = &markers[0].1;
        let marker_fid =
            frame_graph::find_marker_func_id(all_func_ids, marker_func_substr, get_name)?;

        // Find RHI thread and compute unified frame boundaries from its merged samples.
        let rhi_cpu = cpu_threads
            .iter()
            .find(|(_, ts)| ts.thread_name.contains("RHIThread"));
        let rhi_boundaries = match rhi_cpu {
            Some((&(pid, tid), rhi_cpu_samples)) => {
                let merged = if let Some(rhi_sched) = sched_threads.get(&(pid, tid)) {
                    frame_graph::merge_oncpu_offcpu_samples(
                        &rhi_cpu_samples.samples,
                        &rhi_sched.samples,
                    )
                } else {
                    let mut samples: Vec<TimedSample> = rhi_cpu_samples
                        .samples
                        .iter()
                        .map(|s| TimedSample {
                            time: s.time,
                            period: s.period,
                            callstack_func_ids: s.callstack_func_ids.clone(),
                            sample_type: frame_graph::SampleType::OnCpu,
                        })
                        .collect();
                    samples.sort_by_key(|s| s.time);
                    samples
                };
                frame_graph::compute_frame_boundaries(&merged, marker_fid)
            }
            None => return None,
        };

        if rhi_boundaries.is_empty() {
            return None;
        }

        let mut threads_info = Vec::new();

        for (&(pid, tid), cpu_thread_samples) in cpu_threads {
            // Check if this thread matches any marker pattern.
            let matched = markers
                .iter()
                .any(|(pattern, _)| cpu_thread_samples.thread_name.contains(pattern.as_str()));
            if !matched {
                continue;
            }

            // Merge on-CPU + off-CPU samples.
            let merged = if let Some(sched_thread_samples) = sched_threads.get(&(pid, tid)) {
                frame_graph::merge_oncpu_offcpu_samples(
                    &cpu_thread_samples.samples,
                    &sched_thread_samples.samples,
                )
            } else {
                let mut samples: Vec<TimedSample> = cpu_thread_samples
                    .samples
                    .iter()
                    .map(|s| TimedSample {
                        time: s.time,
                        period: s.period,
                        callstack_func_ids: s.callstack_func_ids.clone(),
                        sample_type: frame_graph::SampleType::OnCpu,
                    })
                    .collect();
                samples.sort_by_key(|s| s.time);
                samples
            };

            let frames = frame_graph::analyze_frames_wallclock_with_boundaries(
                &merged,
                &rhi_boundaries,
            );

            let marker_name = get_name(marker_fid);
            info!(
                "FrameGraph: combined thread '{}' marker '{}' => {} frames",
                cpu_thread_samples.thread_name,
                marker_name,
                frames.len()
            );

            threads_info.push(frame_graph::FrameGraphThreadInfo {
                pid: cpu_thread_samples.pid,
                tid: cpu_thread_samples.tid,
                thread_name: cpu_thread_samples.thread_name.clone(),
                marker_func: marker_name,
                marker_func_id: marker_fid,
                frames,
            });
        }

        if threads_info.is_empty() {
            return None;
        }

        Some(FrameGraphEventInfo {
            event_name: "cpu-cycles + sched:sched_switch (combined)".to_string(),
            threads: threads_info,
        })
    }
}

#[derive(Serialize)]
pub struct FuncData {
    pub l: i64,
    pub f: String,
}

#[derive(Serialize)]
pub struct RecordInfo {
    #[serde(rename = "recordTime")]
    pub record_time: String,
    #[serde(rename = "machineType")]
    pub machine_type: String,
    #[serde(rename = "androidVersion")]
    pub android_version: String,
    #[serde(rename = "androidBuildFingerprint")]
    pub android_build_fingerprint: String,
    #[serde(rename = "kernelVersion")]
    pub kernel_version: String,
    #[serde(rename = "recordCmdline")]
    pub record_cmdline: String,
    #[serde(rename = "totalSamples")]
    pub total_samples: u64,
    #[serde(rename = "processNames")]
    pub process_names: HashMap<u32, String>,
    #[serde(rename = "threadNames")]
    pub thread_names: HashMap<u32, String>,
    #[serde(rename = "libList")]
    pub lib_list: Vec<String>,
    #[serde(rename = "functionMap")]
    pub function_map: HashMap<i64, FuncData>,
    #[serde(rename = "sampleInfo")]
    pub sample_info: Vec<EventScopeInfo>,
    #[serde(rename = "sourceFiles")]
    pub source_files: Vec<serde_json::Value>,
    #[serde(rename = "frameGraphData", skip_serializing_if = "Vec::is_empty")]
    pub frame_graph_data: Vec<FrameGraphEventInfo>,
}

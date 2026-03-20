use std::collections::HashMap;

use serde::ser::{SerializeSeq, Serializer};
use serde::Serialize;

/// Default UE marker configurations: (thread_name_pattern, func_substring).
///
/// All threads use the same marker function (`FVulkanViewport::Present`) so that
/// frame boundaries are aligned across threads — the RHI thread's Present timestamps
/// define global frame boundaries applied to every thread.
pub const DEFAULT_MARKERS: &[(&str, &str)] = &[
    ("GameThread", "FVulkanViewport::Present"),
    ("RHIThread", "FVulkanViewport::Present"),
    ("RenderThread", "FVulkanViewport::Present"),
];

/// Whether a sample represents on-CPU or off-CPU activity.
#[derive(Clone, Debug, PartialEq)]
pub enum SampleType {
    OnCpu,
    OffCpu,
}

/// A raw sample with timestamp and callstack function IDs.
pub struct TimedSample {
    pub time: u64,
    pub period: u64,
    /// Function IDs in the callstack, leaf first (same order as `add_callstack`).
    pub callstack_func_ids: Vec<i64>,
    pub sample_type: SampleType,
}

/// Per-thread collection of timed samples.
pub struct ThreadSamples {
    pub pid: u32,
    pub tid: u32,
    pub thread_name: String,
    pub samples: Vec<TimedSample>,
}

impl ThreadSamples {
    pub fn new(pid: u32, tid: u32, thread_name: String) -> Self {
        Self {
            pid,
            tid,
            thread_name,
            samples: Vec::new(),
        }
    }
}

/// Serializable frame graph info for one event type.
#[derive(Serialize)]
pub struct FrameGraphEventInfo {
    #[serde(rename = "eventName")]
    pub event_name: String,
    pub threads: Vec<FrameGraphThreadInfo>,
}

/// Serializable frame graph info for one thread.
#[derive(Serialize)]
pub struct FrameGraphThreadInfo {
    pub pid: u32,
    pub tid: u32,
    #[serde(rename = "threadName")]
    pub thread_name: String,
    #[serde(rename = "markerFunc")]
    pub marker_func: String,
    #[serde(rename = "markerFuncId")]
    pub marker_func_id: i64,
    pub frames: Vec<FrameEntry>,
}

/// A single frame: serialized as `[total_period, [fid, self, subtree, ...]]`.
pub struct FrameEntry {
    pub total_period: u64,
    pub func_data: Vec<i64>,
}

impl Serialize for FrameEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.total_period)?;
        seq.serialize_element(&self.func_data)?;
        seq.end()
    }
}

/// Merge gap threshold: marker appearances within this interval are considered the same call.
const MARKER_GAP_NS: u64 = 1_000_000; // 1ms

/// Find the marker function ID in a set of function IDs by matching the function name substring.
pub fn find_marker_func_id<F>(func_ids: &[i64], marker_substr: &str, get_name: &F) -> Option<i64>
where
    F: Fn(i64) -> String,
{
    for &fid in func_ids {
        let name = get_name(fid);
        if name.contains(marker_substr) {
            return Some(fid);
        }
    }
    None
}

/// Merge on-CPU and off-CPU samples for the same thread, sorted by timestamp.
/// For off-CPU samples, the period is recalculated as the gap to the next sample (duration of sleep).
/// The last off-CPU sample gets period = 0 (no way to know when it woke up).
pub fn merge_oncpu_offcpu_samples(
    oncpu: &[TimedSample],
    offcpu: &[TimedSample],
) -> Vec<TimedSample> {
    let mut merged: Vec<TimedSample> = Vec::with_capacity(oncpu.len() + offcpu.len());

    for s in oncpu {
        merged.push(TimedSample {
            time: s.time,
            period: s.period,
            callstack_func_ids: s.callstack_func_ids.clone(),
            sample_type: SampleType::OnCpu,
        });
    }
    for s in offcpu {
        merged.push(TimedSample {
            time: s.time,
            period: 0, // will be filled below
            callstack_func_ids: s.callstack_func_ids.clone(),
            sample_type: SampleType::OffCpu,
        });
    }

    merged.sort_by_key(|s| s.time);

    // Recalculate off-CPU durations: gap from this off-CPU sample to the next sample.
    for i in 0..merged.len() {
        if merged[i].sample_type == SampleType::OffCpu && i + 1 < merged.len() {
            merged[i].period = merged[i + 1].time.saturating_sub(merged[i].time);
        }
    }

    merged
}

/// Compute frame boundary timestamps from samples containing the marker function.
///
/// Returns a sorted `Vec<u64>` of frame-start timestamps (merged within `MARKER_GAP_NS`).
/// At least 2 boundaries are needed to form 1 frame; returns empty if fewer.
pub fn compute_frame_boundaries(samples: &[TimedSample], marker_func_id: i64) -> Vec<u64> {
    let mut boundary_times: Vec<u64> = Vec::new();
    for s in samples {
        if s.callstack_func_ids.contains(&marker_func_id) {
            boundary_times.push(s.time);
        }
    }

    if boundary_times.is_empty() {
        return Vec::new();
    }

    // Merge adjacent boundary times within MARKER_GAP_NS into single boundaries.
    let mut frame_starts: Vec<u64> = Vec::new();
    frame_starts.push(boundary_times[0]);
    for i in 1..boundary_times.len() {
        if boundary_times[i] - boundary_times[i - 1] > MARKER_GAP_NS {
            frame_starts.push(boundary_times[i]);
        }
    }

    if frame_starts.len() < 2 {
        return Vec::new();
    }

    frame_starts
}

/// Analyze samples using externally provided frame boundaries.
///
/// `total_period` for each frame = sum of sample periods within `[start, end)`.
pub fn analyze_frames_with_boundaries(
    samples: &[TimedSample],
    frame_starts: &[u64],
) -> Vec<FrameEntry> {
    if frame_starts.len() < 2 {
        return Vec::new();
    }

    let mut frames = Vec::with_capacity(frame_starts.len() - 1);
    let mut sample_idx = 0;

    for fi in 0..frame_starts.len() - 1 {
        let start = frame_starts[fi];
        let end = frame_starts[fi + 1];

        while sample_idx < samples.len() && samples[sample_idx].time < start {
            sample_idx += 1;
        }

        let mut total_period: u64 = 0;
        let mut func_stats: HashMap<i64, (u64, u64)> = HashMap::new();

        let mut si = sample_idx;
        while si < samples.len() && samples[si].time < end {
            let s = &samples[si];
            total_period += s.period;

            let mut seen = std::collections::HashSet::new();
            for (i, &fid) in s.callstack_func_ids.iter().enumerate() {
                if !seen.insert(fid) {
                    continue;
                }
                let entry = func_stats.entry(fid).or_insert((0, 0));
                entry.1 += s.period;
                if i == 0 {
                    entry.0 += s.period;
                }
            }
            si += 1;
        }

        let mut func_data = Vec::with_capacity(func_stats.len() * 3);
        for (fid, (self_ns, subtree_ns)) in &func_stats {
            func_data.push(*fid);
            func_data.push(*self_ns as i64);
            func_data.push(*subtree_ns as i64);
        }

        frames.push(FrameEntry {
            total_period,
            func_data,
        });
    }

    frames
}

/// Analyze samples using externally provided frame boundaries with wall-clock timing.
///
/// `total_period` for each frame = `end - start` (wall-clock duration),
/// while per-function stats still use each sample's period.
pub fn analyze_frames_wallclock_with_boundaries(
    samples: &[TimedSample],
    frame_starts: &[u64],
) -> Vec<FrameEntry> {
    if frame_starts.len() < 2 {
        return Vec::new();
    }

    let mut frames = Vec::with_capacity(frame_starts.len() - 1);
    let mut sample_idx = 0;

    for fi in 0..frame_starts.len() - 1 {
        let start = frame_starts[fi];
        let end = frame_starts[fi + 1];

        while sample_idx < samples.len() && samples[sample_idx].time < start {
            sample_idx += 1;
        }

        let total_period = end - start;
        let mut func_stats: HashMap<i64, (u64, u64)> = HashMap::new();

        let mut si = sample_idx;
        while si < samples.len() && samples[si].time < end {
            let s = &samples[si];
            let mut seen = std::collections::HashSet::new();
            for (i, &fid) in s.callstack_func_ids.iter().enumerate() {
                if !seen.insert(fid) {
                    continue;
                }
                let entry = func_stats.entry(fid).or_insert((0, 0));
                entry.1 += s.period;
                if i == 0 {
                    entry.0 += s.period;
                }
            }
            si += 1;
        }

        let mut func_data = Vec::with_capacity(func_stats.len() * 3);
        for (fid, (self_ns, subtree_ns)) in &func_stats {
            func_data.push(*fid);
            func_data.push(*self_ns as i64);
            func_data.push(*subtree_ns as i64);
        }

        frames.push(FrameEntry {
            total_period,
            func_data,
        });
    }

    frames
}



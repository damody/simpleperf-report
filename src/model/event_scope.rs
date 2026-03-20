use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;
use serde::Serialize;

use super::call_node::CallNode;
use super::lib_scope::{trim_lib_functions, LibScope, LibScopeInfo};

/// Top-level scope for one event type.
pub struct EventScope {
    pub name: String,
    pub processes: HashMap<u32, ProcessScope>,
    pub sample_count: u64,
    pub event_count: u64,
}

impl EventScope {
    pub fn new(name: String) -> Self {
        Self {
            name,
            processes: HashMap::new(),
            sample_count: 0,
            event_count: 0,
        }
    }

    pub fn get_process(&mut self, pid: u32) -> &mut ProcessScope {
        self.processes
            .entry(pid)
            .or_insert_with(|| ProcessScope::new(pid))
    }

    pub fn get_sample_info(&self) -> EventScopeInfo {
        let mut processes: Vec<_> = self.processes.values().collect();
        processes.sort_by(|a, b| b.event_count.cmp(&a.event_count));
        EventScopeInfo {
            event_name: self.name.clone(),
            event_count: self.event_count,
            processes: processes.iter().map(|p| p.get_sample_info()).collect(),
        }
    }

    /// Iterate all threads across all processes.
    pub fn threads_mut(&mut self) -> impl Iterator<Item = &mut ThreadScope> {
        self.processes
            .values_mut()
            .flat_map(|p| p.threads.values_mut())
    }
}

/// Per-process scope.
pub struct ProcessScope {
    pub pid: u32,
    pub name: String,
    pub event_count: u64,
    pub threads: HashMap<u32, ThreadScope>,
}

impl ProcessScope {
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            name: String::new(),
            event_count: 0,
            threads: HashMap::new(),
        }
    }

    pub fn get_thread(&mut self, tid: u32, thread_name: &str) -> &mut ThreadScope {
        let thread = self
            .threads
            .entry(tid)
            .or_insert_with(|| ThreadScope::new(tid));
        thread.name = thread_name.to_string();
        if self.pid == tid {
            self.name = thread_name.to_string();
        }
        thread
    }

    pub fn get_sample_info(&self) -> ProcessScopeInfo {
        let mut threads: Vec<_> = self.threads.values().collect();
        threads.sort_by(|a, b| b.sample_count.cmp(&a.sample_count));
        ProcessScopeInfo {
            pid: self.pid,
            event_count: self.event_count,
            threads: threads.iter().map(|t| t.get_sample_info()).collect(),
        }
    }

    pub fn merge_by_thread_name(&mut self, other: ProcessScope) {
        self.event_count += other.event_count;
        let all_threads: Vec<ThreadScope> = self
            .threads
            .drain()
            .map(|(_, t)| t)
            .chain(other.threads.into_values())
            .collect();

        let mut by_name: HashMap<String, ThreadScope> = HashMap::new();
        for thread in all_threads {
            match by_name.get_mut(&thread.name) {
                Some(existing) => existing.merge(thread),
                None => {
                    by_name.insert(thread.name.clone(), thread);
                }
            }
        }
        self.threads = by_name
            .into_values()
            .map(|t| (t.tid, t))
            .collect();
    }
}

/// Per-thread scope.
pub struct ThreadScope {
    pub tid: u32,
    pub name: String,
    pub event_count: u64,
    pub sample_count: u64,
    pub libs: IndexMap<i64, LibScope>,
    pub call_graph: CallNode,
    pub reverse_call_graph: CallNode,
}

impl ThreadScope {
    pub fn new(tid: u32) -> Self {
        Self {
            tid,
            name: String::new(),
            event_count: 0,
            sample_count: 0,
            libs: IndexMap::new(),
            call_graph: CallNode::new(-1),
            reverse_call_graph: CallNode::new(-1),
        }
    }

    /// Add a callstack to this thread.
    /// `callstack` is a list of (lib_id, func_id, vaddr).
    /// callstack[0] is the leaf (current PC), callstack[N] is the caller.
    pub fn add_callstack(&mut self, event_count: u64, callstack: &[(i64, i64, u64)]) {
        let mut hit_func_ids = HashSet::new();

        for (i, &(lib_id, func_id, _addr)) in callstack.iter().enumerate() {
            if !hit_func_ids.insert(func_id) {
                continue; // skip recursive duplicate
            }

            let lib = self
                .libs
                .entry(lib_id)
                .or_insert_with(|| LibScope::new(lib_id));
            if i == 0 {
                lib.event_count += event_count;
            }
            let function = lib.get_function(func_id);
            function.subtree_event_count += event_count;
            if i == 0 {
                function.event_count += event_count;
                function.sample_count += 1;
            }
        }

        // Build forward call graph (root→leaf)
        let mut node = &mut self.call_graph;
        for &(_, func_id, _) in callstack.iter().rev() {
            node = node.get_child(func_id);
        }
        node.event_count += event_count;

        // Build reverse call graph (leaf→root)
        let mut node = &mut self.reverse_call_graph;
        for &(_, func_id, _) in callstack.iter() {
            node = node.get_child(func_id);
        }
        node.event_count += event_count;
    }

    pub fn update_subtree_event_count(&mut self) {
        self.call_graph.update_subtree_event_count();
        self.reverse_call_graph.update_subtree_event_count();
    }

    pub fn limit_percents(
        &mut self,
        min_func_limit: f64,
        min_callchain_percent: f64,
        hit_func_ids: &mut HashSet<i64>,
    ) {
        for lib in self.libs.values_mut() {
            trim_lib_functions(lib, min_func_limit, hit_func_ids);
        }
        let min_limit = min_callchain_percent * 0.01 * self.call_graph.subtree_event_count as f64;
        self.call_graph.cut_edge(min_limit, hit_func_ids);
        self.reverse_call_graph.cut_edge(min_limit, hit_func_ids);
    }

    pub fn get_sample_info(&self) -> ThreadScopeInfo {
        ThreadScopeInfo {
            tid: self.tid,
            event_count: self.event_count,
            sample_count: self.sample_count,
            libs: self.libs.values().map(|l| l.gen_sample_info()).collect(),
            g: self.call_graph.gen_sample_info(),
            rg: self.reverse_call_graph.gen_sample_info(),
        }
    }

    pub fn merge(&mut self, other: ThreadScope) {
        self.event_count += other.event_count;
        self.sample_count += other.sample_count;
        for (lib_id, lib) in other.libs {
            match self.libs.get_mut(&lib_id) {
                Some(existing) => existing.merge(lib),
                None => {
                    self.libs.insert(lib_id, lib);
                }
            }
        }
        self.call_graph.merge(other.call_graph);
        self.reverse_call_graph.merge(other.reverse_call_graph);
    }

    pub fn sort_call_graph_by_function_name<F: Fn(i64) -> String>(&mut self, get_name: &F) {
        self.call_graph.sort_by_function_name(get_name);
        self.reverse_call_graph.sort_by_function_name(get_name);
    }
}

// --- Serializable info types ---

use super::call_node::CallNodeInfo;

#[derive(Serialize)]
pub struct EventScopeInfo {
    #[serde(rename = "eventName")]
    pub event_name: String,
    #[serde(rename = "eventCount")]
    pub event_count: u64,
    pub processes: Vec<ProcessScopeInfo>,
}

#[derive(Serialize)]
pub struct ProcessScopeInfo {
    pub pid: u32,
    #[serde(rename = "eventCount")]
    pub event_count: u64,
    pub threads: Vec<ThreadScopeInfo>,
}

#[derive(Serialize)]
pub struct ThreadScopeInfo {
    pub tid: u32,
    #[serde(rename = "eventCount")]
    pub event_count: u64,
    #[serde(rename = "sampleCount")]
    pub sample_count: u64,
    pub libs: Vec<LibScopeInfo>,
    pub g: CallNodeInfo,
    pub rg: CallNodeInfo,
}

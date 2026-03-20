use std::collections::HashSet;

use indexmap::IndexMap;
use serde::Serialize;

/// Per-library scope within a thread.
pub struct LibScope {
    pub lib_id: i64,
    pub event_count: u64,
    pub functions: IndexMap<i64, FunctionScope>,
}

impl LibScope {
    pub fn new(lib_id: i64) -> Self {
        Self {
            lib_id,
            event_count: 0,
            functions: IndexMap::new(),
        }
    }

    pub fn get_function(&mut self, func_id: i64) -> &mut FunctionScope {
        self.functions
            .entry(func_id)
            .or_insert_with(|| FunctionScope::new(func_id))
    }

    pub fn gen_sample_info(&self) -> LibScopeInfo {
        LibScopeInfo {
            lib_id: self.lib_id,
            event_count: self.event_count,
            functions: self.functions.values().map(|f| f.gen_sample_info()).collect(),
        }
    }

    pub fn merge(&mut self, other: LibScope) {
        self.event_count += other.event_count;
        for (func_id, function) in other.functions {
            match self.functions.get_mut(&func_id) {
                Some(existing) => existing.merge(function),
                None => {
                    self.functions.insert(func_id, function);
                }
            }
        }
    }
}

/// Per-function scope within a library.
pub struct FunctionScope {
    pub func_id: i64,
    pub sample_count: u64,
    pub event_count: u64,
    pub subtree_event_count: u64,
}

impl FunctionScope {
    pub fn new(func_id: i64) -> Self {
        Self {
            func_id,
            sample_count: 0,
            event_count: 0,
            subtree_event_count: 0,
        }
    }

    pub fn gen_sample_info(&self) -> FuncScopeInfo {
        FuncScopeInfo {
            f: self.func_id,
            c: vec![self.sample_count, self.event_count, self.subtree_event_count],
        }
    }

    pub fn merge(&mut self, other: FunctionScope) {
        self.sample_count += other.sample_count;
        self.event_count += other.event_count;
        self.subtree_event_count += other.subtree_event_count;
    }
}

/// Trim functions below threshold from a LibScope.
pub fn trim_lib_functions(lib: &mut LibScope, min_limit: f64, hit_func_ids: &mut HashSet<i64>) {
    lib.functions.retain(|_, function| {
        if (function.subtree_event_count as f64) < min_limit {
            false
        } else {
            hit_func_ids.insert(function.func_id);
            true
        }
    });
}

#[derive(Serialize)]
pub struct LibScopeInfo {
    #[serde(rename = "libId")]
    pub lib_id: i64,
    #[serde(rename = "eventCount")]
    pub event_count: u64,
    pub functions: Vec<FuncScopeInfo>,
}

#[derive(Serialize)]
pub struct FuncScopeInfo {
    pub f: i64,
    pub c: Vec<u64>,
}

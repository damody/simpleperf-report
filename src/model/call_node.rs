use std::collections::HashSet;

use indexmap::IndexMap;
use serde::Serialize;

/// A node in the call graph / reverse call graph tree.
pub struct CallNode {
    pub func_id: i64,
    pub event_count: u64,
    pub subtree_event_count: u64,
    pub children: IndexMap<i64, CallNode>,
}

impl CallNode {
    pub fn new(func_id: i64) -> Self {
        Self {
            func_id,
            event_count: 0,
            subtree_event_count: 0,
            children: IndexMap::new(),
        }
    }

    pub fn get_child(&mut self, func_id: i64) -> &mut CallNode {
        self.children
            .entry(func_id)
            .or_insert_with(|| CallNode::new(func_id))
    }

    /// Recursively compute subtree_event_count. Returns self.subtree_event_count.
    pub fn update_subtree_event_count(&mut self) -> u64 {
        self.subtree_event_count = self.event_count;
        for child in self.children.values_mut() {
            self.subtree_event_count += child.update_subtree_event_count();
        }
        self.subtree_event_count
    }

    /// Remove children whose subtree_event_count < min_limit.
    pub fn cut_edge(&mut self, min_limit: f64, hit_func_ids: &mut HashSet<i64>) {
        hit_func_ids.insert(self.func_id);
        self.children.retain(|_, child| {
            if (child.subtree_event_count as f64) < min_limit {
                false
            } else {
                child.cut_edge(min_limit, hit_func_ids);
                true
            }
        });
    }

    /// Generate JSON-compatible info.
    pub fn gen_sample_info(&self) -> CallNodeInfo {
        CallNodeInfo {
            e: self.event_count,
            s: self.subtree_event_count,
            f: self.func_id,
            c: self.children.values().map(|c| c.gen_sample_info()).collect(),
        }
    }

    /// Merge another node into this one.
    pub fn merge(&mut self, other: CallNode) {
        self.event_count += other.event_count;
        self.subtree_event_count += other.subtree_event_count;
        for (key, child) in other.children {
            match self.children.get_mut(&key) {
                Some(existing) => existing.merge(child),
                None => {
                    self.children.insert(key, child);
                }
            }
        }
    }

    /// Sort children by function name, recursively.
    pub fn sort_by_function_name<F: Fn(i64) -> String>(&mut self, get_name: &F) {
        if !self.children.is_empty() {
            self.children
                .sort_by(|a, _, b, _| get_name(*a).cmp(&get_name(*b)));
            for child in self.children.values_mut() {
                child.sort_by_function_name(get_name);
            }
        }
    }
}

#[derive(Serialize)]
pub struct CallNodeInfo {
    pub e: u64,
    pub s: u64,
    pub f: i64,
    pub c: Vec<CallNodeInfo>,
}

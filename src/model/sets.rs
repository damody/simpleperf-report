use std::collections::{HashMap, HashSet};

/// Information about a shared library.
pub struct LibInfo {
    pub name: String,
    pub build_id: String,
}

/// Collection of shared libraries.
pub struct LibSet {
    lib_name_to_id: HashMap<String, i64>,
    libs: Vec<LibInfo>,
}

impl LibSet {
    pub fn new() -> Self {
        Self {
            lib_name_to_id: HashMap::new(),
            libs: Vec::new(),
        }
    }

    pub fn get_lib_id(&self, name: &str) -> Option<i64> {
        self.lib_name_to_id.get(name).copied()
    }

    pub fn add_lib(&mut self, name: String, build_id: String) -> i64 {
        let id = self.libs.len() as i64;
        self.lib_name_to_id.insert(name.clone(), id);
        self.libs.push(LibInfo { name, build_id });
        id
    }

    pub fn get_lib(&self, id: i64) -> &LibInfo {
        &self.libs[id as usize]
    }

    pub fn libs(&self) -> &[LibInfo] {
        &self.libs
    }
}

/// A function in a shared library.
pub struct Function {
    pub lib_id: i64,
    pub func_name: String,
    pub func_id: i64,
    pub start_addr: u64,
    pub addr_len: u64,
}

/// Collection of functions.
pub struct FunctionSet {
    name_to_func: HashMap<(i64, String), i64>,
    id_to_func: HashMap<i64, Function>,
}

impl FunctionSet {
    pub fn new() -> Self {
        Self {
            name_to_func: HashMap::new(),
            id_to_func: HashMap::new(),
        }
    }

    pub fn get_func_id(
        &mut self,
        lib_id: i64,
        symbol_name: &str,
        symbol_addr: u64,
        symbol_len: u64,
    ) -> i64 {
        let key = (lib_id, symbol_name.to_string());
        if let Some(&id) = self.name_to_func.get(&key) {
            return id;
        }
        let func_id = self.id_to_func.len() as i64;
        let function = Function {
            lib_id,
            func_name: symbol_name.to_string(),
            func_id,
            start_addr: symbol_addr,
            addr_len: symbol_len,
        };
        self.name_to_func.insert(key, func_id);
        self.id_to_func.insert(func_id, function);
        func_id
    }

    pub fn get_func_name(&self, func_id: i64) -> String {
        self.id_to_func
            .get(&func_id)
            .map(|f| f.func_name.clone())
            .unwrap_or_default()
    }

    pub fn get_func(&self, func_id: i64) -> Option<&Function> {
        self.id_to_func.get(&func_id)
    }

    /// Remove functions not in `left_func_ids`.
    pub fn trim_functions(&mut self, left_func_ids: &HashSet<i64>) {
        self.id_to_func
            .retain(|id, _| left_func_ids.contains(id));
        // name_to_func is no longer needed after trimming
    }

    pub fn sorted_func_ids(&self) -> Vec<i64> {
        let mut ids: Vec<i64> = self.id_to_func.keys().copied().collect();
        ids.sort();
        ids
    }

    pub fn all_func_ids(&self) -> Vec<i64> {
        self.id_to_func.keys().copied().collect()
    }
}

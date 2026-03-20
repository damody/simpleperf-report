use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Cursor, Read as _};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use libloading::Library;

use super::types::*;

// Function pointer types for the DLL API
type CreateReportLibFn = unsafe extern "C" fn() -> *mut ReportLibStruct;
type DestroyReportLibFn = unsafe extern "C" fn(*mut ReportLibStruct);
type SetLogSeverityFn = unsafe extern "C" fn(*mut ReportLibStruct, *const c_char) -> bool;
type SetSymfsFn = unsafe extern "C" fn(*mut ReportLibStruct, *const c_char) -> bool;
type SetRecordFileFn = unsafe extern "C" fn(*mut ReportLibStruct, *const c_char) -> bool;
type ShowIpForUnknownSymbolFn = unsafe extern "C" fn(*mut ReportLibStruct);
type ShowArtFramesFn = unsafe extern "C" fn(*mut ReportLibStruct, bool);
type AddProguardMappingFileFn = unsafe extern "C" fn(*mut ReportLibStruct, *const c_char) -> bool;
type SetTraceOffCpuModeFn = unsafe extern "C" fn(*mut ReportLibStruct, *const c_char) -> bool;
type SetSampleFilterFn =
    unsafe extern "C" fn(*mut ReportLibStruct, *const *const c_char, usize) -> bool;
type AggregateThreadsFn =
    unsafe extern "C" fn(*mut ReportLibStruct, *const *const c_char, usize) -> bool;
type GetNextSampleFn = unsafe extern "C" fn(*mut ReportLibStruct) -> *const SampleStruct;
type GetEventOfCurrentSampleFn = unsafe extern "C" fn(*mut ReportLibStruct) -> *const EventStruct;
type GetSymbolOfCurrentSampleFn =
    unsafe extern "C" fn(*mut ReportLibStruct) -> *const SymbolStruct;
type GetCallChainOfCurrentSampleFn =
    unsafe extern "C" fn(*mut ReportLibStruct) -> *const CallChainStructure;
type GetBuildIdForPathFn =
    unsafe extern "C" fn(*mut ReportLibStruct, *const c_char) -> *const c_char;
type GetFeatureSectionFn =
    unsafe extern "C" fn(*mut ReportLibStruct, *const c_char) -> *const FeatureSectionStructure;

/// Cached function pointers from the DLL, resolved once at construction.
struct FnTable {
    destroy: DestroyReportLibFn,
    set_log_severity: SetLogSeverityFn,
    set_symfs: SetSymfsFn,
    set_record_file: SetRecordFileFn,
    show_ip_for_unknown_symbol: ShowIpForUnknownSymbolFn,
    show_art_frames: ShowArtFramesFn,
    add_proguard_mapping_file: AddProguardMappingFileFn,
    set_trace_offcpu_mode: SetTraceOffCpuModeFn,
    set_sample_filter: SetSampleFilterFn,
    aggregate_threads: AggregateThreadsFn,
    get_next_sample: GetNextSampleFn,
    get_event_of_current_sample: GetEventOfCurrentSampleFn,
    get_symbol_of_current_sample: GetSymbolOfCurrentSampleFn,
    get_callchain_of_current_sample: GetCallChainOfCurrentSampleFn,
    get_build_id_for_path: GetBuildIdForPathFn,
    get_feature_section: GetFeatureSectionFn,
}

/// Safe wrapper around `libsimpleperf_report.dll`.
/// All DLL function pointers are cached at construction time for performance.
pub struct ReportLib {
    _dep_lib: Option<Library>,
    _lib: Library,
    instance: *mut ReportLibStruct,
    fns: FnTable,
}

/// Copied sample data (owned strings).
pub struct Sample {
    pub pid: u32,
    pub tid: u32,
    pub thread_comm: String,
    pub period: u64,
}

/// Copied event data (owned string).
pub struct Event {
    pub name: String,
}

/// Copied symbol data (owned strings).
pub struct SymbolInfo {
    pub dso_name: String,
    pub vaddr_in_file: u64,
    pub symbol_name: String,
    pub symbol_addr: u64,
    pub symbol_len: u64,
}

/// A single callchain entry (owned strings).
pub struct CallChainEntry {
    pub symbol: SymbolInfo,
}

/// Callchain (owned).
pub struct CallChain {
    pub entries: Vec<CallChainEntry>,
}

unsafe fn ptr_to_string(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

fn resolve_dll_dir(exe_dir: &Path) -> PathBuf {
    let sub = exe_dir.join("bin").join("windows").join("x86_64");
    if sub.join("libsimpleperf_report.dll").exists() {
        return sub;
    }
    exe_dir.to_path_buf()
}

macro_rules! load_fn {
    ($lib:expr, $name:literal, $ty:ty) => {
        unsafe {
            *$lib
                .get::<$ty>($name)
                .with_context(|| {
                    format!(
                        "Symbol {:?} not found",
                        String::from_utf8_lossy($name)
                    )
                })?
        }
    };
}

impl ReportLib {
    /// Create a new ReportLib by loading the DLL and caching all function pointers.
    /// `dll_dir_hint`: directory containing (or parent of bin/windows/x86_64/) the DLLs.
    pub fn new(dll_dir_hint: &Path) -> Result<Self> {
        let dll_dir = resolve_dll_dir(dll_dir_hint);

        // Load dependent lib (libwinpthread-1.dll) first on Windows
        let dep_lib = {
            let dep_path = dll_dir.join("libwinpthread-1.dll");
            if dep_path.exists() {
                Some(unsafe {
                    Library::new(&dep_path)
                        .with_context(|| format!("Failed to load {:?}", dep_path))?
                })
            } else {
                None
            }
        };

        let lib_path = dll_dir.join("libsimpleperf_report.dll");
        let lib = unsafe {
            Library::new(&lib_path)
                .with_context(|| format!("Failed to load {:?}", lib_path))?
        };

        // Cache all function pointers once
        let fns = FnTable {
            destroy: load_fn!(lib, b"DestroyReportLib", DestroyReportLibFn),
            set_log_severity: load_fn!(lib, b"SetLogSeverity", SetLogSeverityFn),
            set_symfs: load_fn!(lib, b"SetSymfs", SetSymfsFn),
            set_record_file: load_fn!(lib, b"SetRecordFile", SetRecordFileFn),
            show_ip_for_unknown_symbol: load_fn!(
                lib,
                b"ShowIpForUnknownSymbol",
                ShowIpForUnknownSymbolFn
            ),
            show_art_frames: load_fn!(lib, b"ShowArtFrames", ShowArtFramesFn),
            add_proguard_mapping_file: load_fn!(
                lib,
                b"AddProguardMappingFile",
                AddProguardMappingFileFn
            ),
            set_trace_offcpu_mode: load_fn!(lib, b"SetTraceOffCpuMode", SetTraceOffCpuModeFn),
            set_sample_filter: load_fn!(lib, b"SetSampleFilter", SetSampleFilterFn),
            aggregate_threads: load_fn!(lib, b"AggregateThreads", AggregateThreadsFn),
            get_next_sample: load_fn!(lib, b"GetNextSample", GetNextSampleFn),
            get_event_of_current_sample: load_fn!(
                lib,
                b"GetEventOfCurrentSample",
                GetEventOfCurrentSampleFn
            ),
            get_symbol_of_current_sample: load_fn!(
                lib,
                b"GetSymbolOfCurrentSample",
                GetSymbolOfCurrentSampleFn
            ),
            get_callchain_of_current_sample: load_fn!(
                lib,
                b"GetCallChainOfCurrentSample",
                GetCallChainOfCurrentSampleFn
            ),
            get_build_id_for_path: load_fn!(lib, b"GetBuildIdForPath", GetBuildIdForPathFn),
            get_feature_section: load_fn!(lib, b"GetFeatureSection", GetFeatureSectionFn),
        };

        let create: CreateReportLibFn = load_fn!(lib, b"CreateReportLib", CreateReportLibFn);
        let instance = unsafe { create() };
        if instance.is_null() {
            bail!("CreateReportLib returned null");
        }

        Ok(Self {
            _dep_lib: dep_lib,
            _lib: lib,
            instance,
            fns,
        })
    }

    pub fn set_symfs(&self, dir: &str) -> Result<()> {
        let c = CString::new(dir)?;
        let ok = unsafe { (self.fns.set_symfs)(self.instance, c.as_ptr()) };
        if !ok {
            bail!("SetSymfs failed");
        }
        Ok(())
    }

    pub fn set_record_file(&self, path: &str) -> Result<()> {
        let c = CString::new(path)?;
        let ok = unsafe { (self.fns.set_record_file)(self.instance, c.as_ptr()) };
        if !ok {
            bail!("SetRecordFile({}) failed", path);
        }
        Ok(())
    }

    pub fn show_ip_for_unknown_symbol(&self) {
        unsafe { (self.fns.show_ip_for_unknown_symbol)(self.instance) };
    }

    pub fn show_art_frames(&self, show: bool) {
        unsafe { (self.fns.show_art_frames)(self.instance, show) };
    }

    pub fn add_proguard_mapping_file(&self, path: &str) -> Result<()> {
        let c = CString::new(path)?;
        let ok = unsafe { (self.fns.add_proguard_mapping_file)(self.instance, c.as_ptr()) };
        if !ok {
            bail!("AddProguardMappingFile({}) failed", path);
        }
        Ok(())
    }

    pub fn set_trace_offcpu_mode(&self, mode: &str) -> Result<()> {
        let c = CString::new(mode)?;
        let ok = unsafe { (self.fns.set_trace_offcpu_mode)(self.instance, c.as_ptr()) };
        if !ok {
            bail!("SetTraceOffCpuMode({}) failed", mode);
        }
        Ok(())
    }

    pub fn set_sample_filter(&self, filters: &[String]) -> Result<()> {
        let c_strings: Vec<CString> = filters
            .iter()
            .map(|s| CString::new(s.as_str()))
            .collect::<Result<_, _>>()?;
        let ptrs: Vec<*const c_char> = c_strings.iter().map(|s| s.as_ptr()).collect();
        let ok = unsafe { (self.fns.set_sample_filter)(self.instance, ptrs.as_ptr(), ptrs.len()) };
        if !ok {
            bail!("SetSampleFilter failed");
        }
        Ok(())
    }

    pub fn aggregate_threads(&self, regexes: &[String]) -> Result<()> {
        let c_strings: Vec<CString> = regexes
            .iter()
            .map(|s| CString::new(s.as_str()))
            .collect::<Result<_, _>>()?;
        let ptrs: Vec<*const c_char> = c_strings.iter().map(|s| s.as_ptr()).collect();
        let ok =
            unsafe { (self.fns.aggregate_threads)(self.instance, ptrs.as_ptr(), ptrs.len()) };
        if !ok {
            bail!("AggregateThreads failed");
        }
        Ok(())
    }

    /// Get next sample. Returns None when no more samples.
    #[inline]
    pub fn get_next_sample(&self) -> Option<Sample> {
        let ptr = unsafe { (self.fns.get_next_sample)(self.instance) };
        if ptr.is_null() {
            return None;
        }
        let s = unsafe { &*ptr };
        Some(Sample {
            pid: s.pid,
            tid: s.tid,
            thread_comm: unsafe { ptr_to_string(s.thread_comm) },
            period: s.period,
        })
    }

    #[inline]
    pub fn get_event_of_current_sample(&self) -> Event {
        let ptr = unsafe { (self.fns.get_event_of_current_sample)(self.instance) };
        let e = unsafe { &*ptr };
        Event {
            name: unsafe { ptr_to_string(e.name) },
        }
    }

    #[inline]
    pub fn get_symbol_of_current_sample(&self) -> SymbolInfo {
        let ptr = unsafe { (self.fns.get_symbol_of_current_sample)(self.instance) };
        let s = unsafe { &*ptr };
        SymbolInfo {
            dso_name: unsafe { ptr_to_string(s.dso_name) },
            vaddr_in_file: s.vaddr_in_file,
            symbol_name: unsafe { ptr_to_string(s.symbol_name) },
            symbol_addr: s.symbol_addr,
            symbol_len: s.symbol_len,
        }
    }

    #[inline]
    pub fn get_callchain_of_current_sample(&self) -> CallChain {
        let ptr = unsafe { (self.fns.get_callchain_of_current_sample)(self.instance) };
        let cc = unsafe { &*ptr };
        let mut entries = Vec::with_capacity(cc.nr as usize);
        for i in 0..cc.nr as usize {
            let entry = unsafe { &*cc.entries.add(i) };
            entries.push(CallChainEntry {
                symbol: SymbolInfo {
                    dso_name: unsafe { ptr_to_string(entry.symbol.dso_name) },
                    vaddr_in_file: entry.symbol.vaddr_in_file,
                    symbol_name: unsafe { ptr_to_string(entry.symbol.symbol_name) },
                    symbol_addr: entry.symbol.symbol_addr,
                    symbol_len: entry.symbol.symbol_len,
                },
            });
        }
        CallChain { entries }
    }

    pub fn get_build_id_for_path(&self, path: &str) -> Result<String> {
        let c = CString::new(path)?;
        let ptr = unsafe { (self.fns.get_build_id_for_path)(self.instance, c.as_ptr()) };
        Ok(unsafe { ptr_to_string(ptr) })
    }

    /// Parse the `cmdline` feature section -> record command string.
    pub fn get_record_cmd(&self) -> Result<String> {
        let c = CString::new("cmdline")?;
        let ptr = unsafe { (self.fns.get_feature_section)(self.instance, c.as_ptr()) };
        if ptr.is_null() {
            return Ok(String::new());
        }
        let fs = unsafe { &*ptr };
        if fs.data.is_null() || fs.data_size == 0 {
            return Ok(String::new());
        }
        let data =
            unsafe { std::slice::from_raw_parts(fs.data as *const u8, fs.data_size as usize) };
        let mut cur = Cursor::new(data);
        let mut buf4 = [0u8; 4];

        cur.read_exact(&mut buf4)?;
        let arg_count = u32::from_le_bytes(buf4) as usize;

        let mut args = Vec::with_capacity(arg_count);
        for _ in 0..arg_count {
            cur.read_exact(&mut buf4)?;
            let str_len = u32::from_le_bytes(buf4) as usize;
            let mut str_buf = vec![0u8; str_len];
            cur.read_exact(&mut str_buf)?;
            while str_buf.last() == Some(&0) {
                str_buf.pop();
            }
            let s = String::from_utf8_lossy(&str_buf).into_owned();
            if s.contains(' ') {
                args.push(format!("\"{}\"", s));
            } else {
                args.push(s);
            }
        }
        Ok(args.join(" "))
    }

    /// Parse the `arch` feature section.
    pub fn get_arch(&self) -> Result<String> {
        self.get_feature_string("arch")
    }

    /// Parse the `meta_info` feature section -> key/value pairs.
    pub fn get_meta_info(&self) -> Result<HashMap<String, String>> {
        let c = CString::new("meta_info")?;
        let ptr = unsafe { (self.fns.get_feature_section)(self.instance, c.as_ptr()) };
        if ptr.is_null() {
            return Ok(HashMap::new());
        }
        let fs = unsafe { &*ptr };
        if fs.data.is_null() || fs.data_size == 0 {
            return Ok(HashMap::new());
        }
        let data =
            unsafe { std::slice::from_raw_parts(fs.data as *const u8, fs.data_size as usize) };

        let mut strings = Vec::new();
        let mut current = Vec::new();
        for &byte in data {
            if byte == 0 {
                strings.push(String::from_utf8_lossy(&current).into_owned());
                current.clear();
            } else {
                current.push(byte);
            }
        }

        let mut map = HashMap::new();
        let mut i = 0;
        while i + 1 < strings.len() {
            map.insert(strings[i].clone(), strings[i + 1].clone());
            i += 2;
        }
        Ok(map)
    }

    fn get_feature_string(&self, name: &str) -> Result<String> {
        let c = CString::new(name)?;
        let ptr = unsafe { (self.fns.get_feature_section)(self.instance, c.as_ptr()) };
        if ptr.is_null() {
            return Ok(String::new());
        }
        let fs = unsafe { &*ptr };
        if fs.data.is_null() || fs.data_size == 0 {
            return Ok(String::new());
        }
        let data =
            unsafe { std::slice::from_raw_parts(fs.data as *const u8, fs.data_size as usize) };
        let mut cur = Cursor::new(data);
        let mut buf4 = [0u8; 4];
        cur.read_exact(&mut buf4)?;
        let str_len = u32::from_le_bytes(buf4) as usize;
        let mut str_buf = vec![0u8; str_len];
        cur.read_exact(&mut str_buf)?;
        while str_buf.last() == Some(&0) {
            str_buf.pop();
        }
        Ok(String::from_utf8_lossy(&str_buf).into_owned())
    }
}

impl Drop for ReportLib {
    fn drop(&mut self) {
        if !self.instance.is_null() {
            unsafe { (self.fns.destroy)(self.instance) };
            self.instance = std::ptr::null_mut();
        }
    }
}

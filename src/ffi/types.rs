use std::os::raw::c_char;

/// Opaque handle returned by CreateReportLib.
#[repr(C)]
pub struct ReportLibStruct {
    _private: [u8; 0],
}

/// A sample in perf.data.
#[repr(C)]
pub struct SampleStruct {
    pub ip: u64,
    pub pid: u32,
    pub tid: u32,
    pub thread_comm: *const c_char,
    pub time: u64,
    pub in_kernel: u32,
    pub cpu: u32,
    pub period: u64,
}

/// Format of a tracing field.
#[repr(C)]
pub struct TracingFieldFormatStruct {
    pub name: *const c_char,
    pub offset: u32,
    pub elem_size: u32,
    pub elem_count: u32,
    pub is_signed: u32,
    pub is_dynamic: u32,
}

/// Format of tracing data.
#[repr(C)]
pub struct TracingDataFormatStruct {
    pub size: u32,
    pub field_count: u32,
    pub fields: *const TracingFieldFormatStruct,
}

/// Event type of a sample.
#[repr(C)]
pub struct EventStruct {
    pub name: *const c_char,
    pub tracing_data_format: TracingDataFormatStruct,
}

/// A mapping area.
#[repr(C)]
pub struct MappingStruct {
    pub start: u64,
    pub end: u64,
    pub pgoff: u64,
}

/// Symbol info.
#[repr(C)]
pub struct SymbolStruct {
    pub dso_name: *const c_char,
    pub vaddr_in_file: u64,
    pub symbol_name: *const c_char,
    pub symbol_addr: u64,
    pub symbol_len: u64,
    pub mapping: *const MappingStruct,
}

/// A callchain entry.
#[repr(C)]
pub struct CallChainEntryStructure {
    pub ip: u64,
    pub symbol: SymbolStruct,
}

/// Callchain info.
#[repr(C)]
pub struct CallChainStructure {
    pub nr: u32,
    pub entries: *const CallChainEntryStructure,
}

/// Feature section.
#[repr(C)]
pub struct FeatureSectionStructure {
    pub data: *const c_char,
    pub data_size: u32,
}

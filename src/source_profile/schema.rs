#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaInfo {
    pub name: String,
    pub version: SchemaVersion,
    pub min_reader_version: SchemaVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProducerInfo {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub git_revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub manufacturer: Option<String>,
    #[serde(default)]
    pub android_release: Option<String>,
    #[serde(default)]
    pub android_sdk: Option<u32>,
    #[serde(default)]
    pub android_build_fingerprint: Option<String>,
    pub abi: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingInfo {
    pub started_utc: String,
    #[serde(default)]
    pub ended_utc: Option<String>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuSelection {
    #[serde(default)]
    pub selected_cpus: Vec<u32>,
    #[serde(default)]
    pub selected_clusters: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaneState {
    pub enabled: bool,
    pub available: bool,
    #[serde(default)]
    pub missing_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaneSelection {
    pub pmu: LaneState,
    pub spe: LaneState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureOptions {
    pub sample_period: u64,
    pub callchain_depth: u32,
    pub pmu_buffer_pages: u32,
    #[serde(default)]
    pub spe_aux_buffer_bytes: Option<u64>,
    #[serde(default)]
    pub duration_ms_requested: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRemap {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputHints {
    #[serde(default)]
    pub debug_elf_hints: Vec<String>,
    #[serde(default)]
    pub source_root_hints: Vec<String>,
    #[serde(default)]
    pub path_remaps: Vec<PathRemap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleFile {
    pub path: String,
    pub role: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPaths {
    pub html: String,
    pub xlsx: String,
    pub json: String,
    pub csv_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    #[serde(default)]
    pub files: Vec<BundleFile>,
    pub report_paths: ReportPaths,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProfileManifest {
    pub schema: SchemaInfo,
    pub producer: ProducerInfo,
    pub session_id: String,
    pub created_utc: String,
    pub recording: RecordingInfo,
    pub device: DeviceInfo,
    pub target: TargetInfo,
    pub cpu: CpuSelection,
    pub lanes: LaneSelection,
    pub capture_options: CaptureOptions,
    pub inputs: InputHints,
    pub artifacts: ArtifactInfo,
    #[serde(default)]
    pub compatibility: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProfileCapability {
    pub session_id: String,
    #[serde(default)]
    pub cpus: Vec<CpuCapability>,
    #[serde(default)]
    pub clusters: Vec<ClusterCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuCapability {
    pub cpu: u32,
    pub cluster: String,
    pub summary: CapabilitySummary,
    #[serde(default)]
    pub details: Vec<EventOpenDetail>,
    #[serde(default)]
    pub spe: Option<SpeDeviceMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterCapability {
    pub cluster: String,
    #[serde(default)]
    pub cpus: Vec<u32>,
    pub summary: CapabilitySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySummary {
    pub spe: bool,
    pub cycles: bool,
    pub instructions: bool,
    pub cache: bool,
    pub branch: bool,
    pub callchain: bool,
    pub source_sample_fields: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventOpenDetail {
    pub event_key: String,
    pub raw_event_name: String,
    pub event_source: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub config: String,
    pub supported: bool,
    #[serde(default)]
    pub errno: Option<i32>,
    #[serde(default)]
    pub failure_reason: Option<String>,
    #[serde(default)]
    pub kernel_path: Option<String>,
    #[serde(default)]
    pub sysfs_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeDeviceMetadata {
    pub device_path: String,
    #[serde(default)]
    pub aux_supported: bool,
    #[serde(default)]
    pub min_interval: Option<u64>,
    #[serde(default)]
    pub raw_metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProfileMaps {
    pub session_id: String,
    #[serde(default)]
    pub maps: Vec<ProcessMapRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMapRecord {
    pub mapping_id: u64,
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub device: String,
    pub inode: u64,
    #[serde(default)]
    pub path: Option<String>,
    pub module_id: String,
    pub load_bias: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProfileThreads {
    pub session_id: String,
    #[serde(default)]
    pub threads: Vec<ThreadRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadRecord {
    pub pid: u32,
    pub tid: u32,
    pub tgid: u32,
    pub thread_name: String,
    pub process_name: String,
    pub first_seen_utc: String,
    pub last_seen_utc: String,
    #[serde(default)]
    pub cpu_affinity: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProfileBuildIds {
    pub session_id: String,
    #[serde(default)]
    pub modules: Vec<BuildIdRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildIdRecord {
    pub module_id: String,
    pub runtime_path: String,
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub soname: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
    #[serde(default)]
    pub mtime_utc: Option<String>,
    #[serde(default)]
    pub debug_elf_candidate_path: Option<String>,
    pub match_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProfileLoss {
    pub session_id: String,
    #[serde(default)]
    pub totals: LossTotals,
    #[serde(default)]
    pub by_event_cpu: Vec<EventCpuLoss>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LossTotals {
    #[serde(default)]
    pub pmu_lost_records: u64,
    #[serde(default)]
    pub ring_buffer_overruns: u64,
    #[serde(default)]
    pub reader_lag_records: u64,
    #[serde(default)]
    pub spe_aux_truncations: u64,
    #[serde(default)]
    pub spe_decode_errors: u64,
    #[serde(default)]
    pub dropped_records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCpuLoss {
    pub event_key: String,
    pub cpu: u32,
    #[serde(default)]
    pub run_id: Option<String>,
    pub counts: LossTotals,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProfileEventCatalog {
    pub session_id: String,
    #[serde(default)]
    pub events: Vec<EventDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDefinition {
    pub event_key: String,
    pub display_name: String,
    pub source: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub config: String,
    #[serde(default)]
    pub arm_arch_event_code: Option<String>,
    pub sample_period: u64,
    pub unit: String,
    #[serde(default)]
    pub semantic_tags: Vec<String>,
    #[serde(default)]
    pub per_cpu_support: Vec<CpuSupportState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuSupportState {
    pub cpu: u32,
    pub supported: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProfileMetricCatalog {
    pub session_id: String,
    #[serde(default)]
    pub metrics: Vec<MetricDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDefinition {
    pub metric_key: String,
    pub display_name: String,
    pub formula: String,
    pub unit: String,
    #[serde(default)]
    pub required_events: Vec<String>,
    #[serde(default)]
    pub fallback_events: Vec<String>,
    pub missing_behavior: String,
    pub physical_meaning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProfileEventRuns {
    pub session_id: String,
    #[serde(default)]
    pub runs: Vec<EventRunRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRunRecord {
    pub run_id: String,
    pub event_key: String,
    pub cpu: u32,
    #[serde(default)]
    pub pid_scope: Option<u32>,
    #[serde(default)]
    pub tid_scope: Option<u32>,
    pub start_timestamp_ns: u64,
    pub end_timestamp_ns: u64,
    pub time_enabled_ns: u64,
    pub time_running_ns: u64,
    pub raw_count: u64,
    pub scaled_count: f64,
    pub sample_count: u64,
    pub sample_weight_sum: u64,
    pub lost_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_metadata_fixture(prefix: &str) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("source_profile")
            .join(prefix);
        serde_json::from_str::<SourceProfileManifest>(
            &std::fs::read_to_string(format!("{}/manifest.json", root.display())).unwrap(),
        )
        .unwrap();
        serde_json::from_str::<SourceProfileCapability>(
            &std::fs::read_to_string(format!("{}/capability.json", root.display())).unwrap(),
        )
        .unwrap();
        serde_json::from_str::<SourceProfileMaps>(
            &std::fs::read_to_string(format!("{}/maps.json", root.display())).unwrap(),
        )
        .unwrap();
        serde_json::from_str::<SourceProfileThreads>(
            &std::fs::read_to_string(format!("{}/threads.json", root.display())).unwrap(),
        )
        .unwrap();
        serde_json::from_str::<SourceProfileBuildIds>(
            &std::fs::read_to_string(format!("{}/build_ids.json", root.display())).unwrap(),
        )
        .unwrap();
        serde_json::from_str::<SourceProfileLoss>(
            &std::fs::read_to_string(format!("{}/loss.json", root.display())).unwrap(),
        )
        .unwrap();
        serde_json::from_str::<SourceProfileEventCatalog>(
            &std::fs::read_to_string(format!("{}/event_catalog.json", root.display())).unwrap(),
        )
        .unwrap();
        serde_json::from_str::<SourceProfileMetricCatalog>(
            &std::fs::read_to_string(format!("{}/metric_catalog.json", root.display())).unwrap(),
        )
        .unwrap();
        serde_json::from_str::<SourceProfileEventRuns>(
            &std::fs::read_to_string(format!("{}/event_runs.json", root.display())).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn parses_source_profile_metadata_fixtures() {
        parse_metadata_fixture("minimal");
        parse_metadata_fixture("cache");
        parse_metadata_fixture("stall");
        parse_metadata_fixture("missing");
        parse_metadata_fixture("unresolved");
        parse_metadata_fixture("loss");
        parse_metadata_fixture("arpg4_like");
    }
}

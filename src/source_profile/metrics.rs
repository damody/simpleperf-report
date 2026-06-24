#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::Result;

use super::instruction_class::InstructionClass;
use super::sample_stream::{for_each_pmu_sample, PmuSample, SampleStreamHeader, SpeSample};
use super::schema::SourceProfileEventCatalog;

#[derive(Debug, Clone)]
pub struct SourceLineKey {
    pub file: PathBuf,
    pub line: u32,
    pub function: Option<String>,
}

#[derive(Debug, Clone)]
pub enum MetricValue {
    Number(f64),
    Missing(String),
    Unresolved(String),
    Undefined(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricSemantics {
    Missing,
    Unresolved,
    Zero,
    NonZero,
    Undefined,
}

pub fn classify_metric_value(value: &MetricValue) -> MetricSemantics {
    match value {
        MetricValue::Number(value) if *value == 0.0 => MetricSemantics::Zero,
        MetricValue::Number(_) => MetricSemantics::NonZero,
        MetricValue::Missing(_) => MetricSemantics::Missing,
        MetricValue::Unresolved(_) => MetricSemantics::Unresolved,
        MetricValue::Undefined(_) => MetricSemantics::Undefined,
    }
}

pub fn source_line_metric_value(
    metric_key: &str,
    capability_available: bool,
    attribution_resolved: bool,
    numeric_value: Option<f64>,
) -> MetricValue {
    if !capability_available {
        return MetricValue::Missing(format!("{metric_key} capability is unavailable"));
    }
    if !attribution_resolved {
        return MetricValue::Unresolved(format!(
            "{metric_key} samples exist but source attribution failed"
        ));
    }
    MetricValue::Number(numeric_value.unwrap_or(0.0))
}

#[derive(Debug, Clone)]
pub struct SourceLineMetrics {
    pub key: SourceLineKey,
    pub code: String,
    pub values: BTreeMap<String, MetricValue>,
}

#[derive(Debug, Clone)]
pub struct SourceLineReportRow {
    pub file: PathBuf,
    pub line_number: u32,
    pub function: Option<String>,
    pub module_id: Option<String>,
    pub thread_ids: Vec<u32>,
    pub cpu_ids: Vec<u32>,
    pub code: String,
    pub pmu_values: BTreeMap<String, MetricValue>,
    pub spe_values: BTreeMap<String, MetricValue>,
    pub status_flags: Vec<LineStatusFlag>,
}

#[derive(Debug, Default, Clone)]
pub struct FileSummary {
    pub file: PathBuf,
    pub total_self_weight: f64,
    pub total_accumulated_weight: f64,
    pub sample_count: u64,
    pub nonzero_line_count: u64,
    pub unresolved_count: u64,
    pub missing_metric_count: u64,
}

pub fn summarize_files(rows: &[SourceLineReportRow]) -> BTreeMap<PathBuf, FileSummary> {
    let mut summaries = BTreeMap::new();
    for row in rows {
        let summary: &mut FileSummary =
            summaries
                .entry(row.file.clone())
                .or_insert_with(|| FileSummary {
                    file: row.file.clone(),
                    ..FileSummary::default()
                });
        let mut row_has_nonzero = false;
        for value in row.pmu_values.values().chain(row.spe_values.values()) {
            match classify_metric_value(value) {
                MetricSemantics::NonZero => {
                    row_has_nonzero = true;
                    if let MetricValue::Number(value) = value {
                        summary.total_self_weight += *value;
                    }
                }
                MetricSemantics::Missing => summary.missing_metric_count += 1,
                MetricSemantics::Unresolved => summary.unresolved_count += 1,
                MetricSemantics::Zero | MetricSemantics::Undefined => {}
            }
        }
        if row_has_nonzero {
            summary.nonzero_line_count += 1;
            summary.sample_count += 1;
        }
    }
    summaries
}

#[derive(Debug, Default, Clone)]
pub struct FunctionSummary {
    pub function: String,
    pub file: PathBuf,
    pub line_start: u32,
    pub line_end: u32,
    pub module_id: Option<String>,
    pub self_weight: f64,
    pub accumulated_weight: f64,
    pub sample_count: u64,
    pub hot_lines: Vec<u32>,
}

pub fn summarize_functions(
    rows: &[SourceLineReportRow],
) -> BTreeMap<(PathBuf, String), FunctionSummary> {
    let mut summaries = BTreeMap::new();
    for row in rows {
        let function = row
            .function
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        let key = (row.file.clone(), function.clone());
        let summary: &mut FunctionSummary =
            summaries.entry(key).or_insert_with(|| FunctionSummary {
                function,
                file: row.file.clone(),
                line_start: row.line_number,
                line_end: row.line_number,
                module_id: row.module_id.clone(),
                ..FunctionSummary::default()
            });
        summary.line_start = summary.line_start.min(row.line_number);
        summary.line_end = summary.line_end.max(row.line_number);

        let mut row_self = 0.0;
        for value in row.pmu_values.values().chain(row.spe_values.values()) {
            if let MetricValue::Number(value) = value {
                row_self += *value;
            }
        }
        if row_self > 0.0 {
            summary.self_weight += row_self;
            summary.sample_count += 1;
            summary.hot_lines.push(row.line_number);
        }
    }
    summaries
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineStatusFlag {
    NonZero,
    Missing,
    Unresolved,
    Undefined,
    LossWarning,
}

impl SourceLineReportRow {
    pub fn refresh_status_flags(&mut self) {
        let mut flags = Vec::new();
        for value in self.pmu_values.values().chain(self.spe_values.values()) {
            match classify_metric_value(value) {
                MetricSemantics::Missing => push_unique(&mut flags, LineStatusFlag::Missing),
                MetricSemantics::Unresolved => push_unique(&mut flags, LineStatusFlag::Unresolved),
                MetricSemantics::Zero => {}
                MetricSemantics::NonZero => push_unique(&mut flags, LineStatusFlag::NonZero),
                MetricSemantics::Undefined => push_unique(&mut flags, LineStatusFlag::Undefined),
            }
        }
        self.status_flags = flags;
    }
}

fn push_unique(flags: &mut Vec<LineStatusFlag>, flag: LineStatusFlag) {
    if !flags.contains(&flag) {
        flags.push(flag);
    }
}

pub trait MetricAggregator {
    fn line_metrics(&self) -> &[SourceLineMetrics];
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct PercentageMetrics {
    pub p_pct: f64,
    pub acc_p_pct: f64,
    pub file_p_pct: f64,
    pub file_acc_p_pct: f64,
}

pub fn compute_percentages(
    self_weight: f64,
    accumulated_weight: f64,
    total_self_weight: f64,
    total_accumulated_weight: f64,
    file_self_weight: f64,
    file_accumulated_weight: f64,
) -> PercentageMetrics {
    PercentageMetrics {
        p_pct: percent(self_weight, total_self_weight),
        acc_p_pct: percent(accumulated_weight, total_accumulated_weight),
        file_p_pct: percent(self_weight, file_self_weight),
        file_acc_p_pct: percent(accumulated_weight, file_accumulated_weight),
    }
}

pub fn derive_pmu_metrics(
    weights: &BTreeMap<String, u64>,
    effective_time_seconds: Option<f64>,
) -> BTreeMap<String, MetricValue> {
    let mut values = BTreeMap::new();
    insert_ratio(
        &mut values,
        "cpi",
        weights,
        "cpu_cycles",
        "inst_retired",
        1.0,
    );
    insert_cache_hit_rate(
        &mut values,
        "l1d_cache_hit_rate",
        weights,
        "l1d_cache_access",
        "l1d_cache_refill",
    );
    insert_cache_hit_rate(
        &mut values,
        "l2d_cache_hit_rate",
        weights,
        "l2d_cache_access",
        "l2d_cache_refill",
    );
    insert_cache_hit_rate(
        &mut values,
        "l3d_cache_hit_rate",
        weights,
        "l3d_cache_access",
        "l3d_cache_refill",
    );
    insert_ratio(
        &mut values,
        "branch_miss_rate",
        weights,
        "branch_mispredict",
        "branch_retired",
        1.0,
    );
    insert_ratio(
        &mut values,
        "mpki",
        weights,
        "l1d_cache_refill",
        "inst_retired",
        1000.0,
    );

    insert_rate(
        &mut values,
        "mips",
        weights.get("inst_retired").copied(),
        effective_time_seconds,
        1_000_000.0,
    );
    insert_rate(
        &mut values,
        "mcps",
        weights.get("cpu_cycles").copied(),
        effective_time_seconds,
        1_000_000.0,
    );
    values
}

fn insert_ratio(
    values: &mut BTreeMap<String, MetricValue>,
    metric_key: &str,
    weights: &BTreeMap<String, u64>,
    numerator_key: &str,
    denominator_key: &str,
    scale: f64,
) {
    let Some(numerator) = weights.get(numerator_key).copied() else {
        values.insert(
            metric_key.to_string(),
            MetricValue::Missing(format!("{numerator_key} is missing")),
        );
        return;
    };
    let Some(denominator) = weights.get(denominator_key).copied() else {
        values.insert(
            metric_key.to_string(),
            MetricValue::Missing(format!("{denominator_key} is missing")),
        );
        return;
    };
    if denominator == 0 {
        values.insert(
            metric_key.to_string(),
            MetricValue::Undefined(format!("{denominator_key} is zero")),
        );
        return;
    }
    values.insert(
        metric_key.to_string(),
        MetricValue::Number(numerator as f64 / denominator as f64 * scale),
    );
}

fn insert_cache_hit_rate(
    values: &mut BTreeMap<String, MetricValue>,
    metric_key: &str,
    weights: &BTreeMap<String, u64>,
    access_key: &str,
    refill_key: &str,
) {
    let Some(access) = weights.get(access_key).copied() else {
        values.insert(
            metric_key.to_string(),
            MetricValue::Missing(format!("{access_key} is missing")),
        );
        return;
    };
    let Some(refill) = weights.get(refill_key).copied() else {
        values.insert(
            metric_key.to_string(),
            MetricValue::Missing(format!("{refill_key} is missing")),
        );
        return;
    };
    if access == 0 {
        values.insert(
            metric_key.to_string(),
            MetricValue::Undefined(format!("{access_key} is zero")),
        );
        return;
    }
    values.insert(
        metric_key.to_string(),
        MetricValue::Number((access.saturating_sub(refill)) as f64 / access as f64),
    );
}

fn insert_rate(
    values: &mut BTreeMap<String, MetricValue>,
    metric_key: &str,
    numerator: Option<u64>,
    seconds: Option<f64>,
    divisor: f64,
) {
    let Some(numerator) = numerator else {
        values.insert(
            metric_key.to_string(),
            MetricValue::Missing("required event is missing".to_string()),
        );
        return;
    };
    let Some(seconds) = seconds else {
        values.insert(
            metric_key.to_string(),
            MetricValue::Missing("effective time is missing".to_string()),
        );
        return;
    };
    if seconds <= 0.0 {
        values.insert(
            metric_key.to_string(),
            MetricValue::Undefined("effective time is zero".to_string()),
        );
        return;
    }
    values.insert(
        metric_key.to_string(),
        MetricValue::Number(numerator as f64 / seconds / divisor),
    );
}

fn percent(value: f64, denominator: f64) -> f64 {
    if denominator > 0.0 {
        value / denominator * 100.0
    } else {
        0.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PmuAddressKey {
    pub mapping_id: u64,
    pub ip: u64,
}

#[derive(Debug, Default, Clone)]
pub struct PmuAddressAggregate {
    pub sample_count: u64,
    pub cpus: BTreeSet<u32>,
    pub tids: BTreeSet<u32>,
    pub self_weight_by_event: BTreeMap<String, u64>,
    pub accumulated_weight_by_event: BTreeMap<String, u64>,
    pub self_samples_by_event: BTreeMap<String, u64>,
    pub accumulated_samples_by_event: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
pub struct PmuAggregateResult {
    pub header: SampleStreamHeader,
    pub rows: BTreeMap<PmuAddressKey, PmuAddressAggregate>,
    pub observed_cpus: BTreeSet<u32>,
    pub observed_event_keys: BTreeSet<String>,
    pub sample_count: u64,
}

pub fn aggregate_pmu_by_address(
    samples: &[PmuSample],
    event_catalog: &SourceProfileEventCatalog,
) -> BTreeMap<PmuAddressKey, PmuAddressAggregate> {
    let mut rows = BTreeMap::new();
    for sample in samples {
        aggregate_one_pmu_sample(&mut rows, sample, event_catalog);
    }
    rows
}

pub fn aggregate_pmu_file(
    path: &Path,
    event_catalog: &SourceProfileEventCatalog,
) -> Result<PmuAggregateResult> {
    let mut rows = BTreeMap::new();
    let mut observed_cpus = BTreeSet::new();
    let mut observed_event_keys = BTreeSet::new();
    let mut sample_count = 0_u64;
    let header = for_each_pmu_sample(path, |sample| {
        sample_count += 1;
        observed_cpus.insert(sample.cpu);
        if let Some(event) = event_catalog.events.get(sample.event_key_ref as usize) {
            observed_event_keys.insert(event.event_key.clone());
        }
        aggregate_one_pmu_sample(&mut rows, &sample, event_catalog);
        Ok(())
    })?;
    Ok(PmuAggregateResult {
        header,
        rows,
        observed_cpus,
        observed_event_keys,
        sample_count,
    })
}

fn aggregate_one_pmu_sample(
    rows: &mut BTreeMap<PmuAddressKey, PmuAddressAggregate>,
    sample: &PmuSample,
    event_catalog: &SourceProfileEventCatalog,
) {
    let event_key = event_catalog
        .events
        .get(sample.event_key_ref as usize)
        .map(|event| event.event_key.as_str())
        .unwrap_or("unknown_event")
        .to_string();
    let key = PmuAddressKey {
        mapping_id: sample.mapping_id,
        ip: sample.ip,
    };
    let row: &mut PmuAddressAggregate = rows.entry(key).or_default();
    row.sample_count += 1;
    row.cpus.insert(sample.cpu);
    row.tids.insert(sample.tid);
    *row.self_weight_by_event
        .entry(event_key.clone())
        .or_default() += sample.period_or_weight;
    *row.self_samples_by_event
        .entry(event_key.clone())
        .or_default() += 1;

    for callchain_ip in &sample.callchain_ips {
        let callchain_key = PmuAddressKey {
            mapping_id: sample.mapping_id,
            ip: *callchain_ip,
        };
        let callchain_row: &mut PmuAddressAggregate = rows.entry(callchain_key).or_default();
        callchain_row.cpus.insert(sample.cpu);
        callchain_row.tids.insert(sample.tid);
        *callchain_row
            .accumulated_weight_by_event
            .entry(event_key.clone())
            .or_default() += sample.period_or_weight;
        *callchain_row
            .accumulated_samples_by_event
            .entry(event_key.clone())
            .or_default() += 1;
    }
}

#[derive(Debug, Default, Clone)]
pub struct SpeAddressAggregate {
    pub cpus: BTreeSet<u32>,
    pub tids: BTreeSet<u32>,
    pub sample_count: u64,
    pub latency_cycles_sum: u64,
    pub latency_sample_count: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub branch_correct: u64,
    pub branch_mispredict: u64,
    pub data_source_counts: BTreeMap<u16, u64>,
    pub operation_flags_or: u32,
    pub event_flags_or: u64,
    pub decode_error_count: u64,
}

pub const SPE_OP_LOAD: u32 = 1 << 0;
pub const SPE_OP_STORE: u32 = 1 << 1;
pub const SPE_OP_BRANCH: u32 = 1 << 2;
pub const SPE_OP_OTHER: u32 = 1 << 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpeReportCategory {
    LoadL1,
    LoadL2,
    LoadL3,
    LoadLlc,
    LoadDram,
    LoadRemote,
    LoadIo,
    LoadUnknown,
    StoreL1,
    StoreL2,
    StoreL3,
    StoreLlc,
    StoreDram,
    StoreRemote,
    StoreIo,
    StoreUnknown,
    AtomicL1,
    AtomicL2,
    AtomicL3,
    AtomicDram,
    AtomicUnknown,
    BranchHit,
    BranchMiss,
    BranchUnknown,
    ComputeInt,
    ComputeFpSimd,
    ComputeCrypto,
    ComputeUnknown,
    FrontendOrDecode,
    SystemInstruction,
    ExceptionOrTrap,
    DecodeUnknown,
    DataSourceUnknown,
    OtherUnknown,
}

#[derive(Debug, Default, Clone)]
pub struct SpeCategoryAggregate {
    pub sample_count: u64,
    pub latency_cycles_sum: u64,
    pub latency_sample_count: u64,
    pub latency_cycles_square_sum: f64,
    pub latency_cycles_min: Option<u32>,
    pub latency_cycles_max: Option<u32>,
}

impl SpeCategoryAggregate {
    pub fn record_latency(&mut self, latency: u32) {
        self.latency_cycles_sum = self.latency_cycles_sum.saturating_add(u64::from(latency));
        self.latency_sample_count = self.latency_sample_count.saturating_add(1);
        let latency_f64 = f64::from(latency);
        self.latency_cycles_square_sum += latency_f64 * latency_f64;
        self.latency_cycles_min = Some(
            self.latency_cycles_min
                .map(|current| current.min(latency))
                .unwrap_or(latency),
        );
        self.latency_cycles_max = Some(
            self.latency_cycles_max
                .map(|current| current.max(latency))
                .unwrap_or(latency),
        );
    }

    pub fn merge_from(&mut self, other: &SpeCategoryAggregate) {
        self.sample_count = self.sample_count.saturating_add(other.sample_count);
        self.latency_cycles_sum = self
            .latency_cycles_sum
            .saturating_add(other.latency_cycles_sum);
        self.latency_sample_count = self
            .latency_sample_count
            .saturating_add(other.latency_sample_count);
        self.latency_cycles_square_sum += other.latency_cycles_square_sum;
        if let Some(value) = other.latency_cycles_min {
            self.latency_cycles_min = Some(
                self.latency_cycles_min
                    .map(|current| current.min(value))
                    .unwrap_or(value),
            );
        }
        if let Some(value) = other.latency_cycles_max {
            self.latency_cycles_max = Some(
                self.latency_cycles_max
                    .map(|current| current.max(value))
                    .unwrap_or(value),
            );
        }
    }

    pub fn avg_latency_cycles(&self) -> Option<f64> {
        (self.latency_sample_count > 0)
            .then(|| self.latency_cycles_sum as f64 / self.latency_sample_count as f64)
    }

    pub fn std_latency_cycles(&self) -> Option<f64> {
        let count = self.latency_sample_count;
        if count == 0 {
            return None;
        }
        let avg = self.latency_cycles_sum as f64 / count as f64;
        let variance = (self.latency_cycles_square_sum / count as f64) - (avg * avg);
        Some(variance.max(0.0).sqrt())
    }
}

#[derive(Debug, Default, Clone)]
pub struct SpeAddressCategoryAggregate {
    pub sample_count: u64,
    pub categories: BTreeMap<SpeReportCategory, SpeCategoryAggregate>,
    pub cpu_categories: BTreeMap<u32, BTreeMap<SpeReportCategory, SpeCategoryAggregate>>,
}

#[derive(Debug, Default, Clone)]
pub struct InstructionClassAddressAggregate {
    pub sample_count: u64,
    pub classes: BTreeMap<InstructionClass, SpeCategoryAggregate>,
    pub cpu_classes: BTreeMap<u32, BTreeMap<InstructionClass, SpeCategoryAggregate>>,
}

pub fn aggregate_spe_by_address(
    samples: &[SpeSample],
) -> BTreeMap<PmuAddressKey, SpeAddressAggregate> {
    let mut rows = BTreeMap::new();
    for sample in samples {
        let key = PmuAddressKey {
            mapping_id: sample.mapping_id,
            ip: sample.pc,
        };
        let row: &mut SpeAddressAggregate = rows.entry(key).or_default();
        row.cpus.insert(sample.cpu);
        row.tids.insert(sample.tid);
        row.sample_count += 1;
        if let Some(latency) = sample.latency_cycles {
            row.latency_cycles_sum += u64::from(latency);
            row.latency_sample_count += 1;
        }
        match sample.cache_result {
            1 => row.cache_hits += 1,
            2 => row.cache_misses += 1,
            _ => {}
        }
        match sample.branch_result {
            1 => row.branch_correct += 1,
            2 => row.branch_mispredict += 1,
            _ => {}
        }
        if sample.data_source != 0 {
            *row.data_source_counts
                .entry(sample.data_source)
                .or_default() += 1;
        }
        row.operation_flags_or |= sample.operation_flags;
        row.event_flags_or |= sample.event_flags;
        if sample.decode_status != 0 {
            row.decode_error_count += 1;
        }
    }
    rows
}

pub fn spe_category(sample: &SpeSample) -> SpeReportCategory {
    if sample.decode_status != 0 {
        return SpeReportCategory::DecodeUnknown;
    }
    if sample.operation_flags & (SPE_OP_LOAD | SPE_OP_STORE) == (SPE_OP_LOAD | SPE_OP_STORE) {
        return atomic_category(sample.data_source);
    }
    if sample.operation_flags & SPE_OP_LOAD != 0 {
        return load_category(sample.data_source);
    }
    if sample.operation_flags & SPE_OP_STORE != 0 {
        return store_category(sample.data_source);
    }
    if sample.operation_flags & SPE_OP_BRANCH != 0 {
        return match sample.branch_result {
            1 => SpeReportCategory::BranchHit,
            2 => SpeReportCategory::BranchMiss,
            _ => SpeReportCategory::BranchUnknown,
        };
    }
    if sample.operation_flags & SPE_OP_OTHER != 0 {
        return SpeReportCategory::ComputeUnknown;
    }
    SpeReportCategory::OtherUnknown
}

fn load_category(data_source: u16) -> SpeReportCategory {
    match data_source {
        u16::MAX => SpeReportCategory::LoadUnknown,
        0x00 => SpeReportCategory::LoadL1,
        0x08 => SpeReportCategory::LoadL2,
        0x09 | 0x0a => SpeReportCategory::LoadL3,
        0x0b => SpeReportCategory::LoadLlc,
        0x0c => SpeReportCategory::LoadRemote,
        0x0d | 0x0f => SpeReportCategory::LoadIo,
        0x0e => SpeReportCategory::LoadDram,
        _ => SpeReportCategory::LoadUnknown,
    }
}

fn store_category(data_source: u16) -> SpeReportCategory {
    match data_source {
        u16::MAX => SpeReportCategory::StoreUnknown,
        0x00 => SpeReportCategory::StoreL1,
        0x08 => SpeReportCategory::StoreL2,
        0x09 | 0x0a => SpeReportCategory::StoreL3,
        0x0b => SpeReportCategory::StoreLlc,
        0x0c => SpeReportCategory::StoreRemote,
        0x0d | 0x0f => SpeReportCategory::StoreIo,
        0x0e => SpeReportCategory::StoreDram,
        _ => SpeReportCategory::StoreUnknown,
    }
}

fn atomic_category(data_source: u16) -> SpeReportCategory {
    match data_source {
        0x00 => SpeReportCategory::AtomicL1,
        0x08 => SpeReportCategory::AtomicL2,
        0x09 | 0x0a | 0x0b => SpeReportCategory::AtomicL3,
        0x0e => SpeReportCategory::AtomicDram,
        _ => SpeReportCategory::AtomicUnknown,
    }
}

pub fn aggregate_spe_categories_by_address(
    samples: &[SpeSample],
) -> BTreeMap<PmuAddressKey, SpeAddressCategoryAggregate> {
    let mut rows = BTreeMap::new();
    for sample in samples {
        let key = PmuAddressKey {
            mapping_id: sample.mapping_id,
            ip: sample.pc,
        };
        let row: &mut SpeAddressCategoryAggregate = rows.entry(key).or_default();
        row.sample_count += 1;
        let category = spe_category(sample);
        let category_row = row.categories.entry(category).or_default();
        category_row.sample_count += 1;
        if let Some(latency) = sample.latency_cycles {
            category_row.record_latency(latency);
        }
        let cpu_category_row = row
            .cpu_categories
            .entry(sample.cpu)
            .or_default()
            .entry(category)
            .or_default();
        cpu_category_row.sample_count += 1;
        if let Some(latency) = sample.latency_cycles {
            cpu_category_row.record_latency(latency);
        }
    }
    rows
}

pub fn aggregate_instruction_classes_by_address(
    samples: &[SpeSample],
    mut classify: impl FnMut(&SpeSample) -> InstructionClass,
) -> BTreeMap<PmuAddressKey, InstructionClassAddressAggregate> {
    let mut rows = BTreeMap::new();
    for sample in samples {
        let key = PmuAddressKey {
            mapping_id: sample.mapping_id,
            ip: sample.pc,
        };
        let class = classify(sample);
        let row: &mut InstructionClassAddressAggregate = rows.entry(key).or_default();
        row.sample_count = row.sample_count.saturating_add(1);
        let class_row = row.classes.entry(class).or_default();
        class_row.sample_count = class_row.sample_count.saturating_add(1);
        if let Some(latency) = sample.latency_cycles {
            class_row.record_latency(latency);
        }

        let cpu_class_row = row
            .cpu_classes
            .entry(sample.cpu)
            .or_default()
            .entry(class)
            .or_default();
        cpu_class_row.sample_count = cpu_class_row.sample_count.saturating_add(1);
        if let Some(latency) = sample.latency_cycles {
            cpu_class_row.record_latency(latency);
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::source_profile::sample_stream::read_pmu_samples;

    #[test]
    fn aggregates_minimal_pmu_samples_by_address() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/source_profile/minimal");
        let event_catalog: SourceProfileEventCatalog = serde_json::from_str(
            &std::fs::read_to_string(root.join("event_catalog.json")).unwrap(),
        )
        .unwrap();
        let (_, samples) = read_pmu_samples(&root.join("pmu_samples.bin")).unwrap();
        let rows = aggregate_pmu_by_address(&samples, &event_catalog);
        let cycles: u64 = rows
            .values()
            .map(|row| {
                row.self_weight_by_event
                    .get("cpu_cycles")
                    .copied()
                    .unwrap_or(0)
            })
            .sum();
        let instructions: u64 = rows
            .values()
            .map(|row| {
                row.self_weight_by_event
                    .get("inst_retired")
                    .copied()
                    .unwrap_or(0)
            })
            .sum();
        assert_eq!(cycles, 3000);
        assert_eq!(instructions, 2000);
        assert!(rows
            .values()
            .any(|row| row.accumulated_weight_by_event.contains_key("cpu_cycles")));
    }

    #[test]
    fn aggregate_pmu_by_address_tracks_cpu_and_tid() {
        let event_catalog = SourceProfileEventCatalog {
            session_id: "test".to_string(),
            events: vec![crate::source_profile::schema::EventDefinition {
                event_key: "cpu_cycles".to_string(),
                display_name: "CPU Cycles".to_string(),
                source: "pmu".to_string(),
                event_type: "hardware".to_string(),
                config: "0".to_string(),
                arm_arch_event_code: None,
                sample_period: 1000,
                unit: "cycles".to_string(),
                semantic_tags: Vec::new(),
                per_cpu_support: Vec::new(),
            }],
        };
        let rows = aggregate_pmu_by_address(
            &[
                PmuSample {
                    flags: 0,
                    event_run_ref: 0,
                    event_key_ref: 0,
                    sample_kind: 1,
                    pid: 10,
                    tid: 101,
                    cpu: 0,
                    mapping_id: 1,
                    timestamp_ns: 1,
                    ip: 0x1000,
                    period_or_weight: 1000,
                    callchain_ips: vec![0x900],
                },
                PmuSample {
                    flags: 0,
                    event_run_ref: 0,
                    event_key_ref: 0,
                    sample_kind: 1,
                    pid: 10,
                    tid: 102,
                    cpu: 7,
                    mapping_id: 1,
                    timestamp_ns: 2,
                    ip: 0x1000,
                    period_or_weight: 1000,
                    callchain_ips: vec![0x900],
                },
            ],
            &event_catalog,
        );
        let row = rows
            .get(&PmuAddressKey {
                mapping_id: 1,
                ip: 0x1000,
            })
            .unwrap();
        assert_eq!(row.cpus, BTreeSet::from([0, 7]));
        assert_eq!(row.tids, BTreeSet::from([101, 102]));
        let callchain = rows
            .get(&PmuAddressKey {
                mapping_id: 1,
                ip: 0x900,
            })
            .unwrap();
        assert_eq!(callchain.cpus, BTreeSet::from([0, 7]));
        assert_eq!(callchain.tids, BTreeSet::from([101, 102]));
    }

    #[test]
    fn aggregates_spe_samples_by_address() {
        let samples = vec![
            SpeSample {
                flags: 0,
                event_run_ref: 0,
                pid: 1,
                tid: 1,
                cpu: 0,
                mapping_id: 1,
                timestamp_ns: 100,
                pc: 0x1000,
                latency_cycles: Some(10),
                operation_flags: 1,
                event_flags: 2,
                cache_level: 1,
                cache_result: 1,
                branch_result: 3,
                data_source: 7,
                decode_status: 0,
                raw_packet_offset: 0,
            },
            SpeSample {
                flags: 0,
                event_run_ref: 0,
                pid: 1,
                tid: 1,
                cpu: 0,
                mapping_id: 1,
                timestamp_ns: 110,
                pc: 0x1000,
                latency_cycles: Some(30),
                operation_flags: 4,
                event_flags: 8,
                cache_level: 1,
                cache_result: 2,
                branch_result: 2,
                data_source: 7,
                decode_status: 1,
                raw_packet_offset: 0,
            },
        ];
        let rows = aggregate_spe_by_address(&samples);
        let row = rows
            .get(&PmuAddressKey {
                mapping_id: 1,
                ip: 0x1000,
            })
            .unwrap();
        assert_eq!(row.sample_count, 2);
        assert_eq!(row.latency_cycles_sum, 40);
        assert_eq!(row.cache_hits, 1);
        assert_eq!(row.cache_misses, 1);
        assert_eq!(row.branch_mispredict, 1);
        assert_eq!(row.data_source_counts.get(&7), Some(&2));
        assert_eq!(row.decode_error_count, 1);
    }

    #[test]
    fn spe_other_operation_reports_compute_unknown() {
        let sample = SpeSample {
            flags: 0,
            event_run_ref: 0,
            pid: 1,
            tid: 1,
            cpu: 0,
            mapping_id: 1,
            timestamp_ns: 100,
            pc: 0x1000,
            latency_cycles: Some(10),
            operation_flags: SPE_OP_OTHER,
            event_flags: 0,
            cache_level: 0,
            cache_result: 0,
            branch_result: 0,
            data_source: 0,
            decode_status: 0,
            raw_packet_offset: 0,
        };

        assert_eq!(spe_category(&sample), SpeReportCategory::ComputeUnknown);
    }

    #[test]
    fn aggregates_spe_categories_by_address() {
        let samples = vec![
            SpeSample {
                flags: 0,
                event_run_ref: 0,
                pid: 1,
                tid: 1,
                cpu: 0,
                mapping_id: 7,
                timestamp_ns: 100,
                pc: 0x1000,
                latency_cycles: Some(10),
                operation_flags: SPE_OP_LOAD,
                event_flags: 0,
                cache_level: 0,
                cache_result: 0,
                branch_result: 0,
                data_source: 0x0e,
                decode_status: 0,
                raw_packet_offset: 0,
            },
            SpeSample {
                flags: 0,
                event_run_ref: 0,
                pid: 1,
                tid: 1,
                cpu: 0,
                mapping_id: 7,
                timestamp_ns: 110,
                pc: 0x1000,
                latency_cycles: Some(30),
                operation_flags: SPE_OP_STORE,
                event_flags: 0,
                cache_level: 0,
                cache_result: 0,
                branch_result: 0,
                data_source: u16::MAX,
                decode_status: 0,
                raw_packet_offset: 8,
            },
        ];

        let rows = aggregate_spe_categories_by_address(&samples);
        let row = rows
            .get(&PmuAddressKey {
                mapping_id: 7,
                ip: 0x1000,
            })
            .unwrap();

        assert_eq!(row.sample_count, 2);
        assert_eq!(row.categories[&SpeReportCategory::LoadDram].sample_count, 1);
        assert_eq!(
            row.categories[&SpeReportCategory::LoadDram].latency_cycles_sum,
            10
        );
        assert_eq!(
            row.categories[&SpeReportCategory::LoadDram].latency_cycles_min,
            Some(10)
        );
        assert_eq!(
            row.categories[&SpeReportCategory::LoadDram].latency_cycles_max,
            Some(10)
        );
        assert_eq!(
            row.categories[&SpeReportCategory::StoreUnknown].sample_count,
            1
        );
        assert_eq!(
            row.categories[&SpeReportCategory::StoreUnknown].latency_cycles_sum,
            30
        );
        assert_eq!(
            row.categories[&SpeReportCategory::StoreUnknown].avg_latency_cycles(),
            Some(30.0)
        );
        assert_eq!(
            row.categories[&SpeReportCategory::StoreUnknown].std_latency_cycles(),
            Some(0.0)
        );
    }

    #[test]
    fn aggregates_instruction_classes_by_address() {
        let samples = vec![
            SpeSample {
                flags: 0,
                event_run_ref: 0,
                pid: 1,
                tid: 10,
                cpu: 4,
                mapping_id: 7,
                timestamp_ns: 100,
                pc: 0x1000,
                latency_cycles: Some(20),
                operation_flags: SPE_OP_OTHER,
                event_flags: 0,
                cache_level: 0,
                cache_result: 0,
                branch_result: 0,
                data_source: 0,
                decode_status: 0,
                raw_packet_offset: 0,
            },
            SpeSample {
                flags: 0,
                event_run_ref: 0,
                pid: 1,
                tid: 11,
                cpu: 4,
                mapping_id: 7,
                timestamp_ns: 110,
                pc: 0x1004,
                latency_cycles: Some(40),
                operation_flags: SPE_OP_LOAD,
                event_flags: 0,
                cache_level: 0,
                cache_result: 0,
                branch_result: 0,
                data_source: 0,
                decode_status: 0,
                raw_packet_offset: 8,
            },
        ];
        let rows = aggregate_instruction_classes_by_address(&samples, |sample| match sample.pc {
            0x1000 => InstructionClass::ComputeFpSimd,
            0x1004 => InstructionClass::VectorLoad,
            _ => InstructionClass::MissingInstruction,
        });
        let row = rows
            .get(&PmuAddressKey {
                mapping_id: 7,
                ip: 0x1000,
            })
            .unwrap();

        assert_eq!(row.sample_count, 1);
        assert_eq!(
            row.classes[&InstructionClass::ComputeFpSimd].sample_count,
            1
        );
        assert_eq!(
            row.classes[&InstructionClass::ComputeFpSimd].latency_cycles_sum,
            20
        );
        assert_eq!(
            row.cpu_classes[&4][&InstructionClass::ComputeFpSimd].latency_cycles_sum,
            20
        );
    }

    #[test]
    fn computes_global_and_file_local_percentages() {
        let percentages = compute_percentages(5.0, 20.0, 100.0, 200.0, 10.0, 40.0);
        assert_eq!(percentages.p_pct, 5.0);
        assert_eq!(percentages.acc_p_pct, 10.0);
        assert_eq!(percentages.file_p_pct, 50.0);
        assert_eq!(percentages.file_acc_p_pct, 50.0);
    }

    #[test]
    fn derives_pmu_metrics_without_turning_missing_into_zero() {
        let weights = BTreeMap::from([
            ("cpu_cycles".to_string(), 2000),
            ("inst_retired".to_string(), 1000),
            ("l1d_cache_access".to_string(), 100),
            ("l1d_cache_refill".to_string(), 10),
            ("branch_retired".to_string(), 50),
            ("branch_mispredict".to_string(), 5),
        ]);
        let values = derive_pmu_metrics(&weights, Some(0.001));
        assert!(matches!(values["cpi"], MetricValue::Number(2.0)));
        assert!(
            matches!(values["l1d_cache_hit_rate"], MetricValue::Number(v) if (v - 0.9).abs() < f64::EPSILON)
        );
        assert!(
            matches!(values["branch_miss_rate"], MetricValue::Number(v) if (v - 0.1).abs() < f64::EPSILON)
        );
        assert!(matches!(values["mips"], MetricValue::Number(1.0)));
        assert!(matches!(values["mcps"], MetricValue::Number(2.0)));
        assert!(matches!(
            values["l2d_cache_hit_rate"],
            MetricValue::Missing(_)
        ));
    }

    #[test]
    fn classifies_missing_unresolved_and_true_zero() {
        let missing = source_line_metric_value("l3d_cache_hit_rate", false, true, Some(1.0));
        let unresolved = source_line_metric_value("cpu_cycles", true, false, Some(10.0));
        let zero = source_line_metric_value("cpu_cycles", true, true, None);
        let nonzero = source_line_metric_value("cpu_cycles", true, true, Some(10.0));

        assert_eq!(classify_metric_value(&missing), MetricSemantics::Missing);
        assert_eq!(
            classify_metric_value(&unresolved),
            MetricSemantics::Unresolved
        );
        assert_eq!(classify_metric_value(&zero), MetricSemantics::Zero);
        assert_eq!(classify_metric_value(&nonzero), MetricSemantics::NonZero);
    }

    #[test]
    fn source_line_report_row_refreshes_status_flags() {
        let mut row = SourceLineReportRow {
            file: PathBuf::from("fixture.cpp"),
            line_number: 4,
            function: Some("hot".to_string()),
            module_id: Some("libfixture.so".to_string()),
            thread_ids: vec![4242],
            cpu_ids: vec![0],
            code: "sum += values[i] * 3;".to_string(),
            pmu_values: BTreeMap::from([
                ("cpu_cycles".to_string(), MetricValue::Number(1000.0)),
                (
                    "l3d".to_string(),
                    MetricValue::Missing("unsupported".to_string()),
                ),
            ]),
            spe_values: BTreeMap::from([(
                "spe_latency".to_string(),
                MetricValue::Unresolved("no line".to_string()),
            )]),
            status_flags: Vec::new(),
        };
        row.refresh_status_flags();
        assert!(row.status_flags.contains(&LineStatusFlag::NonZero));
        assert!(row.status_flags.contains(&LineStatusFlag::Missing));
        assert!(row.status_flags.contains(&LineStatusFlag::Unresolved));
    }

    #[test]
    fn summarizes_files_from_line_rows() {
        let rows = vec![
            SourceLineReportRow {
                file: PathBuf::from("a.cpp"),
                line_number: 1,
                function: None,
                module_id: None,
                thread_ids: vec![],
                cpu_ids: vec![],
                code: "x".to_string(),
                pmu_values: BTreeMap::from([("cycles".to_string(), MetricValue::Number(10.0))]),
                spe_values: BTreeMap::new(),
                status_flags: vec![],
            },
            SourceLineReportRow {
                file: PathBuf::from("a.cpp"),
                line_number: 2,
                function: None,
                module_id: None,
                thread_ids: vec![],
                cpu_ids: vec![],
                code: "y".to_string(),
                pmu_values: BTreeMap::from([(
                    "l3".to_string(),
                    MetricValue::Missing("unsupported".to_string()),
                )]),
                spe_values: BTreeMap::new(),
                status_flags: vec![],
            },
        ];
        let summary = summarize_files(&rows);
        assert_eq!(summary[&PathBuf::from("a.cpp")].nonzero_line_count, 1);
        assert_eq!(summary[&PathBuf::from("a.cpp")].missing_metric_count, 1);
    }

    #[test]
    fn summarizes_functions_from_line_rows() {
        let rows = vec![SourceLineReportRow {
            file: PathBuf::from("a.cpp"),
            line_number: 7,
            function: Some("foo".to_string()),
            module_id: Some("liba.so".to_string()),
            thread_ids: vec![],
            cpu_ids: vec![],
            code: "work();".to_string(),
            pmu_values: BTreeMap::from([("cycles".to_string(), MetricValue::Number(10.0))]),
            spe_values: BTreeMap::new(),
            status_flags: vec![],
        }];
        let summary = summarize_functions(&rows);
        let key = (PathBuf::from("a.cpp"), "foo".to_string());
        assert_eq!(summary[&key].module_id.as_deref(), Some("liba.so"));
        assert_eq!(summary[&key].line_start, 7);
        assert_eq!(summary[&key].self_weight, 10.0);
        assert_eq!(summary[&key].hot_lines, vec![7]);
    }
}

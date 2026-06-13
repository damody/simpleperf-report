#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::bundle::SourceProfileBundle;
use super::line_resolver::{
    resolve_source_path, runtime_address_to_relative, CachedElfLineResolver,
};
use super::metrics::{
    aggregate_pmu_file, aggregate_spe_by_address, compute_percentages, derive_pmu_metrics,
    MetricValue, PmuAddressAggregate, SpeAddressAggregate,
};
use super::sample_stream::read_spe_samples;
use super::source_loader::load_source_file;
use super::symbol_resolver::{discover_debug_elfs, match_debug_elfs, ElfMatchQuality};

pub const RAW_PMU_COLUMNS: &[&str] = &[
    "cpu_cycles",
    "inst_retired",
    "l1d_cache_access",
    "l1d_cache_refill",
    "l2d_cache_access",
    "l2d_cache_refill",
    "l3d_cache_access",
    "l3d_cache_refill",
    "ll_cache_read",
    "ll_cache_read_miss",
    "branch_retired",
    "branch_mispredict",
    "stall_frontend",
    "stall_backend",
];

pub const DERIVED_PMU_COLUMNS: &[&str] = &[
    "cpi",
    "l1d_cache_hit_rate",
    "l2d_cache_hit_rate",
    "l3d_cache_hit_rate",
    "branch_miss_rate",
    "mpki",
    "mips",
    "mcps",
];

pub const SPE_COLUMNS: &[&str] = &[
    "spe_sample_count",
    "spe_latency_cycles_avg",
    "spe_cache_hit_rate",
    "spe_branch_miss_rate",
    "spe_decode_errors",
];

#[derive(Debug, Clone)]
pub struct ReportModel {
    pub rows: Vec<ReportLineRow>,
    pub files: Vec<ReportFileRow>,
    pub functions: Vec<ReportFunctionRow>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReportLineRow {
    pub file: String,
    pub line: u32,
    pub function: String,
    pub module: String,
    pub code: String,
    pub status: String,
    pub cpu: String,
    pub thread: String,
    pub sample_count: u64,
    pub self_weight: f64,
    pub accumulated_weight: f64,
    pub p_pct: f64,
    pub acc_p_pct: f64,
    pub file_p_pct: f64,
    pub file_acc_p_pct: f64,
    pub pmu_values: BTreeMap<String, MetricValue>,
    pub spe_values: BTreeMap<String, MetricValue>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ReportFileRow {
    pub file: String,
    pub self_weight: f64,
    pub accumulated_weight: f64,
    pub sample_count: u64,
    pub hot_lines: u64,
    pub missing: u64,
    pub unresolved: u64,
    pub hot_line: u32,
}

#[derive(Debug, Clone)]
pub struct ReportFunctionRow {
    pub function: String,
    pub file: String,
    pub line_start: u32,
    pub line_end: u32,
    pub module: String,
    pub self_weight: f64,
    pub accumulated_weight: f64,
    pub sample_count: u64,
    pub hot_lines: String,
}

#[derive(Debug, Clone)]
struct MutableLineRow {
    file: PathBuf,
    line: u32,
    function: String,
    module: String,
    code: String,
    cpus: BTreeSet<u32>,
    tids: BTreeSet<u32>,
    pmu_self: BTreeMap<String, u64>,
    pmu_acc: BTreeMap<String, u64>,
    pmu_self_samples: BTreeMap<String, u64>,
    pmu_acc_samples: BTreeMap<String, u64>,
    pmu_sample_count: u64,
    spe: Option<SpeAddressAggregate>,
    unresolved: Vec<String>,
}

#[derive(Default)]
struct SourceCodeCache {
    files: BTreeMap<PathBuf, Vec<String>>,
}

impl SourceCodeCache {
    fn line_code(&mut self, file: &Path, line: u32) -> String {
        let key = normalize_existing_path(file.to_path_buf());
        if !self.files.contains_key(&key) {
            let lines = load_source_file(&key)
                .map(|lines| lines.into_iter().map(|line| line.code).collect())
                .unwrap_or_default();
            self.files.insert(key.clone(), lines);
        }
        self.files
            .get(&key)
            .and_then(|lines| lines.get(line.saturating_sub(1) as usize))
            .cloned()
            .unwrap_or_default()
    }
}

impl MutableLineRow {
    fn new(file: PathBuf, line: u32, code: String) -> Self {
        Self {
            file,
            line,
            function: String::new(),
            module: String::new(),
            code,
            cpus: BTreeSet::new(),
            tids: BTreeSet::new(),
            pmu_self: BTreeMap::new(),
            pmu_acc: BTreeMap::new(),
            pmu_self_samples: BTreeMap::new(),
            pmu_acc_samples: BTreeMap::new(),
            pmu_sample_count: 0,
            spe: None,
            unresolved: Vec::new(),
        }
    }
}

pub fn build_report_model(bundle: &SourceProfileBundle) -> Result<ReportModel> {
    let source_files = discover_source_files(bundle)?;
    let source_roots = absolute_source_roots(bundle);
    let path_remaps = absolute_path_remaps(bundle);
    let mut rows = BTreeMap::<(PathBuf, u32), MutableLineRow>::new();
    let mut source_by_name = BTreeMap::<String, PathBuf>::new();
    let mut source_code_cache = SourceCodeCache::default();

    for file in &source_files {
        if let Some(name) = file.file_name().and_then(|name| name.to_str()) {
            source_by_name.insert(name.to_string(), file.clone());
        }
        for line in load_source_file(file)? {
            rows.entry((line.file.clone(), line.line_number))
                .or_insert_with(|| MutableLineRow::new(line.file, line.line_number, line.code));
        }
    }

    let elf_matches = load_elf_matches(bundle)?;
    let mut warnings = collect_quality_warnings(bundle);
    let mut line_resolver = CachedElfLineResolver::default();
    for matched in elf_matches.values() {
        if matched.quality == ElfMatchQuality::Missing && should_warn_missing_debug_elf(matched) {
            warnings.push(format!("Debug ELF Missing for {}", matched.module_id));
        }
    }

    if let Some(path) = &bundle.pmu_samples_path {
        let aggregate_result = aggregate_pmu_file(path, &bundle.event_catalog)?;
        append_cpu_coverage_diagnostic(
            bundle,
            aggregate_result.sample_count,
            &aggregate_result.observed_cpus,
            &mut warnings,
        );
        append_pmu_event_coverage_diagnostic(
            aggregate_result.sample_count,
            &aggregate_result.observed_event_keys,
            &mut warnings,
        );
        let aggregates = aggregate_result.rows;
        for (key, aggregate) in aggregates {
            if let Some((file, line, function, module)) = resolve_key(
                bundle,
                &elf_matches,
                &source_roots,
                &path_remaps,
                &source_by_name,
                &mut line_resolver,
                key.mapping_id,
                key.ip,
            )? {
                let code = source_code_cache.line_code(&file, line);
                let row = rows
                    .entry((file.clone(), line))
                    .or_insert_with(|| MutableLineRow::new(file.clone(), line, code));
                if row.code.is_empty() {
                    row.code = source_code_cache.line_code(&file, line);
                }
                row.function = prefer_nonempty(&row.function, function);
                row.module = prefer_nonempty(&row.module, module);
                merge_pmu(row, aggregate);
            } else {
                warnings.push(format!(
                    "Unresolved PMU sample mapping={} ip=0x{:x}",
                    key.mapping_id, key.ip
                ));
            }
        }
    }

    if let Some(path) = &bundle.spe_samples_path {
        let (_, samples) = read_spe_samples(path)?;
        let aggregates = aggregate_spe_by_address(&samples);
        for (key, aggregate) in aggregates {
            let sample_meta = samples
                .iter()
                .find(|sample| sample.mapping_id == key.mapping_id && sample.pc == key.ip);
            if let Some((file, line, function, module)) = resolve_key(
                bundle,
                &elf_matches,
                &source_roots,
                &path_remaps,
                &source_by_name,
                &mut line_resolver,
                key.mapping_id,
                key.ip,
            )? {
                let code = source_code_cache.line_code(&file, line);
                let row = rows
                    .entry((file.clone(), line))
                    .or_insert_with(|| MutableLineRow::new(file.clone(), line, code));
                if row.code.is_empty() {
                    row.code = source_code_cache.line_code(&file, line);
                }
                if let Some(sample) = sample_meta {
                    row.cpus.insert(sample.cpu);
                    row.tids.insert(sample.tid);
                }
                row.function = prefer_nonempty(&row.function, function);
                row.module = prefer_nonempty(&row.module, module);
                row.spe = Some(aggregate);
            } else {
                warnings.push(format!(
                    "Unresolved SPE sample mapping={} pc=0x{:x}",
                    key.mapping_id, key.ip
                ));
            }
        }
    }

    let mut line_rows = finalize_rows(bundle, rows);
    compute_row_percentages(&mut line_rows);
    append_attribution_diagnostics(bundle, &line_rows, &mut warnings);
    let files = summarize_files(&line_rows);
    let functions = summarize_functions(&line_rows);
    Ok(ReportModel {
        rows: line_rows,
        files,
        functions,
        warnings,
    })
}

fn load_elf_matches(
    bundle: &SourceProfileBundle,
) -> Result<BTreeMap<String, super::symbol_resolver::ElfMatch>> {
    let debug_hints = bundle
        .manifest
        .inputs
        .debug_elf_hints
        .iter()
        .map(|hint| absolute_bundle_path(bundle, hint))
        .collect::<Vec<_>>();
    let candidates = discover_debug_elfs(&debug_hints)?;
    let matches = match_debug_elfs(&bundle.build_ids.modules, &candidates)?;
    Ok(matches
        .into_iter()
        .map(|matched| (matched.module_id.clone(), matched))
        .collect())
}

fn should_warn_missing_debug_elf(matched: &super::symbol_resolver::ElfMatch) -> bool {
    let module = matched.module_id.as_str();
    let runtime_path = matched.runtime_path.replace('\\', "/");
    if is_android_os_module(module, &runtime_path) {
        return false;
    }
    is_app_native_module(module, &runtime_path)
}

fn is_android_os_module(module: &str, runtime_path: &str) -> bool {
    let module_lower = module.to_ascii_lowercase();
    let path_lower = runtime_path.to_ascii_lowercase();
    if module_lower.starts_with("memfd:")
        || module_lower.starts_with("mali")
        || module_lower == "binder"
        || module_lower.contains("@resource-cache@")
        || module_lower.contains("(deleted)")
        || path_lower.starts_with("/dev/")
        || path_lower.starts_with("/memfd:")
        || path_lower.starts_with("/mali")
    {
        return true;
    }
    if module_lower.starts_with("android.")
        || module_lower.starts_with("androidx.")
        || module_lower.starts_with("com.android.")
    {
        return true;
    }
    if module_lower.ends_with(".jar")
        || module_lower.ends_with(".odex")
        || module_lower.ends_with(".vdex")
        || module_lower.ends_with(".apk")
        || module_lower.ends_with(".map")
        || module_lower.ends_with(".val")
        || module_lower.ends_with(".txt")
    {
        return true;
    }
    path_lower.starts_with("/system/")
        || path_lower.starts_with("/system_ext/")
        || path_lower.starts_with("/vendor/")
        || path_lower.starts_with("/product/")
        || path_lower.starts_with("/apex/")
        || path_lower.starts_with("/odm/")
        || path_lower.starts_with("/oem/")
}

fn is_app_native_module(module: &str, runtime_path: &str) -> bool {
    let module_lower = module.to_ascii_lowercase();
    let path_lower = runtime_path.to_ascii_lowercase();
    let is_native = module_lower.ends_with(".so") || module_lower.contains(".so.");
    is_native
        && (path_lower.starts_with("/data/app/")
            || path_lower.starts_with("/data/data/")
            || path_lower.starts_with("/data/user/")
            || path_lower.starts_with("/data/local/tmp/"))
}

fn resolve_key(
    bundle: &SourceProfileBundle,
    elf_matches: &BTreeMap<String, super::symbol_resolver::ElfMatch>,
    source_roots: &[PathBuf],
    path_remaps: &[super::schema::PathRemap],
    source_by_name: &BTreeMap<String, PathBuf>,
    line_resolver: &mut CachedElfLineResolver,
    mapping_id: u64,
    ip: u64,
) -> Result<Option<(PathBuf, u32, String, String)>> {
    let Some(mapping) = bundle
        .maps
        .maps
        .iter()
        .find(|map| map.mapping_id == mapping_id)
    else {
        return Ok(None);
    };
    let Some(relative) = runtime_address_to_relative(&bundle.maps.maps, ip) else {
        return Ok(None);
    };
    let Some(matched) = elf_matches.get(&relative.module_id) else {
        return Ok(None);
    };
    let Some(elf_path) = &matched.candidate_path else {
        return Ok(None);
    };
    let Some(location) = line_resolver
        .resolve(elf_path, relative.relative_address)
        .with_context(|| format!("Failed to resolve 0x{:x}", relative.relative_address))?
    else {
        return Ok(None);
    };
    let file = resolve_source_path(&location.file, None, source_roots, path_remaps)
        .or_else(|| {
            location
                .file
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| source_by_name.get(name).cloned())
        })
        .unwrap_or(location.file);
    let file = normalize_existing_path(file);
    Ok(Some((
        file,
        location.line,
        location.function.unwrap_or_default(),
        mapping.module_id.clone(),
    )))
}

fn merge_pmu(row: &mut MutableLineRow, aggregate: PmuAddressAggregate) {
    row.cpus.extend(aggregate.cpus);
    row.tids.extend(aggregate.tids);
    row.pmu_sample_count = row.pmu_sample_count.saturating_add(aggregate.sample_count);
    for (event, value) in aggregate.self_weight_by_event {
        *row.pmu_self.entry(event).or_default() += value;
    }
    for (event, value) in aggregate.accumulated_weight_by_event {
        *row.pmu_acc.entry(event).or_default() += value;
    }
    for (event, value) in aggregate.self_samples_by_event {
        *row.pmu_self_samples.entry(event).or_default() += value;
    }
    for (event, value) in aggregate.accumulated_samples_by_event {
        *row.pmu_acc_samples.entry(event).or_default() += value;
    }
}

fn append_cpu_coverage_diagnostic(
    bundle: &SourceProfileBundle,
    sample_count: u64,
    observed: &BTreeSet<u32>,
    warnings: &mut Vec<String>,
) {
    let selected = bundle
        .manifest
        .cpu
        .selected_cpus
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if selected.len() <= 1 || sample_count == 0 {
        return;
    }
    if observed.len() < selected.len() {
        warnings.push(format!(
            "PMU sample CPU coverage is incomplete: selected CPUs [{}], observed sample CPUs [{}]. If observed CPUs are unexpectedly limited, check realtime_profile PERF_SAMPLE_CPU parsing/capture.",
            join_u32_set(&selected),
            join_u32_set(&observed),
        ));
    }
}

fn append_pmu_event_coverage_diagnostic(
    sample_count: u64,
    observed: &BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    if sample_count == 0 {
        return;
    }
    if observed.len() <= 1 {
        warnings.push(format!(
            "PMU samples only contain event(s) [{}]. Metrics requiring instructions/cache/branch events, such as CPI, MIPS, cache hit rate, and branch miss rate, will be Missing unless those PMU events are captured.",
            observed.iter().cloned().collect::<Vec<_>>().join(",")
        ));
    }
}

fn join_u32_set(values: &BTreeSet<u32>) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn append_attribution_diagnostics(
    bundle: &SourceProfileBundle,
    rows: &[ReportLineRow],
    warnings: &mut Vec<String>,
) {
    if rows.is_empty() {
        warnings.push(
            "No source rows were generated. Check source_root_hints/path_remaps and source file availability."
                .to_string(),
        );
        return;
    }

    let has_sample_stream = bundle.pmu_samples_path.is_some() || bundle.spe_samples_path.is_some();
    let sampled_rows = rows
        .iter()
        .filter(|row| row.self_weight > 0.0 || row.accumulated_weight > 0.0)
        .count();
    let function_rows = rows
        .iter()
        .filter(|row| has_known_function(&row.function))
        .count();
    let sampled_function_rows = rows
        .iter()
        .filter(|row| {
            (row.self_weight > 0.0 || row.accumulated_weight > 0.0)
                && has_known_function(&row.function)
        })
        .count();

    if has_sample_stream && sampled_rows == 0 {
        warnings.push(
            "No sampled source rows were attributed. PMU/SPE samples exist, but no sample address resolved to source; check --elf debug ELF paths/build-id matching first, then source roots/path remaps."
                .to_string(),
        );
    }
    if function_rows == 0 {
        warnings.push(
            "No source rows contain function names. This usually means no matching unstripped debug ELF/DWARF was available; pass debug ELF files or directories with --elf and verify build IDs."
                .to_string(),
        );
    } else if sampled_rows > 0 && sampled_function_rows == 0 {
        warnings.push(
            "Sampled source rows were attributed, but none include function names. Check whether matched ELF files contain function/debug information."
                .to_string(),
        );
    }
}

fn has_known_function(function: &str) -> bool {
    let trimmed = function.trim();
    !trimmed.is_empty() && trimmed != "<unknown>"
}

fn finalize_rows(
    bundle: &SourceProfileBundle,
    rows: BTreeMap<(PathBuf, u32), MutableLineRow>,
) -> Vec<ReportLineRow> {
    let event_support = event_support_map(bundle);
    let effective_seconds = effective_time_seconds(bundle);
    rows.into_values()
        .map(|row| {
            let mut pmu_values = BTreeMap::new();
            let dense_pmu_self_samples =
                dense_supported_pmu_counts(&row.pmu_self_samples, &event_support);
            for key in RAW_PMU_COLUMNS {
                if !event_support.get(*key).copied().unwrap_or(false) {
                    pmu_values.insert(
                        (*key).to_string(),
                        MetricValue::Missing(format!("{key} is not available")),
                    );
                } else {
                    let sample_count = dense_pmu_self_samples.get(*key).copied().unwrap_or(0);
                    let ratio = if row.pmu_sample_count > 0 {
                        sample_count as f64 / row.pmu_sample_count as f64
                    } else {
                        0.0
                    };
                    pmu_values.insert((*key).to_string(), MetricValue::Number(ratio));
                }
            }
            for (key, value) in derive_pmu_metrics(&dense_pmu_self_samples, effective_seconds) {
                pmu_values.insert(key, value);
            }

            let spe_values = make_spe_values(bundle, row.spe.as_ref());
            let self_weight =
                row.pmu_self
                    .get("cpu_cycles")
                    .copied()
                    .unwrap_or_else(|| row.pmu_self.values().copied().sum()) as f64;
            let accumulated_weight =
                row.pmu_acc
                    .get("cpu_cycles")
                    .copied()
                    .unwrap_or_else(|| row.pmu_acc.values().copied().sum()) as f64;
            let status = status_text(&pmu_values, &spe_values, !row.unresolved.is_empty());
            let detail = metric_detail(&pmu_values, &spe_values, &row.unresolved);
            ReportLineRow {
                file: row.file.to_string_lossy().to_string(),
                line: row.line,
                function: row.function,
                module: row.module,
                code: row.code,
                status,
                cpu: join_numbers(&row.cpus),
                thread: join_numbers(&row.tids),
                sample_count: row.pmu_sample_count,
                self_weight,
                accumulated_weight,
                p_pct: 0.0,
                acc_p_pct: 0.0,
                file_p_pct: 0.0,
                file_acc_p_pct: 0.0,
                pmu_values,
                spe_values,
                detail,
            }
        })
        .collect()
}

fn dense_supported_pmu_counts(
    sparse: &BTreeMap<String, u64>,
    event_support: &BTreeMap<&str, bool>,
) -> BTreeMap<String, u64> {
    let mut dense = BTreeMap::new();
    for key in RAW_PMU_COLUMNS {
        if event_support.get(*key).copied().unwrap_or(false) {
            dense.insert((*key).to_string(), sparse.get(*key).copied().unwrap_or(0));
        }
    }
    dense
}

fn make_spe_values(
    bundle: &SourceProfileBundle,
    aggregate: Option<&SpeAddressAggregate>,
) -> BTreeMap<String, MetricValue> {
    let mut values = BTreeMap::new();
    if !bundle.manifest.lanes.spe.available {
        for key in SPE_COLUMNS {
            values.insert(
                (*key).to_string(),
                MetricValue::Missing(
                    bundle
                        .manifest
                        .lanes
                        .spe
                        .missing_reason
                        .clone()
                        .unwrap_or_else(|| "SPE unavailable".to_string()),
                ),
            );
        }
        return values;
    }

    let Some(aggregate) = aggregate else {
        for key in SPE_COLUMNS {
            values.insert((*key).to_string(), MetricValue::Number(0.0));
        }
        return values;
    };
    values.insert(
        "spe_sample_count".to_string(),
        MetricValue::Number(aggregate.sample_count as f64),
    );
    values.insert(
        "spe_latency_cycles_avg".to_string(),
        if aggregate.latency_sample_count == 0 {
            MetricValue::Missing("SPE latency field unavailable".to_string())
        } else {
            MetricValue::Number(
                aggregate.latency_cycles_sum as f64 / aggregate.latency_sample_count as f64,
            )
        },
    );
    let cache_total = aggregate.cache_hits + aggregate.cache_misses;
    values.insert(
        "spe_cache_hit_rate".to_string(),
        if cache_total == 0 {
            MetricValue::Missing("SPE cache outcome unavailable".to_string())
        } else {
            MetricValue::Number(aggregate.cache_hits as f64 / cache_total as f64)
        },
    );
    let branch_total = aggregate.branch_correct + aggregate.branch_mispredict;
    values.insert(
        "spe_branch_miss_rate".to_string(),
        if branch_total == 0 {
            MetricValue::Missing("SPE branch outcome unavailable".to_string())
        } else {
            MetricValue::Number(aggregate.branch_mispredict as f64 / branch_total as f64)
        },
    );
    values.insert(
        "spe_decode_errors".to_string(),
        MetricValue::Number(aggregate.decode_error_count as f64),
    );
    values
}

fn compute_row_percentages(rows: &mut [ReportLineRow]) {
    let total_self = rows.iter().map(|row| row.self_weight).sum::<f64>();
    let total_acc = rows.iter().map(|row| row.accumulated_weight).sum::<f64>();
    let mut file_totals = BTreeMap::<String, (f64, f64)>::new();
    for row in rows.iter() {
        let entry = file_totals.entry(row.file.clone()).or_default();
        entry.0 += row.self_weight;
        entry.1 += row.accumulated_weight;
    }
    for row in rows {
        let (file_self, file_acc) = file_totals.get(&row.file).copied().unwrap_or_default();
        let pct = compute_percentages(
            row.self_weight,
            row.accumulated_weight,
            total_self,
            total_acc,
            file_self,
            file_acc,
        );
        row.p_pct = pct.p_pct;
        row.acc_p_pct = pct.acc_p_pct;
        row.file_p_pct = pct.file_p_pct;
        row.file_acc_p_pct = pct.file_acc_p_pct;
    }
}

fn summarize_files(rows: &[ReportLineRow]) -> Vec<ReportFileRow> {
    let mut summaries = BTreeMap::<String, ReportFileRow>::new();
    for row in rows {
        let summary = summaries
            .entry(row.file.clone())
            .or_insert_with(|| ReportFileRow {
                file: row.file.clone(),
                self_weight: 0.0,
                accumulated_weight: 0.0,
                sample_count: 0,
                hot_lines: 0,
                missing: 0,
                unresolved: 0,
                hot_line: row.line,
            });
        summary.self_weight += row.self_weight;
        summary.accumulated_weight += row.accumulated_weight;
        if row.status.contains("NonZero") {
            summary.sample_count += 1;
            summary.hot_lines += 1;
            summary.hot_line = row.line;
        }
        if row.status.contains("Missing") {
            summary.missing += 1;
        }
        if row.status.contains("Unresolved") {
            summary.unresolved += 1;
        }
    }
    summaries.into_values().collect()
}

fn summarize_functions(rows: &[ReportLineRow]) -> Vec<ReportFunctionRow> {
    let mut summaries = BTreeMap::<(String, String), ReportFunctionRow>::new();
    for row in rows {
        let function = if row.function.is_empty() {
            "<unknown>".to_string()
        } else {
            row.function.clone()
        };
        let key = (row.file.clone(), function.clone());
        let summary = summaries.entry(key).or_insert_with(|| ReportFunctionRow {
            function,
            file: row.file.clone(),
            line_start: row.line,
            line_end: row.line,
            module: row.module.clone(),
            self_weight: 0.0,
            accumulated_weight: 0.0,
            sample_count: 0,
            hot_lines: String::new(),
        });
        summary.line_start = summary.line_start.min(row.line);
        summary.line_end = summary.line_end.max(row.line);
        summary.self_weight += row.self_weight;
        summary.accumulated_weight += row.accumulated_weight;
        if row.status.contains("NonZero") {
            summary.sample_count += 1;
            if !summary.hot_lines.is_empty() {
                summary.hot_lines.push_str(", ");
            }
            summary.hot_lines.push_str(&row.line.to_string());
        }
    }
    summaries.into_values().collect()
}

pub fn metric_value_text(value: Option<&MetricValue>) -> String {
    match value {
        Some(MetricValue::Number(value)) => format_number(*value),
        Some(MetricValue::Missing(_)) => "Missing".to_string(),
        Some(MetricValue::Unresolved(_)) => "Unresolved".to_string(),
        Some(MetricValue::Undefined(_)) => "Undefined".to_string(),
        None => "Missing".to_string(),
    }
}

pub fn metric_value_number(value: Option<&MetricValue>) -> Option<f64> {
    match value {
        Some(MetricValue::Number(value)) => Some(*value),
        _ => None,
    }
}

fn status_text(
    pmu_values: &BTreeMap<String, MetricValue>,
    spe_values: &BTreeMap<String, MetricValue>,
    unresolved: bool,
) -> String {
    let mut flags = Vec::new();
    if pmu_values
        .values()
        .chain(spe_values.values())
        .any(|value| matches!(value, MetricValue::Number(number) if *number > 0.0))
    {
        flags.push("NonZero");
    }
    if pmu_values
        .values()
        .chain(spe_values.values())
        .any(|value| matches!(value, MetricValue::Missing(_)))
    {
        flags.push("Missing");
    }
    if unresolved
        || pmu_values
            .values()
            .chain(spe_values.values())
            .any(|value| matches!(value, MetricValue::Unresolved(_)))
    {
        flags.push("Unresolved");
    }
    if pmu_values
        .values()
        .chain(spe_values.values())
        .any(|value| matches!(value, MetricValue::Undefined(_)))
    {
        flags.push("Undefined");
    }
    if flags.is_empty() {
        "0".to_string()
    } else {
        flags.join("|")
    }
}

fn metric_detail(
    pmu_values: &BTreeMap<String, MetricValue>,
    spe_values: &BTreeMap<String, MetricValue>,
    unresolved: &[String],
) -> String {
    let mut parts = Vec::new();
    for (key, value) in pmu_values.iter().chain(spe_values.iter()) {
        parts.push(format!("{key}={}", metric_value_text(Some(value))));
    }
    for item in unresolved {
        parts.push(format!("unresolved={item}"));
    }
    parts.join("; ")
}

fn event_support_map(bundle: &SourceProfileBundle) -> BTreeMap<&str, bool> {
    let mut map = BTreeMap::new();
    for key in RAW_PMU_COLUMNS {
        let supported = bundle
            .event_catalog
            .events
            .iter()
            .find(|event| event.event_key == *key)
            .is_some_and(|event| {
                event.per_cpu_support.is_empty()
                    || event.per_cpu_support.iter().any(|cpu| cpu.supported)
            });
        map.insert(*key, supported);
    }
    map
}

fn effective_time_seconds(bundle: &SourceProfileBundle) -> Option<f64> {
    let ns = bundle
        .event_runs
        .runs
        .iter()
        .map(|run| run.time_running_ns)
        .max()
        .or_else(|| {
            bundle
                .manifest
                .recording
                .duration_ms
                .map(|ms| ms * 1_000_000)
        })?;
    (ns > 0).then_some(ns as f64 / 1_000_000_000.0)
}

fn collect_quality_warnings(bundle: &SourceProfileBundle) -> Vec<String> {
    let mut warnings = Vec::new();
    if !bundle.manifest.lanes.pmu.available {
        warnings.push(format!(
            "PMU Missing: {}",
            bundle
                .manifest
                .lanes
                .pmu
                .missing_reason
                .as_deref()
                .unwrap_or("unknown")
        ));
    }
    if !bundle.manifest.lanes.spe.available {
        warnings.push(format!(
            "SPE Missing: {}",
            bundle
                .manifest
                .lanes
                .spe
                .missing_reason
                .as_deref()
                .unwrap_or("unknown")
        ));
    }
    if bundle.loss.totals.pmu_lost_records > 0 {
        warnings.push(format!(
            "PMU lost records: {}",
            bundle.loss.totals.pmu_lost_records
        ));
    }
    if bundle.loss.totals.spe_decode_errors > 0 {
        warnings.push(format!(
            "SPE decode errors: {}",
            bundle.loss.totals.spe_decode_errors
        ));
    }
    warnings
}

fn discover_source_files(bundle: &SourceProfileBundle) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for hint in &bundle.manifest.inputs.source_root_hints {
        let root = absolute_bundle_path(bundle, hint);
        if root.is_file() && is_source_file(&root) {
            files.push(normalize_existing_path(root));
        } else if root.is_dir() && should_preload_source_root(&root) {
            collect_source_files(&root, &mut files)?;
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn should_preload_source_root(root: &Path) -> bool {
    let normalized = root.to_string_lossy().replace('\\', "/");
    !normalized.contains("/Engine/Source")
}

fn collect_source_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if should_skip_source_dir(dir) {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read source directory '{}'", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_source_files(&path, files)?;
        } else if path.is_file() && is_source_file(&path) {
            files.push(normalize_existing_path(path));
        }
    }
    Ok(())
}

fn should_skip_source_dir(dir: &Path) -> bool {
    let Some(name) = dir.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name,
        ".git"
            | ".vs"
            | "Binaries"
            | "DerivedDataCache"
            | "Intermediate"
            | "Saved"
            | "Build"
            | "target"
            | "node_modules"
    )
}

fn is_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "hh" | "inl")
    )
}

fn absolute_source_roots(bundle: &SourceProfileBundle) -> Vec<PathBuf> {
    bundle
        .manifest
        .inputs
        .source_root_hints
        .iter()
        .map(|hint| absolute_bundle_path(bundle, hint))
        .collect()
}

fn absolute_path_remaps(bundle: &SourceProfileBundle) -> Vec<super::schema::PathRemap> {
    bundle
        .manifest
        .inputs
        .path_remaps
        .iter()
        .map(|remap| super::schema::PathRemap {
            from: remap.from.clone(),
            to: absolute_bundle_path(bundle, &remap.to)
                .to_string_lossy()
                .to_string(),
        })
        .collect()
}

fn absolute_bundle_path(bundle: &SourceProfileBundle, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        bundle.root.join(path)
    }
}

fn normalize_existing_path(path: PathBuf) -> PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path)
}

fn join_numbers(values: &BTreeSet<u32>) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn prefer_nonempty(current: &str, next: String) -> String {
    if current.is_empty() && !next.is_empty() {
        next
    } else {
        current.to_string()
    }
}

fn format_number(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.6}")
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn builds_report_model_with_nonzero_minimal_rows() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let model = build_report_model(&bundle).unwrap();
        assert!(model.rows.iter().any(|row| row.status.contains("NonZero")));
        assert!(model
            .rows
            .iter()
            .any(|row| metric_value_number(row.pmu_values.get("cpu_cycles")).unwrap_or(0.0) > 0.0));
    }

    #[test]
    fn raw_pmu_columns_are_event_sample_ratio_over_line_samples() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let row = MutableLineRow {
            file: PathBuf::from("fixture.cpp"),
            line: 1,
            function: "tick".to_string(),
            module: "libfixture.so".to_string(),
            code: "Tick();".to_string(),
            cpus: BTreeSet::from([0]),
            tids: BTreeSet::from([42]),
            pmu_self: BTreeMap::from([
                ("cpu_cycles".to_string(), 1000),
                ("inst_retired".to_string(), 1000),
            ]),
            pmu_acc: BTreeMap::new(),
            pmu_self_samples: BTreeMap::from([
                ("cpu_cycles".to_string(), 1),
                ("inst_retired".to_string(), 1),
            ]),
            pmu_acc_samples: BTreeMap::new(),
            pmu_sample_count: 2,
            spe: None,
            unresolved: Vec::new(),
        };
        let rows = finalize_rows(
            &bundle,
            BTreeMap::from([((row.file.clone(), row.line), row)]),
        );

        assert!(matches!(
            rows[0].pmu_values.get("cpu_cycles"),
            Some(MetricValue::Number(value)) if (*value - 0.5).abs() < f64::EPSILON
        ));
        assert!(matches!(
            rows[0].pmu_values.get("inst_retired"),
            Some(MetricValue::Number(value)) if (*value - 0.5).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn supported_zero_pmu_events_do_not_make_derived_metrics_missing() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let model = build_report_model(&bundle).unwrap();
        let row = model
            .rows
            .iter()
            .find(|row| {
                matches!(
                    row.pmu_values.get("cpu_cycles"),
                    Some(MetricValue::Number(0.0))
                ) && matches!(
                    row.pmu_values.get("inst_retired"),
                    Some(MetricValue::Number(0.0))
                )
            })
            .expect("fixture should include a supported source row without PMU samples");

        assert!(!matches!(
            row.pmu_values.get("cpi"),
            Some(MetricValue::Missing(_))
        ));
        assert!(matches!(
            row.pmu_values.get("cpi"),
            Some(MetricValue::Undefined(_))
        ));
        assert!(matches!(
            row.pmu_values.get("mips"),
            Some(MetricValue::Number(0.0))
        ));
        assert!(matches!(
            row.pmu_values.get("mcps"),
            Some(MetricValue::Number(0.0))
        ));
    }

    #[test]
    fn attribution_diagnostics_explain_empty_function_output() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let rows = vec![ReportLineRow {
            file: "a.cpp".to_string(),
            line: 1,
            function: String::new(),
            module: String::new(),
            code: "int main() {}".to_string(),
            status: "Missing".to_string(),
            cpu: String::new(),
            thread: String::new(),
            sample_count: 0,
            self_weight: 0.0,
            accumulated_weight: 0.0,
            p_pct: 0.0,
            acc_p_pct: 0.0,
            file_p_pct: 0.0,
            file_acc_p_pct: 0.0,
            pmu_values: BTreeMap::new(),
            spe_values: BTreeMap::new(),
            detail: String::new(),
        }];
        let mut warnings = Vec::new();

        append_attribution_diagnostics(&bundle, &rows, &mut warnings);

        assert!(warnings
            .iter()
            .any(|warning| warning.contains("No sampled source rows were attributed")));
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("No source rows contain function names")));
    }

    #[test]
    fn cpu_coverage_diagnostic_warns_when_samples_only_cover_one_selected_cpu() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        bundle.manifest.cpu.selected_cpus = vec![0, 1, 2, 3];
        let mut warnings = Vec::new();

        append_cpu_coverage_diagnostic(&bundle, 1, &BTreeSet::from([0]), &mut warnings);

        assert!(warnings
            .iter()
            .any(|warning| warning.contains("selected CPUs [0,1,2,3]")));
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("observed sample CPUs [0]")));
    }

    #[test]
    fn pmu_event_coverage_diagnostic_explains_missing_derived_metrics() {
        let mut warnings = Vec::new();

        append_pmu_event_coverage_diagnostic(
            1,
            &BTreeSet::from(["cpu_cycles".to_string()]),
            &mut warnings,
        );

        assert!(warnings.iter().any(|warning| {
            warning.contains("PMU samples only contain event(s)") && warning.contains("CPI")
        }));
    }

    #[test]
    fn missing_debug_elf_warning_ignores_android_os_modules() {
        let os_match = crate::source_profile::symbol_resolver::ElfMatch {
            module_id: "android.hardware.graphics.mapper@4.0.so".to_string(),
            runtime_path: "/system/lib64/android.hardware.graphics.mapper@4.0.so".to_string(),
            candidate_path: None,
            quality: ElfMatchQuality::Missing,
            reason: "missing".to_string(),
        };
        let app_match = crate::source_profile::symbol_resolver::ElfMatch {
            module_id: "libUE4.so".to_string(),
            runtime_path: "/data/app/pkg/lib/arm64/libUE4.so".to_string(),
            candidate_path: None,
            quality: ElfMatchQuality::Missing,
            reason: "missing".to_string(),
        };
        let pseudo_match = crate::source_profile::symbol_resolver::ElfMatch {
            module_id: "memfd:jit-cache (deleted)".to_string(),
            runtime_path: "/memfd:jit-cache (deleted)".to_string(),
            candidate_path: None,
            quality: ElfMatchQuality::Missing,
            reason: "missing".to_string(),
        };

        assert!(!should_warn_missing_debug_elf(&os_match));
        assert!(!should_warn_missing_debug_elf(&pseudo_match));
        assert!(should_warn_missing_debug_elf(&app_match));
    }
}

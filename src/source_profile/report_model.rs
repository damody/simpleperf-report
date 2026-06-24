#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use object::{Object, ObjectSymbol, SymbolKind};

use super::bundle::SourceProfileBundle;
use super::line_resolver::{
    resolve_source_path, runtime_address_to_relative, CachedElfLineResolver,
};
use super::metrics::{
    aggregate_pmu_file, aggregate_spe_by_address, aggregate_spe_categories_by_address,
    compute_percentages, derive_pmu_metrics, MetricValue, PmuAddressAggregate, SpeAddressAggregate,
    SpeAddressCategoryAggregate,
};
use super::sample_stream::{for_each_pmu_sample, read_spe_samples, PmuSample};
use super::schema::ProcessMapRecord;
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

pub fn pmu_raw_column_keys(bundle: &SourceProfileBundle) -> Vec<String> {
    let requested = &bundle.manifest.capture_options.requested_event_keys;
    let selected = requested.iter().cloned().collect::<BTreeSet<_>>();

    let mut keys = Vec::new();
    for event in &bundle.event_catalog.events {
        if (selected.is_empty() && event.source == "pmu") || selected.contains(&event.event_key) {
            keys.push(event.event_key.clone());
        }
    }
    for key in selected {
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    if keys.is_empty() {
        keys.extend(RAW_PMU_COLUMNS.iter().map(|key| (*key).to_string()));
    }
    keys
}

pub fn pmu_column_keys(bundle: &SourceProfileBundle) -> Vec<String> {
    let mut keys = pmu_raw_column_keys(bundle);
    keys.extend(pmu_derived_column_keys(bundle));
    keys
}

pub fn pmu_derived_column_keys(bundle: &SourceProfileBundle) -> Vec<String> {
    let raw = pmu_raw_column_keys(bundle)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let has = |key: &str| raw.contains(key);
    let mut keys = Vec::new();
    if has("cpu_cycles") && has("inst_retired") {
        keys.push("cpi".to_string());
    }
    if has("l1d_cache_access") && has("l1d_cache_refill") {
        keys.push("l1d_cache_hit_rate".to_string());
    }
    if has("l2d_cache_access") && has("l2d_cache_refill") {
        keys.push("l2d_cache_hit_rate".to_string());
    }
    if has("l3d_cache_access") && has("l3d_cache_refill") {
        keys.push("l3d_cache_hit_rate".to_string());
    }
    if has("branch_mispredict") && has("branch_retired") {
        keys.push("branch_miss_rate".to_string());
    }
    if has("l1d_cache_refill") && has("inst_retired") {
        keys.push("mpki".to_string());
    }
    if has("inst_retired") {
        keys.push("mips".to_string());
    }
    if has("cpu_cycles") {
        keys.push("mcps".to_string());
    }
    keys
}

#[derive(Debug, Clone)]
pub struct ReportModel {
    pub rows: Vec<ReportLineRow>,
    pub files: Vec<ReportFileRow>,
    pub functions: Vec<ReportFunctionRow>,
    pub frames: Vec<ReportFrameRow>,
    pub callchains: Vec<ReportCallchainRow>,
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
pub struct ReportFrameRow {
    pub role: String,
    pub module: String,
    pub function: String,
    pub ip: u64,
    pub relative_address: u64,
    pub mapping_id: u64,
    pub cpu: String,
    pub thread: String,
    pub sample_count: u64,
    pub self_weight: f64,
    pub accumulated_weight: f64,
    pub p_pct: f64,
    pub acc_p_pct: f64,
    pub event_weights: String,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct ReportCallchainRow {
    pub stack: String,
    pub leaf: String,
    pub root: String,
    pub cpu: String,
    pub thread: String,
    pub sample_count: u64,
    pub weight: f64,
    pub p_pct: f64,
    pub event_weights: String,
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
    spe_categories: Option<SpeAddressCategoryAggregate>,
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
            spe_categories: None,
            unresolved: Vec::new(),
        }
    }
}

pub fn build_report_model(bundle: &SourceProfileBundle) -> Result<ReportModel> {
    let total_start = Instant::now();
    let mut phase_start = Instant::now();
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
    log_timing(
        "build_model.source_discovery_and_preload",
        phase_start.elapsed(),
    );

    phase_start = Instant::now();
    let elf_matches = load_elf_matches(bundle)?;
    let mut warnings = collect_quality_warnings(bundle);
    let mut line_resolver = CachedElfLineResolver::default();
    let mut frames = Vec::new();
    let mut callchains = Vec::new();
    for matched in elf_matches.values() {
        if matched.quality == ElfMatchQuality::Missing && should_warn_missing_debug_elf(matched) {
            warnings.push(format!("Debug ELF Missing for {}", matched.module_id));
        } else if matched.quality != ElfMatchQuality::Missing
            && should_warn_missing_debug_elf(matched)
            && !matched.has_dwarf_debug_info
        {
            let candidate = matched
                .candidate_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            warnings.push(format!(
                "Debug ELF for {} matched {}, but it has no DWARF .debug_line/.debug_info sections. Source Lines cannot be generated from this stripped ELF; use an unstripped device library or enable local program analysis with an unstripped ELF.",
                matched.module_id, candidate
            ));
        }
    }
    log_timing("build_model.elf_matching", phase_start.elapsed());

    if let Some(path) = &bundle.pmu_samples_path {
        phase_start = Instant::now();
        let stack_report = build_pmu_stack_fallback(bundle, path, &elf_matches)?;
        frames = stack_report.0;
        callchains = stack_report.1;
        log_timing("build_model.pmu_stack_fallback", phase_start.elapsed());

        phase_start = Instant::now();
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
        log_timing("build_model.pmu_aggregate", phase_start.elapsed());

        phase_start = Instant::now();
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
        log_timing("build_model.pmu_resolve_merge_rows", phase_start.elapsed());
    }

    if let Some(path) = &bundle.spe_samples_path {
        phase_start = Instant::now();
        let (_, samples) = read_spe_samples(path)?;
        let aggregates = aggregate_spe_by_address(&samples);
        let mut category_aggregates = aggregate_spe_categories_by_address(&samples);
        log_timing("build_model.spe_read_aggregate", phase_start.elapsed());

        phase_start = Instant::now();
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
                row.spe_categories = category_aggregates.remove(&key);
                row.spe = Some(aggregate);
            } else {
                warnings.push(format!(
                    "Unresolved SPE sample mapping={} pc=0x{:x}",
                    key.mapping_id, key.ip
                ));
            }
        }
        log_timing("build_model.spe_resolve_merge_rows", phase_start.elapsed());
    }

    phase_start = Instant::now();
    let mut line_rows = finalize_rows(bundle, rows);
    compute_row_percentages(&mut line_rows);
    append_attribution_diagnostics(bundle, &line_rows, &mut warnings);
    let files = summarize_files(&line_rows);
    let functions = summarize_functions(&line_rows);
    log_timing("build_model.finalize_summaries", phase_start.elapsed());
    log_timing("build_model.total", total_start.elapsed());
    Ok(ReportModel {
        rows: line_rows,
        files,
        functions,
        frames,
        callchains,
        warnings,
    })
}

fn log_timing(phase: &str, elapsed: Duration) {
    eprintln!("[MProfilerTiming] {phase} ({:.1}s)", elapsed.as_secs_f64());
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
    let Some(relative_address) = relative_address_for_mapping(mapping, ip) else {
        return Ok(None);
    };
    let Some(matched) = elf_matches.get(&mapping.module_id) else {
        return Ok(None);
    };
    let Some(elf_path) = &matched.candidate_path else {
        return Ok(None);
    };
    let Some(location) = line_resolver
        .resolve(elf_path, relative_address)
        .with_context(|| format!("Failed to resolve 0x{:x}", relative_address))?
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

fn relative_address_for_mapping(mapping: &ProcessMapRecord, ip: u64) -> Option<u64> {
    if ip < mapping.start || ip >= mapping.end {
        return None;
    }
    if mapping.load_bias != 0 {
        if mapping.load_bias >= 0 {
            ip.checked_sub(mapping.load_bias as u64)
        } else {
            ip.checked_add((-mapping.load_bias) as u64)
        }
    } else {
        ip.checked_sub(mapping.start)?.checked_add(mapping.offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FrameKey {
    role: String,
    module: String,
    function: String,
    ip: u64,
    relative_address: u64,
    mapping_id: u64,
}

#[derive(Debug, Default)]
struct MutableFrameRow {
    cpus: BTreeSet<u32>,
    tids: BTreeSet<u32>,
    sample_count: u64,
    self_weight: u64,
    accumulated_weight: u64,
    event_weights: BTreeMap<String, u64>,
}

#[derive(Debug, Default)]
struct MutableCallchainRow {
    leaf: String,
    root: String,
    cpus: BTreeSet<u32>,
    tids: BTreeSet<u32>,
    sample_count: u64,
    weight: u64,
    event_weights: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
struct NamedAddress {
    mapping_id: u64,
    module: String,
    function: String,
    ip: u64,
    relative_address: u64,
}

#[derive(Debug, Clone)]
struct ElfSymbolName {
    address: u64,
    size: u64,
    name: String,
}

#[derive(Default)]
struct SymbolNameCache {
    by_module: BTreeMap<String, Vec<ElfSymbolName>>,
}

impl SymbolNameCache {
    fn from_matches(matches: &BTreeMap<String, super::symbol_resolver::ElfMatch>) -> Result<Self> {
        let mut cache = Self::default();
        for matched in matches.values() {
            let Some(path) = matched.candidate_path.as_deref() else {
                continue;
            };
            let bytes = match fs::read(path) {
                Ok(bytes) => bytes,
                Err(err) => {
                    eprintln!(
                        "Warning: skipping ELF symbol cache for '{}': failed to read: {err}",
                        path.display()
                    );
                    continue;
                }
            };
            let object = match object::File::parse(&*bytes) {
                Ok(object) => object,
                Err(err) => {
                    eprintln!(
                        "Warning: skipping ELF symbol cache for '{}': failed to parse ELF: {err}",
                        path.display()
                    );
                    continue;
                }
            };
            let mut symbols = Vec::new();
            collect_object_symbols(&object, &mut symbols);
            symbols.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| b.size.cmp(&a.size)));
            symbols.dedup_by(|a, b| a.address == b.address && a.name == b.name);
            cache.by_module.insert(matched.module_id.clone(), symbols);
        }
        Ok(cache)
    }

    fn resolve(&self, module: &str, relative_address: u64) -> String {
        let Some(symbols) = self.by_module.get(module) else {
            return String::new();
        };
        let mut low = 0_usize;
        let mut high = symbols.len();
        while low < high {
            let mid = (low + high) / 2;
            if symbols[mid].address <= relative_address {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        if low == 0 {
            return String::new();
        }
        let symbol = &symbols[low - 1];
        if symbol.size == 0 || relative_address < symbol.address.saturating_add(symbol.size) {
            symbol.name.clone()
        } else {
            String::new()
        }
    }
}

fn collect_object_symbols(object: &object::File<'_>, out: &mut Vec<ElfSymbolName>) {
    for symbol in object.symbols() {
        push_object_symbol(symbol, out);
    }
    for symbol in object.dynamic_symbols() {
        push_object_symbol(symbol, out);
    }
}

fn push_object_symbol(symbol: object::Symbol<'_, '_>, out: &mut Vec<ElfSymbolName>) {
    if symbol.kind() != SymbolKind::Text || symbol.address() == 0 {
        return;
    }
    let Ok(name) = symbol.name() else {
        return;
    };
    if name.is_empty() {
        return;
    }
    out.push(ElfSymbolName {
        address: symbol.address(),
        size: symbol.size(),
        name: demangle_symbol_name(name),
    });
}

fn demangle_symbol_name(name: &str) -> String {
    let Ok(symbol) = cpp_demangle::Symbol::new(name) else {
        return name.to_string();
    };
    symbol
        .demangle(&cpp_demangle::DemangleOptions::default())
        .unwrap_or_else(|_| name.to_string())
}

fn build_pmu_stack_fallback(
    bundle: &SourceProfileBundle,
    path: &Path,
    elf_matches: &BTreeMap<String, super::symbol_resolver::ElfMatch>,
) -> Result<(Vec<ReportFrameRow>, Vec<ReportCallchainRow>)> {
    let symbols = SymbolNameCache::from_matches(elf_matches)?;
    let mut frames = BTreeMap::<FrameKey, MutableFrameRow>::new();
    let mut callchains = BTreeMap::<String, MutableCallchainRow>::new();
    let mut address_cache = BTreeMap::<u64, NamedAddress>::new();

    for_each_pmu_sample(path, |sample| {
        aggregate_stack_sample(
            bundle,
            &symbols,
            &mut address_cache,
            &mut frames,
            &mut callchains,
            &sample,
        );
        Ok(())
    })?;

    let total_self = frames.values().map(|row| row.self_weight).sum::<u64>() as f64;
    let total_acc = frames
        .values()
        .map(|row| row.accumulated_weight)
        .sum::<u64>() as f64;
    let mut frame_rows = frames
        .into_iter()
        .map(|(key, row)| {
            let status = if key.function.is_empty() {
                "UnresolvedSymbol".to_string()
            } else {
                "Symbol".to_string()
            };
            ReportFrameRow {
                role: key.role,
                module: key.module,
                function: key.function,
                ip: key.ip,
                relative_address: key.relative_address,
                mapping_id: key.mapping_id,
                cpu: join_u32s(&row.cpus),
                thread: join_u32s(&row.tids),
                sample_count: row.sample_count,
                self_weight: row.self_weight as f64,
                accumulated_weight: row.accumulated_weight as f64,
                p_pct: percent(row.self_weight as f64, total_self),
                acc_p_pct: percent(row.accumulated_weight as f64, total_acc),
                event_weights: event_weights_text(&row.event_weights),
                status,
            }
        })
        .collect::<Vec<_>>();
    frame_rows.sort_by(|a, b| {
        b.self_weight
            .partial_cmp(&a.self_weight)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b.accumulated_weight
                    .partial_cmp(&a.accumulated_weight)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    let total_callchain = callchains.values().map(|row| row.weight).sum::<u64>() as f64;
    let mut callchain_rows = callchains
        .into_iter()
        .map(|(stack, row)| ReportCallchainRow {
            stack,
            leaf: row.leaf,
            root: row.root,
            cpu: join_u32s(&row.cpus),
            thread: join_u32s(&row.tids),
            sample_count: row.sample_count,
            weight: row.weight as f64,
            p_pct: percent(row.weight as f64, total_callchain),
            event_weights: event_weights_text(&row.event_weights),
        })
        .collect::<Vec<_>>();
    callchain_rows.sort_by(|a, b| {
        b.weight
            .partial_cmp(&a.weight)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok((frame_rows, callchain_rows))
}

fn aggregate_stack_sample(
    bundle: &SourceProfileBundle,
    symbols: &SymbolNameCache,
    address_cache: &mut BTreeMap<u64, NamedAddress>,
    frames: &mut BTreeMap<FrameKey, MutableFrameRow>,
    callchains: &mut BTreeMap<String, MutableCallchainRow>,
    sample: &PmuSample,
) {
    let event_key = bundle
        .event_catalog
        .events
        .get(sample.event_key_ref as usize)
        .map(|event| event.event_key.as_str())
        .unwrap_or("unknown_event")
        .to_string();
    let leaf = describe_runtime_ip_cached(bundle, symbols, address_cache, sample.ip);
    add_frame_row(
        frames,
        "self",
        &leaf,
        sample,
        &event_key,
        sample.period_or_weight,
        0,
    );

    let mut stack = Vec::with_capacity(sample.callchain_ips.len() + 1);
    stack.push(frame_label(&leaf));
    for ip in &sample.callchain_ips {
        let frame = describe_runtime_ip_cached(bundle, symbols, address_cache, *ip);
        add_frame_row(
            frames,
            "callchain",
            &frame,
            sample,
            &event_key,
            0,
            sample.period_or_weight,
        );
        stack.push(frame_label(&frame));
    }

    let stack_text = stack.join(" <- ");
    let row = callchains.entry(stack_text).or_default();
    if row.leaf.is_empty() {
        row.leaf = stack.first().cloned().unwrap_or_default();
        row.root = stack.last().cloned().unwrap_or_default();
    }
    row.cpus.insert(sample.cpu);
    row.tids.insert(sample.tid);
    row.sample_count += 1;
    row.weight += sample.period_or_weight;
    *row.event_weights.entry(event_key).or_default() += sample.period_or_weight;
}

fn add_frame_row(
    frames: &mut BTreeMap<FrameKey, MutableFrameRow>,
    role: &str,
    frame: &NamedAddress,
    sample: &PmuSample,
    event_key: &str,
    self_weight: u64,
    accumulated_weight: u64,
) {
    let key = FrameKey {
        role: role.to_string(),
        module: frame.module.clone(),
        function: frame.function.clone(),
        ip: frame.ip,
        relative_address: frame.relative_address,
        mapping_id: frame.mapping_id,
    };
    let row = frames.entry(key).or_default();
    row.cpus.insert(sample.cpu);
    row.tids.insert(sample.tid);
    row.sample_count += 1;
    row.self_weight += self_weight;
    row.accumulated_weight += accumulated_weight;
    *row.event_weights.entry(event_key.to_string()).or_default() +=
        self_weight.saturating_add(accumulated_weight);
}

fn describe_runtime_ip_cached(
    bundle: &SourceProfileBundle,
    symbols: &SymbolNameCache,
    cache: &mut BTreeMap<u64, NamedAddress>,
    ip: u64,
) -> NamedAddress {
    if let Some(frame) = cache.get(&ip) {
        return frame.clone();
    }
    let frame = describe_runtime_ip(bundle, symbols, ip);
    cache.insert(ip, frame.clone());
    frame
}

fn describe_runtime_ip(
    bundle: &SourceProfileBundle,
    symbols: &SymbolNameCache,
    ip: u64,
) -> NamedAddress {
    if let Some(relative) = runtime_address_to_relative(&bundle.maps.maps, ip) {
        return NamedAddress {
            mapping_id: relative.mapping_id,
            function: symbols.resolve(&relative.module_id, relative.relative_address),
            module: relative.module_id,
            ip,
            relative_address: relative.relative_address,
        };
    }
    NamedAddress {
        mapping_id: 0,
        module: "<unknown>".to_string(),
        function: String::new(),
        ip,
        relative_address: ip,
    }
}

fn frame_label(frame: &NamedAddress) -> String {
    if frame.function.is_empty() {
        format!("{}+0x{:x}", frame.module, frame.relative_address)
    } else {
        format!("{} ({})", frame.function, frame.module)
    }
}

fn join_u32s(values: &BTreeSet<u32>) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn event_weights_text(values: &BTreeMap<String, u64>) -> String {
    values
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn percent(value: f64, denominator: f64) -> f64 {
    if denominator > 0.0 {
        value / denominator * 100.0
    } else {
        0.0
    }
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
    let raw_pmu_keys = pmu_raw_column_keys(bundle);
    let event_support = event_support_map(bundle, &raw_pmu_keys);
    let effective_seconds = effective_time_seconds(bundle);
    rows.into_values()
        .map(|row| {
            let mut pmu_values = BTreeMap::new();
            let dense_pmu_self_samples =
                dense_supported_pmu_counts(&row.pmu_self_samples, &raw_pmu_keys, &event_support);
            for key in &raw_pmu_keys {
                if !event_support.get(key.as_str()).copied().unwrap_or(false) {
                    pmu_values.insert(
                        key.clone(),
                        MetricValue::Missing(format!("{key} is not available")),
                    );
                } else {
                    let sample_count = dense_pmu_self_samples.get(key).copied().unwrap_or(0);
                    let ratio = if row.pmu_sample_count > 0 {
                        sample_count as f64 / row.pmu_sample_count as f64
                    } else {
                        0.0
                    };
                    pmu_values.insert(key.clone(), MetricValue::Number(ratio));
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
    raw_pmu_keys: &[String],
    event_support: &BTreeMap<&str, bool>,
) -> BTreeMap<String, u64> {
    let mut dense = BTreeMap::new();
    for key in raw_pmu_keys {
        if event_support.get(key.as_str()).copied().unwrap_or(false) {
            dense.insert(key.clone(), sparse.get(key).copied().unwrap_or(0));
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

fn event_support_map<'a>(
    bundle: &SourceProfileBundle,
    raw_pmu_keys: &'a [String],
) -> BTreeMap<&'a str, bool> {
    let mut map = BTreeMap::new();
    for key in raw_pmu_keys {
        let supported = bundle
            .event_catalog
            .events
            .iter()
            .find(|event| event.event_key == *key)
            .is_some_and(|event| {
                event.per_cpu_support.is_empty()
                    || event.per_cpu_support.iter().any(|cpu| cpu.supported)
            });
        map.insert(key.as_str(), supported);
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
            | "reports"
            | "annotated_source"
            | "Binaries"
            | "DerivedDataCache"
            | "Intermediate"
            | "Saved"
            | "Build"
            | "target"
            | "node_modules"
    ) || name.starts_with("annotated_files")
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
            spe_categories: None,
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
    fn pmu_columns_follow_requested_manifest_keys_in_catalog_order() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        bundle.manifest.capture_options.requested_event_keys = vec![
            "stall_backend_membound".to_string(),
            "cpu_cycles".to_string(),
        ];
        bundle
            .event_catalog
            .events
            .push(crate::source_profile::schema::EventDefinition {
                event_key: "stall_backend_membound".to_string(),
                display_name: "Backend stall memory-bound".to_string(),
                source: "pmu".to_string(),
                event_type: "PERF_TYPE_RAW".to_string(),
                config: "0x8164".to_string(),
                arm_arch_event_code: Some("0x8164".to_string()),
                sample_period: 1000,
                unit: "samples".to_string(),
                semantic_tags: vec!["stall".to_string(), "backend".to_string()],
                per_cpu_support: Vec::new(),
            });

        let keys = pmu_raw_column_keys(&bundle);
        assert!(keys.contains(&"cpu_cycles".to_string()));
        assert!(keys.contains(&"stall_backend_membound".to_string()));
        assert!(!keys.contains(&"stall_backend_l2d".to_string()));
    }

    #[test]
    fn pmu_columns_default_to_catalog_events_not_fixed_list() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        bundle.manifest.capture_options.requested_event_keys.clear();
        bundle
            .event_catalog
            .events
            .retain(|event| event.event_key != "branch_mispredict");

        let keys = pmu_raw_column_keys(&bundle);

        assert!(!keys.contains(&"branch_mispredict".to_string()));
        assert!(keys.iter().all(|key| bundle
            .event_catalog
            .events
            .iter()
            .any(|event| event.event_key == *key)));
    }

    #[test]
    fn derived_pmu_columns_follow_requested_raw_events() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        bundle.manifest.capture_options.requested_event_keys =
            vec!["cpu_cycles".to_string(), "stall_backend".to_string()];

        let keys = pmu_derived_column_keys(&bundle);

        assert_eq!(keys, vec!["mcps".to_string()]);
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
            has_dwarf_debug_info: false,
        };
        let app_match = crate::source_profile::symbol_resolver::ElfMatch {
            module_id: "libUE4.so".to_string(),
            runtime_path: "/data/app/pkg/lib/arm64/libUE4.so".to_string(),
            candidate_path: None,
            quality: ElfMatchQuality::Missing,
            reason: "missing".to_string(),
            has_dwarf_debug_info: false,
        };
        let pseudo_match = crate::source_profile::symbol_resolver::ElfMatch {
            module_id: "memfd:jit-cache (deleted)".to_string(),
            runtime_path: "/memfd:jit-cache (deleted)".to_string(),
            candidate_path: None,
            quality: ElfMatchQuality::Missing,
            reason: "missing".to_string(),
            has_dwarf_debug_info: false,
        };

        assert!(!should_warn_missing_debug_elf(&os_match));
        assert!(!should_warn_missing_debug_elf(&pseudo_match));
        assert!(should_warn_missing_debug_elf(&app_match));
    }

    #[test]
    fn symbol_name_cache_skips_unparseable_elf_candidates() {
        let path = std::env::temp_dir().join(format!(
            "mprofiler-unparseable-elf-{}.so",
            std::process::id()
        ));
        std::fs::write(&path, b"\x7fELF\x02\x01\x01").expect("write malformed ELF fixture");
        let matches = BTreeMap::from([(
            "libbad.so".to_string(),
            crate::source_profile::symbol_resolver::ElfMatch {
                module_id: "libbad.so".to_string(),
                runtime_path: "/data/app/pkg/lib/arm64/libbad.so".to_string(),
                candidate_path: Some(path.clone()),
                quality: ElfMatchQuality::PathHint,
                reason: "runtime filename match".to_string(),
                has_dwarf_debug_info: false,
            },
        )]);

        let cache = SymbolNameCache::from_matches(&matches)
            .expect("unparseable debug ELF candidates should be skipped");

        assert!(cache.by_module.is_empty());
        let _ = std::fs::remove_file(path);
    }
}

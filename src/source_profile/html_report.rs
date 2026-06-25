#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use super::bundle::SourceProfileBundle;
use super::metrics::MetricValue;
use super::report_model::{
    build_report_model, pmu_derived_column_keys, pmu_raw_column_keys, ReportModel,
    INSTRUCTION_CLASS_METRICS, INSTRUCTION_CLASS_NAMES, LOAD_INSTRUCTION_KIND_NAMES,
    LOAD_INSTRUCTION_METRICS, SPE_CATEGORY_METRICS, SPE_CATEGORY_NAMES,
};
use super::summary::SourceReportSummary;

pub trait HtmlReportWriter {
    fn write_html(&self, summary: &SourceReportSummary, output: &Path) -> Result<()>;
}

pub fn write_html_summary(bundle: &SourceProfileBundle, output: &Path) -> Result<()> {
    let model = build_report_model(bundle)?;
    write_html_summary_from_model(bundle, &model, output)
}

pub fn write_html_summary_from_model(
    bundle: &SourceProfileBundle,
    model: &ReportModel,
    output: &Path,
) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create '{}'", parent.display()))?;
    }
    let manifest = &bundle.manifest;
    let raw_pmu_columns = pmu_raw_column_keys(bundle);
    let raw_pmu_columns_json =
        serde_json::to_string(&raw_pmu_columns).unwrap_or_else(|_| "[]".to_string());
    let derived_pmu_columns = pmu_derived_column_keys(bundle);
    let derived_pmu_columns_json =
        serde_json::to_string(&derived_pmu_columns).unwrap_or_else(|_| "[]".to_string());
    let mut spe_columns = displayed_spe_column_keys(model);
    spe_columns.extend(displayed_instruction_class_column_keys(model));
    spe_columns.extend(displayed_load_instruction_column_keys(model));
    let spe_columns_json = serde_json::to_string(&spe_columns).unwrap_or_else(|_| "[]".to_string());
    let spe_hierarchy_histograms_json =
        serde_json::to_string(&model.spe_hierarchical_cpu_histograms)
            .unwrap_or_else(|_| "{}".to_string());
    let mut default_source_columns = vec![
        "file".to_string(),
        "line".to_string(),
        "function".to_string(),
        "module".to_string(),
        "cpu".to_string(),
        "thread".to_string(),
        "sample_count".to_string(),
    ];
    default_source_columns.extend(raw_pmu_columns.iter().cloned());
    default_source_columns.extend(derived_pmu_columns.iter().cloned());
    default_source_columns.extend(default_spe_source_columns(&spe_columns, model));
    default_source_columns.push("code".to_string());
    let default_source_columns_json =
        serde_json::to_string(&default_source_columns).unwrap_or_else(|_| "[]".to_string());
    let html = format!(
        r##"<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <title>SourceLine Report - {session_id}</title>
  <style>
    body {{ font-family: "Segoe UI", sans-serif; margin: 24px; color: #1f2328; }}
    h1 {{ font-size: 24px; margin-bottom: 8px; }}
    h2 {{ font-size: 18px; margin-top: 24px; }}
    table {{ border-collapse: collapse; min-width: 720px; }}
    th, td {{ border: 1px solid #d0d7de; padding: 6px 8px; text-align: left; }}
    th {{ background: #f6f8fa; cursor: pointer; }}
    .table-scroll {{ overflow-x: auto; max-width: 100%; }}
    #sourceTable {{ table-layout: fixed; width: max-content; min-width: 5200px; }}
    #sourceTable.expanded {{ min-width: 7600px; }}
    #sourceTable.expanded .col-file {{ width: 760px; max-width: 760px; }}
    #sourceTable.expanded .col-function {{ width: 900px; max-width: 900px; }}
    #sourceTable.expanded .col-code {{ width: 900px; max-width: 900px; }}
    #sourceTable th,
    #sourceTable td {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: top; }}
    #sourceTable .col-file {{ width: 220px; max-width: 220px; }}
    #sourceTable .col-function {{ width: 220px; max-width: 220px; }}
    #sourceTable .truncate {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    #sourceTable .col-line {{ width: 64px; }}
    #sourceTable .col-module {{ width: 120px; }}
    #sourceTable .col-cpu {{ width: 64px; }}
    #sourceTable .col-thread {{ width: 170px; max-width: 170px; }}
    #sourceTable .col-metric {{ width: 92px; }}
    #sourceTable .col-wide-metric {{ width: 132px; }}
    #sourceTable .col-code {{ width: 360px; max-width: 360px; }}
    #sourceTable code {{ white-space: nowrap; }}
    #sourceTable th[data-source-sort] {{ user-select: none; }}
    #sourceTable th.sorted {{ background: #eef2f8; }}
    #filesTable th[data-file-sort] {{ cursor: pointer; user-select: none; }}
    #filesTable th.sorted {{ background: #eef2f8; }}
    .sort-indicator {{ display: inline-block; min-width: 1em; margin-left: 4px; color: #59636e; }}
    .source-line {{ display: grid; grid-template-columns: 72px minmax(0, 1fr); gap: 8px; font-family: Consolas, monospace; padding: 2px 4px; }}
    .source-line.NonZero {{ background: #fff8c5; }}
    .source-line.Missing {{ background: #ffebe9; }}
    .source-line.Unresolved {{ background: #fff1e5; }}
    .stack-table td {{ vertical-align: top; }}
    .stack-text {{ font-family: Consolas, monospace; max-width: 1200px; white-space: normal; overflow-wrap: anywhere; }}
    .toolbar {{ display: flex; gap: 8px; align-items: center; margin: 8px 0; flex-wrap: wrap; }}
    .toolbar input {{ padding: 4px 6px; }}
    .column-panel {{ border: 1px solid #d0d7de; background: #f6f8fa; padding: 8px; margin: 8px 0; }}
    .column-panel > summary {{ cursor: pointer; font-weight: 600; }}
    .column-panel[open] > summary {{ margin-bottom: 6px; }}
    .column-picker-controls {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, max-content)); gap: 8px 18px; align-items: start; }}
    .column-group {{ display: grid; gap: 3px; align-content: start; }}
    .column-group-title {{ display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 700; color: #57606a; text-transform: uppercase; }}
    .column-group-title input {{ width: 16px; height: 16px; }}
    .column-group label {{ white-space: nowrap; }}
    .spe-summary-table tbody tr.cpu-shade-0 td {{ background: #f7fbff; }}
    .spe-summary-table tbody tr.cpu-shade-1 td {{ background: #f7fff9; }}
    .spe-summary-table tbody tr.cpu-shade-2 td {{ background: #fffdf4; }}
    .spe-summary-table tbody tr.cpu-shade-3 td {{ background: #fff8fb; }}
    .spe-summary-table tbody tr.cpu-shade-4 td {{ background: #f8fbfa; }}
    .spe-summary-table tbody tr.cpu-shade-5 td {{ background: #fbf8ff; }}
    .spe-summary-table tbody tr[data-spe-parent] {{ cursor: pointer; }}
    .spe-child-label {{ padding-left: 24px; }}
    .spe-collapse-indicator {{ display: inline-block; width: 14px; color: #57606a; font-weight: 600; }}
    .spe-summary-table tbody tr.selected td {{ outline: 2px solid #2563eb; outline-offset: -2px; }}
    .spe-histogram-panel {{ position: fixed; top: 0; left: 0; width: min(620px, calc(100vw - 24px)); max-height: calc(100vh - 24px); overflow: auto; border: 1px solid #d0d7de; padding: 10px; background: #fff; box-shadow: 0 8px 24px rgba(15, 23, 42, 0.18); z-index: 20; border-radius: 4px; }}
    .spe-histogram-panel[hidden] {{ display: none; }}
    .spe-histogram-header {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; margin-bottom: 8px; cursor: move; user-select: none; }}
    .spe-histogram-title {{ font-weight: 600; }}
    .spe-histogram-hide {{ border: 1px solid #d0d7de; background: #fff; color: #24292f; padding: 2px 6px; cursor: pointer; border-radius: 4px; }}
    .spe-histogram-row {{ display: grid; grid-template-columns: 160px minmax(120px, 1fr) 64px; align-items: center; gap: 8px; margin: 4px 0; }}
    .spe-histogram-label {{ font-family: Consolas, monospace; font-size: 12px; }}
    .spe-histogram-bar-track {{ height: 14px; background: #f1f5f9; border: 1px solid #d0d7de; }}
    .spe-histogram-bar-track.empty {{ background: #fff; }}
    .spe-histogram-bar {{ height: 100%; background: #2563eb; min-width: 2px; }}
    .spe-histogram-count {{ text-align: right; font-variant-numeric: tabular-nums; }}
    details.report-section {{ margin-top: 24px; }}
    details.report-section > summary {{ cursor: pointer; font-size: 18px; font-weight: 600; }}
    details.report-section > table,
    details.report-section > .toolbar {{ margin-top: 8px; }}
    code {{ font-family: Consolas, monospace; }}
  </style>
</head>
<body>
  <h1>SourceLine Report</h1>
  <details class="report-section">
  <summary>Column Help</summary>
  <table>
    <tr><th>Column / Metric</th><th>Formula / Source</th><th>意義 / 限制</th></tr>
    {column_help_rows}
  </table>
  </details>
  <details class="report-section" open>
  <summary>Summary</summary>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Session</td><td><code>{session_id}</code></td></tr>
    <tr><td>Target package</td><td><code>{package}</code></td></tr>
    <tr><td>PID</td><td>{pid}</td></tr>
    <tr><td>Duration</td><td>{duration_ms} ms</td></tr>
    <tr><td>Device</td><td>{device}</td></tr>
    <tr><td>ABI</td><td>{abi}</td></tr>
    <tr><td>Selected CPUs</td><td>{cpus}</td></tr>
    <tr><td>Selected clusters</td><td>{clusters}</td></tr>
    <tr><td>PMU lane</td><td>{pmu_lane}</td></tr>
    <tr><td>SPE lane</td><td>{spe_lane}</td></tr>
    <tr><td>PMU buffer pages</td><td>{pmu_buffer_pages}</td></tr>
    <tr><td>SPE AUX buffer bytes</td><td>{spe_aux_buffer_bytes}</td></tr>
    <tr><td>Sample period</td><td>{sample_period}</td></tr>
    <tr><td>Callchain depth</td><td>{callchain_depth}</td></tr>
  </table>
  </details>
  <details class="report-section" open>
  <summary>SPE Hierarchical Breakdown</summary>
  <p>SPE parent rows are CPU-relative. Child rows are relative to their parent category.</p>
  <details class="column-panel">
    <summary>SPE Hierarchical Breakdown Columns</summary>
    <div id="speBreakdownColumnPicker" class="column-picker-controls"></div>
  </details>
  <table class="spe-summary-table">
    <tr><th data-spe-column="cpu">CPU</th><th data-spe-column="category">Category</th><th data-spe-column="sample_pct">sample%</th><th data-spe-column="est_time_pct">est_time%</th><th data-spe-column="all_est_time_pct">all est_time%</th><th data-spe-column="min_latency_cycles">min_latency_cycles</th><th data-spe-column="max_latency_cycles">max_latency_cycles</th><th data-spe-column="avg_latency_cycles">avg_latency_cycles</th><th data-spe-column="std_latency_cycles">std_latency_cycles</th><th data-spe-column="p95_latency_cycles">p95_latency_cycles</th><th data-spe-column="p99_latency_cycles">p99_latency_cycles</th><th data-spe-column="over_theory_sample_pct">&gt;theory sample%</th><th data-spe-column="over_theory_est_time_pct">&gt;theory est_time%</th><th data-spe-column="over_p95_est_time_pct">&gt;p95 est_time%</th><th data-spe-column="over_avg_est_time_pct">&gt;avg est_time%</th><th data-spe-column="over_p95_all_est_time_pct">&gt;p95 all est_time%</th><th data-spe-column="over_avg_all_est_time_pct">&gt;avg all est_time%</th></tr>
    {spe_hierarchy_summary_rows}
  </table>
  <div id="speHierarchyHistogram" class="spe-histogram-panel" hidden></div>
  </details>
  <details class="report-section">
    <summary>Quality</summary>
    <table>
      <thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
      <tbody id="qualityRows">
        {quality_rows}
      </tbody>
    </table>
  </details>
  <details class="report-section" open>
  <summary>Source Lines</summary>
  <div class="toolbar">
    <input id="sourceFilter" placeholder="filter file/function/code" oninput="renderSourceRows()">
    <label><input type="checkbox" id="sampledFirst" onchange="renderSourceRows()" checked> sampled first</label>
    <label><input type="checkbox" id="functionFirst" onchange="renderSourceRows()" checked> function first</label>
    <label><input type="checkbox" id="functionOnly" onchange="renderSourceRows()"> function only</label>
    <label><input type="checkbox" id="nonzeroOnly" onchange="renderSourceRows()"> nonzero only</label>
    <label><input type="checkbox" id="missingOnly" onchange="renderSourceRows()"> Missing only</label>
    <label><input type="checkbox" id="unresolvedOnly" onchange="renderSourceRows()"> Unresolved only</label>
    <input id="cpuFilter" placeholder="CPU" oninput="renderSourceRows()">
    <input id="threadFilter" placeholder="thread" oninput="renderSourceRows()">
    <label>min samples <input id="minSamples" type="number" min="0" value="0" oninput="resetSourcePaging()"></label>
    <label>page size <input id="pageSize" type="number" min="1" max="10000" value="1000" onchange="resetSourcePaging()"></label>
    <button id="sourceWidthToggle" onclick="toggleSourceWidth()">Expand width</button>
    <button onclick="previousSourcePage()">Prev</button>
    <button onclick="nextSourcePage()">Next</button>
    <span id="sourcePageStatus"></span>
  </div>
  <details class="column-panel">
    <summary>Source Lines Columns</summary>
    <div id="sourceColumnPicker" class="column-picker-controls"></div>
  </details>
  <div class="table-scroll">
  <table id="sourceTable">
    <thead>
      <tr id="sourceHeaderRow"><th data-source-sort="p_pct" hidden></th><th data-source-sort="mcps" hidden></th></tr>
    </thead>
    <tbody></tbody>
  </table>
  </div>
  </details>
  <details class="report-section">
  <summary>Files</summary>
  <div class="toolbar">
    <input id="fileFilter" placeholder="filter file" oninput="resetFilePaging()">
    <label>page size <input id="filePageSize" type="number" min="1" max="10000" value="1000" onchange="resetFilePaging()"></label>
    <button onclick="previousFilePage()">Prev</button>
    <button onclick="nextFilePage()">Next</button>
    <span id="filePageStatus"></span>
  </div>
  <table id="filesTable">
    <thead><tr><th data-file-sort="file" onclick="sortFileRows('file')">File <span class="sort-indicator"></span></th><th data-file-sort="self" onclick="sortFileRows('self')">Self <span class="sort-indicator"></span></th><th data-file-sort="acc" onclick="sortFileRows('acc')">Accumulated <span class="sort-indicator"></span></th><th data-file-sort="samples" onclick="sortFileRows('samples')">Samples <span class="sort-indicator"></span></th><th data-file-sort="hot_lines" onclick="sortFileRows('hot_lines')">Hot Lines <span class="sort-indicator"></span></th><th data-file-sort="missing" onclick="sortFileRows('missing')">Missing <span class="sort-indicator"></span></th><th data-file-sort="unresolved" onclick="sortFileRows('unresolved')">Unresolved <span class="sort-indicator"></span></th></tr></thead>
    <tbody></tbody>
  </table>
  </details>
  <details class="report-section">
  <summary>Functions</summary>
  <table id="functionsTable">
    <thead><tr><th>Function</th><th>File</th><th>Lines</th><th>Module</th><th>Self</th><th>Accumulated</th><th>Samples</th><th>Hot Lines</th></tr></thead>
    <tbody></tbody>
  </table>
  </details>
  <details class="report-section" open>
  <summary>Callchain Frames</summary>
  <div class="table-scroll">
  <table class="stack-table">
    <thead><tr><th>Role</th><th>Module</th><th>Function</th><th>IP</th><th>Relative</th><th>CPU</th><th>Thread</th><th>Samples</th><th>Self</th><th>Accumulated</th><th>p %</th><th>acc_p %</th><th>Status</th></tr></thead>
    <tbody>{frame_rows}</tbody>
  </table>
  </div>
  </details>
  <details class="report-section" open>
  <summary>Callchains</summary>
  <div class="table-scroll">
  <table class="stack-table">
    <thead><tr><th>Stack</th><th>Leaf</th><th>Root</th><th>CPU</th><th>Thread</th><th>Samples</th><th>Weight</th><th>p %</th></tr></thead>
    <tbody>{callchain_rows}</tbody>
  </table>
  </div>
  </details>
  <details class="report-section">
  <summary>Artifacts</summary>
  <table>
    <tr><th>Role</th><th>Path</th><th>Required</th><th>Encoding</th></tr>
    {artifact_rows}
  </table>
  </details>
  <script>
    const query = new URLSearchParams(location.search);
    const API_BASE = query.get("api") || (location.protocol.startsWith("http") ? location.origin : "http://127.0.0.1:9600");
    let sourceSortKey = "file";
    let sourceSortAsc = true;
    let sourceOffset = 0;
    let sourceTotal = 0;
    let fileOffset = 0;
    let fileTotal = 0;
    let fileSortKey = "self";
    let fileSortAsc = false;
    let activeFileRows = [];
    let activeSourceRows = [];
    let speHistogramDrag = null;
    let speHistogramManuallyPositioned = false;
    const RAW_PMU_COLUMNS = {raw_pmu_columns_json};
    const DERIVED_PMU_COLUMNS = {derived_pmu_columns_json};
    const SPE_COLUMNS = {spe_columns_json};
    const SPE_HIERARCHY_HISTOGRAMS = {spe_hierarchy_histograms_json};
    const SPE_BREAKDOWN_COLUMNS = [
      {{ key: "cpu", label: "CPU" }},
      {{ key: "category", label: "Category" }},
      {{ key: "sample_pct", label: "sample%" }},
      {{ key: "est_time_pct", label: "est_time%" }},
      {{ key: "all_est_time_pct", label: "all est_time%" }},
      {{ key: "min_latency_cycles", label: "min_latency_cycles" }},
      {{ key: "max_latency_cycles", label: "max_latency_cycles" }},
      {{ key: "avg_latency_cycles", label: "avg_latency_cycles" }},
      {{ key: "std_latency_cycles", label: "std_latency_cycles" }},
      {{ key: "p95_latency_cycles", label: "p95_latency_cycles" }},
      {{ key: "p99_latency_cycles", label: "p99_latency_cycles" }},
      {{ key: "over_theory_sample_pct", label: ">theory sample%" }},
      {{ key: "over_theory_est_time_pct", label: ">theory est_time%" }},
      {{ key: "over_p95_est_time_pct", label: ">p95 est_time%" }},
      {{ key: "over_avg_est_time_pct", label: ">avg est_time%" }},
      {{ key: "over_p95_all_est_time_pct", label: ">p95 all est_time%" }},
      {{ key: "over_avg_all_est_time_pct", label: ">avg all est_time%" }},
    ];
    let visibleSpeBreakdownColumns = new Set(SPE_BREAKDOWN_COLUMNS.map(column => column.key));
    const SOURCE_COLUMNS = [
      {{ key: "file", label: "File", cls: "col-file truncate", value: row => row.file }},
      {{ key: "line", label: "Line", cls: "col-line", value: row => row.line }},
      {{ key: "function", label: "Function", cls: "col-function truncate", value: row => row.function }},
      {{ key: "module", label: "Module", cls: "col-module truncate", value: row => row.module }},
      {{ key: "cpu", label: "CPU", cls: "col-cpu", value: row => row.cpu }},
      {{ key: "thread", label: "Thread", cls: "col-thread truncate", value: row => row.thread }},
      {{ key: "sample_count", label: "Samples", cls: "col-metric", value: row => row.sample_count, format: formatMetric }},
      {{ key: "p_pct", label: "p %", cls: "col-metric", value: row => row.p_pct, format: formatPercent }},
      {{ key: "acc_p_pct", label: "acc %", cls: "col-metric", value: row => row.acc_p_pct, format: formatPercent }},
      {{ key: "file_p_pct", label: "file p %", cls: "col-wide-metric", value: row => row.file_p_pct, format: formatPercent }},
      {{ key: "file_acc_p_pct", label: "file acc %", cls: "col-wide-metric", value: row => row.file_acc_p_pct, format: formatPercent }},
      ...RAW_PMU_COLUMNS.map(key => ({{ key, label: key, cls: "col-wide-metric", value: row => metricValue(row, key) }})),
      ...DERIVED_PMU_COLUMNS.map(key => ({{ key, label: key, cls: "col-wide-metric", value: row => metricValue(row, key) }})),
      ...SPE_COLUMNS.map(key => ({{ key, label: key, cls: "col-wide-metric", value: row => metricValue(row, key) }})),
      {{ key: "code", label: "Code", cls: "col-code truncate", value: row => row.code, code: true }},
    ];
    const SOURCE_COLUMN_GROUPS = [
      {{ title: "Basic", keys: ["file", "line", "function", "module", "cpu", "thread", "sample_count"] }},
      {{ title: "Percent", keys: ["p_pct", "acc_p_pct", "file_p_pct", "file_acc_p_pct"] }},
      {{ title: "Recorded PMU", keys: RAW_PMU_COLUMNS }},
      {{ title: "Derived PMU", keys: DERIVED_PMU_COLUMNS }},
      {{ title: "Recorded SPE", keys: SPE_COLUMNS }},
      {{ title: "Source", keys: ["code"] }},
    ];
    const DEFAULT_SOURCE_COLUMNS = {default_source_columns_json};
    let visibleSourceColumns = new Set(DEFAULT_SOURCE_COLUMNS);
    function escapeText(value) {{
      return String(value ?? "").replace(/[&<>"']/g, ch => ({{"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}}[ch]));
    }}
    function pageSize() {{
      const input = document.getElementById("pageSize");
      const value = Number.parseInt(input.value || "1000", 10);
      const clamped = Math.min(10000, Math.max(1, Number.isFinite(value) ? value : 1000));
      input.value = String(clamped);
      return clamped;
    }}
    function filePageSize() {{
      const input = document.getElementById("filePageSize");
      const value = Number.parseInt(input.value || "1000", 10);
      const clamped = Math.min(10000, Math.max(1, Number.isFinite(value) ? value : 1000));
      input.value = String(clamped);
      return clamped;
    }}
    function resetFilePaging() {{
      fileOffset = 0;
      renderFiles();
    }}
    function sortFileRows(key) {{
      if (fileSortKey === key) {{
        fileSortAsc = !fileSortAsc;
      }} else {{
        fileSortKey = key;
        fileSortAsc = key === "file";
      }}
      fileOffset = 0;
      renderFiles();
    }}
    function updateFileSortIndicators() {{
      document.querySelectorAll("#filesTable th[data-file-sort]").forEach(th => {{
        const active = th.dataset.fileSort === fileSortKey;
        th.classList.toggle("sorted", active);
        th.setAttribute("aria-sort", active ? (fileSortAsc ? "ascending" : "descending") : "none");
        const indicator = th.querySelector(".sort-indicator");
        if (indicator) indicator.textContent = active ? (fileSortAsc ? "▲" : "▼") : "";
      }});
    }}
    function resetSourcePaging() {{
      sourceOffset = 0;
      renderSourceRows();
    }}
    function visibleSpeBreakdownColumnList() {{
      return SPE_BREAKDOWN_COLUMNS.filter(column => visibleSpeBreakdownColumns.has(column.key));
    }}
    function applySpeBreakdownColumnVisibility() {{
      document.querySelectorAll("[data-spe-column]").forEach(cell => {{
        cell.hidden = !visibleSpeBreakdownColumns.has(cell.dataset.speColumn);
      }});
    }}
    function toggleSpeBreakdownColumn(key, checked) {{
      if (checked) {{
        visibleSpeBreakdownColumns.add(key);
      }} else if (visibleSpeBreakdownColumns.size > 1) {{
        visibleSpeBreakdownColumns.delete(key);
      }}
      applySpeBreakdownColumnVisibility();
      renderSpeBreakdownColumnPicker();
      hideSpeHierarchyHistogram();
    }}
    function renderSpeBreakdownColumnPicker() {{
      document.getElementById("speBreakdownColumnPicker").innerHTML = SPE_BREAKDOWN_COLUMNS
        .map(column => `<label><input type="checkbox" onchange="toggleSpeBreakdownColumn('${{column.key}}', this.checked)" ${{visibleSpeBreakdownColumns.has(column.key) ? "checked" : ""}}> ${{escapeText(column.label)}}</label>`)
        .join("");
    }}
    function speHierarchyChildRows(cpu, parent) {{
      return Array.from(document.querySelectorAll(".spe-summary-table tr[data-spe-child]"))
        .filter(row => row.dataset.speCpu === cpu && row.dataset.speParent === parent && row.dataset.speChild);
    }}
    function toggleSpeHierarchyChildren(row) {{
      if (row.dataset.speCollapsible !== "true" || row.dataset.speChild) return;
      const expanded = row.getAttribute("aria-expanded") !== "true";
      row.setAttribute("aria-expanded", expanded ? "true" : "false");
      const indicator = row.querySelector(".spe-collapse-indicator");
      if (indicator) indicator.textContent = expanded ? "-" : "+";
      speHierarchyChildRows(row.dataset.speCpu, row.dataset.speParent).forEach(childRow => {{
        childRow.hidden = !expanded;
      }});
    }}
    function positionSpeHierarchyHistogram(row) {{
      const panel = document.getElementById("speHierarchyHistogram");
      if (!panel || panel.hidden) return;
      if (speHistogramManuallyPositioned) return;
      const margin = 12;
      const gap = 10;
      const rowRect = row.getBoundingClientRect();
      const panelWidth = Math.min(620, window.innerWidth - margin * 2);
      panel.style.width = `${{panelWidth}}px`;
      const left = Math.max(margin, window.innerWidth - panelWidth - margin);
      const panelHeight = Math.min(panel.scrollHeight, window.innerHeight - margin * 2);
      let top = rowRect.bottom + gap;
      if (top + panelHeight > window.innerHeight - margin) {{
        top = Math.max(margin, window.innerHeight - panelHeight - margin);
      }}
      panel.style.left = `${{left}}px`;
      panel.style.top = `${{Math.max(margin, top)}}px`;
    }}
    function clampSpeHistogramPosition(left, top) {{
      const panel = document.getElementById("speHierarchyHistogram");
      const margin = 12;
      const rect = panel.getBoundingClientRect();
      return {{
        left: Math.min(Math.max(margin, left), Math.max(margin, window.innerWidth - rect.width - margin)),
        top: Math.min(Math.max(margin, top), Math.max(margin, window.innerHeight - rect.height - margin)),
      }};
    }}
    function startSpeHistogramDrag(event) {{
      if (event.target.closest("button")) return;
      const panel = document.getElementById("speHierarchyHistogram");
      if (!panel || panel.hidden) return;
      const rect = panel.getBoundingClientRect();
      speHistogramDrag = {{
        pointerId: event.pointerId,
        offsetX: event.clientX - rect.left,
        offsetY: event.clientY - rect.top,
      }};
      speHistogramManuallyPositioned = true;
      event.currentTarget.setPointerCapture(event.pointerId);
      event.preventDefault();
    }}
    function moveSpeHistogramDrag(event) {{
      if (!speHistogramDrag || event.pointerId !== speHistogramDrag.pointerId) return;
      const panel = document.getElementById("speHierarchyHistogram");
      const position = clampSpeHistogramPosition(
        event.clientX - speHistogramDrag.offsetX,
        event.clientY - speHistogramDrag.offsetY,
      );
      panel.style.left = `${{position.left}}px`;
      panel.style.top = `${{position.top}}px`;
    }}
    function endSpeHistogramDrag(event) {{
      if (!speHistogramDrag || event.pointerId !== speHistogramDrag.pointerId) return;
      speHistogramDrag = null;
    }}
    function hideSpeHierarchyHistogram() {{
      const panel = document.getElementById("speHierarchyHistogram");
      if (panel) panel.hidden = true;
      speHistogramDrag = null;
      speHistogramManuallyPositioned = false;
      document.querySelectorAll(".spe-summary-table tr.selected").forEach(active => active.classList.remove("selected"));
    }}
    function speHistogramHeader(title) {{
      return `<div class="spe-histogram-header" onpointerdown="startSpeHistogramDrag(event)" onpointermove="moveSpeHistogramDrag(event)" onpointerup="endSpeHistogramDrag(event)" onpointercancel="endSpeHistogramDrag(event)"><div class="spe-histogram-title">${{title}}</div><button type="button" class="spe-histogram-hide" onclick="hideSpeHierarchyHistogram()">Hide</button></div>`;
    }}
    function renderSpeHierarchyHistogram(row) {{
      document.querySelectorAll(".spe-summary-table tr.selected").forEach(active => active.classList.remove("selected"));
      row.classList.add("selected");
      toggleSpeHierarchyChildren(row);
      const cpu = row.dataset.speCpu;
      const parent = row.dataset.speParent;
      const child = row.dataset.speChild;
      const key = child ? `${{parent}}.${{child}}` : parent;
      const title = child ? `CPU ${{escapeText(cpu)}} / ${{escapeText(parent)}} / ${{escapeText(child)}}` : `CPU ${{escapeText(cpu)}} / ${{escapeText(parent)}}`;
      const histogram = SPE_HIERARCHY_HISTOGRAMS?.[cpu]?.[key];
      const panel = document.getElementById("speHierarchyHistogram");
      if (!histogram || !Array.isArray(histogram.bins) || histogram.bins.length === 0) {{
        panel.innerHTML = `${{speHistogramHeader(title)}}<div>No latency histogram data</div>`;
        panel.hidden = false;
        speHistogramManuallyPositioned = false;
        positionSpeHierarchyHistogram(row);
        return;
      }}
      const maxCount = Math.max(...histogram.bins.map(bin => Number(bin.count) || 0), 1);
      const rows = histogram.bins.map(bin => {{
        const count = Number(bin.count) || 0;
        const width = count > 0 ? Math.max(2, count / maxCount * 100) : 0;
        const start = formatMetric(bin.start_latency_cycles);
        const end = formatMetric(bin.end_latency_cycles);
        const trackClass = count === 0 ? "spe-histogram-bar-track empty" : "spe-histogram-bar-track";
        const bar = count > 0 ? `<div class="spe-histogram-bar" style="width:${{width}}%"></div>` : "";
        return `<div class="spe-histogram-row"><div class="spe-histogram-label">${{start}}-${{end}}</div><div class="${{trackClass}}">${{bar}}</div><div class="spe-histogram-count">${{count}}</div></div>`;
      }}).join("");
      const histogramTitle = `${{title}} latency cycles histogram (${{histogram.count}} samples, min ${{formatMetric(histogram.min_latency_cycles)}}, max ${{formatMetric(histogram.max_latency_cycles)}})`;
      panel.innerHTML = `${{speHistogramHeader(histogramTitle)}}${{rows}}`;
      panel.hidden = false;
      speHistogramManuallyPositioned = false;
      positionSpeHierarchyHistogram(row);
    }}
    window.addEventListener("resize", () => {{
      const row = document.querySelector(".spe-summary-table tr.selected");
      if (row) positionSpeHierarchyHistogram(row);
    }});
    window.addEventListener("scroll", () => {{
      const row = document.querySelector(".spe-summary-table tr.selected");
      if (row) positionSpeHierarchyHistogram(row);
    }}, true);
    function metricValue(row, key) {{
      return row.pmu_values?.[key] ?? row.spe_values?.[key] ?? row.instruction_values?.[key] ?? row.load_instruction_values?.[key] ?? "0";
    }}
    function visibleSourceColumnList() {{
      return SOURCE_COLUMNS.filter(column => visibleSourceColumns.has(column.key));
    }}
    function toggleSourceColumn(key, checked) {{
      if (checked) {{
        visibleSourceColumns.add(key);
      }} else if (visibleSourceColumns.size > 1) {{
        visibleSourceColumns.delete(key);
      }}
      renderSourceHeaders();
      renderSourceBody();
      updateSourceColumnGroupChecks();
    }}
    function toggleSourceColumnGroup(groupIndex, checked) {{
      const byKey = new Map(SOURCE_COLUMNS.map(column => [column.key, column]));
      const keys = SOURCE_COLUMN_GROUPS[groupIndex].keys.filter(key => byKey.has(key));
      if (checked) {{
        keys.forEach(key => visibleSourceColumns.add(key));
      }} else {{
        keys.forEach(key => visibleSourceColumns.delete(key));
        if (visibleSourceColumns.size === 0 && keys.length > 0) {{
          visibleSourceColumns.add(keys[0]);
        }}
      }}
      renderSourceHeaders();
      renderSourceBody();
      renderSourceColumnPicker();
    }}
    function updateSourceColumnGroupChecks() {{
      const byKey = new Map(SOURCE_COLUMNS.map(column => [column.key, column]));
      SOURCE_COLUMN_GROUPS.forEach((group, index) => {{
        const input = document.querySelector(`input[data-column-group="${{index}}"]`);
        if (!input) return;
        const keys = group.keys.filter(key => byKey.has(key));
        const selected = keys.filter(key => visibleSourceColumns.has(key)).length;
        input.checked = keys.length > 0 && selected === keys.length;
        input.indeterminate = selected > 0 && selected < keys.length;
      }});
    }}
    function renderSourceColumnPicker() {{
      const byKey = new Map(SOURCE_COLUMNS.map(column => [column.key, column]));
      document.getElementById("sourceColumnPicker").innerHTML = SOURCE_COLUMN_GROUPS
        .map((group, groupIndex) => {{
          const controls = group.keys
            .map(key => byKey.get(key))
            .filter(Boolean)
            .map(column => `<label><input type="checkbox" onchange="toggleSourceColumn('${{column.key}}', this.checked)" ${{visibleSourceColumns.has(column.key) ? "checked" : ""}}> ${{escapeText(column.label)}}</label>`)
            .join("");
          return `<div class="column-group"><label class="column-group-title"><input type="checkbox" data-column-group="${{groupIndex}}" onchange="toggleSourceColumnGroup(${{groupIndex}}, this.checked)"> ${{escapeText(group.title)}}</label>${{controls}}</div>`;
        }})
        .join("");
      updateSourceColumnGroupChecks();
    }}
    function renderSourceHeaders() {{
      document.getElementById("sourceHeaderRow").innerHTML = visibleSourceColumnList().map(column => `<th class="${{escapeText(column.cls || "col-metric")}}" data-source-sort="${{escapeText(column.key)}}" onclick="sortSourceRows('${{escapeText(column.key)}}')">${{escapeText(column.label)}} <span class="sort-indicator"></span></th>`).join("");
      updateSourceSortIndicators();
    }}
    function renderSourceBody() {{
      const tbody = document.querySelector("#sourceTable tbody");
      const columns = visibleSourceColumnList();
      if (activeSourceRows.length === 0) {{
        tbody.innerHTML = `<tr><td colspan="${{columns.length}}">No rows</td></tr>`;
        return;
      }}
      tbody.innerHTML = activeSourceRows.map(row => {{
        const annotation = row.annotation || row.detail || row.status;
        return `<tr title="${{escapeText(annotation)}}">${{columns.map(column => sourceCellHtml(row, column)).join("")}}</tr>`;
      }}).join("");
    }}
    function sourceCellHtml(row, column) {{
      const value = column.value(row);
      const text = column.format ? column.format(value) : escapeText(value);
      const title = column.key === "code" ? row.annotation || row.detail || row.status : value;
      const body = column.code ? `<code>${{text}}</code>` : text;
      return `<td class="${{escapeText(column.cls || "col-metric")}}" title="${{escapeText(title)}}">${{body}}</td>`;
    }}
    function toggleSourceWidth() {{
      const table = document.getElementById("sourceTable");
      const expanded = table.classList.toggle("expanded");
      document.getElementById("sourceWidthToggle").textContent = expanded ? "Compact width" : "Expand width";
    }}
    function sortSourceRows(key) {{
      if (sourceSortKey === key) sourceSortAsc = !sourceSortAsc;
      sourceSortKey = key;
      sourceOffset = 0;
      renderSourceRows();
    }}
    function updateSourceSortIndicators() {{
      document.querySelectorAll("#sourceTable th[data-source-sort]").forEach(th => {{
        const active = th.dataset.sourceSort === sourceSortKey;
        th.classList.toggle("sorted", active);
        th.setAttribute("aria-sort", active ? (sourceSortAsc ? "ascending" : "descending") : "none");
        const indicator = th.querySelector(".sort-indicator");
        if (indicator) indicator.textContent = active ? (sourceSortAsc ? "▲" : "▼") : "";
      }});
    }}
    async function renderSourceRows() {{
      const tbody = document.querySelector("#sourceTable tbody");
      updateSourceSortIndicators();
      tbody.innerHTML = `<tr><td colspan="${{visibleSourceColumnList().length}}">Loading...</td></tr>`;
      const params = new URLSearchParams();
      params.set("limit", String(pageSize()));
      params.set("offset", String(sourceOffset));
      params.set("sort", sourceSortKey);
      params.set("desc", String(!sourceSortAsc));
      const filter = document.getElementById("sourceFilter").value.trim();
      const cpu = document.getElementById("cpuFilter").value.trim();
      const thread = document.getElementById("threadFilter").value.trim();
      const minSamples = Number.parseInt(document.getElementById("minSamples").value || "0", 10);
      if (filter) params.set("filter", filter);
      if (cpu) params.set("cpu", cpu);
      if (thread) params.set("thread", thread);
      if (Number.isFinite(minSamples) && minSamples > 0) params.set("min_samples", String(minSamples));
      if (document.getElementById("sampledFirst").checked) params.set("sampled_first", "true");
      if (document.getElementById("functionFirst").checked) params.set("function_first", "true");
      if (document.getElementById("functionOnly").checked) params.set("function_only", "true");
      if (document.getElementById("nonzeroOnly").checked) params.set("nonzero_only", "true");
      if (document.getElementById("missingOnly").checked) params.set("missing_only", "true");
      if (document.getElementById("unresolvedOnly").checked) params.set("unresolved_only", "true");
      try {{
        const response = await fetch(`${{API_BASE}}/api/source-lines?${{params}}`);
        if (!response.ok) throw new Error(await response.text());
        const payload = await response.json();
        activeSourceRows = payload.rows || [];
        sourceTotal = payload.total || 0;
        sourceOffset = payload.offset || 0;
        renderSourceBody();
        renderPageStatus();
      }} catch (error) {{
        tbody.innerHTML = `<tr><td colspan="${{visibleSourceColumnList().length}}">Start the data server: simpleperf_report source --httpd --db SourceLine.sqlite --http-port 9600<br>${{escapeText(error.message)}}</td></tr>`;
      }}
    }}
    function formatMetric(value) {{
      const number = Number(value);
      if (!Number.isFinite(number)) return escapeText(value);
      return number.toLocaleString(undefined, {{ maximumFractionDigits: 3 }});
    }}
    function formatPercent(value) {{
      const number = Number(value);
      if (!Number.isFinite(number)) return escapeText(value);
      return number.toFixed(3);
    }}
    function renderPageStatus() {{
      const start = sourceTotal === 0 ? 0 : sourceOffset + 1;
      const end = Math.min(sourceOffset + activeSourceRows.length, sourceTotal);
      document.getElementById("sourcePageStatus").textContent = `showing ${{start}}-${{end}} of ${{sourceTotal}}`;
    }}
    function previousSourcePage() {{
      sourceOffset = Math.max(0, sourceOffset - pageSize());
      renderSourceRows();
    }}
    function nextSourcePage() {{
      if (sourceOffset + pageSize() < sourceTotal) {{
        sourceOffset += pageSize();
        renderSourceRows();
      }}
    }}
    function jumpToFileLine(file, line) {{
      document.getElementById("sourceFilter").value = file;
      sourceOffset = 0;
      renderSourceRows();
    }}
    async function renderFiles() {{
      const tbody = document.querySelector("#filesTable tbody");
      updateFileSortIndicators();
      tbody.innerHTML = `<tr><td colspan="7">Loading...</td></tr>`;
      const params = new URLSearchParams();
      params.set("limit", String(filePageSize()));
      params.set("offset", String(fileOffset));
      params.set("sort", fileSortKey);
      params.set("desc", String(!fileSortAsc));
      const filter = document.getElementById("fileFilter").value.trim();
      if (filter) params.set("filter", filter);
      try {{
        const response = await fetch(`${{API_BASE}}/api/files?${{params}}`);
        if (!response.ok) throw new Error(await response.text());
        const payload = await response.json();
        activeFileRows = payload.rows || [];
        fileTotal = payload.total || 0;
        fileOffset = payload.offset || 0;
        tbody.innerHTML = activeFileRows.map(row => `<tr data-file="${{escapeText(row.file)}}" data-line="${{row.hot_line ?? 0}}" onclick="jumpToFileLine(this.dataset.file, Number(this.dataset.line))"><td>${{escapeText(row.file)}}</td><td>${{row.self_weight}}</td><td>${{row.accumulated_weight}}</td><td>${{row.sample_count}}</td><td>${{row.hot_lines}}</td><td>${{row.missing}}</td><td>${{row.unresolved}}</td></tr>`).join("");
        if (activeFileRows.length === 0) tbody.innerHTML = `<tr><td colspan="7">No rows</td></tr>`;
        renderFilePageStatus();
      }} catch (error) {{
        tbody.innerHTML = `<tr><td colspan="7">Data server unavailable</td></tr>`;
      }}
    }}
    function renderFilePageStatus() {{
      const start = fileTotal === 0 ? 0 : fileOffset + 1;
      const end = Math.min(fileOffset + activeFileRows.length, fileTotal);
      document.getElementById("filePageStatus").textContent = `showing ${{start}}-${{end}} of ${{fileTotal}}`;
    }}
    function previousFilePage() {{
      fileOffset = Math.max(0, fileOffset - filePageSize());
      renderFiles();
    }}
    function nextFilePage() {{
      if (fileOffset + filePageSize() < fileTotal) {{
        fileOffset += filePageSize();
        renderFiles();
      }}
    }}
    async function renderFilesAndFunctions() {{
      try {{
        const functions = await fetch(`${{API_BASE}}/api/functions`).then(response => response.json());
        document.querySelector("#functionsTable tbody").innerHTML = functions.map(row => `<tr data-file="${{escapeText(row.file)}}" data-line="${{row.line_start ?? 0}}" onclick="jumpToFileLine(this.dataset.file, Number(this.dataset.line))"><td>${{escapeText(row.function)}}</td><td>${{escapeText(row.file)}}</td><td>${{row.line_start}}-${{row.line_end}}</td><td>${{escapeText(row.module)}}</td><td>${{row.self_weight}}</td><td>${{row.accumulated_weight}}</td><td>${{row.sample_count}}</td><td>${{escapeText(row.hot_lines)}}</td></tr>`).join("");
      }} catch (error) {{
        document.querySelector("#functionsTable tbody").innerHTML = `<tr><td colspan="8">Data server unavailable</td></tr>`;
      }}
    }}
    async function renderDiagnostics() {{
      try {{
        const summary = await fetch(`${{API_BASE}}/api/summary`).then(response => response.json());
        const warnings = Array.isArray(summary.warnings) ? summary.warnings : [];
        if (warnings.length === 0) return;
        const rows = warnings.slice(0, 80).map(warning => `<tr><td>Diagnostic</td><td>Warning</td><td>${{escapeText(warning)}}</td></tr>`);
        if (warnings.length > 80) rows.push(`<tr><td>Diagnostic</td><td>Warning</td><td>${{warnings.length - 80}} additional warnings omitted</td></tr>`);
        document.getElementById("qualityRows").insertAdjacentHTML("beforeend", rows.join(""));
      }} catch (error) {{
        document.getElementById("qualityRows").insertAdjacentHTML("beforeend", `<tr><td>Diagnostics</td><td>Unavailable</td><td>${{escapeText(error.message)}}</td></tr>`);
      }}
    }}
    renderSpeBreakdownColumnPicker();
    applySpeBreakdownColumnVisibility();
    renderSourceColumnPicker();
    renderSourceHeaders();
    renderSourceRows();
    renderFiles();
    renderFilesAndFunctions();
    renderDiagnostics();
  </script>
</body>
</html>
"##,
        session_id = escape_html(&manifest.session_id),
        package = escape_html(manifest.target.package.as_deref().unwrap_or("")),
        pid = manifest
            .target
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        duration_ms = manifest
            .recording
            .duration_ms
            .map(|duration| duration.to_string())
            .unwrap_or_else(|| "partial".to_string()),
        device = escape_html(&format!(
            "{} {} Android {}",
            manifest.device.manufacturer.as_deref().unwrap_or(""),
            manifest.device.model.as_deref().unwrap_or(""),
            manifest.device.android_release.as_deref().unwrap_or("")
        )),
        abi = escape_html(&manifest.device.abi),
        cpus = manifest
            .cpu
            .selected_cpus
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        clusters = escape_html(&manifest.cpu.selected_clusters.join(", ")),
        pmu_lane = lane_text(manifest.lanes.pmu.enabled, manifest.lanes.pmu.available),
        spe_lane = lane_text(manifest.lanes.spe.enabled, manifest.lanes.spe.available),
        pmu_buffer_pages = manifest.capture_options.pmu_buffer_pages,
        spe_aux_buffer_bytes = manifest
            .capture_options
            .spe_aux_buffer_bytes
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        sample_period = manifest.capture_options.sample_period,
        callchain_depth = manifest.capture_options.callchain_depth,
        raw_pmu_columns_json = raw_pmu_columns_json,
        derived_pmu_columns_json = derived_pmu_columns_json,
        spe_columns_json = spe_columns_json,
        spe_hierarchy_histograms_json = spe_hierarchy_histograms_json,
        default_source_columns_json = default_source_columns_json,
        spe_hierarchy_summary_rows =
            spe_hierarchy_summary_rows_html(model, manifest.lanes.spe.available),
        column_help_rows =
            column_help_rows(bundle, &raw_pmu_columns, &derived_pmu_columns, &spe_columns),
        quality_rows = quality_rows(bundle),
        artifact_rows = manifest
            .artifacts
            .files
            .iter()
            .map(|file| format!(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                escape_html(&file.role),
                escape_html(&file.path),
                file.required,
                escape_html(file.encoding.as_deref().unwrap_or(""))
            ))
            .collect::<Vec<_>>()
            .join("\n"),
        frame_rows = frame_rows_html(&model.frames),
        callchain_rows = callchain_rows_html(&model.callchains)
    );
    fs::write(output, html).with_context(|| format!("Failed to write '{}'", output.display()))
}

fn default_spe_source_columns(spe_columns: &[String], model: &ReportModel) -> Vec<String> {
    let mut columns = ["spe_sample_count"]
        .into_iter()
        .filter(|key| spe_columns.iter().any(|column| column == key))
        .map(str::to_string)
        .collect::<Vec<_>>();

    for category in SPE_CATEGORY_NAMES {
        let key = format!("{category}.sample_count");
        if spe_columns.iter().any(|column| column == &key)
            && !is_zero_or_absent_summary(&summarize_spe_category_metric(model, &key, false))
        {
            columns.push(key);
        }
    }

    for class in INSTRUCTION_CLASS_NAMES {
        let key = format!("instruction_class.{class}.sample_count");
        if spe_columns.iter().any(|column| column == &key)
            && !is_zero_or_absent_summary(&summarize_instruction_class_metric(model, &key, false))
        {
            columns.push(key);
        }
    }

    for kind in LOAD_INSTRUCTION_KIND_NAMES {
        let key = format!("load_instruction.{kind}.sample_count");
        if spe_columns.iter().any(|column| column == &key)
            && !is_zero_or_absent_summary(&summarize_load_instruction_metric(model, &key, false))
        {
            columns.push(key);
        }
    }

    columns
}

fn displayed_spe_column_keys(model: &ReportModel) -> Vec<String> {
    let mut keys = vec!["spe_sample_count".to_string()];

    for category in SPE_CATEGORY_NAMES {
        let key = format!("{category}.sample_count");
        if !is_zero_or_absent_summary(&summarize_spe_category_metric(model, &key, false)) {
            keys.push(key);
        }
    }

    keys
}

fn displayed_instruction_class_column_keys(model: &ReportModel) -> Vec<String> {
    let mut keys = Vec::new();
    for class in INSTRUCTION_CLASS_NAMES {
        let key = format!("instruction_class.{class}.sample_count");
        if !is_zero_or_absent_summary(&summarize_instruction_class_metric(model, &key, false)) {
            keys.push(key);
        }
    }
    keys
}

fn displayed_load_instruction_column_keys(model: &ReportModel) -> Vec<String> {
    let mut keys = Vec::new();
    for kind in LOAD_INSTRUCTION_KIND_NAMES {
        let key = format!("load_instruction.{kind}.sample_count");
        if !is_zero_or_absent_summary(&summarize_load_instruction_metric(model, &key, false)) {
            keys.push(key);
        }
    }
    keys
}

fn spe_hierarchy_summary_rows_html(model: &ReportModel, spe_available: bool) -> String {
    let metrics = [
        ("sample_pct", "sample_pct", false),
        ("est_time_pct", "est_time_pct", false),
        ("all_est_time_pct", "all_est_time_pct", false),
        ("min_latency_cycles", "min_latency_cycles", false),
        ("max_latency_cycles", "max_latency_cycles", false),
        ("avg_latency_cycles", "avg_latency_cycles", false),
        ("std_latency_cycles", "std_latency_cycles", false),
        ("p95_latency_cycles", "p95_latency_cycles", false),
        ("p99_latency_cycles", "p99_latency_cycles", false),
        ("over_theory_sample_pct", "over_theory_sample_pct", false),
        (
            "over_theory_est_time_pct",
            "over_theory_est_time_pct",
            false,
        ),
        ("over_p95_est_time_pct", "over_p95_est_time_pct", false),
        ("over_avg_est_time_pct", "over_avg_est_time_pct", false),
        (
            "over_p95_all_est_time_pct",
            "over_p95_all_est_time_pct",
            false,
        ),
        (
            "over_avg_all_est_time_pct",
            "over_avg_all_est_time_pct",
            false,
        ),
    ];
    if !spe_available {
        return "<tr><td colspan=\"17\">SPE samples unavailable</td></tr>".to_string();
    }

    let rows = model
        .spe_hierarchical_cpu_values
        .iter()
        .flat_map(|(cpu, values_by_key)| {
            SPE_CATEGORY_NAMES.iter().flat_map(move |parent| {
                let parent_values = metrics
                    .iter()
                    .map(|(_, metric, show_na)| {
                        let key = format!("{parent}.{metric}");
                        summarize_spe_hierarchy_metric_from_values(values_by_key, &key, *show_na)
                    })
                    .collect::<Vec<_>>();
                if parent_values
                    .iter()
                    .all(|value| is_zero_or_absent_summary(value))
                {
                    return Vec::new();
                }

                let row_shade = cpu_row_shade(*cpu);
                let parent_cells = parent_values
                    .into_iter()
                    .zip(metrics.iter())
                    .map(|(value, (column, _, _))| {
                        format!(
                            "<td data-spe-column=\"{}\">{}</td>",
                            escape_html(column),
                            escape_html(&value)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("");
                let child_rows = INSTRUCTION_CLASS_NAMES
                    .iter()
                    .filter_map(|child| {
                        let child_values = metrics
                            .iter()
                            .map(|(_, metric, show_na)| {
                                let key = format!("{parent}.{child}.{metric}");
                                    summarize_spe_hierarchy_metric_from_values(
                                        values_by_key,
                                        &key,
                                        *show_na,
                                )
                            })
                            .collect::<Vec<_>>();
                        if child_values
                            .iter()
                            .all(|value| is_zero_or_absent_summary(value))
                        {
                            return None;
                        }
                        let cells = child_values
                            .into_iter()
                            .zip(metrics.iter())
                            .map(|(value, (column, _, _))| {
                                format!(
                                    "<td data-spe-column=\"{}\">{}</td>",
                                    escape_html(column),
                                    escape_html(&value)
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("");
                        Some(format!(
                            "<tr class=\"cpu-shade-{row_shade}\" data-spe-cpu=\"{}\" data-spe-parent=\"{}\" data-spe-child=\"{}\" onclick=\"renderSpeHierarchyHistogram(this)\" hidden><td data-spe-column=\"cpu\">{}</td><td data-spe-column=\"category\" class=\"spe-child-label\"><code>{}</code></td>{}</tr>",
                            cpu,
                            escape_html(parent),
                            escape_html(child),
                            cpu,
                            escape_html(child),
                            cells
                        ))
                    })
                    .collect::<Vec<_>>();
                let indicator = if child_rows.is_empty() { "" } else { "+" };
                let collapsible_attrs = if child_rows.is_empty() {
                    String::new()
                } else {
                    " data-spe-collapsible=\"true\" aria-expanded=\"false\"".to_string()
                };
                let mut rows = vec![format!(
                    "<tr class=\"cpu-shade-{row_shade}\" data-spe-cpu=\"{}\" data-spe-parent=\"{}\" data-spe-child=\"\"{} onclick=\"renderSpeHierarchyHistogram(this)\"><td data-spe-column=\"cpu\">{}</td><td data-spe-column=\"category\"><span class=\"spe-collapse-indicator\">{}</span><code>{}</code></td>{}</tr>",
                    cpu,
                    escape_html(parent),
                    collapsible_attrs,
                    cpu,
                    indicator,
                    escape_html(parent),
                    parent_cells
                )];

                rows.extend(child_rows);
                rows
            })
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return "<tr><td colspan=\"17\">No SPE hierarchy samples</td></tr>".to_string();
    }
    rows.join("\n")
}

fn cpu_row_shade(cpu: u32) -> u32 {
    cpu % 6
}

fn is_zero_or_absent_summary(value: &str) -> bool {
    if matches!(value, "N/A" | "Missing" | "Unresolved") {
        return true;
    }
    value
        .trim_end_matches('%')
        .parse::<f64>()
        .map(|number| number == 0.0)
        .unwrap_or(false)
}

fn summarize_spe_category_metric(
    model: &ReportModel,
    key: &str,
    show_na_for_undefined: bool,
) -> String {
    let mut sum = 0.0;
    let mut saw_number = false;
    let mut saw_missing = false;
    let mut saw_unresolved = false;
    let mut saw_undefined = false;
    for row in &model.rows {
        match row.spe_values.get(key) {
            Some(MetricValue::Number(value)) => {
                saw_number = true;
                sum += value;
            }
            Some(MetricValue::Missing(_)) => saw_missing = true,
            None => {}
            Some(MetricValue::Unresolved(_)) => saw_unresolved = true,
            Some(MetricValue::Undefined(_)) => saw_undefined = true,
        }
    }
    if saw_number {
        return format_metric_for_summary(key, sum);
    }
    if saw_undefined && show_na_for_undefined {
        return "N/A".to_string();
    }
    if saw_unresolved {
        return "Unresolved".to_string();
    }
    if saw_missing {
        return "Missing".to_string();
    }
    if saw_undefined {
        return "N/A".to_string();
    }
    "0".to_string()
}

fn summarize_instruction_class_metric(
    model: &ReportModel,
    key: &str,
    show_na_for_undefined: bool,
) -> String {
    let mut sum = 0.0;
    let mut saw_number = false;
    let mut saw_missing = false;
    let mut saw_unresolved = false;
    let mut saw_undefined = false;
    for row in &model.rows {
        match row.instruction_values.get(key) {
            Some(MetricValue::Number(value)) => {
                saw_number = true;
                sum += value;
            }
            Some(MetricValue::Missing(_)) => saw_missing = true,
            None => {}
            Some(MetricValue::Unresolved(_)) => saw_unresolved = true,
            Some(MetricValue::Undefined(_)) => saw_undefined = true,
        }
    }
    if saw_number {
        return format_metric_for_summary(key, sum);
    }
    if saw_undefined && show_na_for_undefined {
        return "N/A".to_string();
    }
    if saw_unresolved {
        return "Unresolved".to_string();
    }
    if saw_missing {
        return "Missing".to_string();
    }
    if saw_undefined {
        return "N/A".to_string();
    }
    "0".to_string()
}

fn summarize_load_instruction_metric(
    model: &ReportModel,
    key: &str,
    show_na_for_undefined: bool,
) -> String {
    let mut sum = 0.0;
    let mut saw_number = false;
    let mut saw_missing = false;
    let mut saw_unresolved = false;
    let mut saw_undefined = false;
    for row in &model.rows {
        match row.load_instruction_values.get(key) {
            Some(MetricValue::Number(value)) => {
                saw_number = true;
                sum += value;
            }
            Some(MetricValue::Missing(_)) => saw_missing = true,
            None => {}
            Some(MetricValue::Unresolved(_)) => saw_unresolved = true,
            Some(MetricValue::Undefined(_)) => saw_undefined = true,
        }
    }
    if saw_number {
        return format_metric_for_summary(key, sum);
    }
    if saw_undefined && show_na_for_undefined {
        return "N/A".to_string();
    }
    if saw_unresolved {
        return "Unresolved".to_string();
    }
    if saw_missing {
        return "Missing".to_string();
    }
    if saw_undefined {
        return "N/A".to_string();
    }
    "0".to_string()
}

fn summarize_spe_category_metric_from_values(
    values: &BTreeMap<String, MetricValue>,
    key: &str,
    show_na_for_undefined: bool,
) -> String {
    match values.get(key) {
        Some(MetricValue::Number(value)) => format_metric_for_summary(key, *value),
        Some(MetricValue::Undefined(_)) if show_na_for_undefined => "N/A".to_string(),
        Some(MetricValue::Unresolved(_)) => "Unresolved".to_string(),
        Some(MetricValue::Missing(_)) => "Missing".to_string(),
        None => "0".to_string(),
        Some(MetricValue::Undefined(_)) => "N/A".to_string(),
    }
}

fn summarize_spe_hierarchy_metric_from_values(
    values: &BTreeMap<String, MetricValue>,
    key: &str,
    show_na_for_undefined: bool,
) -> String {
    if is_spe_theory_metric_key(key) && !values.contains_key(key) {
        String::new()
    } else {
        summarize_spe_category_metric_from_values(values, key, show_na_for_undefined)
    }
}

fn is_spe_theory_metric_key(key: &str) -> bool {
    key.ends_with(".over_theory_sample_pct") || key.ends_with(".over_theory_est_time_pct")
}

fn format_metric_for_summary(key: &str, value: f64) -> String {
    if is_percent_metric(key) {
        format_percentage_for_summary(value)
    } else {
        format_number_for_summary(value)
    }
}

fn is_percent_metric(key: &str) -> bool {
    key.ends_with("_pct")
}

fn format_percentage_for_summary(value: f64) -> String {
    if value.abs() >= 1000.0 {
        format!("{value:.0}%")
    } else {
        format!("{value:.3}%")
    }
}

fn format_number_for_summary(value: f64) -> String {
    if value.abs() >= 1000.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.3}")
    }
}

fn column_help_rows(
    bundle: &SourceProfileBundle,
    raw_pmu_columns: &[String],
    derived_pmu_columns: &[String],
    spe_columns: &[String],
) -> String {
    let mut rows = vec![
        help_row(
            "File",
            "source path",
            "取樣位址經符號化與 debug line table 對應後落到的原始碼檔案；它代表 CPU 當下執行或 SPE 記錄的指令位置，不代表整個函式所有成本都來自此檔案。",
        ),
        help_row(
            "Line",
            "source line number",
            "取樣位址對應到的原始碼行號；這是 profiler 看到硬體事件發生時 program counter 所在位置，若編譯器 inline、重排或最佳化，成本可能集中到看起來不直覺的行。",
        ),
        help_row(
            "Function",
            "symbolized function",
            "取樣位址符號化後所屬函式；物理上表示事件發生時 CPU 正在執行的指令範圍，inline 或尾呼叫可能讓 source function 和執行位址的關係變得間接。",
        ),
        help_row(
            "Module",
            "ELF / shared object",
            "取樣位址所在的 ELF 或 shared object；可用來分辨成本來自 app、系統函式庫或 JIT/匿名映射。",
        ),
        help_row(
            "CPU",
            "PERF_SAMPLE_CPU",
            "產生 sample 的 CPU id；代表事件實際在該核心上被硬體計數器或 SPE 捕捉到，可用來看負載是否偏向特定核心或 cluster。",
        ),
        help_row(
            "Thread",
            "sample TID",
            "產生 sample 的 thread id；代表事件發生時正在該 CPU 上執行的 Linux thread，可用來分辨熱點是由哪條執行緒造成。",
        ),
        help_row(
            "Samples",
            "line PMU sample count",
            "此 source line 收到的 PMU sample 次數；sample 越多代表該行在取樣期間越常觸發選定事件，統計可信度較高，但它仍是抽樣結果，不是精確執行次數。",
        ),
        help_row(
            "p %",
            "line self weight / global self weight * 100",
            "此行自身事件權重佔全程自身事件權重的比例；物理意義是全域硬體事件熱度集中度，適合找直接落在該行的熱點，預設隱藏可在 Columns 開啟。",
        ),
        help_row(
            "acc %",
            "line accumulated weight / global accumulated weight * 100",
            "此行在 callchain 累積後佔全程累積權重的比例；代表包含子呼叫路徑後的整體成本歸因，適合找上層呼叫入口，預設隱藏可在 Columns 開啟。",
        ),
        help_row(
            "file p %",
            "line self weight / same-file self weight * 100",
            "此行自身事件權重佔同一 source file 自身事件權重的比例；用來看檔案內部哪幾行最集中硬體事件，避免大檔案被全域比例稀釋。",
        ),
        help_row(
            "file acc %",
            "line accumulated weight / same-file accumulated weight * 100",
            "此行 callchain 累積權重佔同一 source file 累積權重的比例；用來比較同檔案內各呼叫入口或熱路徑的相對重要性。",
        ),
    ];

    rows.extend(spe_hierarchical_breakdown_help_rows());

    for key in raw_pmu_columns {
        let event = bundle
            .event_catalog
            .events
            .iter()
            .find(|event| event.event_key == *key);
        let source = event
            .map(|event| format!("PMU event {} / {}", event.event_type, event.config))
            .unwrap_or_else(|| "PMU event selected by MProfiler".to_string());
        let meaning = event
            .map(|event| {
                format!(
                    "硬體 PMU 事件：{}。Source Lines 顯示此 event 在該列取樣資料中的比例或狀態；比例越高代表該原始碼位置越常伴隨此硬體現象，但受取樣週期、事件 multiplex 與歸因精度影響。",
                    event.display_name
                )
            })
            .unwrap_or_else(|| {
                "MProfiler 選擇的 PMU event；Source Lines 顯示此列 sample 中的 event 比例或 Missing/Undefined。比例代表硬體事件在該 source line 的抽樣集中程度，不是精確事件總數。"
                    .to_string()
            });
        rows.push(help_row(&format!("`{key}`"), &source, &meaning));
    }

    for key in derived_pmu_columns {
        rows.push(match key.as_str() {
            "cpi" => help_row(
                "`cpi`",
                "cpu_cycles / inst_retired",
                "平均每退休一條指令消耗的 CPU cycles；數值越高通常代表 pipeline stall、memory 等待、分支錯誤或其他延遲較多。分母缺失或為 0 時為 Missing/Undefined。",
            ),
            "l1d_cache_hit_rate" => help_row(
                "`l1d_cache_hit_rate`",
                "(l1d_cache_access - l1d_cache_refill) / l1d_cache_access",
                "L1 data cache 存取命中比例的 sampling 近似；越高表示資料多半在 L1D 取得，越低通常代表較多 refill，需要往 L2/L3/DRAM 等更慢層級查找。",
            ),
            "l2d_cache_hit_rate" => help_row(
                "`l2d_cache_hit_rate`",
                "(l2d_cache_access - l2d_cache_refill) / l2d_cache_access",
                "L2 data cache 存取命中比例的 sampling 近似；可用來判斷 L1 miss 後是否多半由 L2 承接，較低通常表示更多請求流向 LLC 或 DRAM。",
            ),
            "l3d_cache_hit_rate" => help_row(
                "`l3d_cache_hit_rate`",
                "(l3d_cache_access - l3d_cache_refill) / l3d_cache_access",
                "L3/LLC data cache 存取命中比例的 sampling 近似；較低代表更多資料請求離開片上 cache，可能造成 DRAM latency 與頻寬壓力。",
            ),
            "branch_miss_rate" => help_row(
                "`branch_miss_rate`",
                "branch_mispredict / branch_retired",
                "退休分支中被硬體分支預測器猜錯的比例；越高代表 pipeline flush 較多，控制流程不可預測性可能正在消耗 cycles。",
            ),
            "mpki" => help_row(
                "`mpki`",
                "l1d_cache_refill / inst_retired * 1000",
                "每千條退休指令觸發多少次 L1D refill 的 sampling 近似；用來把 cache miss 壓力正規化到指令量，方便比較不同熱點的記憶體行為。",
            ),
            "mips" => help_row(
                "`mips`",
                "inst_retired / effective_time_seconds / 1,000,000",
                "每秒百萬退休指令；代表 CPU 在此區域完成指令的吞吐量。Source line 層級是 sample 歸因後的近似活動量，不等同單行實際執行速度。",
            ),
            "mcps" => help_row(
                "`mcps`",
                "cpu_cycles / effective_time_seconds / 1,000,000",
                "每秒百萬 CPU cycles；代表此區域消耗核心時鐘週期的強度。Source line 層級是 sample 歸因近似，適合和 CPI、cache/branch 指標一起判斷瓶頸來源。",
            ),
            _ => help_row(
                &format!("`{key}`"),
                "derived PMU metric",
                "由 MProfiler 選擇的 PMU events 推導出的硬體行為指標；物理意義取決於分子與分母事件，通常用來把原始計數轉成率、比例或正規化壓力。",
            ),
        });
    }

    for key in spe_columns {
        rows.push(match key.as_str() {
            "spe_sample_count" => help_row(
                "`spe_sample_count`",
                "decoded SPE sample count",
                "此列歸因到的 Arm SPE sample 數；每個 sample 代表硬體抽樣到的一次資料存取、分支或指令事件，數量越多代表該 source line 的 SPE 觀測越穩定。",
            ),
            "spe_latency_cycles_avg" => help_row(
                "`spe_latency_cycles_avg`",
                "SPE latency cycles sum / count",
                "SPE 記錄的平均 latency cycles；物理上是被抽樣事件從發出到完成或被量測到的延遲週期，越高通常代表 memory hierarchy、同步或 pipeline 等待較重。缺 latency field 時為 Missing。",
            ),
            "spe_cache_hit_rate" => help_row(
                "`spe_cache_hit_rate`",
                "SPE cache hit / cache total",
                "SPE packet 解碼後判定為 cache hit 的比例；越高表示被抽樣的資料存取較常在片上 cache 命中，越低表示較多存取落到較慢層級或無法判定。",
            ),
            "spe_branch_miss_rate" => help_row(
                "`spe_branch_miss_rate`",
                "SPE branch miss / branch total",
                "SPE packet 解碼後分支 miss 的比例；反映被抽樣分支中造成預測失敗或控制流程延遲的程度，適合搭配 branch_unknown / branch_miss 類別檢查。",
            ),
            "spe_decode_errors" => help_row(
                "`spe_decode_errors`",
                "SPE decode error count",
                "SPE packet decode 失敗數；代表部分硬體記錄無法被解析成完整事件，數值越高表示 SPE 指標可能低估或分類不完整。",
            ),
            _ if is_spe_category_metric(key) => help_row(
                &format!("`{key}`"),
                spe_category_metric_formula(key),
                spe_category_metric_meaning(key),
            ),
            _ if is_instruction_class_metric(key) => help_row(
                &format!("`{key}`"),
                instruction_class_metric_formula(key),
                instruction_class_metric_meaning(key),
            ),
            _ if is_load_instruction_metric(key) => help_row(
                &format!("`{key}`"),
                load_instruction_metric_formula(key),
                load_instruction_metric_meaning(key),
            ),
            _ => help_row(
                &format!("`{key}`"),
                "SPE metric",
                "Arm SPE 解碼後的硬體取樣指標；代表被抽樣到的實際執行或記憶體事件，仍受 SPE 取樣率、packet 欄位完整度與位址歸因影響。",
            ),
        });
    }

    rows.push(help_row(
        "Code",
        "source text",
        "該 source line 的原始碼內容；用來把硬體事件歸因結果和程式碼對齊，但最佳化後的機器指令可能不會一對一對應到這行文字。",
    ));
    rows.join("\n")
}

fn spe_hierarchical_breakdown_help_rows() -> Vec<String> {
    vec![
        help_row(
            "SPE Hierarchical Breakdown: CPU",
            "PERF_SAMPLE_CPU",
            "該 SPE breakdown row 所屬 CPU；代表這一列的 SPE samples 是在這顆核心上被硬體記錄到，可用來看某個核心或 cluster 是否承擔特定 memory / branch / compute 行為。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: Category",
            "SPE parent category or parent.child category",
            "父節點是 SPE 對資料來源或操作種類的分類，例如 load_l1、load_dram、branch_unknown、compute_unknown；展開後的子節點是該父節點底下的 instruction class，用來看同一硬體現象主要由哪類指令造成。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: sample%",
            "parent: category samples / CPU SPE samples; child: child samples / parent samples",
            "sample 數量佔比，反映某類事件在 SPE 抽樣中出現的頻率。父節點用該 CPU 全部 SPE samples 當分母；子節點用父分類 samples 當分母。它描述發生頻率，不代表耗時，低頻但高 latency 的事件仍可能很重要。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: est_time%",
            "parent: category latency cycles / CPU SPE latency cycles; child: child latency cycles / parent latency cycles",
            "估算時間佔比，以 SPE latency cycles 當作時間權重。父節點是 CPU-relative，表示此硬體分類佔該 CPU 被 SPE 觀測到的總 latency 比例；子節點是 parent-relative，用來看父分類內部由哪些指令類型貢獻 latency。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: all est_time%",
            "row latency cycles / CPU SPE latency cycles",
            "全域估算時間佔比，不論父節點或子節點都用該 CPU 全部 SPE latency cycles 當分母。它保留子節點對整體時間的真實權重，適合比較展開後哪個子項真正佔整體 latency，而不是只看父分類內的比例。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: min_latency_cycles",
            "minimum SPE latency cycles in this row",
            "此 row 被抽樣事件中最小的 latency cycles；代表該硬體現象在最佳情況下的觀測延遲。沒有 latency field 時為 Missing，且單一極小值容易受取樣雜訊影響。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: max_latency_cycles",
            "maximum SPE latency cycles in this row",
            "此 row 被抽樣事件中最大的 latency cycles；代表最極端的長尾延遲。它能暴露偶發 stall，但單一最大值可能是離群點，需要搭配 p95、p99 和時間佔比判斷。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: avg_latency_cycles",
            "row latency cycles sum / row sample count",
            "此 row 的平均 SPE latency cycles；代表每次被抽樣事件平均等待多少核心週期。平均值會被少量長尾拉高，所以要和 p95/p99 一起看分布形狀。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: std_latency_cycles",
            "population standard deviation of row latency cycles",
            "此 row latency cycles 的 population standard deviation；數值越大表示延遲越不穩定，可能存在 cache 層級混雜、同步等待或偶發 DRAM/remote access。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: p95_latency_cycles",
            "nearest-rank p95 SPE latency cycles in this row",
            "此 row 的 p95 latency 門檻；約 95% samples 的 latency 不超過此值。它比平均值更能描述長尾開始的位置，用來切出高延遲區段。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: p99_latency_cycles",
            "nearest-rank p99 SPE latency cycles in this row",
            "此 row 的 p99 latency 門檻；描述最慢 1% 附近的延遲水準。它對樣本數較敏感，樣本很少時應視為方向性訊號。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: >theory sample%",
            "samples where latency cycles > theoretical threshold / latency samples in this row",
            "超過理論 latency 的 sample 數比例；目前只套用 load_l1=4T、load_l2=10T、load_l3=60T、store*=3T，其它分類留空。它描述超標事件發生頻率，不代表超標事件耗掉多少時間。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: >theory est_time%",
            "latency cycles where latency cycles > theoretical threshold / row latency cycles",
            "超過理論 latency 的 samples 所累積的 latency cycles，佔此 row 總 latency 的比例；目前只套用 load_l1=4T、load_l2=10T、load_l3=60T、store*=3T，其它分類留空。它比 sample% 更能看出超標事件是否真的吃掉主要等待時間。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: >p95 est_time%",
            "latency cycles where sample latency > row p95 / row latency cycles",
            "此 row 內 latency 超過 p95 的 samples 所累積的 latency cycles，佔此 row 自身總 latency 的比例。它回答「這個分類自己的時間有多少被最慢那段長尾吃掉」。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: >avg est_time%",
            "latency cycles where sample latency > row average / row latency cycles",
            "此 row 內 latency 超過平均值的 samples 所累積的 latency cycles，佔此 row 自身總 latency 的比例。它用平均值作為較寬鬆門檻，觀察高於一般水準的等待時間佔比。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: >p95 all est_time%",
            "latency cycles where sample latency > row p95 / CPU SPE latency cycles",
            "此 row 超過 p95 的長尾 latency 佔該 CPU 全部 SPE latency 的比例。它回答「這個分類最慢 5% 左右的高峰延遲，對整體時間到底有多大」，適合比較哪個長尾最值得優先處理。",
        ),
        help_row(
            "SPE Hierarchical Breakdown: >avg all est_time%",
            "latency cycles where sample latency > row average / CPU SPE latency cycles",
            "此 row 超過平均值的 latency 佔該 CPU 全部 SPE latency 的比例。它比 p95 門檻涵蓋更多高於一般水準的等待時間，可用來比較哪個分類的高延遲區段對整體成本影響最大。",
        ),
    ]
}

fn is_spe_category_metric(key: &str) -> bool {
    key.rsplit_once('.')
        .map(|(category, metric)| {
            !category.starts_with("instruction_class.")
                && !category.starts_with("load_instruction.")
                && (metric == "sample_count" || SPE_CATEGORY_METRICS.contains(&metric))
        })
        .unwrap_or(false)
}

fn is_instruction_class_metric(key: &str) -> bool {
    let Some((prefix, metric)) = key.rsplit_once('.') else {
        return false;
    };
    prefix.starts_with("instruction_class.")
        && (metric == "sample_count" || INSTRUCTION_CLASS_METRICS.contains(&metric))
}

fn is_load_instruction_metric(key: &str) -> bool {
    let Some((prefix, metric)) = key.rsplit_once('.') else {
        return false;
    };
    prefix.starts_with("load_instruction.")
        && (metric == "sample_count" || LOAD_INSTRUCTION_METRICS.contains(&metric))
}

fn instruction_class_metric_formula(key: &str) -> &'static str {
    match key.rsplit_once('.').map(|(_, metric)| metric) {
        Some("sample_count") => "instruction-class SPE sample count",
        Some("sample_pct") => "instruction-class SPE samples / total SPE samples",
        Some("spe_latency_pct") => {
            "instruction-class SPE latency cycles / total SPE latency cycles"
        }
        Some("est_time_pct") => "estimated time percentage",
        Some("min_latency_cycles") => "minimum SPE latency cycles in this instruction class",
        Some("max_latency_cycles") => "maximum SPE latency cycles in this instruction class",
        Some("avg_latency_cycles") => "average SPE latency cycles in this instruction class",
        Some("std_latency_cycles") => {
            "population standard deviation of SPE latency cycles in this instruction class"
        }
        Some("p95_latency_cycles") => {
            "nearest-rank p95 SPE latency cycles in this instruction class"
        }
        Some("p99_latency_cycles") => {
            "nearest-rank p99 SPE latency cycles in this instruction class"
        }
        Some("over_p95_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this instruction class p95 / this instruction class estimated time"
        }
        Some("over_avg_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this instruction class average / this instruction class estimated time"
        }
        Some("over_p95_all_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this instruction class p95 / total estimated time"
        }
        Some("over_avg_all_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this instruction class average / total estimated time"
        }
        _ => "instruction-class SPE metric",
    }
}

fn instruction_class_metric_meaning(key: &str) -> &'static str {
    match key.rsplit_once('.').map(|(_, metric)| metric) {
        Some("sample_count") => {
            "此 source line 歸因到這個 instruction class 的 SPE sample 數；Source Lines 只做 sample 計數，不把單行抽樣點解讀成 latency 或時間分布。"
        }
        Some("sample_pct") => {
            "此 instruction class 在 SPE samples 中出現的比例；物理上代表硬體抽樣到的指令種類分布，不等同執行時間。"
        }
        Some("spe_latency_pct") | Some("est_time_pct") => {
            "此 instruction class 累積 SPE latency cycles 佔總 SPE latency 的比例；可視為該類指令對被觀測等待時間的貢獻，但不是精確 wall time。"
        }
        Some("min_latency_cycles") => {
            "此 instruction class 被抽樣事件的最小 latency cycles；反映該類指令在最佳觀測情況下的等待成本。"
        }
        Some("max_latency_cycles") => {
            "此 instruction class 被抽樣事件的最大 latency cycles；用來暴露該類指令是否曾出現極端 stall。"
        }
        Some("avg_latency_cycles") => {
            "此 instruction class 的平均 SPE latency cycles；代表該類指令每次被抽樣時平均等待多少核心週期，會受長尾事件拉高。"
        }
        Some("std_latency_cycles") => {
            "此 instruction class latency cycles 的離散程度；越高表示同類指令的延遲不穩定，可能混合不同 cache 層級或同步狀態。"
        }
        Some("p95_latency_cycles") => {
            "此 instruction class 的 p95 latency 門檻；用來判斷該類指令高延遲長尾從哪個週期數開始。"
        }
        Some("p99_latency_cycles") => {
            "此 instruction class 的 p99 latency 門檻；描述最慢一小段樣本的延遲水準，樣本少時需謹慎解讀。"
        }
        Some("over_p95_est_time_pct") => {
            "此 instruction class 中超過自身 p95 的長尾 latency，佔該類指令自身 latency 的比例；用來看該類指令是否被少量極慢事件主導。"
        }
        Some("over_avg_est_time_pct") => {
            "此 instruction class 中超過自身平均值的 latency，佔該類指令自身 latency 的比例；用較寬鬆門檻觀察高延遲區段。"
        }
        Some("over_p95_all_est_time_pct") => {
            "此 instruction class 超過自身 p95 的長尾 latency，佔全部 SPE latency 的比例；用來比較哪類指令的長尾真正影響整體時間。"
        }
        Some("over_avg_all_est_time_pct") => {
            "此 instruction class 超過自身平均值的 latency，佔全部 SPE latency 的比例；用來比較哪類指令的高延遲區段對整體成本最大。"
        }
        _ => {
            "instruction class 是由 sampled PC 對應到的機器指令 opcode 解碼而來；它描述硬體事件發生時正在執行哪類指令，但不是根因推論。"
        }
    }
}

fn load_instruction_metric_formula(key: &str) -> &'static str {
    match key.rsplit_once('.').map(|(_, metric)| metric) {
        Some("sample_count") => "load-kind SPE sample count",
        Some("sample_pct") => "load-kind SPE samples / total load instruction SPE samples",
        Some("spe_latency_pct") => {
            "load-kind SPE latency cycles / total load instruction SPE latency cycles"
        }
        Some("est_time_pct") => "estimated time percentage",
        Some("min_latency_cycles") => "minimum SPE latency cycles in this load instruction kind",
        Some("max_latency_cycles") => "maximum SPE latency cycles in this load instruction kind",
        Some("avg_latency_cycles") => "average SPE latency cycles in this load instruction kind",
        Some("std_latency_cycles") => {
            "population standard deviation of SPE latency cycles in this load instruction kind"
        }
        Some("p95_latency_cycles") => {
            "nearest-rank p95 SPE latency cycles in this load instruction kind"
        }
        Some("p99_latency_cycles") => {
            "nearest-rank p99 SPE latency cycles in this load instruction kind"
        }
        Some("over_p95_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this load instruction kind p95 / this load instruction kind estimated time"
        }
        Some("over_avg_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this load instruction kind average / this load instruction kind estimated time"
        }
        Some("over_p95_all_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this load instruction kind p95 / total estimated time"
        }
        Some("over_avg_all_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this load instruction kind average / total estimated time"
        }
        _ => "load-instruction SPE metric",
    }
}

fn load_instruction_metric_meaning(key: &str) -> &'static str {
    match key.rsplit_once('.').map(|(_, metric)| metric) {
        Some("sample_count") => {
            "此 source line 歸因到這個 load instruction kind 的 SPE sample 數；Source Lines 只顯示抽樣次數，避免把單行樣本誤解為 latency 統計。"
        }
        Some("sample_pct") => {
            "此 load instruction kind 在 load 類 SPE samples 中出現的比例；物理上代表硬體抽樣到的 load 指令型態分布，不等同耗時。"
        }
        Some("spe_latency_pct") | Some("est_time_pct") => {
            "此 load instruction kind 累積 SPE latency cycles 佔 load 指令總 latency 的比例；可用來看哪種 load 型態消耗最多被觀測等待時間。"
        }
        Some("min_latency_cycles") => {
            "此 load instruction kind 的最小 latency cycles；代表該類 load 在最佳觀測情況下可多快由 cache/memory hierarchy 回應。"
        }
        Some("max_latency_cycles") => {
            "此 load instruction kind 的最大 latency cycles；用來找是否有偶發極慢 load，例如 DRAM、remote 或同步造成的等待。"
        }
        Some("avg_latency_cycles") => {
            "此 load instruction kind 的平均 latency cycles；代表該類 load 平均等待資料返回的核心週期數，會被長尾 memory access 拉高。"
        }
        Some("std_latency_cycles") => {
            "此 load instruction kind latency cycles 的離散程度；越高表示同一 load 型態可能同時打到不同 cache/memory 層級。"
        }
        Some("p95_latency_cycles") => {
            "此 load instruction kind 的 p95 latency 門檻；用來觀察慢速 load 的長尾起點。"
        }
        Some("p99_latency_cycles") => {
            "此 load instruction kind 的 p99 latency 門檻；描述最慢 load 族群的延遲水準，對樣本數較敏感。"
        }
        Some("over_p95_est_time_pct") => {
            "此 load instruction kind 中超過自身 p95 的 load latency，佔該類 load 自身 latency 的比例；可判斷是否少數極慢 load 主導該類成本。"
        }
        Some("over_avg_est_time_pct") => {
            "此 load instruction kind 中超過自身平均值的 load latency，佔該類 load 自身 latency 的比例；用來看高於一般水準的資料等待佔比。"
        }
        Some("over_p95_all_est_time_pct") => {
            "此 load instruction kind 超過自身 p95 的長尾 latency，佔全部 load 指令 latency 的比例；用來比較哪種 load 型態的長尾最影響整體。"
        }
        Some("over_avg_all_est_time_pct") => {
            "此 load instruction kind 超過自身平均值的 latency，佔全部 load 指令 latency 的比例；用來比較哪種 load 型態的高延遲區段最花時間。"
        }
        _ => {
            "load instruction kind 是由 sampled PC 對應到的機器指令 opcode 解碼而來；它描述資料讀取指令型態，不需要 source file，但仍依賴 debug ELF .text 可讀。"
        }
    }
}

fn spe_category_metric_formula(key: &str) -> &'static str {
    match key.rsplit_once('.').map(|(_, metric)| metric) {
        Some("sample_count") => "category SPE sample count",
        Some("sample_pct") => "category SPE samples / total SPE samples",
        Some("spe_latency_pct") => "category SPE latency cycles / total SPE latency cycles",
        Some("est_time_pct") => "estimated time percentage",
        Some("min_latency_cycles") => "minimum SPE latency cycles in this category",
        Some("max_latency_cycles") => "maximum SPE latency cycles in this category",
        Some("avg_latency_cycles") => "average SPE latency cycles in this category",
        Some("std_latency_cycles") => {
            "population standard deviation of SPE latency cycles in this category"
        }
        Some("p95_latency_cycles") => "nearest-rank p95 SPE latency cycles in this category",
        Some("p99_latency_cycles") => "nearest-rank p99 SPE latency cycles in this category",
        Some("over_p95_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this category p95 / this category estimated time"
        }
        Some("over_avg_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this category average / this category estimated time"
        }
        Some("over_p95_all_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this category p95 / total estimated time"
        }
        Some("over_avg_all_est_time_pct") => {
            "estimated time from SPE latency cycles greater than this category average / total estimated time"
        }
        _ => "SPE category metric",
    }
}

fn spe_category_metric_meaning(key: &str) -> &'static str {
    if matches!(
        key.rsplit_once('.').map(|(category, _)| category),
        Some("compute_unknown")
    ) {
        return "SPE 捕捉到非 load/store/branch 的操作，但目前尚未把 sampled PC 的 opcode 細分成 int、FP/SIMD 或 crypto，因此先歸在 compute_unknown；它表示這段時間主要不是明確的記憶體或分支事件。";
    }
    match key.rsplit_once('.').map(|(_, metric)| metric) {
        Some("sample_count") => {
            "此 source line 歸因到這個 SPE category 的 sample 數；Source Lines 只顯示抽樣命中次數，避免把單行樣本誤解為 latency 或時間統計。"
        }
        Some("sample_pct") => {
            "此 SPE category 在整份 session 中的 sample 數量比例；物理上代表硬體抽樣到此類 data source 或 operation 的頻率，不是時間佔比。"
        }
        Some("spe_latency_pct") => {
            "此 SPE category 累積 latency cycles 的比例；物理上代表該類事件對被觀測等待時間的貢獻。沒有 latency field 時為 Missing。"
        }
        Some("est_time_pct") => {
            "估算時間佔比；目前用此分類的 SPE latency cycles 佔整份 session SPE latency cycles 的比例，適合判斷哪類硬體事件最消耗等待時間。"
        }
        Some("min_latency_cycles") => {
            "此類 SPE sample 實測 latency cycles 最小值；代表該類事件在最佳觀測情況下的硬體等待成本。"
        }
        Some("max_latency_cycles") => {
            "此類 SPE sample 實測 latency cycles 最大值；用來暴露該類事件是否存在極端長尾或偶發 stall。"
        }
        Some("avg_latency_cycles") => {
            "此類 SPE sample 實測 latency cycles 平均值；代表每次被抽樣事件平均等待多少核心週期，會被長尾事件影響。"
        }
        Some("std_latency_cycles") => {
            "此類 SPE sample latency cycles 的 population standard deviation；越高表示延遲分布越分散，可能混合多種 cache/memory 層級。"
        }
        Some("p95_latency_cycles") => {
            "此類 SPE sample latency cycles 的 nearest-rank p95；代表高延遲長尾開始的位置，約 95% 樣本不超過此值。"
        }
        Some("p99_latency_cycles") => {
            "此類 SPE sample latency cycles 的 nearest-rank p99；代表最慢 1% 附近的延遲水準，樣本少時需謹慎解讀。"
        }
        Some("over_p95_est_time_pct") => {
            "此類 SPE sample 中 latency cycles 大於該類 p95 的長尾時間，佔此類自身估算時間比例；用來看此分類是否被少量極慢事件主導。"
        }
        Some("over_avg_est_time_pct") => {
            "此類 SPE sample 中 latency cycles 大於該類平均值的時間，佔此類自身估算時間比例；用較寬鬆門檻觀察高於一般水準的等待成本。"
        }
        Some("over_p95_all_est_time_pct") => {
            "此類 SPE sample 中 latency cycles 大於該類 p95 的長尾時間，佔全部 SPE latency 的比例；用來比較哪個分類的最慢區段最花總時間。"
        }
        Some("over_avg_all_est_time_pct") => {
            "此類 SPE sample 中 latency cycles 大於該類平均值的時間，佔全部 SPE latency 的比例；用來比較哪個分類的高延遲區段最影響整體。"
        }
        _ => "Arm SPE 解碼後的 category 指標；描述硬體抽樣到的 data source 或 operation 類型，仍受取樣率與 packet 欄位完整度影響。",
    }
}

fn help_row(column: &str, formula: &str, meaning: &str) -> String {
    format!(
        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
        escape_help_cell(column),
        escape_html(formula),
        escape_html(meaning)
    )
}

fn escape_help_cell(text: &str) -> String {
    if text.starts_with('`') && text.ends_with('`') && text.len() >= 2 {
        format!("<code>{}</code>", escape_html(&text[1..text.len() - 1]))
    } else {
        escape_html(text)
    }
}

fn quality_rows(bundle: &SourceProfileBundle) -> String {
    let manifest = &bundle.manifest;
    let loss = &bundle.loss.totals;
    let rows = [
        (
            "PMU capability",
            if manifest.lanes.pmu.available {
                "OK"
            } else {
                "Missing"
            },
            manifest
                .lanes
                .pmu
                .missing_reason
                .as_deref()
                .unwrap_or("PMU lane accepted"),
        ),
        (
            "SPE capability",
            if manifest.lanes.spe.available {
                "OK"
            } else {
                "Missing"
            },
            manifest
                .lanes
                .spe
                .missing_reason
                .as_deref()
                .unwrap_or("SPE lane accepted"),
        ),
        (
            "PMU lost records",
            if loss.pmu_lost_records == 0 {
                "OK"
            } else {
                "Warning"
            },
            &loss.pmu_lost_records.to_string(),
        ),
        (
            "Ring buffer overrun",
            if loss.ring_buffer_overruns == 0 {
                "OK"
            } else {
                "Warning"
            },
            &loss.ring_buffer_overruns.to_string(),
        ),
        (
            "SPE decode errors",
            if loss.spe_decode_errors == 0 {
                "OK"
            } else {
                "Warning"
            },
            &loss.spe_decode_errors.to_string(),
        ),
        (
            "ELF match quality",
            "Pending",
            "Will be populated by symbol matching stage",
        ),
        (
            "Source attribution rate",
            "Pending",
            "Will be populated after address-to-line attribution",
        ),
    ];
    rows.into_iter()
        .map(|(check, status, detail)| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(check),
                escape_html(status),
                escape_html(detail)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn lane_text(enabled: bool, available: bool) -> &'static str {
    match (enabled, available) {
        (true, true) => "enabled / available",
        (true, false) => "enabled / missing",
        (false, true) => "disabled / available",
        (false, false) => "disabled / missing",
    }
}

fn frame_rows_html(rows: &[super::report_model::ReportFrameRow]) -> String {
    if rows.is_empty() {
        return "<tr><td colspan=\"13\">No callchain frames</td></tr>".to_string();
    }
    rows.iter()
        .take(200)
        .map(|row| {
            format!(
                "<tr><td>{}</td><td>{}</td><td class=\"stack-text\">{}</td><td><code>0x{:x}</code></td><td><code>0x{:x}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{:.0}</td><td>{:.0}</td><td>{:.3}</td><td>{:.3}</td><td>{}</td></tr>",
                escape_html(&row.role),
                escape_html(&row.module),
                escape_html(&row.function),
                row.ip,
                row.relative_address,
                escape_html(&row.cpu),
                escape_html(&row.thread),
                row.sample_count,
                row.self_weight,
                row.accumulated_weight,
                row.p_pct,
                row.acc_p_pct,
                escape_html(&row.status)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn callchain_rows_html(rows: &[super::report_model::ReportCallchainRow]) -> String {
    if rows.is_empty() {
        return "<tr><td colspan=\"8\">No callchains</td></tr>".to_string();
    }
    rows.iter()
        .take(200)
        .map(|row| {
            format!(
                "<tr><td class=\"stack-text\">{}</td><td class=\"stack-text\">{}</td><td class=\"stack-text\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.0}</td><td>{:.3}</td></tr>",
                escape_html(&row.stack),
                escape_html(&row.leaf),
                escape_html(&row.root),
                escape_html(&row.cpu),
                escape_html(&row.thread),
                row.sample_count,
                row.weight,
                row.p_pct
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::Path};

    use crate::source_profile::report_model::ReportLineRow;

    use super::*;

    #[test]
    fn writes_html_summary() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let output = root.join("target/source_profile_tests/SourceLine.summary.html");
        write_html_summary(&bundle, &output).unwrap();
        let html = fs::read_to_string(output).unwrap();
        let default_columns_start = html.find("const DEFAULT_SOURCE_COLUMNS = ").unwrap();
        let default_columns_end = html[default_columns_start..]
            .find(";\n    let visibleSourceColumns")
            .unwrap()
            + default_columns_start;
        let default_columns = &html[default_columns_start..default_columns_end];
        let source_columns_start = html.find("const SOURCE_COLUMNS = ").unwrap();
        let source_columns_end = html[source_columns_start..]
            .find(";\n    const DEFAULT_SOURCE_COLUMNS")
            .unwrap()
            + source_columns_start;
        let source_columns = &html[source_columns_start..source_columns_end];
        assert!(html.contains("SourceLine Report"));
        assert!(html.contains("fixture-minimal-001"));
        assert!(html.contains("PMU buffer pages"));
        assert!(
            html.contains("<details class=\"report-section\" open>\n  <summary>Summary</summary>")
        );
        let summary_pos = html.find("<summary>Summary</summary>").unwrap();
        let spe_summary_pos = html
            .find("<summary>SPE Hierarchical Breakdown</summary>")
            .unwrap();
        let column_help_pos = html.find("<summary>Column Help</summary>").unwrap();
        let source_lines_pos = html.find("<summary>Source Lines</summary>").unwrap();
        assert!(column_help_pos < summary_pos);
        assert!(column_help_pos < spe_summary_pos);
        assert!(column_help_pos < source_lines_pos);
        assert!(html.contains("<table class=\"spe-summary-table\">"));
        assert!(html.contains("<summary>SPE Hierarchical Breakdown Columns</summary>"));
        assert!(html.contains("id=\"speBreakdownColumnPicker\""));
        assert!(html.contains("data-spe-column=\"cpu\""));
        assert!(html.contains("data-spe-column=\"category\""));
        assert!(html.contains("data-spe-column=\"all_est_time_pct\""));
        assert!(html.contains("data-spe-column=\"over_avg_all_est_time_pct\""));
        assert!(!html.contains("data-spe-column=\"est_time_pct_tail\""));
        assert!(!html.contains("data-spe-column=\"all_est_time_pct_tail\""));
        assert!(html.contains("const SPE_BREAKDOWN_COLUMNS = ["));
        assert!(html.contains("visibleSpeBreakdownColumns"));
        assert!(html.contains("toggleSpeBreakdownColumn"));
        assert!(html.contains("renderSpeBreakdownColumnPicker"));
        assert!(html.contains("applySpeBreakdownColumnVisibility"));
        assert!(html.contains("id=\"speHierarchyHistogram\""));
        assert!(html.contains("class=\"spe-histogram-panel\" hidden"));
        assert!(html.contains("const SPE_HIERARCHY_HISTOGRAMS = "));
        assert!(html.contains("function positionSpeHierarchyHistogram(row)"));
        assert!(html.contains("let speHistogramDrag = null;"));
        assert!(html.contains("let speHistogramManuallyPositioned = false;"));
        assert!(html.contains("function startSpeHistogramDrag(event)"));
        assert!(html.contains("function moveSpeHistogramDrag(event)"));
        assert!(html.contains("function endSpeHistogramDrag(event)"));
        assert!(html.contains("function clampSpeHistogramPosition(left, top)"));
        assert!(html.contains("function hideSpeHierarchyHistogram()"));
        assert!(html.contains("function speHistogramHeader(title)"));
        assert!(html.contains("function renderSpeHierarchyHistogram"));
        assert!(html.contains("position: fixed"));
        assert!(html.contains("cursor: move"));
        assert!(html.contains("onpointerdown=\"startSpeHistogramDrag(event)\""));
        assert!(html.contains("onpointermove=\"moveSpeHistogramDrag(event)\""));
        assert!(html.contains("speHistogramManuallyPositioned = true;"));
        assert!(html.contains("class=\"spe-histogram-hide\""));
        assert!(html.contains("onclick=\"hideSpeHierarchyHistogram()\""));
        assert!(html.contains("window.innerWidth - panelWidth - margin"));
        assert!(html.contains("let top = rowRect.bottom + gap;"));
        assert!(html.contains("positionSpeHierarchyHistogram(row);"));
        assert!(html.contains("count > 0 ? Math.max(2, count / maxCount * 100) : 0"));
        assert!(html.contains("spe-histogram-bar-track empty"));
        assert!(!html.contains("<summary>SPE Category Summary</summary>"));
        assert!(!html.contains("<summary>Instruction Class Summary</summary>"));
        assert!(!html.contains("<summary>Load Instruction Summary</summary>"));
        assert!(!html.contains("<th>spe_latency%</th>"));
        assert!(!html.contains("pmu_cycles%"));
        assert!(html.contains("<tr><td colspan=\"17\">SPE samples unavailable</td></tr>"));
        assert!(!html.contains("<tr><td><code>cpu_instruction</code></td>"));
        assert!(
            html.contains("<details class=\"report-section\">\n  <summary>Column Help</summary>")
        );
        assert!(!html
            .contains("<details class=\"report-section\" open>\n  <summary>Column Help</summary>"));
        assert!(html.contains("Formula / Source"));
        assert!(html.contains("意義 / 限制"));
        assert!(!html.contains("Meaning / Limitation"));
        assert!(html.contains("取樣位址經符號化與 debug line table 對應後落到的原始碼檔案"));
        assert!(html.contains("平均每退休一條指令消耗的 CPU cycles"));
        assert!(html.contains("每秒百萬退休指令"));
        assert!(!html.contains("SPE 記錄的平均 latency cycles"));
        assert!(html.contains("SPE Hierarchical Breakdown: sample%"));
        assert!(html.contains("SPE Hierarchical Breakdown: est_time%"));
        assert!(html.contains("SPE Hierarchical Breakdown: all est_time%"));
        assert!(html.contains("SPE Hierarchical Breakdown: &gt;theory sample%"));
        assert!(html.contains("load_l1=4T、load_l2=10T、load_l3=60T、store*=3T"));
        assert!(html.contains("子節點是 parent-relative"));
        assert!(html.contains("全域估算時間佔比"));
        assert!(html.contains("適合比較展開後哪個子項真正佔整體 latency"));
        assert!(html.contains("SPE Hierarchical Breakdown: &gt;p95 all est_time%"));
        assert!(html.contains("line PMU sample count"));
        assert!(html.contains("<code>cpu_cycles</code>"));
        assert!(html.contains("<code>inst_retired</code>"));
        assert!(html.contains("<code>cpi</code>"));
        assert!(html.contains("<code>mips</code>"));
        assert!(html.contains("<code>spe_sample_count</code>"));
        assert!(!html.contains("<code>load_dram.est_time_pct</code>"));
        assert!(!html.contains("<code>load_llc.est_time_pct</code>"));
        assert!(!html.contains("<code>store_unknown.est_time_pct</code>"));
        assert!(html.contains("source text"));
        assert!(html.contains("Quality"));
        assert!(html.contains("<details class=\"report-section\">\n    <summary>Quality</summary>"));
        assert!(html.contains("SPE capability"));
        assert!(html.contains("id=\"qualityRows\""));
        assert!(html.contains("Source Lines"));
        assert!(html.contains(
            "<details class=\"report-section\" open>\n  <summary>Source Lines</summary>"
        ));
        assert!(html.contains("Columns"));
        assert!(html.contains("<code>mcps</code>"));
        assert!(html.contains("col-file"));
        assert!(html.contains("col-function"));
        assert!(html.contains("table-scroll"));
        assert!(html.contains("col-code"));
        assert!(html.contains("col-thread truncate"));
        assert!(html.contains("sourceWidthToggle"));
        assert!(html.contains("toggleSourceWidth"));
        assert!(html.contains("#sourceTable.expanded"));
        assert!(html.contains(
            "<details class=\"column-panel\">\n    <summary>Source Lines Columns</summary>"
        ));
        assert!(!html.contains("<details class=\"column-panel\" open>"));
        assert!(html.contains("id=\"sourceColumnPicker\""));
        assert!(html.contains("id=\"minSamples\""));
        assert!(html.contains("id=\"minSamples\" type=\"number\" min=\"0\" value=\"0\" oninput=\"resetSourcePaging()\""));
        assert!(html.contains("min_samples"));
        assert!(html.contains("RAW_PMU_COLUMNS"));
        assert!(html.contains("DERIVED_PMU_COLUMNS"));
        assert!(html.contains("SPE_COLUMNS"));
        assert!(html.contains("visibleSourceColumns"));
        assert!(html.contains("toggleSourceColumn"));
        assert!(html.contains("toggleSourceColumnGroup"));
        assert!(html.contains("updateSourceColumnGroupChecks"));
        assert!(html.contains("data-column-group"));
        assert!(html.contains("input.indeterminate"));
        assert!(html.contains("renderSourceHeaders"));
        assert!(html.contains("renderSourceBody"));
        assert!(html.contains("sample_count"));
        assert!(html.contains("Samples"));
        assert!(!source_columns.contains("key: \"self_weight\""));
        assert!(!source_columns.contains("key: \"accumulated_weight\""));
        assert!(!source_columns.contains("key: \"status\""));
        assert!(!html.contains("\"load_l1.est_time_pct\""));
        assert!(!html.contains("\"load_llc.est_time_pct\""));
        assert!(!html.contains("\"store_llc.est_time_pct\""));
        assert!(!html.contains("\"branch_unknown.est_time_pct\""));
        assert!(!html.contains("\"compute_unknown.est_time_pct\""));
        assert!(!default_columns.contains("\"p_pct\""));
        assert!(!default_columns.contains("\"acc_p_pct\""));
        assert!(!default_columns.contains("\"file_p_pct\""));
        assert!(!default_columns.contains("\"file_acc_p_pct\""));
        assert!(!default_columns.contains("\"status\""));
        assert!(default_columns.contains("\"spe_sample_count\""));
        assert!(!default_columns.contains("\"spe_latency_cycles_avg\""));
        assert!(!default_columns.contains("\"spe_decode_errors\""));
        assert!(!default_columns.contains("\"load_l1.est_time_pct\""));
        assert!(!default_columns.contains("\"load_l2.est_time_pct\""));
        assert!(!default_columns.contains("\"load_l3.est_time_pct\""));
        assert!(!default_columns.contains("\"load_llc.est_time_pct\""));
        assert!(!default_columns.contains("\"load_dram.est_time_pct\""));
        assert!(!default_columns.contains("\"load_unknown.est_time_pct\""));
        assert!(!default_columns.contains("\"store_l1.est_time_pct\""));
        assert!(!default_columns.contains("\"store_l2.est_time_pct\""));
        assert!(!default_columns.contains("\"store_l3.est_time_pct\""));
        assert!(!default_columns.contains("\"store_llc.est_time_pct\""));
        assert!(!default_columns.contains("\"store_dram.est_time_pct\""));
        assert!(!default_columns.contains("\"store_unknown.est_time_pct\""));
        assert!(html.contains("cpu_cycles"));
        assert!(html.contains("inst_retired"));
        assert!(!html.contains("stall_backend"));
        assert!(html.contains("spe_sample_count"));
        assert!(!html.contains("load_dram.est_time_pct"));
        assert!(!html.contains("store_unknown.est_time_pct"));
        assert!(html.contains("class=\"sort-indicator\""));
        assert!(html.contains("updateSourceSortIndicators"));
        assert!(!html.contains("id=\"sourceDetail\""));
        assert!(!html.contains("showSourceDetail"));
        assert!(!html.contains("data-annotation"));
        assert!(!html.contains("<th onclick=\"sortSourceRows('status')\">Status</th>"));
        assert!(!html.contains("Source Viewer"));
        assert!(!html.contains("sourceViewer"));
        assert!(html.contains("Files"));
        assert!(html.contains("<details class=\"report-section\">\n  <summary>Files</summary>"));
        assert!(html.contains("data-file-sort=\"file\""));
        assert!(html.contains("data-file-sort=\"unresolved\""));
        assert!(html.contains("sortFileRows"));
        assert!(html.contains("updateFileSortIndicators"));
        assert!(html.contains("Functions"));
        assert!(html.contains("<details class=\"report-section\">\n  <summary>Functions</summary>"));
        assert!(html.contains("<details class=\"report-section\">\n  <summary>Artifacts</summary>"));
        assert!(html.contains("Missing"));
        assert!(html.contains("/api/source-lines"));
        assert!(html.contains("value=\"1000\""));
        assert!(html.contains("max=\"10000\""));
        assert!(html.contains("id=\"sampledFirst\""));
        assert!(html.contains("id=\"functionFirst\""));
        assert!(html.contains("id=\"functionOnly\""));
        assert!(html.contains("sampled_first"));
        assert!(html.contains("function_first"));
        assert!(html.contains("function_only"));
        assert!(html.contains("/api/summary"));
        assert!(!html.contains("const sourceRows ="));
    }

    #[test]
    fn displayed_spe_columns_show_only_nonzero_sample_counts() {
        let model = ReportModel {
            rows: vec![ReportLineRow {
                file: "src/main.cpp".to_string(),
                line: 7,
                function: "Tick".to_string(),
                module: "libgame.so".to_string(),
                code: "Tick();".to_string(),
                status: "ok".to_string(),
                cpu: "0".to_string(),
                thread: "1".to_string(),
                sample_count: 0,
                self_weight: 0.0,
                accumulated_weight: 0.0,
                p_pct: 0.0,
                acc_p_pct: 0.0,
                file_p_pct: 0.0,
                file_acc_p_pct: 0.0,
                pmu_values: BTreeMap::new(),
                spe_values: BTreeMap::from([
                    ("load_l1.sample_count".to_string(), MetricValue::Number(3.0)),
                    ("load_l1.sample_pct".to_string(), MetricValue::Number(10.0)),
                    (
                        "load_l1.spe_latency_pct".to_string(),
                        MetricValue::Number(12.0),
                    ),
                    (
                        "load_l1.est_time_pct".to_string(),
                        MetricValue::Number(12.0),
                    ),
                    (
                        "load_llc.sample_count".to_string(),
                        MetricValue::Number(0.0),
                    ),
                    ("load_llc.sample_pct".to_string(), MetricValue::Number(0.0)),
                    (
                        "load_llc.spe_latency_pct".to_string(),
                        MetricValue::Number(0.0),
                    ),
                    (
                        "load_llc.est_time_pct".to_string(),
                        MetricValue::Number(0.0),
                    ),
                ]),
                instruction_values: BTreeMap::from([
                    (
                        "instruction_class.compute_int.sample_count".to_string(),
                        MetricValue::Number(2.0),
                    ),
                    (
                        "instruction_class.compute_int.sample_pct".to_string(),
                        MetricValue::Number(50.0),
                    ),
                    (
                        "instruction_class.compute_int.avg_latency_cycles".to_string(),
                        MetricValue::Number(30.0),
                    ),
                ]),
                load_instruction_values: BTreeMap::from([
                    (
                        "load_instruction.load_scalar_single.sample_count".to_string(),
                        MetricValue::Number(1.0),
                    ),
                    (
                        "load_instruction.load_scalar_single.sample_pct".to_string(),
                        MetricValue::Number(25.0),
                    ),
                    (
                        "load_instruction.load_scalar_single.est_time_pct".to_string(),
                        MetricValue::Number(25.0),
                    ),
                ]),
                detail: String::new(),
            }],
            files: Vec::new(),
            functions: Vec::new(),
            frames: Vec::new(),
            callchains: Vec::new(),
            spe_cpu_category_values: BTreeMap::new(),
            spe_cpu_category_histograms: BTreeMap::new(),
            spe_hierarchical_cpu_values: BTreeMap::new(),
            spe_hierarchical_cpu_histograms: BTreeMap::new(),
            instruction_cpu_class_values: BTreeMap::new(),
            load_cpu_kind_values: BTreeMap::new(),
            warnings: Vec::new(),
        };

        let columns = displayed_spe_column_keys(&model);
        let instruction_columns = displayed_instruction_class_column_keys(&model);
        let load_instruction_columns = displayed_load_instruction_column_keys(&model);

        assert!(columns.contains(&"load_l1.sample_count".to_string()));
        assert!(!columns.contains(&"load_l1.sample_pct".to_string()));
        assert!(!columns.contains(&"load_l1.est_time_pct".to_string()));
        assert!(!columns.contains(&"load_l1.avg_latency_cycles".to_string()));
        assert!(!columns.contains(&"load_llc.sample_count".to_string()));
        assert!(
            instruction_columns.contains(&"instruction_class.compute_int.sample_count".to_string())
        );
        assert!(
            !instruction_columns.contains(&"instruction_class.compute_int.sample_pct".to_string())
        );
        assert!(!instruction_columns
            .contains(&"instruction_class.compute_int.avg_latency_cycles".to_string()));
        assert!(load_instruction_columns
            .contains(&"load_instruction.load_scalar_single.sample_count".to_string()));
        assert!(!load_instruction_columns
            .contains(&"load_instruction.load_scalar_single.est_time_pct".to_string()));
    }

    #[test]
    fn spe_hierarchy_rows_show_empty_state_when_no_hierarchy_samples() {
        let model = ReportModel {
            rows: Vec::new(),
            files: Vec::new(),
            functions: Vec::new(),
            frames: Vec::new(),
            callchains: Vec::new(),
            spe_cpu_category_values: BTreeMap::new(),
            spe_cpu_category_histograms: BTreeMap::new(),
            spe_hierarchical_cpu_values: BTreeMap::new(),
            spe_hierarchical_cpu_histograms: BTreeMap::new(),
            instruction_cpu_class_values: BTreeMap::new(),
            load_cpu_kind_values: BTreeMap::new(),
            warnings: Vec::new(),
        };

        let rows = spe_hierarchy_summary_rows_html(&model, true);

        assert!(rows.contains("No SPE hierarchy samples"));
    }

    #[test]
    fn html_renders_spe_hierarchy_rows_with_clickable_histograms() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let model = ReportModel {
            rows: Vec::new(),
            files: Vec::new(),
            functions: Vec::new(),
            frames: Vec::new(),
            callchains: Vec::new(),
            spe_cpu_category_values: BTreeMap::new(),
            spe_cpu_category_histograms: BTreeMap::new(),
            spe_hierarchical_cpu_values: BTreeMap::from([(
                4,
                BTreeMap::from([
                    ("load_l1.sample_pct".to_string(), MetricValue::Number(100.0)),
                    (
                        "load_l1.est_time_pct".to_string(),
                        MetricValue::Number(100.0),
                    ),
                    (
                        "load_l1.min_latency_cycles".to_string(),
                        MetricValue::Number(10.0),
                    ),
                    (
                        "load_l1.max_latency_cycles".to_string(),
                        MetricValue::Number(80.0),
                    ),
                    (
                        "load_l1.avg_latency_cycles".to_string(),
                        MetricValue::Number(45.0),
                    ),
                    (
                        "load_l1.std_latency_cycles".to_string(),
                        MetricValue::Number(20.0),
                    ),
                    (
                        "load_l1.p95_latency_cycles".to_string(),
                        MetricValue::Number(80.0),
                    ),
                    (
                        "load_l1.p99_latency_cycles".to_string(),
                        MetricValue::Number(80.0),
                    ),
                    (
                        "load_l1.over_theory_sample_pct".to_string(),
                        MetricValue::Number(100.0),
                    ),
                    (
                        "load_l1.over_theory_est_time_pct".to_string(),
                        MetricValue::Number(100.0),
                    ),
                    (
                        "load_l1.over_p95_est_time_pct".to_string(),
                        MetricValue::Number(25.0),
                    ),
                    (
                        "load_l1.over_avg_est_time_pct".to_string(),
                        MetricValue::Number(40.0),
                    ),
                    (
                        "load_l1.over_p95_all_est_time_pct".to_string(),
                        MetricValue::Number(20.0),
                    ),
                    (
                        "load_l1.over_avg_all_est_time_pct".to_string(),
                        MetricValue::Number(35.0),
                    ),
                    (
                        "load_l1.all_est_time_pct".to_string(),
                        MetricValue::Number(100.0),
                    ),
                    (
                        "load_l1.vector_load.sample_pct".to_string(),
                        MetricValue::Number(60.0),
                    ),
                    (
                        "load_l1.vector_load.est_time_pct".to_string(),
                        MetricValue::Number(70.0),
                    ),
                    (
                        "load_l1.vector_load.min_latency_cycles".to_string(),
                        MetricValue::Number(30.0),
                    ),
                    (
                        "load_l1.vector_load.max_latency_cycles".to_string(),
                        MetricValue::Number(80.0),
                    ),
                    (
                        "load_l1.vector_load.avg_latency_cycles".to_string(),
                        MetricValue::Number(55.0),
                    ),
                    (
                        "load_l1.vector_load.std_latency_cycles".to_string(),
                        MetricValue::Number(15.0),
                    ),
                    (
                        "load_l1.vector_load.p95_latency_cycles".to_string(),
                        MetricValue::Number(80.0),
                    ),
                    (
                        "load_l1.vector_load.p99_latency_cycles".to_string(),
                        MetricValue::Number(80.0),
                    ),
                    (
                        "load_l1.vector_load.over_theory_sample_pct".to_string(),
                        MetricValue::Number(50.0),
                    ),
                    (
                        "load_l1.vector_load.over_theory_est_time_pct".to_string(),
                        MetricValue::Number(55.0),
                    ),
                    (
                        "load_l1.vector_load.over_p95_est_time_pct".to_string(),
                        MetricValue::Number(30.0),
                    ),
                    (
                        "load_l1.vector_load.over_avg_est_time_pct".to_string(),
                        MetricValue::Number(50.0),
                    ),
                    (
                        "load_l1.vector_load.over_p95_all_est_time_pct".to_string(),
                        MetricValue::Number(25.0),
                    ),
                    (
                        "load_l1.vector_load.over_avg_all_est_time_pct".to_string(),
                        MetricValue::Number(45.0),
                    ),
                    (
                        "load_l1.vector_load.all_est_time_pct".to_string(),
                        MetricValue::Number(12.5),
                    ),
                ]),
            )]),
            spe_hierarchical_cpu_histograms: BTreeMap::from([(
                4,
                BTreeMap::from([(
                    "load_l1.vector_load".to_string(),
                    super::super::report_model::SpeLatencyHistogram {
                        count: 2,
                        min_latency_cycles: 30,
                        max_latency_cycles: 80,
                        bins: vec![super::super::report_model::SpeLatencyHistogramBin {
                            start_latency_cycles: 30,
                            end_latency_cycles: 80,
                            count: 2,
                        }],
                    },
                )]),
            )]),
            instruction_cpu_class_values: BTreeMap::new(),
            load_cpu_kind_values: BTreeMap::new(),
            warnings: Vec::new(),
        };

        let rows = spe_hierarchy_summary_rows_html(&model, true);

        assert!(rows.contains("data-spe-cpu=\"4\" data-spe-parent=\"load_l1\" data-spe-child=\"\""));
        assert!(rows.contains("data-spe-parent=\"load_l1\" data-spe-child=\"\""));
        assert!(rows.contains("data-spe-collapsible=\"true\" aria-expanded=\"false\""));
        assert!(rows.contains("<td data-spe-column=\"cpu\">4</td>"));
        assert!(rows.contains("<td data-spe-column=\"est_time_pct\">100.000%</td>"));
        assert!(rows.contains("<td data-spe-column=\"all_est_time_pct\">100.000%</td>"));
        assert!(rows.contains("<td data-spe-column=\"over_theory_sample_pct\">100.000%</td>"));
        assert!(rows.contains("<td data-spe-column=\"over_theory_est_time_pct\">100.000%</td>"));
        assert!(rows.contains("<td data-spe-column=\"over_avg_all_est_time_pct\">35.000%</td>"));
        assert!(
            rows.contains("<span class=\"spe-collapse-indicator\">+</span><code>load_l1</code>")
        );
        assert!(rows.contains(
            "data-spe-cpu=\"4\" data-spe-parent=\"load_l1\" data-spe-child=\"vector_load\""
        ));
        assert!(rows.contains("data-spe-parent=\"load_l1\" data-spe-child=\"vector_load\""));
        assert!(rows.contains(
            "data-spe-child=\"vector_load\" onclick=\"renderSpeHierarchyHistogram(this)\" hidden"
        ));
        assert!(rows.contains("<td data-spe-column=\"all_est_time_pct\">12.500%</td>"));
        assert!(rows.contains("<td data-spe-column=\"over_theory_sample_pct\">50.000%</td>"));
        assert!(rows.contains("<td data-spe-column=\"over_theory_est_time_pct\">55.000%</td>"));
        assert!(rows.contains("onclick=\"renderSpeHierarchyHistogram(this)\""));
        assert!(rows.contains("class=\"spe-child-label\""));

        let output = root.join("target/source_profile_tests/SourceLine.spe_hierarchy.html");
        write_html_summary_from_model(&bundle, &model, &output).unwrap();

        let html = fs::read_to_string(output).unwrap();
        assert!(html.contains("<summary>SPE Hierarchical Breakdown</summary>"));
        assert!(html.contains("<summary>SPE Hierarchical Breakdown Columns</summary>"));
        assert!(html.contains("id=\"speBreakdownColumnPicker\""));
        assert!(html.contains("const SPE_HIERARCHY_HISTOGRAMS ="));
        assert!(html.contains("const SPE_BREAKDOWN_COLUMNS ="));
        assert!(html.contains("toggleSpeBreakdownColumn"));
        assert!(html.contains("function toggleSpeHierarchyChildren(row)"));
        assert!(html.contains("function renderSpeHierarchyHistogram"));
        assert!(html.contains("childRow.hidden = !expanded;"));
        assert!(html.contains(r#"const key = child ? `${parent}.${child}` : parent;"#));
        assert!(html.contains("SPE_HIERARCHY_HISTOGRAMS?.[cpu]?.[key]"));
    }

    #[test]
    fn html_omits_legacy_instruction_class_summary_section() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let model = ReportModel {
            rows: Vec::new(),
            files: Vec::new(),
            functions: Vec::new(),
            frames: Vec::new(),
            callchains: Vec::new(),
            spe_cpu_category_values: BTreeMap::new(),
            spe_cpu_category_histograms: BTreeMap::new(),
            spe_hierarchical_cpu_values: BTreeMap::new(),
            spe_hierarchical_cpu_histograms: BTreeMap::new(),
            instruction_cpu_class_values: BTreeMap::from([(
                4,
                BTreeMap::from([
                    (
                        "instruction_class.compute_fp_simd.sample_pct".to_string(),
                        MetricValue::Number(75.0),
                    ),
                    (
                        "instruction_class.compute_fp_simd.est_time_pct".to_string(),
                        MetricValue::Number(80.0),
                    ),
                    (
                        "instruction_class.compute_fp_simd.min_latency_cycles".to_string(),
                        MetricValue::Number(10.0),
                    ),
                    (
                        "instruction_class.compute_fp_simd.max_latency_cycles".to_string(),
                        MetricValue::Number(40.0),
                    ),
                    (
                        "instruction_class.compute_fp_simd.avg_latency_cycles".to_string(),
                        MetricValue::Number(25.0),
                    ),
                    (
                        "instruction_class.compute_fp_simd.std_latency_cycles".to_string(),
                        MetricValue::Number(5.0),
                    ),
                ]),
            )]),
            load_cpu_kind_values: BTreeMap::new(),
            warnings: Vec::new(),
        };
        let output = root.join("target/source_profile_tests/SourceLine.instruction_class.html");

        write_html_summary_from_model(&bundle, &model, &output).unwrap();

        let html = fs::read_to_string(output).unwrap();
        assert!(html.contains("<summary>SPE Hierarchical Breakdown</summary>"));
        assert!(!html.contains("<summary>Instruction Class Summary</summary>"));
        assert!(!html.contains("Instruction classes are decoded from sampled PC opcodes"));
    }

    #[test]
    fn html_omits_legacy_load_instruction_summary_section() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let model = ReportModel {
            rows: Vec::new(),
            files: Vec::new(),
            functions: Vec::new(),
            frames: Vec::new(),
            callchains: Vec::new(),
            spe_cpu_category_values: BTreeMap::new(),
            spe_cpu_category_histograms: BTreeMap::new(),
            spe_hierarchical_cpu_values: BTreeMap::new(),
            spe_hierarchical_cpu_histograms: BTreeMap::new(),
            instruction_cpu_class_values: BTreeMap::new(),
            load_cpu_kind_values: BTreeMap::from([(
                4,
                BTreeMap::from([
                    (
                        "load_instruction.load_scalar_single.sample_pct".to_string(),
                        MetricValue::Number(60.0),
                    ),
                    (
                        "load_instruction.load_scalar_single.est_time_pct".to_string(),
                        MetricValue::Number(70.0),
                    ),
                    (
                        "load_instruction.load_scalar_single.min_latency_cycles".to_string(),
                        MetricValue::Number(8.0),
                    ),
                    (
                        "load_instruction.load_scalar_single.max_latency_cycles".to_string(),
                        MetricValue::Number(80.0),
                    ),
                    (
                        "load_instruction.load_scalar_single.avg_latency_cycles".to_string(),
                        MetricValue::Number(40.0),
                    ),
                    (
                        "load_instruction.load_scalar_single.std_latency_cycles".to_string(),
                        MetricValue::Number(10.0),
                    ),
                ]),
            )]),
            warnings: Vec::new(),
        };
        let output = root.join("target/source_profile_tests/SourceLine.load_instruction.html");

        write_html_summary_from_model(&bundle, &model, &output).unwrap();

        let html = fs::read_to_string(output).unwrap();
        assert!(html.contains("<summary>SPE Hierarchical Breakdown</summary>"));
        assert!(!html.contains("<summary>Load Instruction Summary</summary>"));
        assert!(!html.contains("Load instruction kinds are decoded from sampled PC opcodes"));
    }

    #[test]
    fn writes_html_summary_from_prebuilt_model() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let model = crate::source_profile::report_model::build_report_model(&bundle).unwrap();
        let output = root.join("target/source_profile_tests/SourceLine.from_model.html");

        write_html_summary_from_model(&bundle, &model, &output).unwrap();

        let html = fs::read_to_string(output).unwrap();
        assert!(html.contains("SourceLine Report"));
        assert!(html.contains("fixture-minimal-001"));
        assert!(html.contains("/api/source-lines"));
    }

    #[test]
    fn html_help_explains_compute_unknown() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let model = ReportModel {
            rows: vec![ReportLineRow {
                file: "src/main.cpp".to_string(),
                line: 7,
                function: "Tick".to_string(),
                module: "libgame.so".to_string(),
                code: "Tick();".to_string(),
                status: "ok".to_string(),
                cpu: "0".to_string(),
                thread: "1".to_string(),
                sample_count: 1,
                self_weight: 0.0,
                accumulated_weight: 0.0,
                p_pct: 0.0,
                acc_p_pct: 0.0,
                file_p_pct: 0.0,
                file_acc_p_pct: 0.0,
                pmu_values: BTreeMap::new(),
                spe_values: BTreeMap::from([(
                    "compute_unknown.sample_count".to_string(),
                    MetricValue::Number(100.0),
                )]),
                instruction_values: BTreeMap::new(),
                load_instruction_values: BTreeMap::new(),
                detail: String::new(),
            }],
            files: Vec::new(),
            functions: Vec::new(),
            frames: Vec::new(),
            callchains: Vec::new(),
            spe_cpu_category_values: BTreeMap::new(),
            spe_cpu_category_histograms: BTreeMap::new(),
            spe_hierarchical_cpu_values: BTreeMap::new(),
            spe_hierarchical_cpu_histograms: BTreeMap::new(),
            instruction_cpu_class_values: BTreeMap::new(),
            load_cpu_kind_values: BTreeMap::new(),
            warnings: Vec::new(),
        };
        let output = root.join("target/source_profile_tests/SourceLine.compute_unknown.html");

        write_html_summary_from_model(&bundle, &model, &output).unwrap();

        let html = fs::read_to_string(output).unwrap();
        assert!(html.contains("SPE 捕捉到非 load/store/branch 的操作"));
        assert!(html.contains("目前尚未把 sampled PC 的 opcode 細分成 int"));
    }
}

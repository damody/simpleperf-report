#![allow(dead_code)]

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use super::bundle::SourceProfileBundle;
use super::report_model::pmu_raw_column_keys;
use super::summary::SourceReportSummary;

pub trait HtmlReportWriter {
    fn write_html(&self, summary: &SourceReportSummary, output: &Path) -> Result<()>;
}

pub fn write_html_summary(bundle: &SourceProfileBundle, output: &Path) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create '{}'", parent.display()))?;
    }
    let manifest = &bundle.manifest;
    let raw_pmu_columns = pmu_raw_column_keys(bundle);
    let raw_pmu_columns_json =
        serde_json::to_string(&raw_pmu_columns).unwrap_or_else(|_| "[]".to_string());
    let mut default_source_columns = vec![
        "file".to_string(),
        "line".to_string(),
        "function".to_string(),
        "module".to_string(),
        "cpu".to_string(),
        "thread".to_string(),
        "sample_count".to_string(),
        "self_weight".to_string(),
        "accumulated_weight".to_string(),
    ];
    default_source_columns.extend(raw_pmu_columns.iter().cloned());
    default_source_columns.extend([
        "cpi".to_string(),
        "l1d_cache_hit_rate".to_string(),
        "mips".to_string(),
        "mcps".to_string(),
        "code".to_string(),
    ]);
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
    #sourceTable .col-status {{ width: 170px; max-width: 170px; }}
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
    .toolbar {{ display: flex; gap: 8px; align-items: center; margin: 8px 0; flex-wrap: wrap; }}
    .toolbar input {{ padding: 4px 6px; }}
    .column-picker {{ display: inline-block; }}
    .column-picker summary {{ cursor: pointer; }}
    .column-picker-controls {{ display: grid; grid-template-columns: repeat(4, max-content); gap: 4px 12px; padding: 8px; border: 1px solid #d0d7de; background: #fff; position: absolute; z-index: 2; }}
    details.report-section {{ margin-top: 24px; }}
    details.report-section > summary {{ cursor: pointer; font-size: 18px; font-weight: 600; }}
    details.report-section > table,
    details.report-section > .toolbar {{ margin-top: 8px; }}
    code {{ font-family: Consolas, monospace; }}
  </style>
</head>
<body>
  <h1>SourceLine Report</h1>
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
    <details class="column-picker">
      <summary>Columns</summary>
      <div id="sourceColumnPicker" class="column-picker-controls"></div>
    </details>
    <button onclick="previousSourcePage()">Prev</button>
    <button onclick="nextSourcePage()">Next</button>
    <span id="sourcePageStatus"></span>
  </div>
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
  <details class="report-section">
  <summary>Column Help</summary>
  <table>
    <tr><th>Column / Metric</th><th>Formula</th><th>Physical Meaning / Limitation</th></tr>
    <tr><td><code>p %</code></td><td>line self weight / global self weight * 100</td><td>這一行本身 sample 權重佔整個 session 的比例。</td></tr>
    <tr><td><code>acc_p %</code></td><td>line accumulated weight / global accumulated weight * 100</td><td>包含 callchain 歸因後，這一行在呼叫路徑上的累積比例。</td></tr>
    <tr><td><code>file p %</code></td><td>line self weight / same-file self weight * 100</td><td>這一行在同檔案內的 self 熱度比例。</td></tr>
    <tr><td><code>file acc_p %</code></td><td>line accumulated weight / same-file accumulated weight * 100</td><td>這一行在同檔案內的 callchain 累積比例。</td></tr>
    <tr><td>Cycles</td><td>PMU cpu_cycles sample weight</td><td>CPU cycle 活動量；line-level 是 sampling attribution，不是每次 cycle 完整記錄。</td></tr>
    <tr><td>instructions</td><td>PMU inst_retired sample weight</td><td>退休指令量；可搭配 cycles 算 CPI。</td></tr>
    <tr><td>CPI</td><td>cpu_cycles / inst_retired</td><td>平均每退休一條指令消耗的 cycles；分母缺失或為 0 時不輸出 0。</td></tr>
    <tr><td>MCPS</td><td>cpu_cycles / effective_time_seconds / 1000000</td><td>每秒百萬 CPU cycles；source line 層級是 sample 歸因後的近似活動量。</td></tr>
    <tr><td>cache hit rate</td><td>(access - refill) / access</td><td>Cache hit rate 的統計近似；不是每一次 cache access 的完整 trace。</td></tr>
    <tr><td>branch miss rate</td><td>branch_mispredict / branch_retired</td><td>分支預測錯誤比例的 sampling 近似。</td></tr>
    <tr><td>SPE latency / data source</td><td>SPE normalized fields</td><td>來自 Arm SPE packet decode；欄位可因 CPU/kernel 缺失而 Missing。</td></tr>
    <tr><td>Missing</td><td>capability unavailable</td><td>硬體、kernel 或 event-open 不支援，不能解讀成 0。</td></tr>
    <tr><td>Unresolved</td><td>sample captured but no source attribution</td><td>sample 有 IP，但 build-id、DWARF 或 source root 解析失敗。</td></tr>
    <tr><td>0</td><td>capability exists and attribution succeeded, no samples</td><td>資料存在且能歸因，只是這一行沒有該 metric sample。</td></tr>
  </table>
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
    const RAW_PMU_COLUMNS = {raw_pmu_columns_json};
    const DERIVED_PMU_COLUMNS = ["cpi", "l1d_cache_hit_rate", "l2d_cache_hit_rate", "l3d_cache_hit_rate", "branch_miss_rate", "mpki", "mips", "mcps"];
    const SPE_COLUMNS = ["spe_sample_count", "spe_latency_cycles_avg", "spe_cache_hit_rate", "spe_branch_miss_rate", "spe_decode_errors"];
    const SOURCE_COLUMNS = [
      {{ key: "file", label: "File", cls: "col-file truncate", value: row => row.file }},
      {{ key: "line", label: "Line", cls: "col-line", value: row => row.line }},
      {{ key: "function", label: "Function", cls: "col-function truncate", value: row => row.function }},
      {{ key: "module", label: "Module", cls: "col-module truncate", value: row => row.module }},
      {{ key: "cpu", label: "CPU", cls: "col-cpu", value: row => row.cpu }},
      {{ key: "thread", label: "Thread", cls: "col-thread truncate", value: row => row.thread }},
      {{ key: "sample_count", label: "Samples", cls: "col-metric", value: row => row.sample_count, format: formatMetric }},
      {{ key: "self_weight", label: "Self", cls: "col-metric", value: row => row.self_weight, format: formatMetric }},
      {{ key: "accumulated_weight", label: "Acc", cls: "col-metric", value: row => row.accumulated_weight, format: formatMetric }},
      {{ key: "p_pct", label: "p %", cls: "col-metric", value: row => row.p_pct, format: formatPercent }},
      {{ key: "acc_p_pct", label: "acc %", cls: "col-metric", value: row => row.acc_p_pct, format: formatPercent }},
      {{ key: "file_p_pct", label: "file p %", cls: "col-wide-metric", value: row => row.file_p_pct, format: formatPercent }},
      {{ key: "file_acc_p_pct", label: "file acc %", cls: "col-wide-metric", value: row => row.file_acc_p_pct, format: formatPercent }},
      ...RAW_PMU_COLUMNS.map(key => ({{ key, label: key, cls: "col-wide-metric", value: row => metricValue(row, key) }})),
      ...DERIVED_PMU_COLUMNS.map(key => ({{ key, label: key, cls: "col-wide-metric", value: row => metricValue(row, key) }})),
      ...SPE_COLUMNS.map(key => ({{ key, label: key, cls: "col-wide-metric", value: row => metricValue(row, key) }})),
      {{ key: "status", label: "Status", cls: "col-status truncate", value: row => row.status }},
      {{ key: "code", label: "Code", cls: "col-code truncate", value: row => row.code, code: true }},
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
    function metricValue(row, key) {{
      return row.pmu_values?.[key] ?? row.spe_values?.[key] ?? "Missing";
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
    }}
    function renderSourceColumnPicker() {{
      document.getElementById("sourceColumnPicker").innerHTML = SOURCE_COLUMNS.map(column => `<label><input type="checkbox" onchange="toggleSourceColumn('${{column.key}}', this.checked)" ${{visibleSourceColumns.has(column.key) ? "checked" : ""}}> ${{escapeText(column.label)}}</label>`).join("");
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
        default_source_columns_json = default_source_columns_json,
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
            .join("\n")
    );
    fs::write(output, html).with_context(|| format!("Failed to write '{}'", output.display()))
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

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

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
        assert!(html.contains("SourceLine Report"));
        assert!(html.contains("fixture-minimal-001"));
        assert!(html.contains("PMU buffer pages"));
        assert!(
            html.contains("<details class=\"report-section\" open>\n  <summary>Summary</summary>")
        );
        assert!(html.contains("Quality"));
        assert!(html.contains("<details class=\"report-section\">\n    <summary>Quality</summary>"));
        assert!(html.contains("SPE capability"));
        assert!(html.contains("id=\"qualityRows\""));
        assert!(html.contains("Source Lines"));
        assert!(html.contains(
            "<details class=\"report-section\" open>\n  <summary>Source Lines</summary>"
        ));
        assert!(html.contains("Columns"));
        assert!(html.contains("MCPS"));
        assert!(html.contains("col-file"));
        assert!(html.contains("col-function"));
        assert!(html.contains("table-scroll"));
        assert!(html.contains("col-code"));
        assert!(html.contains("col-thread truncate"));
        assert!(html.contains("sourceWidthToggle"));
        assert!(html.contains("toggleSourceWidth"));
        assert!(html.contains("#sourceTable.expanded"));
        assert!(html.contains("id=\"sourceColumnPicker\""));
        assert!(html.contains("id=\"minSamples\""));
        assert!(html.contains("id=\"minSamples\" type=\"number\" min=\"0\" value=\"0\" oninput=\"resetSourcePaging()\""));
        assert!(html.contains("min_samples"));
        assert!(html.contains("RAW_PMU_COLUMNS"));
        assert!(html.contains("DERIVED_PMU_COLUMNS"));
        assert!(html.contains("SPE_COLUMNS"));
        assert!(html.contains("visibleSourceColumns"));
        assert!(html.contains("toggleSourceColumn"));
        assert!(html.contains("renderSourceHeaders"));
        assert!(html.contains("renderSourceBody"));
        assert!(html.contains("sample_count"));
        assert!(html.contains("Samples"));
        assert!(!default_columns.contains("\"p_pct\""));
        assert!(!default_columns.contains("\"acc_p_pct\""));
        assert!(!default_columns.contains("\"file_p_pct\""));
        assert!(!default_columns.contains("\"file_acc_p_pct\""));
        assert!(!default_columns.contains("\"status\""));
        assert!(html.contains("cpu_cycles"));
        assert!(html.contains("stall_backend"));
        assert!(html.contains("spe_sample_count"));
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
        assert!(html.contains("Column Help"));
        assert!(
            html.contains("<details class=\"report-section\">\n  <summary>Column Help</summary>")
        );
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
}

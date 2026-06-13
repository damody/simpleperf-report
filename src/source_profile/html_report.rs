#![allow(dead_code)]

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

use super::bundle::SourceProfileBundle;
use super::report_model::{build_report_model, metric_value_text};
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
    let model = build_report_model(bundle)?;
    let source_rows_json = serde_json::to_string(
        &model
            .rows
            .iter()
            .map(|row| json!({
                "file": row.file,
                "line": row.line,
                "function": row.function,
                "module": row.module,
                "cpu": row.cpu,
                "thread": row.thread,
                "status": row.status,
                "code": row.code,
                "detail": row.detail,
                "self": row.self_weight,
                "acc": row.accumulated_weight,
                "p_pct": row.p_pct,
                "acc_p_pct": row.acc_p_pct,
                "cpi": metric_value_text(row.pmu_values.get("cpi")),
                "l1d_cache_hit_rate": metric_value_text(row.pmu_values.get("l1d_cache_hit_rate")),
                "mips": metric_value_text(row.pmu_values.get("mips")),
                "mcps": metric_value_text(row.pmu_values.get("mcps")),
            }))
            .collect::<Vec<_>>(),
    )?;
    let file_rows_json = serde_json::to_string(
        &model
            .files
            .iter()
            .map(|row| {
                json!({
                    "file": row.file,
                    "self": row.self_weight,
                    "acc": row.accumulated_weight,
                    "samples": row.sample_count,
                    "hotLines": row.hot_lines,
                    "missing": row.missing,
                    "unresolved": row.unresolved,
                    "hotLine": row.hot_line,
                })
            })
            .collect::<Vec<_>>(),
    )?;
    let function_rows_json = serde_json::to_string(
        &model
            .functions
            .iter()
            .map(|row| {
                json!({
                    "function": row.function,
                    "file": row.file,
                    "lineStart": row.line_start,
                    "lineEnd": row.line_end,
                    "module": row.module,
                    "self": row.self_weight,
                    "acc": row.accumulated_weight,
                    "samples": row.sample_count,
                    "hotLines": row.hot_lines,
                })
            })
            .collect::<Vec<_>>(),
    )?;
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
    .source-line {{ display: grid; grid-template-columns: 72px 120px minmax(0, 1fr); gap: 8px; font-family: Consolas, monospace; padding: 2px 4px; }}
    .source-line.NonZero {{ background: #fff8c5; }}
    .source-line.Missing {{ background: #ffebe9; }}
    .source-line.Unresolved {{ background: #fff1e5; }}
    .toolbar {{ display: flex; gap: 8px; align-items: center; margin: 8px 0; flex-wrap: wrap; }}
    .toolbar input {{ padding: 4px 6px; }}
    code {{ font-family: Consolas, monospace; }}
  </style>
</head>
<body>
  <h1>SourceLine Report</h1>
  <h2>Summary</h2>
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
  <h2>Quality</h2>
  <table>
    <tr><th>Check</th><th>Status</th><th>Detail</th></tr>
    {quality_rows}
  </table>
  <h2>Source Lines</h2>
  <div class="toolbar">
    <input id="sourceFilter" placeholder="filter file/function/code" oninput="renderSourceRows()">
    <label><input type="checkbox" id="nonzeroOnly" onchange="renderSourceRows()"> nonzero only</label>
    <label><input type="checkbox" id="missingOnly" onchange="renderSourceRows()"> Missing only</label>
    <label><input type="checkbox" id="unresolvedOnly" onchange="renderSourceRows()"> Unresolved only</label>
    <input id="cpuFilter" placeholder="CPU" oninput="renderSourceRows()">
    <input id="threadFilter" placeholder="thread" oninput="renderSourceRows()">
  </div>
  <table id="sourceTable">
    <thead>
      <tr>
        <th onclick="sortSourceRows('file')">File</th>
        <th onclick="sortSourceRows('line')">Line</th>
        <th onclick="sortSourceRows('function')">Function</th>
        <th onclick="sortSourceRows('module')">Module</th>
        <th onclick="sortSourceRows('cpu')">CPU</th>
        <th onclick="sortSourceRows('thread')">Thread</th>
        <th onclick="sortSourceRows('status')">Status</th>
        <th>Code</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>
  <h2>Source Viewer</h2>
  <div id="sourceViewer"></div>
  <h2>Files</h2>
  <table id="filesTable">
    <thead><tr><th>File</th><th>Self</th><th>Accumulated</th><th>Samples</th><th>Hot Lines</th><th>Missing</th><th>Unresolved</th></tr></thead>
    <tbody></tbody>
  </table>
  <h2>Functions</h2>
  <table id="functionsTable">
    <thead><tr><th>Function</th><th>File</th><th>Lines</th><th>Module</th><th>Self</th><th>Accumulated</th><th>Samples</th><th>Hot Lines</th></tr></thead>
    <tbody></tbody>
  </table>
  <h2>Column Help</h2>
  <table>
    <tr><th>Column / Metric</th><th>Formula</th><th>Physical Meaning / Limitation</th></tr>
    <tr><td><code>p %</code></td><td>line self weight / global self weight * 100</td><td>這一行本身 sample 權重佔整個 session 的比例。</td></tr>
    <tr><td><code>acc_p %</code></td><td>line accumulated weight / global accumulated weight * 100</td><td>包含 callchain 歸因後，這一行在呼叫路徑上的累積比例。</td></tr>
    <tr><td><code>file p %</code></td><td>line self weight / same-file self weight * 100</td><td>這一行在同檔案內的 self 熱度比例。</td></tr>
    <tr><td><code>file acc_p %</code></td><td>line accumulated weight / same-file accumulated weight * 100</td><td>這一行在同檔案內的 callchain 累積比例。</td></tr>
    <tr><td>cycles</td><td>PMU cpu_cycles sample weight</td><td>CPU cycle 活動量；line-level 是 sampling attribution，不是每次 cycle 完整記錄。</td></tr>
    <tr><td>instructions</td><td>PMU inst_retired sample weight</td><td>退休指令量；可搭配 cycles 算 CPI。</td></tr>
    <tr><td>CPI</td><td>cpu_cycles / inst_retired</td><td>平均每退休一條指令消耗的 cycles；分母缺失或為 0 時不輸出 0。</td></tr>
    <tr><td>cache hit rate</td><td>(access - refill) / access</td><td>Cache hit rate 的統計近似；不是每一次 cache access 的完整 trace。</td></tr>
    <tr><td>branch miss rate</td><td>branch_mispredict / branch_retired</td><td>分支預測錯誤比例的 sampling 近似。</td></tr>
    <tr><td>SPE latency / data source</td><td>SPE normalized fields</td><td>來自 Arm SPE packet decode；欄位可因 CPU/kernel 缺失而 Missing。</td></tr>
    <tr><td>Missing</td><td>capability unavailable</td><td>硬體、kernel 或 event-open 不支援，不能解讀成 0。</td></tr>
    <tr><td>Unresolved</td><td>sample captured but no source attribution</td><td>sample 有 IP，但 build-id、DWARF 或 source root 解析失敗。</td></tr>
    <tr><td>0</td><td>capability exists and attribution succeeded, no samples</td><td>資料存在且能歸因，只是這一行沒有該 metric sample。</td></tr>
  </table>
  <h2>Artifacts</h2>
  <table>
    <tr><th>Role</th><th>Path</th><th>Required</th><th>Encoding</th></tr>
    {artifact_rows}
  </table>
  <script>
    const sourceRows = {source_rows_json};
    const fileRows = {file_rows_json};
    const functionRows = {function_rows_json};
    let sourceSortKey = "file";
    let sourceSortAsc = true;
    function sortSourceRows(key) {{
      if (sourceSortKey === key) sourceSortAsc = !sourceSortAsc;
      sourceSortKey = key;
      renderSourceRows();
    }}
    function rowMatchesFilters(row) {{
      const text = document.getElementById("sourceFilter").value.toLowerCase();
      const cpu = document.getElementById("cpuFilter").value;
      const thread = document.getElementById("threadFilter").value;
      const nonzeroOnly = document.getElementById("nonzeroOnly").checked;
      const missingOnly = document.getElementById("missingOnly").checked;
      const unresolvedOnly = document.getElementById("unresolvedOnly").checked;
      const haystack = `${{row.file}} ${{row.function}} ${{row.code}}`.toLowerCase();
      if (text && !haystack.includes(text)) return false;
      if (cpu && !String(row.cpu).includes(cpu)) return false;
      if (thread && !String(row.thread).includes(thread)) return false;
      if (nonzeroOnly && !row.status.includes("NonZero")) return false;
      if (missingOnly && !row.status.includes("Missing")) return false;
      if (unresolvedOnly && !row.status.includes("Unresolved")) return false;
      return true;
    }}
    function renderSourceRows() {{
      const tbody = document.querySelector("#sourceTable tbody");
      const rows = sourceRows.filter(rowMatchesFilters).sort((a, b) => {{
        const av = a[sourceSortKey] ?? "";
        const bv = b[sourceSortKey] ?? "";
        return sourceSortAsc ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
      }});
      tbody.innerHTML = rows.map(row => `<tr><td>${{row.file}}</td><td>${{row.line}}</td><td>${{row.function}}</td><td>${{row.module}}</td><td>${{row.cpu}}</td><td>${{row.thread}}</td><td>${{row.status}}</td><td><code>${{row.code}}</code></td></tr>`).join("");
      renderSourceViewer(rows);
    }}
    function renderSourceViewer(rows) {{
      const viewer = document.getElementById("sourceViewer");
      viewer.innerHTML = rows.map(row => `<div class="source-line ${{row.status}}" title="${{row.detail ?? row.status}}" onclick="alert(row.detail ?? row.status)"><span>${{row.line}}</span><span>${{row.status}}</span><code>${{row.code}}</code></div>`).join("");
    }}
    function jumpToFileLine(file, line) {{
      document.getElementById("sourceFilter").value = file;
      renderSourceRows();
      const viewer = document.getElementById("sourceViewer");
      viewer.scrollIntoView({{ behavior: "smooth", block: "start" }});
    }}
    function renderFilesAndFunctions() {{
      document.querySelector("#filesTable tbody").innerHTML = fileRows.map(row => `<tr onclick="jumpToFileLine('${{row.file}}', ${{row.hotLine ?? 0}})"><td>${{row.file}}</td><td>${{row.self}}</td><td>${{row.acc}}</td><td>${{row.samples}}</td><td>${{row.hotLines}}</td><td>${{row.missing}}</td><td>${{row.unresolved}}</td></tr>`).join("");
      document.querySelector("#functionsTable tbody").innerHTML = functionRows.map(row => `<tr onclick="jumpToFileLine('${{row.file}}', ${{row.lineStart ?? 0}})"><td>${{row.function}}</td><td>${{row.file}}</td><td>${{row.lineStart}}-${{row.lineEnd}}</td><td>${{row.module}}</td><td>${{row.self}}</td><td>${{row.acc}}</td><td>${{row.samples}}</td><td>${{row.hotLines}}</td></tr>`).join("");
    }}
    renderSourceRows();
    renderFilesAndFunctions();
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
        quality_rows = quality_rows(bundle),
        source_rows_json = source_rows_json,
        file_rows_json = file_rows_json,
        function_rows_json = function_rows_json,
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
        assert!(html.contains("SourceLine Report"));
        assert!(html.contains("fixture-minimal-001"));
        assert!(html.contains("PMU buffer pages"));
        assert!(html.contains("Quality"));
        assert!(html.contains("SPE capability"));
        assert!(html.contains("Source Lines"));
        assert!(html.contains("Source Viewer"));
        assert!(html.contains("Files"));
        assert!(html.contains("Functions"));
        assert!(html.contains("Column Help"));
        assert!(html.contains("Missing"));
        assert!(html.contains("renderSourceRows"));
    }
}

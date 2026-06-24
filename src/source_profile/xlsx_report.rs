#![allow(dead_code)]

use std::path::Path;

use anyhow::{Context, Result};
use rust_xlsxwriter::{Color, Format, FormatAlign, Workbook, Worksheet};

use super::bundle::SourceProfileBundle;
use super::report_model::{
    build_report_model, instruction_class_column_keys, load_instruction_column_keys,
    metric_value_number, metric_value_text, pmu_column_keys, spe_column_keys, ReportModel,
    INSTRUCTION_CLASS_NAMES, LOAD_INSTRUCTION_KIND_NAMES,
};
use super::source_loader::{load_source_file, SourceLine};
use super::summary::SourceReportSummary;

pub trait XlsxReportWriter {
    fn write_xlsx(&self, summary: &SourceReportSummary, output: &Path) -> Result<()>;
}

pub fn write_summary_workbook(bundle: &SourceProfileBundle, output: &Path) -> Result<()> {
    let model = build_report_model(bundle)?;
    write_summary_workbook_from_model(bundle, &model, output)
}

pub fn write_summary_workbook_from_model(
    bundle: &SourceProfileBundle,
    model: &ReportModel,
    output: &Path,
) -> Result<()> {
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create '{}'", parent.display()))?;
    }
    let mut workbook = Workbook::new();
    let styles = WorkbookStyles::new();
    let worksheet = workbook.add_worksheet();
    worksheet.set_name("Summary")?;
    worksheet.write_string_with_format(0, 0, "Field", &styles.header)?;
    worksheet.write_string_with_format(0, 1, "Value", &styles.header)?;
    format_basic_sheet(worksheet, 1, 1, &[24.0, 72.0])?;

    let manifest = &bundle.manifest;
    let rows = [
        ("Session", manifest.session_id.clone()),
        (
            "Target package",
            manifest.target.package.clone().unwrap_or_default(),
        ),
        (
            "PID",
            manifest
                .target
                .pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
        ),
        (
            "Duration ms",
            manifest
                .recording
                .duration_ms
                .map(|duration| duration.to_string())
                .unwrap_or_else(|| "partial".to_string()),
        ),
        ("ABI", manifest.device.abi.clone()),
        (
            "Selected CPUs",
            manifest
                .cpu
                .selected_cpus
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        (
            "Selected clusters",
            manifest.cpu.selected_clusters.join(", "),
        ),
        (
            "PMU lane",
            format!(
                "enabled={}, available={}",
                manifest.lanes.pmu.enabled, manifest.lanes.pmu.available
            ),
        ),
        (
            "SPE lane",
            format!(
                "enabled={}, available={}",
                manifest.lanes.spe.enabled, manifest.lanes.spe.available
            ),
        ),
        (
            "PMU buffer pages",
            manifest.capture_options.pmu_buffer_pages.to_string(),
        ),
        (
            "SPE AUX buffer bytes",
            manifest
                .capture_options
                .spe_aux_buffer_bytes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
        ),
        (
            "Overall quality",
            if bundle.loss.totals.pmu_lost_records == 0
                && bundle.loss.totals.ring_buffer_overruns == 0
                && bundle.loss.totals.spe_decode_errors == 0
            {
                "OK".to_string()
            } else {
                "Warning".to_string()
            },
        ),
        (
            "HTML report path",
            manifest.artifacts.report_paths.html.clone(),
        ),
        (
            "XLSX report path",
            manifest.artifacts.report_paths.xlsx.clone(),
        ),
    ];

    for (index, (field, value)) in rows.iter().enumerate() {
        let row = (index + 1) as u32;
        worksheet.write_string(row, 0, *field)?;
        worksheet.write_string(row, 1, value)?;
    }

    let capability = workbook.add_worksheet();
    capability.set_name("CPU Capability")?;
    format_basic_sheet(
        capability,
        1,
        17,
        &[
            8.0, 12.0, 8.0, 8.0, 12.0, 8.0, 8.0, 10.0, 14.0, 20.0, 24.0, 18.0, 18.0, 10.0, 8.0,
            36.0, 42.0, 42.0,
        ],
    )?;
    for (col, header) in [
        "CPU",
        "Cluster",
        "SPE",
        "Cycles",
        "Instructions",
        "Cache",
        "Branch",
        "Callchain",
        "Source Fields",
        "Event Key",
        "Raw Event",
        "Type",
        "Config",
        "Supported",
        "Errno",
        "Failure Reason",
        "Sysfs Path",
        "SPE Device",
    ]
    .iter()
    .enumerate()
    {
        capability.write_string_with_format(0, col as u16, *header, &styles.header)?;
    }
    let mut row = 1_u32;
    for cpu in &bundle.capability.cpus {
        if cpu.details.is_empty() {
            write_capability_row(capability, row, cpu, None)?;
            row += 1;
        } else {
            for detail in &cpu.details {
                write_capability_row(capability, row, cpu, Some(detail))?;
                row += 1;
            }
        }
    }

    let all_lines = workbook.add_worksheet();
    all_lines.set_name("All Lines")?;
    let pmu_columns = pmu_column_keys(bundle);
    write_line_sheet(all_lines, &model.rows, &pmu_columns, false, &styles)?;

    let sampled_lines = workbook.add_worksheet();
    sampled_lines.set_name("Sampled Lines")?;
    write_line_sheet(sampled_lines, &model.rows, &pmu_columns, true, &styles)?;

    let files = workbook.add_worksheet();
    files.set_name("Files")?;
    write_files_sheet(files, &model.files, &styles)?;

    let functions = workbook.add_worksheet();
    functions.set_name("Functions")?;
    write_functions_sheet(functions, &model.functions, &styles)?;

    let frames = workbook.add_worksheet();
    frames.set_name("Callchain Frames")?;
    write_frames_sheet(frames, &model.frames, &styles)?;

    let callchains = workbook.add_worksheet();
    callchains.set_name("Callchains")?;
    write_callchains_sheet(callchains, &model.callchains, &styles)?;

    let instruction_class = workbook.add_worksheet();
    instruction_class.set_name("InstructionClass")?;
    write_instruction_class_sheet(instruction_class, model, &styles)?;

    let load_instruction = workbook.add_worksheet();
    load_instruction.set_name("LoadInstruction")?;
    write_load_instruction_sheet(load_instruction, model, &styles)?;

    let column_help = workbook.add_worksheet();
    column_help.set_name("Column Help")?;
    write_column_help_sheet(column_help, &styles)?;

    workbook
        .save(output)
        .with_context(|| format!("Failed to write '{}'", output.display()))
}

fn load_manifest_source_lines(bundle: &SourceProfileBundle) -> Result<Vec<SourceLine>> {
    let mut lines = Vec::new();
    for source_file in discover_manifest_source_files(bundle)? {
        lines.extend(load_source_file(&source_file)?);
    }
    Ok(lines)
}

struct WorkbookStyles {
    header: Format,
    zero: Format,
    missing: Format,
}

impl WorkbookStyles {
    fn new() -> Self {
        Self {
            header: Format::new()
                .set_bold()
                .set_background_color(Color::RGB(0xE6EEF8))
                .set_align(FormatAlign::Center),
            zero: Format::new().set_font_color(Color::RGB(0x666666)),
            missing: Format::new().set_background_color(Color::RGB(0xFFC7CE)),
        }
    }
}

fn format_basic_sheet(
    worksheet: &mut Worksheet,
    freeze_row: u32,
    last_col: u16,
    widths: &[f64],
) -> Result<()> {
    worksheet.set_freeze_panes(freeze_row, 0)?;
    worksheet.autofilter(0, 0, 0, last_col)?;
    for (col, width) in widths.iter().enumerate() {
        worksheet.set_column_width(col as u16, *width)?;
    }
    Ok(())
}

fn write_line_sheet(
    worksheet: &mut Worksheet,
    lines: &[super::report_model::ReportLineRow],
    pmu_columns: &[String],
    sampled_only: bool,
    styles: &WorkbookStyles,
) -> Result<()> {
    let mut headers = vec![
        "File",
        "Line",
        "Function",
        "Module",
        "CPU",
        "Thread",
        "Code",
        "Status",
        "p %",
        "acc_p %",
        "file p %",
        "file acc_p %",
        "Self Weight",
        "Accumulated Weight",
    ];
    headers.extend(pmu_columns.iter().map(String::as_str));
    let spe_columns = spe_column_keys();
    headers.extend(spe_columns.iter().map(String::as_str));
    let instruction_columns = instruction_class_column_keys();
    headers.extend(instruction_columns.iter().map(String::as_str));
    let load_instruction_columns = load_instruction_column_keys();
    headers.extend(load_instruction_columns.iter().map(String::as_str));
    let widths = vec![
        48.0, 8.0, 28.0, 20.0, 10.0, 14.0, 96.0, 18.0, 10.0, 10.0, 10.0, 12.0, 14.0, 18.0,
    ];
    format_basic_sheet(worksheet, 1, (headers.len() - 1) as u16, &widths)?;
    for (col, header) in headers.iter().enumerate() {
        worksheet.write_string_with_format(0, col as u16, *header, &styles.header)?;
    }
    let mut row = 1_u32;
    for line in lines {
        if sampled_only && line.status == "0" {
            continue;
        }
        worksheet.write_string(row, 0, &line.file)?;
        worksheet.write_number(row, 1, f64::from(line.line))?;
        worksheet.write_string(row, 2, &line.function)?;
        worksheet.write_string(row, 3, &line.module)?;
        worksheet.write_string(row, 4, &line.cpu)?;
        worksheet.write_string(row, 5, &line.thread)?;
        worksheet.write_string(row, 6, &line.code)?;
        worksheet.write_string(row, 7, &line.status)?;
        worksheet.write_number(row, 8, line.p_pct)?;
        worksheet.write_number(row, 9, line.acc_p_pct)?;
        worksheet.write_number(row, 10, line.file_p_pct)?;
        worksheet.write_number(row, 11, line.file_acc_p_pct)?;
        worksheet.write_number(row, 12, line.self_weight)?;
        worksheet.write_number(row, 13, line.accumulated_weight)?;
        let mut col = 14_u16;
        for key in pmu_columns {
            write_metric_cell(worksheet, row, col, line.pmu_values.get(key), styles)?;
            col += 1;
        }
        for key in &spe_columns {
            write_metric_cell(worksheet, row, col, line.spe_values.get(key), styles)?;
            col += 1;
        }
        for key in &instruction_columns {
            write_metric_cell(
                worksheet,
                row,
                col,
                line.instruction_values.get(key),
                styles,
            )?;
            col += 1;
        }
        for key in &load_instruction_columns {
            write_metric_cell(
                worksheet,
                row,
                col,
                line.load_instruction_values.get(key),
                styles,
            )?;
            col += 1;
        }
        row += 1;
    }
    Ok(())
}

fn write_instruction_class_sheet(
    worksheet: &mut Worksheet,
    model: &ReportModel,
    styles: &WorkbookStyles,
) -> Result<()> {
    let headers = [
        "CPU",
        "Instruction class",
        "sample%",
        "est_time%",
        "min_latency_cycles",
        "max_latency_cycles",
        "avg_latency_cycles",
        "std_latency_cycles",
        "p95_latency_cycles",
        "p99_latency_cycles",
        ">avg*3%",
    ];
    format_basic_sheet(
        worksheet,
        1,
        (headers.len() - 1) as u16,
        &[
            8.0, 28.0, 12.0, 12.0, 20.0, 20.0, 20.0, 20.0, 20.0, 20.0, 12.0,
        ],
    )?;
    for (col, header) in headers.iter().enumerate() {
        worksheet.write_string_with_format(0, col as u16, *header, &styles.header)?;
    }

    let metrics = [
        "sample_pct",
        "est_time_pct",
        "min_latency_cycles",
        "max_latency_cycles",
        "avg_latency_cycles",
        "std_latency_cycles",
        "p95_latency_cycles",
        "p99_latency_cycles",
        "over_avg_x3_pct",
    ];
    let mut row = 1_u32;
    for (cpu, values_by_key) in &model.instruction_cpu_class_values {
        for class in INSTRUCTION_CLASS_NAMES {
            let has_value = metrics.iter().any(|metric| {
                let key = format!("instruction_class.{class}.{metric}");
                metric_value_number(values_by_key.get(&key)).is_some_and(|value| value != 0.0)
            });
            if !has_value {
                continue;
            }
            worksheet.write_number(row, 0, f64::from(*cpu))?;
            worksheet.write_string(row, 1, *class)?;
            for (offset, metric) in metrics.iter().enumerate() {
                let key = format!("instruction_class.{class}.{metric}");
                write_metric_cell(
                    worksheet,
                    row,
                    (offset + 2) as u16,
                    values_by_key.get(&key),
                    styles,
                )?;
            }
            row += 1;
        }
    }
    Ok(())
}

fn write_load_instruction_sheet(
    worksheet: &mut Worksheet,
    model: &ReportModel,
    styles: &WorkbookStyles,
) -> Result<()> {
    let headers = [
        "CPU",
        "Load instruction",
        "sample%",
        "est_time%",
        "min_latency_cycles",
        "max_latency_cycles",
        "avg_latency_cycles",
        "std_latency_cycles",
        "p95_latency_cycles",
        "p99_latency_cycles",
        ">avg*3%",
    ];
    format_basic_sheet(
        worksheet,
        1,
        (headers.len() - 1) as u16,
        &[
            8.0, 28.0, 12.0, 12.0, 20.0, 20.0, 20.0, 20.0, 20.0, 20.0, 12.0,
        ],
    )?;
    for (col, header) in headers.iter().enumerate() {
        worksheet.write_string_with_format(0, col as u16, *header, &styles.header)?;
    }

    let metrics = [
        "sample_pct",
        "est_time_pct",
        "min_latency_cycles",
        "max_latency_cycles",
        "avg_latency_cycles",
        "std_latency_cycles",
        "p95_latency_cycles",
        "p99_latency_cycles",
        "over_avg_x3_pct",
    ];
    let mut row = 1_u32;
    for (cpu, values_by_key) in &model.load_cpu_kind_values {
        for kind in LOAD_INSTRUCTION_KIND_NAMES {
            let has_value = metrics.iter().any(|metric| {
                let key = format!("load_instruction.{kind}.{metric}");
                metric_value_number(values_by_key.get(&key)).is_some_and(|value| value != 0.0)
            });
            if !has_value {
                continue;
            }
            worksheet.write_number(row, 0, f64::from(*cpu))?;
            worksheet.write_string(row, 1, *kind)?;
            for (offset, metric) in metrics.iter().enumerate() {
                let key = format!("load_instruction.{kind}.{metric}");
                write_metric_cell(
                    worksheet,
                    row,
                    (offset + 2) as u16,
                    values_by_key.get(&key),
                    styles,
                )?;
            }
            row += 1;
        }
    }
    Ok(())
}

fn write_metric_cell(
    worksheet: &mut Worksheet,
    row: u32,
    col: u16,
    value: Option<&super::metrics::MetricValue>,
    styles: &WorkbookStyles,
) -> Result<()> {
    if let Some(number) = metric_value_number(value) {
        if number == 0.0 {
            worksheet.write_number_with_format(row, col, number, &styles.zero)?;
        } else {
            worksheet.write_number(row, col, number)?;
        }
    } else {
        worksheet.write_string_with_format(row, col, &metric_value_text(value), &styles.missing)?;
    }
    Ok(())
}

fn write_files_sheet(
    worksheet: &mut Worksheet,
    lines: &[super::report_model::ReportFileRow],
    styles: &WorkbookStyles,
) -> Result<()> {
    format_basic_sheet(worksheet, 1, 6, &[48.0, 14.0, 18.0, 14.0, 14.0, 16.0, 18.0])?;
    for (col, header) in [
        "File",
        "Self Weight",
        "Accumulated Weight",
        "Sample Count",
        "Hot Line Count",
        "Unresolved Count",
        "Missing Metric Count",
    ]
    .iter()
    .enumerate()
    {
        worksheet.write_string_with_format(0, col as u16, *header, &styles.header)?;
    }
    for (index, file) in lines.iter().enumerate() {
        let row = (index + 1) as u32;
        worksheet.write_string(row, 0, &file.file)?;
        worksheet.write_number(row, 1, file.self_weight)?;
        worksheet.write_number(row, 2, file.accumulated_weight)?;
        worksheet.write_number(row, 3, file.sample_count as f64)?;
        worksheet.write_number(row, 4, file.hot_lines as f64)?;
        worksheet.write_number(row, 5, file.unresolved as f64)?;
        worksheet.write_number(row, 6, file.missing as f64)?;
    }
    Ok(())
}

fn write_functions_sheet(
    worksheet: &mut Worksheet,
    lines: &[super::report_model::ReportFunctionRow],
    styles: &WorkbookStyles,
) -> Result<()> {
    format_basic_sheet(
        worksheet,
        1,
        8,
        &[28.0, 48.0, 10.0, 10.0, 18.0, 14.0, 18.0, 14.0, 18.0],
    )?;
    for (col, header) in [
        "Function",
        "File",
        "Line Start",
        "Line End",
        "Module",
        "Self Weight",
        "Accumulated Weight",
        "Sample Count",
        "Hot Lines",
    ]
    .iter()
    .enumerate()
    {
        worksheet.write_string_with_format(0, col as u16, *header, &styles.header)?;
    }
    let mut row = 1_u32;
    for line in lines {
        worksheet.write_string(row, 0, &line.function)?;
        worksheet.write_string(row, 1, &line.file)?;
        worksheet.write_number(row, 2, f64::from(line.line_start))?;
        worksheet.write_number(row, 3, f64::from(line.line_end))?;
        worksheet.write_string(row, 4, &line.module)?;
        worksheet.write_number(row, 5, line.self_weight)?;
        worksheet.write_number(row, 6, line.accumulated_weight)?;
        worksheet.write_number(row, 7, line.sample_count as f64)?;
        worksheet.write_string(row, 8, &line.hot_lines)?;
        row += 1;
    }
    Ok(())
}

fn write_frames_sheet(
    worksheet: &mut Worksheet,
    lines: &[super::report_model::ReportFrameRow],
    styles: &WorkbookStyles,
) -> Result<()> {
    format_basic_sheet(
        worksheet,
        1,
        14,
        &[
            12.0, 24.0, 56.0, 18.0, 18.0, 12.0, 12.0, 16.0, 14.0, 14.0, 18.0, 10.0, 10.0, 48.0,
            18.0,
        ],
    )?;
    for (col, header) in [
        "Role",
        "Module",
        "Function",
        "IP",
        "Relative Address",
        "Mapping ID",
        "CPU",
        "Thread",
        "Sample Count",
        "Self Weight",
        "Accumulated Weight",
        "p %",
        "acc_p %",
        "Event Weights",
        "Status",
    ]
    .iter()
    .enumerate()
    {
        worksheet.write_string_with_format(0, col as u16, *header, &styles.header)?;
    }
    for (index, line) in lines.iter().take(200_000).enumerate() {
        let row = (index + 1) as u32;
        worksheet.write_string(row, 0, &line.role)?;
        worksheet.write_string(row, 1, &line.module)?;
        worksheet.write_string(row, 2, &line.function)?;
        worksheet.write_string(row, 3, format!("0x{:x}", line.ip))?;
        worksheet.write_string(row, 4, format!("0x{:x}", line.relative_address))?;
        worksheet.write_number(row, 5, line.mapping_id as f64)?;
        worksheet.write_string(row, 6, &line.cpu)?;
        worksheet.write_string(row, 7, &line.thread)?;
        worksheet.write_number(row, 8, line.sample_count as f64)?;
        worksheet.write_number(row, 9, line.self_weight)?;
        worksheet.write_number(row, 10, line.accumulated_weight)?;
        worksheet.write_number(row, 11, line.p_pct)?;
        worksheet.write_number(row, 12, line.acc_p_pct)?;
        worksheet.write_string(row, 13, &line.event_weights)?;
        worksheet.write_string(row, 14, &line.status)?;
    }
    Ok(())
}

fn write_callchains_sheet(
    worksheet: &mut Worksheet,
    lines: &[super::report_model::ReportCallchainRow],
    styles: &WorkbookStyles,
) -> Result<()> {
    format_basic_sheet(
        worksheet,
        1,
        8,
        &[120.0, 56.0, 56.0, 12.0, 16.0, 14.0, 14.0, 10.0, 48.0],
    )?;
    for (col, header) in [
        "Stack",
        "Leaf",
        "Root",
        "CPU",
        "Thread",
        "Sample Count",
        "Weight",
        "p %",
        "Event Weights",
    ]
    .iter()
    .enumerate()
    {
        worksheet.write_string_with_format(0, col as u16, *header, &styles.header)?;
    }
    for (index, line) in lines.iter().take(200_000).enumerate() {
        let row = (index + 1) as u32;
        worksheet.write_string(row, 0, &line.stack)?;
        worksheet.write_string(row, 1, &line.leaf)?;
        worksheet.write_string(row, 2, &line.root)?;
        worksheet.write_string(row, 3, &line.cpu)?;
        worksheet.write_string(row, 4, &line.thread)?;
        worksheet.write_number(row, 5, line.sample_count as f64)?;
        worksheet.write_number(row, 6, line.weight)?;
        worksheet.write_number(row, 7, line.p_pct)?;
        worksheet.write_string(row, 8, &line.event_weights)?;
    }
    Ok(())
}

fn write_column_help_sheet(worksheet: &mut Worksheet, styles: &WorkbookStyles) -> Result<()> {
    format_basic_sheet(worksheet, 1, 3, &[22.0, 42.0, 72.0, 72.0])?;
    for (col, header) in [
        "Column / Metric",
        "Formula",
        "Physical Meaning",
        "Missing / 0 Semantics",
    ]
    .iter()
    .enumerate()
    {
        worksheet.write_string_with_format(0, col as u16, *header, &styles.header)?;
    }
    let rows = [
        (
            "p %",
            "line self weight / global self weight * 100",
            "這一行本身的 sample 權重佔整個 session 的比例。",
            "分母為 0 時為 Undefined，不應寫成 0。",
        ),
        (
            "acc_p %",
            "line accumulated weight / global accumulated weight * 100",
            "包含 callchain 歸因後，該行在呼叫路徑上的累積比例。",
            "callchain 缺失時可能 Missing。",
        ),
        (
            "file p %",
            "line self weight / same-file self weight * 100",
            "這一行在同檔案內的 self 熱度比例。",
            "同檔案分母為 0 時為 Undefined。",
        ),
        (
            "file acc_p %",
            "line accumulated weight / same-file accumulated weight * 100",
            "這一行在同檔案內的 callchain 累積比例。",
            "callchain 缺失時可能 Missing。",
        ),
        (
            "cycles",
            "PMU cpu_cycles sample weight",
            "CPU cycle 活動量；line-level 數值是 statistical attribution，不是逐 cycle 完整紀錄。",
            "event 不支援為 Missing；支援且已歸因但無 sample 為 0。",
        ),
        (
            "instructions",
            "PMU inst_retired sample weight",
            "退休指令量；搭配 cycles 可計算 CPI。",
            "event 不支援為 Missing。",
        ),
        (
            "CPI",
            "cpu_cycles / inst_retired",
            "平均每退休一條指令消耗的 cycles；越高通常代表等待或低效率越多。",
            "instructions 缺失為 Missing，instructions=0 為 Undefined。",
        ),
        (
            "cache hit rate",
            "(access - refill) / access",
            "Cache 命中率的 sampling 近似；不是每一次 cache access 完整 trace。",
            "access/refill 缺失為 Missing，access=0 為 Undefined。",
        ),
        (
            "branch miss rate",
            "branch_mispredict / branch_retired",
            "分支預測錯誤比例的 sampling 近似。",
            "branch events 缺失為 Missing，branch_retired=0 為 Undefined。",
        ),
        (
            "SPE latency / data source",
            "SPE normalized packet fields",
            "Arm SPE 取樣到的 latency、cache outcome、branch outcome、data source。",
            "CPU/kernel 未 expose SPE 或 packet 欄位缺失為 Missing。",
        ),
        (
            "Missing",
            "capability unavailable",
            "硬體、kernel、permission 或 event-open 不支援該資料。",
            "不能解讀成 0。",
        ),
        (
            "Unresolved",
            "sample captured but no source attribution",
            "sample 有 IP，但 build-id、DWARF、source root 或 path remap 解析失敗。",
            "不能解讀成 0。",
        ),
        (
            "0",
            "capability exists and attribution succeeded, no samples",
            "資料來源存在且 source attribution 成功，只是該行沒有該 metric sample。",
            "這才是真正 numeric zero。",
        ),
    ];
    for (index, row) in rows.iter().enumerate() {
        let sheet_row = (index + 1) as u32;
        worksheet.write_string(sheet_row, 0, row.0)?;
        worksheet.write_string(sheet_row, 1, row.1)?;
        worksheet.write_string(sheet_row, 2, row.2)?;
        worksheet.write_string(sheet_row, 3, row.3)?;
    }
    Ok(())
}

fn discover_manifest_source_files(bundle: &SourceProfileBundle) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for hint in &bundle.manifest.inputs.source_root_hints {
        let path = std::path::PathBuf::from(hint);
        let root = if path.is_absolute() {
            path
        } else {
            bundle.root.join(path)
        };
        if root.is_file() && is_source_file(&root) {
            files.push(root);
        } else if root.is_dir() {
            collect_source_files(&root, &mut files)?;
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn collect_source_files(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read source directory '{}'", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_source_files(&path, files)?;
        } else if path.is_file() && is_source_file(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_source_file(path: &std::path::Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "hh" | "inl")
    )
}

fn write_capability_row(
    worksheet: &mut rust_xlsxwriter::Worksheet,
    row: u32,
    cpu: &super::schema::CpuCapability,
    detail: Option<&super::schema::EventOpenDetail>,
) -> Result<()> {
    worksheet.write_number(row, 0, f64::from(cpu.cpu))?;
    worksheet.write_string(row, 1, &cpu.cluster)?;
    worksheet.write_boolean(row, 2, cpu.summary.spe)?;
    worksheet.write_boolean(row, 3, cpu.summary.cycles)?;
    worksheet.write_boolean(row, 4, cpu.summary.instructions)?;
    worksheet.write_boolean(row, 5, cpu.summary.cache)?;
    worksheet.write_boolean(row, 6, cpu.summary.branch)?;
    worksheet.write_boolean(row, 7, cpu.summary.callchain)?;
    worksheet.write_boolean(row, 8, cpu.summary.source_sample_fields)?;
    if let Some(detail) = detail {
        worksheet.write_string(row, 9, &detail.event_key)?;
        worksheet.write_string(row, 10, &detail.raw_event_name)?;
        worksheet.write_string(row, 11, &detail.event_type)?;
        worksheet.write_string(row, 12, &detail.config)?;
        worksheet.write_boolean(row, 13, detail.supported)?;
        if let Some(errno) = detail.errno {
            worksheet.write_number(row, 14, f64::from(errno))?;
        }
        worksheet.write_string(row, 15, detail.failure_reason.as_deref().unwrap_or(""))?;
        worksheet.write_string(row, 16, detail.sysfs_path.as_deref().unwrap_or(""))?;
    }
    worksheet.write_string(
        row,
        17,
        cpu.spe
            .as_ref()
            .map(|spe| spe.device_path.as_str())
            .unwrap_or(""),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn writes_summary_workbook() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let output = root.join("target/source_profile_tests/SourceLine.summary.xlsx");
        write_summary_workbook(&bundle, &output).unwrap();
        assert!(output.exists());
        assert!(std::fs::metadata(output).unwrap().len() > 0);
    }

    #[test]
    fn discovers_manifest_source_files() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let files = discover_manifest_source_files(&bundle).unwrap();
        assert!(files.iter().any(|file| {
            file.file_name()
                .is_some_and(|name| name.to_string_lossy() == "fixture.cpp")
        }));
    }

    #[test]
    fn loads_manifest_source_lines() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let lines = load_manifest_source_lines(&bundle).unwrap();
        assert!(lines.len() >= 18);
    }
}

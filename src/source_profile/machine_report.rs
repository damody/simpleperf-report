#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

use super::bundle::SourceProfileBundle;
use super::report_model::{
    build_report_model, instruction_class_column_keys, load_instruction_column_keys,
    metric_value_text, pmu_column_keys, spe_column_keys, ReportModel,
};

pub fn write_source_line_json(bundle: &SourceProfileBundle, output: &Path) -> Result<()> {
    let model = build_report_model(bundle)?;
    write_source_line_json_from_model(bundle, &model, output)
}

pub fn write_source_line_json_from_model(
    bundle: &SourceProfileBundle,
    model: &ReportModel,
    output: &Path,
) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create '{}'", parent.display()))?;
    }
    let report = json!({
        "summary": {
            "session_id": bundle.manifest.session_id,
            "target_package": bundle.manifest.target.package,
            "pid": bundle.manifest.target.pid,
            "duration_ms": bundle.manifest.recording.duration_ms,
            "selected_cpus": bundle.manifest.cpu.selected_cpus,
            "selected_clusters": bundle.manifest.cpu.selected_clusters,
            "pmu_lane": bundle.manifest.lanes.pmu,
            "spe_lane": bundle.manifest.lanes.spe,
            "pmu_buffer_pages": bundle.manifest.capture_options.pmu_buffer_pages,
            "spe_aux_buffer_bytes": bundle.manifest.capture_options.spe_aux_buffer_bytes,
            "instruction_cpu_class_values": metric_values_by_cpu_text(&model.instruction_cpu_class_values),
            "load_cpu_kind_values": metric_values_by_cpu_text(&model.load_cpu_kind_values)
        },
        "columns": columns(bundle),
        "rows": model.rows.iter().map(|row| row_to_values(row, bundle)).collect::<Vec<_>>(),
        "callchain_frame_columns": frame_columns(),
        "callchain_frames": model.frames.iter().map(frame_to_values).collect::<Vec<_>>(),
        "callchain_columns": callchain_columns(),
        "callchains": model.callchains.iter().map(callchain_to_values).collect::<Vec<_>>(),
        "warnings": model.warnings
    });
    fs::write(output, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("Failed to write '{}'", output.display()))
}

pub fn write_csv_exports(bundle: &SourceProfileBundle, output_dir: &Path) -> Result<()> {
    let model = build_report_model(bundle)?;
    write_csv_exports_from_model(bundle, &model, output_dir)
}

pub fn write_csv_exports_from_model(
    bundle: &SourceProfileBundle,
    model: &ReportModel,
    output_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create '{}'", output_dir.display()))?;
    write_csv(
        &output_dir.join("AllLines.csv"),
        &columns(bundle),
        &model
            .rows
            .iter()
            .map(|row| row_to_values(row, bundle))
            .collect::<Vec<_>>(),
    )?;
    let sampled_rows = model
        .rows
        .iter()
        .filter(|row| row.status != "0")
        .map(|row| row_to_values(row, bundle))
        .collect::<Vec<_>>();
    write_csv(
        &output_dir.join("SampledLines.csv"),
        &columns(bundle),
        &sampled_rows,
    )?;
    write_csv(
        &output_dir.join("Files.csv"),
        &[
            "file",
            "self_weight",
            "acc_weight",
            "sample_count",
            "hot_lines",
            "unresolved",
            "missing",
        ],
        &model
            .files
            .iter()
            .map(|row| {
                vec![
                    row.file.clone(),
                    format!("{}", row.self_weight),
                    format!("{}", row.accumulated_weight),
                    row.sample_count.to_string(),
                    row.hot_lines.to_string(),
                    row.unresolved.to_string(),
                    row.missing.to_string(),
                ]
            })
            .collect::<Vec<_>>(),
    )?;
    write_csv(
        &output_dir.join("Functions.csv"),
        &[
            "function",
            "file",
            "line_start",
            "line_end",
            "module",
            "self_weight",
            "acc_weight",
            "samples",
        ],
        &model
            .functions
            .iter()
            .map(|row| {
                vec![
                    row.function.clone(),
                    row.file.clone(),
                    row.line_start.to_string(),
                    row.line_end.to_string(),
                    row.module.clone(),
                    format!("{}", row.self_weight),
                    format!("{}", row.accumulated_weight),
                    row.sample_count.to_string(),
                ]
            })
            .collect::<Vec<_>>(),
    )?;
    write_csv(
        &output_dir.join("CallchainFrames.csv"),
        &frame_columns(),
        &model.frames.iter().map(frame_to_values).collect::<Vec<_>>(),
    )?;
    write_csv(
        &output_dir.join("Callchains.csv"),
        &callchain_columns(),
        &model
            .callchains
            .iter()
            .map(callchain_to_values)
            .collect::<Vec<_>>(),
    )
}

fn columns(bundle: &SourceProfileBundle) -> Vec<String> {
    let mut columns = vec![
        "file".to_string(),
        "line".to_string(),
        "function".to_string(),
        "module".to_string(),
        "cpu".to_string(),
        "thread".to_string(),
        "code".to_string(),
        "status".to_string(),
        "p_pct".to_string(),
        "acc_p_pct".to_string(),
        "file_p_pct".to_string(),
        "file_acc_p_pct".to_string(),
        "self_weight".to_string(),
        "acc_weight".to_string(),
    ];
    columns.extend(pmu_column_keys(bundle));
    columns.extend(spe_column_keys());
    columns.extend(instruction_class_column_keys());
    columns.extend(load_instruction_column_keys());
    columns
}

fn row_to_values(
    row: &super::report_model::ReportLineRow,
    bundle: &SourceProfileBundle,
) -> Vec<String> {
    let mut values = vec![
        row.file.clone(),
        row.line.to_string(),
        row.function.clone(),
        row.module.clone(),
        row.cpu.clone(),
        row.thread.clone(),
        row.code.clone(),
        row.status.clone(),
        format!("{:.6}", row.p_pct),
        format!("{:.6}", row.acc_p_pct),
        format!("{:.6}", row.file_p_pct),
        format!("{:.6}", row.file_acc_p_pct),
        format!("{:.0}", row.self_weight),
        format!("{:.0}", row.accumulated_weight),
    ];
    for key in pmu_column_keys(bundle) {
        values.push(metric_value_text(row.pmu_values.get(&key)));
    }
    for key in spe_column_keys() {
        values.push(metric_value_text(row.spe_values.get(&key)));
    }
    for key in instruction_class_column_keys() {
        values.push(metric_value_text(row.instruction_values.get(&key)));
    }
    for key in load_instruction_column_keys() {
        values.push(metric_value_text(row.load_instruction_values.get(&key)));
    }
    values
}

fn frame_columns() -> Vec<String> {
    [
        "role",
        "module",
        "function",
        "ip",
        "relative_address",
        "mapping_id",
        "cpu",
        "thread",
        "sample_count",
        "self_weight",
        "acc_weight",
        "p_pct",
        "acc_p_pct",
        "event_weights",
        "status",
    ]
    .iter()
    .map(|value| (*value).to_string())
    .collect()
}

fn frame_to_values(row: &super::report_model::ReportFrameRow) -> Vec<String> {
    vec![
        row.role.clone(),
        row.module.clone(),
        row.function.clone(),
        format!("0x{:x}", row.ip),
        format!("0x{:x}", row.relative_address),
        row.mapping_id.to_string(),
        row.cpu.clone(),
        row.thread.clone(),
        row.sample_count.to_string(),
        format!("{:.0}", row.self_weight),
        format!("{:.0}", row.accumulated_weight),
        format!("{:.6}", row.p_pct),
        format!("{:.6}", row.acc_p_pct),
        row.event_weights.clone(),
        row.status.clone(),
    ]
}

fn callchain_columns() -> Vec<String> {
    [
        "stack",
        "leaf",
        "root",
        "cpu",
        "thread",
        "sample_count",
        "weight",
        "p_pct",
        "event_weights",
    ]
    .iter()
    .map(|value| (*value).to_string())
    .collect()
}

fn callchain_to_values(row: &super::report_model::ReportCallchainRow) -> Vec<String> {
    vec![
        row.stack.clone(),
        row.leaf.clone(),
        row.root.clone(),
        row.cpu.clone(),
        row.thread.clone(),
        row.sample_count.to_string(),
        format!("{:.0}", row.weight),
        format!("{:.6}", row.p_pct),
        row.event_weights.clone(),
    ]
}

fn metric_values_by_cpu_text(
    values: &BTreeMap<u32, BTreeMap<String, super::metrics::MetricValue>>,
) -> BTreeMap<u32, BTreeMap<String, String>> {
    values
        .iter()
        .map(|(cpu, by_key)| {
            (
                *cpu,
                by_key
                    .iter()
                    .map(|(key, value)| (key.clone(), metric_value_text(Some(value))))
                    .collect(),
            )
        })
        .collect()
}

fn write_csv<S: AsRef<str>>(path: &Path, headers: &[S], rows: &[Vec<String>]) -> Result<()> {
    let mut out = String::new();
    out.push_str(
        &headers
            .iter()
            .map(|h| csv_escape(h.as_ref()))
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push('\n');
    for row in rows {
        out.push_str(
            &row.iter()
                .map(|value| csv_escape(value))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    fs::write(path, out).with_context(|| format!("Failed to write '{}'", path.display()))
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn writes_json_and_csv_exports() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let out = root.join("target/source_profile_tests/machine");
        write_source_line_json(&bundle, &out.join("SourceLine.json")).unwrap();
        write_csv_exports(&bundle, &out.join("csv")).unwrap();
        assert!(out.join("SourceLine.json").exists());
        assert!(out.join("csv/AllLines.csv").exists());
        assert!(out.join("csv/Files.csv").exists());
        assert!(out.join("csv/Functions.csv").exists());
        let text = fs::read_to_string(out.join("SourceLine.json")).unwrap();
        assert!(
            text.contains("instruction_class.compute_fp_simd.sample_pct")
                || text.contains("instruction_values")
        );
    }

    #[test]
    fn writes_json_and_csv_exports_from_prebuilt_model() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let model = build_report_model(&bundle).unwrap();
        let out = root.join("target/source_profile_tests/machine_from_model");
        write_source_line_json_from_model(&bundle, &model, &out.join("SourceLine.json")).unwrap();
        write_csv_exports_from_model(&bundle, &model, &out.join("csv")).unwrap();

        assert!(out.join("SourceLine.json").exists());
        assert!(out.join("csv/AllLines.csv").exists());
        assert!(out.join("csv/Callchains.csv").exists());
        let json = fs::read_to_string(out.join("SourceLine.json")).unwrap();
        assert!(json.contains("load_cpu_kind_values"));
        let csv = fs::read_to_string(out.join("csv/AllLines.csv")).unwrap();
        assert!(csv.contains("load_instruction.load_scalar_single.sample_pct"));
    }
}

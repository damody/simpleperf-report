#![allow(dead_code)]

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

use super::bundle::SourceProfileBundle;
use super::report_model::{
    build_report_model, metric_value_text, DERIVED_PMU_COLUMNS, RAW_PMU_COLUMNS, SPE_COLUMNS,
};

pub fn write_source_line_json(bundle: &SourceProfileBundle, output: &Path) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create '{}'", parent.display()))?;
    }
    let model = build_report_model(bundle)?;
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
            "spe_aux_buffer_bytes": bundle.manifest.capture_options.spe_aux_buffer_bytes
        },
        "columns": columns(),
        "rows": model.rows.iter().map(row_to_values).collect::<Vec<_>>(),
        "warnings": model.warnings
    });
    fs::write(output, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("Failed to write '{}'", output.display()))
}

pub fn write_csv_exports(bundle: &SourceProfileBundle, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create '{}'", output_dir.display()))?;
    let model = build_report_model(bundle)?;
    write_csv(
        &output_dir.join("AllLines.csv"),
        &columns(),
        &model.rows.iter().map(row_to_values).collect::<Vec<_>>(),
    )?;
    let sampled_rows = model
        .rows
        .iter()
        .filter(|row| row.status != "0")
        .map(row_to_values)
        .collect::<Vec<_>>();
    write_csv(
        &output_dir.join("SampledLines.csv"),
        &columns(),
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
    )
}

fn columns() -> Vec<&'static str> {
    let mut columns = vec![
        "file",
        "line",
        "function",
        "module",
        "cpu",
        "thread",
        "code",
        "status",
        "p_pct",
        "acc_p_pct",
        "file_p_pct",
        "file_acc_p_pct",
        "self_weight",
        "acc_weight",
    ];
    columns.extend_from_slice(RAW_PMU_COLUMNS);
    columns.extend_from_slice(DERIVED_PMU_COLUMNS);
    columns.extend_from_slice(SPE_COLUMNS);
    columns
}

fn row_to_values(row: &super::report_model::ReportLineRow) -> Vec<String> {
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
    for key in RAW_PMU_COLUMNS.iter().chain(DERIVED_PMU_COLUMNS.iter()) {
        values.push(metric_value_text(row.pmu_values.get(*key)));
    }
    for key in SPE_COLUMNS {
        values.push(metric_value_text(row.spe_values.get(*key)));
    }
    values
}

fn write_csv(path: &Path, headers: &[&str], rows: &[Vec<String>]) -> Result<()> {
    let mut out = String::new();
    out.push_str(
        &headers
            .iter()
            .map(|h| csv_escape(h))
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
    }
}

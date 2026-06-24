use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde_json::json;

use super::bundle::SourceProfileBundle;
use super::report_model::{build_report_model, metric_value_text, ReportModel};

#[allow(dead_code)]
pub fn write_report_db(bundle: &SourceProfileBundle, output: &Path) -> Result<()> {
    let model = build_report_model(bundle)?;
    write_report_db_from_model(bundle, &model, output)
}

pub fn write_report_db_from_model(
    bundle: &SourceProfileBundle,
    model: &ReportModel,
    output: &Path,
) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create '{}'", parent.display()))?;
    }
    if output.exists() {
        fs::remove_file(output)
            .with_context(|| format!("Failed to replace '{}'", output.display()))?;
    }

    let mut conn = Connection::open(output)
        .with_context(|| format!("Failed to create '{}'", output.display()))?;
    create_schema(&conn)?;
    let tx = conn.transaction()?;

    let summary = json!({
        "session_id": bundle.manifest.session_id,
        "target_package": bundle.manifest.target.package,
        "pid": bundle.manifest.target.pid,
        "duration_ms": bundle.manifest.recording.duration_ms,
        "device": {
            "manufacturer": bundle.manifest.device.manufacturer,
            "model": bundle.manifest.device.model,
            "android_release": bundle.manifest.device.android_release,
            "abi": bundle.manifest.device.abi,
        },
        "selected_cpus": bundle.manifest.cpu.selected_cpus,
        "selected_clusters": bundle.manifest.cpu.selected_clusters,
        "pmu_lane": bundle.manifest.lanes.pmu,
        "spe_lane": bundle.manifest.lanes.spe,
        "capture_options": bundle.manifest.capture_options,
        "warnings": &model.warnings,
    });
    tx.execute(
        "INSERT INTO metadata(key, value) VALUES('summary', ?1)",
        [serde_json::to_string(&summary)?],
    )?;

    {
        let mut stmt = tx.prepare(
            "INSERT INTO source_lines(
                file, line, function, module, cpu, thread, status, code, detail,
                sample_count, self_weight, accumulated_weight, p_pct, acc_p_pct, file_p_pct, file_acc_p_pct,
                cpi, l1d_cache_hit_rate, mips, mcps, pmu_json, spe_json, instruction_json, load_instruction_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
        )?;
        for row in &model.rows {
            let pmu_json = metric_map_json(&row.pmu_values)?;
            let spe_json = sparse_metric_map_json(&row.spe_values)?;
            let instruction_json = sparse_metric_map_json(&row.instruction_values)?;
            let load_instruction_json = sparse_metric_map_json(&row.load_instruction_values)?;
            stmt.execute(params![
                row.file,
                row.line,
                row.function,
                row.module,
                row.cpu,
                row.thread,
                row.status,
                row.code,
                row.detail,
                row.sample_count,
                row.self_weight,
                row.accumulated_weight,
                row.p_pct,
                row.acc_p_pct,
                row.file_p_pct,
                row.file_acc_p_pct,
                metric_value_text(row.pmu_values.get("cpi")),
                metric_value_text(row.pmu_values.get("l1d_cache_hit_rate")),
                metric_value_text(row.pmu_values.get("mips")),
                metric_value_text(row.pmu_values.get("mcps")),
                pmu_json,
                spe_json,
                instruction_json,
                load_instruction_json,
            ])?;
        }
    }

    {
        let mut stmt = tx.prepare(
            "INSERT INTO files(file, self_weight, accumulated_weight, sample_count, hot_lines, missing, unresolved, hot_line)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for row in &model.files {
            stmt.execute(params![
                row.file,
                row.self_weight,
                row.accumulated_weight,
                row.sample_count,
                row.hot_lines,
                row.missing,
                row.unresolved,
                row.hot_line,
            ])?;
        }
    }

    {
        let mut stmt = tx.prepare(
            "INSERT INTO functions(function, file, line_start, line_end, module, self_weight, accumulated_weight, sample_count, hot_lines)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?;
        for row in &model.functions {
            stmt.execute(params![
                row.function,
                row.file,
                row.line_start,
                row.line_end,
                row.module,
                row.self_weight,
                row.accumulated_weight,
                row.sample_count,
                row.hot_lines,
            ])?;
        }
    }

    create_indexes(&tx)?;
    tx.commit()?;
    Ok(())
}

fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;

        CREATE TABLE metadata(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE source_lines(
            id INTEGER PRIMARY KEY,
            file TEXT NOT NULL,
            line INTEGER NOT NULL,
            function TEXT NOT NULL,
            module TEXT NOT NULL,
            cpu TEXT NOT NULL,
            thread TEXT NOT NULL,
            status TEXT NOT NULL,
            code TEXT NOT NULL,
            detail TEXT NOT NULL,
            sample_count INTEGER NOT NULL,
            self_weight REAL NOT NULL,
            accumulated_weight REAL NOT NULL,
            p_pct REAL NOT NULL,
            acc_p_pct REAL NOT NULL,
            file_p_pct REAL NOT NULL,
            file_acc_p_pct REAL NOT NULL,
            cpi TEXT NOT NULL,
            l1d_cache_hit_rate TEXT NOT NULL,
            mips TEXT NOT NULL,
            mcps TEXT NOT NULL,
            pmu_json TEXT NOT NULL,
            spe_json TEXT NOT NULL,
            instruction_json TEXT NOT NULL,
            load_instruction_json TEXT NOT NULL
        );

        CREATE TABLE files(
            id INTEGER PRIMARY KEY,
            file TEXT NOT NULL,
            self_weight REAL NOT NULL,
            accumulated_weight REAL NOT NULL,
            sample_count INTEGER NOT NULL,
            hot_lines INTEGER NOT NULL,
            missing INTEGER NOT NULL,
            unresolved INTEGER NOT NULL,
            hot_line INTEGER NOT NULL
        );

        CREATE TABLE functions(
            id INTEGER PRIMARY KEY,
            function TEXT NOT NULL,
            file TEXT NOT NULL,
            line_start INTEGER NOT NULL,
            line_end INTEGER NOT NULL,
            module TEXT NOT NULL,
            self_weight REAL NOT NULL,
            accumulated_weight REAL NOT NULL,
            sample_count INTEGER NOT NULL,
            hot_lines TEXT NOT NULL
        );

        "#,
    )?;
    Ok(())
}

fn create_indexes(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    tx.execute_batch(
        r#"
        CREATE INDEX source_lines_file_idx ON source_lines(file);
        CREATE INDEX source_lines_function_idx ON source_lines(function);
        CREATE INDEX source_lines_status_idx ON source_lines(status);
        CREATE INDEX source_lines_cpu_idx ON source_lines(cpu);
        CREATE INDEX source_lines_thread_idx ON source_lines(thread);
        CREATE INDEX source_lines_sample_count_idx ON source_lines(sample_count);
        CREATE INDEX source_lines_self_weight_idx ON source_lines(self_weight);
        CREATE INDEX source_lines_accumulated_weight_idx ON source_lines(accumulated_weight);
        CREATE INDEX source_lines_line_idx ON source_lines(line);
        "#,
    )?;
    Ok(())
}

fn metric_map_json(
    values: &std::collections::BTreeMap<String, super::metrics::MetricValue>,
) -> Result<String> {
    let entries = values
        .iter()
        .map(|(key, value)| (key.clone(), metric_value_text(Some(value))))
        .collect::<std::collections::BTreeMap<_, _>>();
    Ok(serde_json::to_string(&entries)?)
}

fn sparse_metric_map_json(
    values: &std::collections::BTreeMap<String, super::metrics::MetricValue>,
) -> Result<String> {
    let entries = values
        .iter()
        .filter(|(_, value)| {
            !matches!(value, super::metrics::MetricValue::Number(number) if *number == 0.0)
        })
        .map(|(key, value)| (key.clone(), metric_value_text(Some(value))))
        .collect::<std::collections::BTreeMap<_, _>>();
    Ok(serde_json::to_string(&entries)?)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use rusqlite::Connection;

    use super::*;

    #[test]
    fn writes_sqlite_report_tables_from_bundle() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let output = root.join("target/source_profile_tests/report_db/SourceLine.sqlite");
        if output.exists() {
            fs::remove_file(&output).unwrap();
        }

        write_report_db(&bundle, &output).unwrap();

        let conn = Connection::open(&output).unwrap();
        for table in ["metadata", "source_lines", "files", "functions"] {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "missing table {table}");
        }
        let line_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM source_lines", [], |row| row.get(0))
            .unwrap();
        assert!(line_count >= 19, "expected all source lines in sqlite");
        let sample_count_total: i64 = conn
            .query_row("SELECT SUM(sample_count) FROM source_lines", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(
            sample_count_total > 0,
            "expected line sample counts in sqlite"
        );
    }

    #[test]
    fn writes_sqlite_report_from_prebuilt_model() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let model = crate::source_profile::report_model::build_report_model(&bundle).unwrap();
        let output =
            root.join("target/source_profile_tests/report_db_from_model/SourceLine.sqlite");
        if output.exists() {
            fs::remove_file(&output).unwrap();
        }

        write_report_db_from_model(&bundle, &model, &output).unwrap();

        let conn = Connection::open(&output).unwrap();
        let line_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM source_lines", [], |row| row.get(0))
            .unwrap();
        assert_eq!(line_count as usize, model.rows.len());
    }

    #[test]
    fn sqlite_rows_include_spe_category_json() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let model = crate::source_profile::report_model::build_report_model(&bundle).unwrap();
        let output =
            root.join("target/source_profile_tests/report_db_spe_categories/SourceLine.sqlite");
        if output.exists() {
            fs::remove_file(&output).unwrap();
        }

        write_report_db_from_model(&bundle, &model, &output).unwrap();

        let conn = Connection::open(&output).unwrap();
        let matching_rows: i64 = conn
            .query_row(
                "SELECT count(*) FROM source_lines WHERE spe_json LIKE '%load_dram.est_time_pct%' AND spe_json LIKE '%store_unknown.est_time_pct%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(matching_rows > 0);
    }

    #[test]
    fn sqlite_schema_includes_instruction_json() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let output =
            root.join("target/source_profile_tests/report_db_instruction/SourceLine.sqlite");
        if output.exists() {
            fs::remove_file(&output).unwrap();
        }

        write_report_db(&bundle, &output).unwrap();

        let conn = Connection::open(output).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info('source_lines') WHERE name = 'instruction_json'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn sqlite_schema_includes_load_instruction_json() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let output =
            root.join("target/source_profile_tests/report_db_load_instruction/SourceLine.sqlite");
        if output.exists() {
            fs::remove_file(&output).unwrap();
        }

        write_report_db(&bundle, &output).unwrap();

        let conn = Connection::open(output).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info('source_lines') WHERE name = 'load_instruction_json'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}

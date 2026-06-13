use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf, Prefix};

use anyhow::{Context, Result};
use serde::Serialize;

use super::bundle::SourceProfileBundle;
use super::report_model::{
    build_report_model, metric_value_text, ReportLineRow, DERIVED_PMU_COLUMNS, RAW_PMU_COLUMNS,
    SPE_COLUMNS,
};
use super::source_loader::load_source_file;

#[derive(Debug, Serialize)]
struct AnnotatedSourceManifest {
    session_id: String,
    target_package: Option<String>,
    output_dir: String,
    files: Vec<AnnotatedSourceFile>,
    skipped_files: Vec<SkippedAnnotatedSourceFile>,
}

#[derive(Debug, Serialize)]
struct AnnotatedSourceFile {
    original_path: String,
    annotated_path: String,
    sampled_lines: usize,
}

#[derive(Debug, Serialize)]
struct SkippedAnnotatedSourceFile {
    original_path: String,
    sampled_lines: usize,
    reason: String,
}

pub fn write_annotated_sources(bundle: &SourceProfileBundle, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create '{}'", output_dir.display()))?;
    let model = build_report_model(bundle)?;
    let roots = absolute_source_roots(bundle);
    let mut by_file = BTreeMap::<PathBuf, BTreeMap<u32, String>>::new();

    for row in model
        .rows
        .iter()
        .filter(|row| row.status.contains("NonZero"))
    {
        by_file
            .entry(PathBuf::from(&row.file))
            .or_default()
            .insert(row.line, format_annotation(row));
    }

    let mut manifest_files = Vec::new();
    let mut skipped_files = Vec::new();
    for (source_file, annotations) in by_file {
        if annotations.is_empty() {
            continue;
        }
        match write_annotated_file(&source_file, &annotations, &roots, output_dir)? {
            Some(file) => manifest_files.push(file),
            None => skipped_files.push(SkippedAnnotatedSourceFile {
                original_path: source_file.to_string_lossy().to_string(),
                sampled_lines: annotations.len(),
                reason: "source file does not exist on this host".to_string(),
            }),
        }
    }

    let manifest = AnnotatedSourceManifest {
        session_id: bundle.manifest.session_id.clone(),
        target_package: bundle.manifest.target.package.clone(),
        output_dir: output_dir.to_string_lossy().to_string(),
        files: manifest_files,
        skipped_files,
    };
    fs::write(
        output_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )
    .with_context(|| {
        format!(
            "Failed to write annotated source manifest in '{}'",
            output_dir.display()
        )
    })
}

fn write_annotated_file(
    source_file: &Path,
    annotations: &BTreeMap<u32, String>,
    roots: &[PathBuf],
    output_dir: &Path,
) -> Result<Option<AnnotatedSourceFile>> {
    if !source_file.is_file() {
        return Ok(None);
    }
    let relative = relative_output_path(source_file, roots);
    let output_path = output_dir.join(relative);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create '{}'", parent.display()))?;
    }
    let lines = load_source_file(source_file)?;
    let mut out = String::new();
    for line in lines {
        if let Some(annotation) = annotations.get(&line.line_number) {
            out.push_str(&leading_whitespace(&line.code));
            out.push_str(annotation);
            out.push('\n');
        }
        out.push_str(&line.code);
        out.push('\n');
    }
    fs::write(&output_path, out)
        .with_context(|| format!("Failed to write '{}'", output_path.display()))?;
    Ok(Some(AnnotatedSourceFile {
        original_path: source_file.to_string_lossy().to_string(),
        annotated_path: output_path.to_string_lossy().to_string(),
        sampled_lines: annotations.len(),
    }))
}

fn format_annotation(row: &ReportLineRow) -> String {
    let mut parts = vec![
        format!("p={:.6}%", row.p_pct),
        format!("acc_p={:.6}%", row.acc_p_pct),
        format!("file_p={:.6}%", row.file_p_pct),
        format!("file_acc_p={:.6}%", row.file_acc_p_pct),
        format!("self_weight={:.0}", row.self_weight),
        format!("acc_weight={:.0}", row.accumulated_weight),
        format!("cpu={}", empty_as_missing(&row.cpu)),
        format!("thread={}", empty_as_missing(&row.thread)),
    ];
    for key in RAW_PMU_COLUMNS.iter().chain(DERIVED_PMU_COLUMNS.iter()) {
        parts.push(format!(
            "{}={}",
            key,
            metric_value_text(row.pmu_values.get(*key))
        ));
    }
    for key in SPE_COLUMNS {
        parts.push(format!(
            "{}={}",
            key,
            metric_value_text(row.spe_values.get(*key))
        ));
    }
    parts.push(format!("status={}", row.status));
    format!("// [MProfiler] {}", parts.join(", "))
}

fn empty_as_missing(value: &str) -> &str {
    if value.is_empty() {
        "Missing"
    } else {
        value
    }
}

fn leading_whitespace(value: &str) -> String {
    value.chars().take_while(|ch| ch.is_whitespace()).collect()
}

fn absolute_source_roots(bundle: &SourceProfileBundle) -> Vec<PathBuf> {
    bundle
        .manifest
        .inputs
        .source_root_hints
        .iter()
        .map(|hint| {
            let path = PathBuf::from(hint);
            let absolute = if path.is_absolute() {
                path
            } else {
                bundle.root.join(path)
            };
            fs::canonicalize(&absolute).unwrap_or(absolute)
        })
        .collect()
}

fn relative_output_path(source_file: &Path, roots: &[PathBuf]) -> PathBuf {
    let normalized_source = fs::canonicalize(source_file).unwrap_or_else(|_| source_file.into());
    let mut best = None::<&PathBuf>;
    for root in roots {
        if normalized_source.starts_with(root)
            && best
                .map(|current| root.components().count() > current.components().count())
                .unwrap_or(true)
        {
            best = Some(root);
        }
    }
    if let Some(root) = best {
        if let Ok(relative) = normalized_source.strip_prefix(root) {
            return relative.to_path_buf();
        }
    }
    PathBuf::from("external").join(sanitized_absolute_path(&normalized_source))
}

fn sanitized_absolute_path(path: &Path) -> PathBuf {
    let mut sanitized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                sanitized.push(safe_prefix_component(prefix.kind()));
            }
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => {
                sanitized.push(safe_path_component(&value.to_string_lossy()))
            }
            Component::ParentDir => sanitized.push("_parent"),
        }
    }
    sanitized
}

fn safe_prefix_component(prefix: Prefix<'_>) -> String {
    match prefix {
        Prefix::Disk(disk) | Prefix::VerbatimDisk(disk) => format!("{}_", disk as char),
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => format!(
            "{}_{}",
            safe_path_component(&server.to_string_lossy()),
            safe_path_component(&share.to_string_lossy())
        ),
        Prefix::Verbatim(value) => safe_path_component(&value.to_string_lossy()),
        Prefix::DeviceNS(value) => {
            format!("device_{}", safe_path_component(&value.to_string_lossy()))
        }
    }
}

fn safe_path_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\\' | '/' | ':' | '?' | '*' | '"' | '<' | '>' | '|' => '_',
            _ => ch,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    #[test]
    fn writes_annotated_source_for_sampled_lines_only() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let out = root.join("target/source_profile_tests/annotated_source");
        let _ = fs::remove_dir_all(&out);

        write_annotated_sources(&bundle, &out).unwrap();

        let annotated = out.join("fixture.cpp");
        let text = fs::read_to_string(&annotated).unwrap();
        assert!(text.contains("// [MProfiler]"));
        assert!(text.contains("p="));
        assert!(text.contains("acc_p="));
        assert!(text.contains("file_p="));
        assert!(text.contains("cpu_cycles="));
        assert!(text.contains("cpi="));
        assert!(text.contains("l1d_cache_hit_rate="));
        assert!(text.contains("sum += values[i] * 3;"));
        assert!(out.join("manifest.json").exists());
    }

    #[test]
    fn sanitizes_verbatim_windows_paths_as_relative_output_paths() {
        let sanitized = sanitized_absolute_path(Path::new(
            r"\\?\C:\Users\damod\AppData\Local\Android\Sdk\ndk\source.cpp",
        ));

        assert!(!sanitized.is_absolute());
        assert!(!sanitized.components().any(|component| {
            matches!(
                component,
                std::path::Component::Prefix(_) | std::path::Component::RootDir
            )
        }));
        assert!(sanitized.to_string_lossy().contains("C_"));
        assert!(sanitized.to_string_lossy().contains("source.cpp"));
    }

    #[test]
    fn skips_missing_sampled_source_files() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = root.join("target/source_profile_tests/missing_annotated_source");
        let _ = fs::remove_dir_all(&out);
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert(1, "// [MProfiler] p=1.000000%".to_string());

        let result =
            write_annotated_file(Path::new(r"E:\missing\source.cpp"), &annotations, &[], &out)
                .unwrap();

        assert!(result.is_none());
        assert!(!out.join("external/E_/missing/source.cpp").exists());
    }
}

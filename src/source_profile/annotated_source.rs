use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use serde::Serialize;

use super::bundle::SourceProfileBundle;
use super::report_model::{
    build_report_model, metric_value_text, pmu_column_keys, ReportLineRow, ReportModel, SPE_COLUMNS,
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
    total_lines: usize,
}

#[derive(Debug, Serialize)]
struct SkippedAnnotatedSourceFile {
    original_path: String,
    sampled_lines: usize,
    reason: String,
}

pub fn write_annotated_sources(bundle: &SourceProfileBundle, output_dir: &Path) -> Result<()> {
    let model = build_report_model(bundle)?;
    write_annotated_sources_from_model(bundle, &model, output_dir)
}

pub fn write_annotated_sources_from_model(
    bundle: &SourceProfileBundle,
    model: &ReportModel,
    output_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create '{}'", output_dir.display()))?;
    let pmu_columns = pmu_column_keys(bundle);
    let roots = absolute_source_roots(bundle);
    let formatter = discover_mprofiler_astyle();
    let mut by_file = BTreeMap::<PathBuf, BTreeMap<u32, String>>::new();

    for row in &model.rows {
        let file = PathBuf::from(&row.file);
        if !is_within_source_roots(&file, &roots) {
            continue;
        }
        let annotations = by_file.entry(file).or_default();
        if row.status.contains("NonZero") {
            annotations.insert(
                row.line,
                format_annotation(row, &pmu_columns, bundle.manifest.lanes.spe.available),
            );
        }
    }

    let entries = by_file
        .into_iter()
        .filter(|(_, annotations)| !annotations.is_empty())
        .collect::<Vec<_>>();
    let worker_count = annotated_source_worker_count(entries.len());
    let pool = ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .build()
        .context("Failed to create annotated source worker pool")?;
    let results = pool.install(|| {
        entries
            .par_iter()
            .map(|(source_file, annotations)| {
                match write_annotated_file_with_formatter(
                    source_file,
                    annotations,
                    &roots,
                    output_dir,
                    formatter.as_ref(),
                )? {
                    Some(file) => Ok(AnnotatedWriteResult::Written(file)),
                    None => Ok(AnnotatedWriteResult::Skipped(SkippedAnnotatedSourceFile {
                        original_path: source_file.to_string_lossy().to_string(),
                        sampled_lines: annotations.len(),
                        reason: "source file does not exist on this host".to_string(),
                    })),
                }
            })
            .collect::<Result<Vec<_>>>()
    })?;

    let mut manifest_files = Vec::new();
    let mut skipped_files = Vec::new();
    for result in results {
        match result {
            AnnotatedWriteResult::Written(file) => manifest_files.push(file),
            AnnotatedWriteResult::Skipped(file) => skipped_files.push(file),
        }
    }
    sort_manifest_entries(&mut manifest_files, &mut skipped_files);

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

enum AnnotatedWriteResult {
    Written(AnnotatedSourceFile),
    Skipped(SkippedAnnotatedSourceFile),
}

fn sort_manifest_entries(
    files: &mut [AnnotatedSourceFile],
    skipped_files: &mut [SkippedAnnotatedSourceFile],
) {
    files.sort_by(|a, b| {
        a.original_path
            .cmp(&b.original_path)
            .then_with(|| a.annotated_path.cmp(&b.annotated_path))
    });
    skipped_files.sort_by(|a, b| a.original_path.cmp(&b.original_path));
}

fn annotated_source_worker_count(entry_count: usize) -> usize {
    let available = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    entry_count.max(1).min(available).min(4)
}

fn is_within_source_roots(path: &Path, roots: &[PathBuf]) -> bool {
    let normalized = normalize_for_prefix_check(path);
    roots.iter().any(|root| {
        let root = normalize_for_prefix_check(root);
        normalized.starts_with(root)
    })
}

fn normalize_for_prefix_check(path: &Path) -> PathBuf {
    let trimmed = path
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_string();
    fs::canonicalize(&trimmed).unwrap_or_else(|_| PathBuf::from(trimmed))
}

#[cfg(test)]
fn write_annotated_file(
    source_file: &Path,
    annotations: &BTreeMap<u32, String>,
    roots: &[PathBuf],
    output_dir: &Path,
) -> Result<Option<AnnotatedSourceFile>> {
    write_annotated_file_with_formatter(source_file, annotations, roots, output_dir, None)
}

#[derive(Debug, Clone)]
struct FormatterCommand {
    program: PathBuf,
    args: Vec<String>,
}

fn write_annotated_file_with_formatter(
    source_file: &Path,
    annotations: &BTreeMap<u32, String>,
    roots: &[PathBuf],
    output_dir: &Path,
    formatter: Option<&FormatterCommand>,
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
    let total_lines = lines.len();
    let mut out = String::new();
    for line in lines {
        if let Some(annotation) = annotations.get(&line.line_number) {
            out.push_str(annotation);
            out.push('\n');
        }
        out.push_str(&line.code);
        out.push('\n');
    }
    fs::write(&output_path, out)
        .with_context(|| format!("Failed to write '{}'", output_path.display()))?;
    if let Some(formatter) = formatter.filter(|_| is_c_like_source(&output_path)) {
        run_formatter(formatter, &output_path)?;
        normalize_mprofiler_comments(&output_path)?;
    }
    Ok(Some(AnnotatedSourceFile {
        original_path: source_file.to_string_lossy().to_string(),
        annotated_path: output_path.to_string_lossy().to_string(),
        sampled_lines: annotations.len(),
        total_lines,
    }))
}

fn run_formatter(formatter: &FormatterCommand, path: &Path) -> Result<()> {
    let Some(file_name) = path.file_name() else {
        anyhow::bail!(
            "Cannot format path without a file name: '{}'",
            path.display()
        );
    };
    let temp_dir = env::temp_dir().join("mprofiler_astyle").join(format!(
        "{}_{}",
        std::process::id(),
        FORMATTER_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&temp_dir).with_context(|| {
        format!(
            "Failed to create formatter temp dir '{}'",
            temp_dir.display()
        )
    })?;
    let temp_path = temp_dir.join(file_name);
    fs::copy(path, &temp_path).with_context(|| {
        format!(
            "Failed to stage '{}' for formatter at '{}'",
            path.display(),
            temp_path.display()
        )
    })?;

    let status = Command::new(&formatter.program)
        .args(&formatter.args)
        .arg(&temp_path)
        .status()
        .with_context(|| format!("Failed to run formatter '{}'", formatter.program.display()))?;
    if !status.success() {
        let _ = fs::remove_dir_all(&temp_dir);
        anyhow::bail!(
            "Formatter '{}' failed with status {status}",
            formatter.program.display()
        );
    }
    fs::copy(&temp_path, path).with_context(|| {
        format!(
            "Failed to copy formatted temp file '{}' back to '{}'",
            temp_path.display(),
            path.display()
        )
    })?;
    let _ = fs::remove_dir_all(&temp_dir);
    Ok(())
}

static FORMATTER_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn discover_mprofiler_astyle() -> Option<FormatterCommand> {
    if let Ok(path) = env::var("MPROFILER_ASTYLE") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(FormatterCommand {
                program: path,
                args: astyle_format_args(),
            });
        }
    }

    let mut roots = Vec::new();
    if let Ok(exe) = env::current_exe() {
        roots.extend(exe.ancestors().map(Path::to_path_buf));
    }
    if let Ok(cwd) = env::current_dir() {
        roots.extend(cwd.ancestors().map(Path::to_path_buf));
    }
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        roots.extend(Path::new(manifest_dir).ancestors().map(Path::to_path_buf));
    }

    roots.sort();
    roots.dedup();
    for root in roots {
        for candidate in astyle_candidates(&root) {
            if candidate.is_file() {
                return Some(FormatterCommand {
                    program: candidate,
                    args: astyle_format_args(),
                });
            }
        }
    }
    None
}

fn astyle_candidates(root: &Path) -> Vec<PathBuf> {
    vec![
        root.join("package/astyle/mprofiler_astyle.exe"),
        root.join("astyle-3.6.16-x64/build/mprofiler/Release/AStyle.exe"),
        root.join("astyle-3.6.16-x64/build/mprofiler/AStyle.exe"),
        root.join("package/astyle/astyle.exe"),
        root.join("astyle-3.6.16-x64/astyle.exe"),
    ]
}

fn normalize_mprofiler_comments(path: &Path) -> Result<()> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("Failed to read formatted '{}'", path.display()))?;
    let normalized = text
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("// [MProfiler]") {
                trimmed
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, format!("{normalized}\n")).with_context(|| {
        format!(
            "Failed to rewrite normalized MProfiler comments in '{}'",
            path.display()
        )
    })
}

fn astyle_format_args() -> Vec<String> {
    vec![
        "--suffix=none".to_string(),
        "--mode=c".to_string(),
        "--indent=spaces=4".to_string(),
        "--keep-one-line-blocks".to_string(),
        "--keep-one-line-statements".to_string(),
        "--quiet".to_string(),
    ]
}

fn is_c_like_source(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase()),
        Some(extension)
            if matches!(
                extension.as_str(),
                "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" | "inl"
            )
    )
}

fn format_annotation(row: &ReportLineRow, pmu_columns: &[String], spe_available: bool) -> String {
    let mut parts = vec![
        format!("sample_count={}", row.sample_count),
        format!("p={:.6}%", row.p_pct),
        format!("acc_p={:.6}%", row.acc_p_pct),
        format!("file_p={:.6}%", row.file_p_pct),
        format!("file_acc_p={:.6}%", row.file_acc_p_pct),
        format!("self_weight={:.0}", row.self_weight),
        format!("acc_weight={:.0}", row.accumulated_weight),
        format!("cpu={}", empty_as_missing(&row.cpu)),
        format!("thread={}", empty_as_missing(&row.thread)),
    ];
    for key in pmu_columns {
        parts.push(format!(
            "{}={}",
            key,
            metric_value_text(row.pmu_values.get(key))
        ));
    }
    if spe_available {
        for key in SPE_COLUMNS {
            parts.push(format!(
                "{}={}",
                key,
                metric_value_text(row.spe_values.get(*key))
            ));
        }
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

    use crate::source_profile::metrics::MetricValue;

    use super::*;

    #[test]
    fn writes_full_source_files_with_sample_annotations() {
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
        assert!(text.contains("inst_retired="));
        assert!(text.contains("cpi="));
        assert!(!text.contains("l1d_cache_hit_rate="));
        assert!(text.contains("sum += values[i] * 3;"));
        assert!(out.join("manifest.json").exists());
    }

    #[test]
    fn writes_annotated_sources_from_prebuilt_model() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle =
            SourceProfileBundle::load(root.join("fixtures/source_profile/minimal")).unwrap();
        let model = crate::source_profile::report_model::build_report_model(&bundle).unwrap();
        let out = root.join("target/source_profile_tests/annotated_source_from_model");
        let _ = fs::remove_dir_all(&out);

        write_annotated_sources_from_model(&bundle, &model, &out).unwrap();

        let manifest = fs::read_to_string(out.join("manifest.json")).unwrap();
        assert!(manifest.contains("fixture.cpp"));
        let annotated = out.join("fixture.cpp");
        let text = fs::read_to_string(&annotated).unwrap();
        assert!(text.contains("// [MProfiler]"));
        assert!(text.contains("sum += values[i] * 3;"));
    }

    #[test]
    fn annotated_manifest_entries_are_sorted() {
        let mut files = vec![
            AnnotatedSourceFile {
                original_path: "z.cpp".to_string(),
                annotated_path: "out/z.cpp".to_string(),
                sampled_lines: 1,
                total_lines: 10,
            },
            AnnotatedSourceFile {
                original_path: "a.cpp".to_string(),
                annotated_path: "out/a.cpp".to_string(),
                sampled_lines: 1,
                total_lines: 10,
            },
        ];
        let mut skipped_files = vec![
            SkippedAnnotatedSourceFile {
                original_path: "z_missing.cpp".to_string(),
                sampled_lines: 1,
                reason: "missing".to_string(),
            },
            SkippedAnnotatedSourceFile {
                original_path: "a_missing.cpp".to_string(),
                sampled_lines: 1,
                reason: "missing".to_string(),
            },
        ];

        sort_manifest_entries(&mut files, &mut skipped_files);

        assert_eq!(files[0].original_path, "a.cpp");
        assert_eq!(files[1].original_path, "z.cpp");
        assert_eq!(skipped_files[0].original_path, "a_missing.cpp");
        assert_eq!(skipped_files[1].original_path, "z_missing.cpp");
    }

    #[test]
    fn annotated_source_worker_count_is_bounded() {
        assert_eq!(annotated_source_worker_count(0), 1);
        assert!(annotated_source_worker_count(1) >= 1);
        assert!(annotated_source_worker_count(1000) <= 4);
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

    #[test]
    fn writes_mprofiler_comments_without_source_indentation() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let source_dir = root.join("target/source_profile_tests/left_aligned_source");
        let out = root.join("target/source_profile_tests/left_aligned_out");
        let _ = fs::remove_dir_all(&source_dir);
        let _ = fs::remove_dir_all(&out);
        fs::create_dir_all(&source_dir).unwrap();
        let source = source_dir.join("indented.cpp");
        fs::write(&source, "void Tick() {\n    DoWork();\n}\n").unwrap();
        let mut annotations = BTreeMap::new();
        annotations.insert(2, "// [MProfiler] cpu_cycles=1000".to_string());

        let annotated = write_annotated_file(&source, &annotations, &[source_dir.clone()], &out)
            .unwrap()
            .unwrap();

        let text = fs::read_to_string(PathBuf::from(annotated.annotated_path)).unwrap();
        assert!(text.contains("\n// [MProfiler] cpu_cycles=1000\n    DoWork();"));
        assert!(!text.contains("\n    // [MProfiler]"));
    }

    #[test]
    fn astyle_arguments_do_not_enable_line_wrapping() {
        let args = astyle_format_args();

        assert!(!args.iter().any(|arg| arg.contains("max-code-length")));
        assert!(!args.iter().any(|arg| arg.contains("break-after-logical")));
        assert!(args.iter().any(|arg| arg == "--keep-one-line-blocks"));
        assert!(args.iter().any(|arg| arg == "--keep-one-line-statements"));
    }

    #[test]
    fn formats_annotated_source_with_astyle_without_indenting_mprofiler_comments() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let source_dir = root.join("target/source_profile_tests/astyle_source");
        let out = root.join("target/source_profile_tests/astyle_out");
        let _ = fs::remove_dir_all(&source_dir);
        let _ = fs::remove_dir_all(&out);
        fs::create_dir_all(&source_dir).unwrap();
        let source = source_dir.join("tick.cpp");
        fs::write(&source, "void Tick(){\n    if(true){DoWork();}\n}\n").unwrap();
        let mut annotations = BTreeMap::new();
        annotations.insert(
            2,
            "// [MProfiler] p=1.000000%, cpu_cycles=1000, l2d_cache_refill=1000".to_string(),
        );

        let formatter_script = source_dir.join("fake_formatter.ps1");
        fs::write(
            &formatter_script,
            r#"
$path = $args[$args.Length - 1]
$text = Get-Content -Raw -LiteralPath $path
$text = $text -replace '(?m)^// \[MProfiler\]', '    // [MProfiler]'
Set-Content -NoNewline -LiteralPath $path -Value $text
"#,
        )
        .unwrap();
        let formatter = FormatterCommand {
            program: PathBuf::from("powershell.exe"),
            args: vec![
                "-NoProfile".to_string(),
                "-ExecutionPolicy".to_string(),
                "Bypass".to_string(),
                "-File".to_string(),
                formatter_script.to_string_lossy().to_string(),
            ],
        };
        let annotated = write_annotated_file_with_formatter(
            &source,
            &annotations,
            &[source_dir.clone()],
            &out,
            Some(&formatter),
        )
        .unwrap()
        .unwrap();

        let text = fs::read_to_string(PathBuf::from(annotated.annotated_path)).unwrap();
        assert!(text.contains("\n// [MProfiler] p=1.000000%, cpu_cycles=1000"));
        assert!(!text.contains("\n    // [MProfiler]"));
        assert_eq!(text.matches("// [MProfiler]").count(), 1);
    }

    #[test]
    fn formatter_uses_short_temporary_path_for_long_output_paths() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let scratch = root.join("target/source_profile_tests/long_path_formatter");
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();
        let mut long_dir = scratch.clone();
        for index in 0..10 {
            long_dir.push(format!("very_long_generated_segment_{index:02}"));
        }
        fs::create_dir_all(&long_dir).unwrap();
        let source = long_dir.join("tick.cpp");
        fs::write(&source, "void Tick() {}\n").unwrap();

        let formatter_script = scratch.join("reject_long_arg.ps1");
        fs::write(
            &formatter_script,
            r#"
$path = $args[$args.Length - 1]
if ($path.Length -gt 120) { exit 23 }
Add-Content -LiteralPath $path -Value "// formatter saw short path"
"#,
        )
        .unwrap();
        let formatter = FormatterCommand {
            program: PathBuf::from("powershell.exe"),
            args: vec![
                "-NoProfile".to_string(),
                "-ExecutionPolicy".to_string(),
                "Bypass".to_string(),
                "-File".to_string(),
                formatter_script.to_string_lossy().to_string(),
            ],
        };

        run_formatter(&formatter, &source).unwrap();

        let text = fs::read_to_string(&source).unwrap();
        assert!(text.contains("formatter saw short path"));
    }

    #[test]
    fn omits_spe_metrics_when_spe_lane_is_unavailable() {
        let row = ReportLineRow {
            file: "fixture.cpp".to_string(),
            line: 1,
            function: "tick".to_string(),
            module: "libfixture.so".to_string(),
            code: "Tick();".to_string(),
            status: "NonZero|Missing".to_string(),
            cpu: "0".to_string(),
            thread: "42".to_string(),
            sample_count: 1,
            self_weight: 1000.0,
            accumulated_weight: 1000.0,
            p_pct: 1.0,
            acc_p_pct: 1.0,
            file_p_pct: 1.0,
            file_acc_p_pct: 1.0,
            pmu_values: BTreeMap::from([
                ("cpu_cycles".to_string(), MetricValue::Number(1.0)),
                ("cpi".to_string(), MetricValue::Number(1.0)),
            ]),
            spe_values: BTreeMap::from([(
                "spe_sample_count".to_string(),
                MetricValue::Missing("SPE unavailable".to_string()),
            )]),
            detail: String::new(),
        };

        let annotation =
            format_annotation(&row, &["cpu_cycles".to_string(), "cpi".to_string()], false);

        assert!(annotation.starts_with("// [MProfiler] sample_count=1, p=1.000000%"));
        assert!(annotation.contains("cpu_cycles=1"));
        assert!(!annotation.contains("spe_sample_count"));
        assert!(!annotation.contains("spe_"));
    }
}

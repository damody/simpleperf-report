use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Args;
use log::info;

use super::annotated_source::write_annotated_sources_from_model;
use super::bundle::SourceProfileBundle;
use super::html_report::write_html_summary_from_model;
use super::httpd::run_httpd;
use super::machine_report::{write_csv_exports_from_model, write_source_line_json_from_model};
use super::report_db::write_report_db_from_model;
use super::report_launcher::write_report_launcher;
use super::report_model::build_report_model;
use super::schema::PathRemap;
use super::xlsx_report::write_summary_workbook_from_model;

#[derive(Args, Debug, Clone)]
pub struct SourceArgs {
    /// Source profile bundle directory produced by realtime_profile.
    #[arg(long)]
    pub bundle: Option<PathBuf>,

    /// Debug ELF file or directory. Can be passed multiple times.
    #[arg(long = "elf")]
    pub elfs: Vec<PathBuf>,

    /// Source root directory. Can be passed multiple times.
    #[arg(long = "source-root")]
    pub source_roots: Vec<PathBuf>,

    /// Path remap in from=to form. Can be passed multiple times.
    #[arg(long = "path-remap")]
    pub path_remaps: Vec<String>,

    /// Output directory for SourceLine reports.
    #[arg(long = "out", default_value = "reports")]
    pub out_dir: PathBuf,

    /// Generate SourceLine.html.
    #[arg(long)]
    pub html: bool,

    /// Generate SourceLine.xlsx.
    #[arg(long)]
    pub xlsx: bool,

    /// Generate SourceLine.json.
    #[arg(long)]
    pub json: bool,

    /// Generate CSV exports.
    #[arg(long)]
    pub csv: bool,

    /// Don't open generated report in browser.
    #[arg(long = "no-browser", alias = "no_browser")]
    pub no_browser: bool,

    /// Highlight threshold for nonzero numeric metrics.
    #[arg(long = "nonzero-threshold", default_value = "0")]
    pub nonzero_threshold: f64,

    /// Write annotated copies of sampled source files into this directory.
    #[arg(long = "annotated-source-out")]
    pub annotated_source_out: Option<PathBuf>,

    /// Serve an existing SourceLine.sqlite database over local HTTP.
    #[arg(long)]
    pub httpd: bool,

    /// SQLite database to serve with --httpd.
    #[arg(long)]
    pub db: Option<PathBuf>,

    /// Port for --httpd.
    #[arg(long = "http-port", default_value_t = 9600)]
    pub http_port: u16,

    /// Listen IP for --httpd.
    #[arg(long = "listen-ip", default_value = "127.0.0.1")]
    pub listen_ip: String,
}

pub fn run_source_command(args: SourceArgs) -> Result<()> {
    let total_start = Instant::now();
    validate_source_args(&args)?;
    if args.httpd {
        let db = args.db.as_ref().expect("validated --db");
        let runtime = tokio::runtime::Runtime::new()?;
        return runtime.block_on(run_httpd(db.clone(), &args.listen_ip, args.http_port));
    }

    let bundle_path = args.bundle.as_ref().expect("validated --bundle");
    let mut bundle = SourceProfileBundle::load(bundle_path)?;

    let path_remaps = parse_path_remaps(&args.path_remaps)?;
    bundle.manifest.inputs.debug_elf_hints.extend(
        args.elfs
            .iter()
            .map(|path| path.to_string_lossy().to_string()),
    );
    bundle.manifest.inputs.source_root_hints.extend(
        args.source_roots
            .iter()
            .map(|path| path.to_string_lossy().to_string()),
    );
    bundle
        .manifest
        .inputs
        .path_remaps
        .extend(path_remaps.clone());
    fs::create_dir_all(&args.out_dir).with_context(|| {
        format!(
            "Failed to create source report output directory '{}'",
            args.out_dir.display()
        )
    })?;

    info!(
        "Validated source profile bundle '{}' for session '{}'",
        bundle_path.display(),
        bundle.manifest.session_id
    );
    info!(
        "Source report ready: elfs={}, source_roots={}, path_remaps={}, out='{}'",
        args.elfs.len(),
        args.source_roots.len(),
        path_remaps.len(),
        args.out_dir.display()
    );
    let shared_model =
        if args.html || args.xlsx || args.json || args.csv || args.annotated_source_out.is_some() {
        let start = Instant::now();
        let model = build_report_model(&bundle)?;
        log_timing("source_command.build_report_model", start.elapsed());
        Some(model)
    } else {
        None
    };

    if args.html {
        let model = shared_model.as_ref().expect("shared model built for html");
        let start = Instant::now();
        write_report_db_from_model(&bundle, model, &args.out_dir.join("SourceLine.sqlite"))?;
        log_timing("source_command.write_sqlite", start.elapsed());
        let start = Instant::now();
        write_html_summary_from_model(&bundle, model, &args.out_dir.join("SourceLine.html"))?;
        log_timing("source_command.write_html", start.elapsed());
        let start = Instant::now();
        write_report_launcher(&args.out_dir)?;
        log_timing("source_command.write_launcher", start.elapsed());
    }
    if args.xlsx {
        let model = shared_model.as_ref().expect("shared model built for xlsx");
        let start = Instant::now();
        write_summary_workbook_from_model(&bundle, model, &args.out_dir.join("SourceLine.xlsx"))?;
        log_timing("source_command.write_xlsx", start.elapsed());
    }
    if args.json {
        let model = shared_model.as_ref().expect("shared model built for json");
        let start = Instant::now();
        write_source_line_json_from_model(&bundle, model, &args.out_dir.join("SourceLine.json"))?;
        log_timing("source_command.write_json", start.elapsed());
    }
    if args.csv {
        let model = shared_model.as_ref().expect("shared model built for csv");
        let start = Instant::now();
        write_csv_exports_from_model(&bundle, model, &args.out_dir.join("csv"))?;
        log_timing("source_command.write_csv", start.elapsed());
    }
    if let Some(output_dir) = &args.annotated_source_out {
        let model = shared_model
            .as_ref()
            .expect("shared model built for annotated source");
        let start = Instant::now();
        write_annotated_sources_from_model(&bundle, model, output_dir)?;
        log_timing("source_command.write_annotated_source", start.elapsed());
    }
    log_timing("source_command.total", total_start.elapsed());
    Ok(())
}

fn log_timing(phase: &str, elapsed: Duration) {
    eprintln!("[MProfilerTiming] {phase} ({:.1}s)", elapsed.as_secs_f64());
}

fn validate_source_args(args: &SourceArgs) -> Result<()> {
    if args.httpd {
        let Some(db) = &args.db else {
            bail!("--httpd requires --db <SourceLine.sqlite>");
        };
        if !db.is_file() {
            bail!("SQLite report database '{}' does not exist", db.display());
        }
        return Ok(());
    }

    let Some(bundle) = &args.bundle else {
        bail!("source report generation requires --bundle <dir>");
    };
    if !bundle.exists() {
        bail!(
            "Source profile bundle '{}' does not exist",
            bundle.display()
        );
    }
    if !bundle.is_dir() {
        bail!(
            "Source profile bundle '{}' is not a directory",
            bundle.display()
        );
    }
    for elf in &args.elfs {
        if !elf.exists() {
            bail!("Debug ELF path '{}' does not exist", elf.display());
        }
    }
    for source_root in &args.source_roots {
        if !source_root.exists() {
            bail!("Source root '{}' does not exist", source_root.display());
        }
        if !source_root.is_dir() {
            bail!("Source root '{}' is not a directory", source_root.display());
        }
    }
    if args.out_dir.exists() && !args.out_dir.is_dir() {
        bail!(
            "Source report output path '{}' exists but is not a directory",
            args.out_dir.display()
        );
    }
    if let Some(output_dir) = &args.annotated_source_out {
        if output_dir.exists() && !output_dir.is_dir() {
            bail!(
                "Annotated source output path '{}' exists but is not a directory",
                output_dir.display()
            );
        }
    }
    Ok(())
}

fn parse_path_remaps(raw: &[String]) -> Result<Vec<PathRemap>> {
    raw.iter()
        .map(|entry| {
            let Some((from, to)) = entry.split_once('=') else {
                bail!("Invalid --path-remap '{}'; expected from=to", entry);
            };
            if from.is_empty() || to.is_empty() {
                bail!(
                    "Invalid --path-remap '{}'; from and to must be non-empty",
                    entry
                );
            }
            Ok(PathRemap {
                from: from.to_string(),
                to: to.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_path_remaps() {
        let remaps = parse_path_remaps(&["/android/path=D:/src".to_string()]).unwrap();
        assert_eq!(remaps[0].from, "/android/path");
        assert_eq!(remaps[0].to, "D:/src");
    }

    #[test]
    fn rejects_invalid_path_remap() {
        assert!(parse_path_remaps(&["missing_separator".to_string()]).is_err());
    }

    #[test]
    fn rejects_annotated_source_output_that_is_a_file() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let file = root.join("target/source_profile_tests/annotated_source_file");
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&file, "not a directory").unwrap();
        let args = SourceArgs {
            bundle: Some(root.join("fixtures/source_profile/minimal")),
            elfs: Vec::new(),
            source_roots: Vec::new(),
            path_remaps: Vec::new(),
            out_dir: root.join("target/source_profile_tests/cli_out"),
            html: false,
            xlsx: false,
            json: false,
            csv: false,
            no_browser: true,
            nonzero_threshold: 0.0,
            annotated_source_out: Some(file),
            httpd: false,
            db: None,
            http_port: 9600,
            listen_ip: "127.0.0.1".to_string(),
        };

        assert!(validate_source_args(&args)
            .unwrap_err()
            .to_string()
            .contains("Annotated source output path"));
    }

    #[test]
    fn source_command_generates_html_xlsx_and_annotated_source_in_one_invocation() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let out = root.join("target/source_profile_tests/cli_combined_html_annotated");
        let _ = fs::remove_dir_all(&out);

        let args = SourceArgs {
            bundle: Some(root.join("fixtures/source_profile/minimal")),
            elfs: Vec::new(),
            source_roots: vec![root.join("fixtures/source_profile/minimal/src")],
            path_remaps: Vec::new(),
            out_dir: out.clone(),
            html: true,
            xlsx: true,
            json: false,
            csv: false,
            no_browser: true,
            nonzero_threshold: 0.0,
            annotated_source_out: Some(out.join("annotated_source")),
            httpd: false,
            db: None,
            http_port: 9600,
            listen_ip: "127.0.0.1".to_string(),
        };

        run_source_command(args).unwrap();

        assert!(out.join("SourceLine.html").exists());
        assert!(out.join("SourceLine.xlsx").exists());
        assert!(out.join("SourceLine.sqlite").exists());
        assert!(out.join("run_html.bat").exists());
        assert!(out.join("annotated_source/manifest.json").exists());
    }
}

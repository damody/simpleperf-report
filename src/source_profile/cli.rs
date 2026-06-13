use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;
use log::info;

use super::bundle::SourceProfileBundle;
use super::html_report::write_html_summary;
use super::machine_report::{write_csv_exports, write_source_line_json};
use super::schema::PathRemap;
use super::xlsx_report::write_summary_workbook;

#[derive(Args, Debug, Clone)]
pub struct SourceArgs {
    /// Source profile bundle directory produced by realtime_profile.
    #[arg(long)]
    pub bundle: PathBuf,

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
}

pub fn run_source_command(args: SourceArgs) -> Result<()> {
    validate_source_args(&args)?;
    let mut bundle = SourceProfileBundle::load(&args.bundle)?;

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
        args.bundle.display(),
        bundle.manifest.session_id
    );
    info!(
        "Source report ready: elfs={}, source_roots={}, path_remaps={}, out='{}'",
        args.elfs.len(),
        args.source_roots.len(),
        path_remaps.len(),
        args.out_dir.display()
    );
    if args.html {
        write_html_summary(&bundle, &args.out_dir.join("SourceLine.html"))?;
    }
    if args.xlsx {
        write_summary_workbook(&bundle, &args.out_dir.join("SourceLine.xlsx"))?;
    }
    if args.json {
        write_source_line_json(&bundle, &args.out_dir.join("SourceLine.json"))?;
    }
    if args.csv {
        write_csv_exports(&bundle, &args.out_dir.join("csv"))?;
    }
    Ok(())
}

fn validate_source_args(args: &SourceArgs) -> Result<()> {
    if !args.bundle.exists() {
        bail!(
            "Source profile bundle '{}' does not exist",
            args.bundle.display()
        );
    }
    if !args.bundle.is_dir() {
        bail!(
            "Source profile bundle '{}' is not a directory",
            args.bundle.display()
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
}

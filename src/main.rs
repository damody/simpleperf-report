mod ffi;
mod html_writer;
mod model;
mod record_data;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use log::info;

#[derive(Parser, Debug)]
#[command(name = "simpleperf_report", about = "Generate HTML flamegraph report from perf.data")]
struct Args {
    /// Input perf.data file(s)
    #[arg(short = 'i', long = "record_file", default_value = "perf.data")]
    record_files: Vec<String>,

    /// Output HTML report path
    #[arg(short = 'o', long = "report_path", default_value = "report.html")]
    report_path: String,

    /// Min percentage of functions shown in the report
    #[arg(long = "min_func_percent", alias = "min-func-percent", default_value = "0.01")]
    min_func_percent: f64,

    /// Min percentage of callchains shown in the report
    #[arg(long = "min_callchain_percent", alias = "min-callchain-percent", default_value = "0.01")]
    min_callchain_percent: f64,

    /// Don't open report in browser
    #[arg(long = "no_browser", alias = "no-browser")]
    no_browser: bool,

    /// Aggregate samples by thread name instead of thread id
    #[arg(long = "aggregate-by-thread-name")]
    aggregate_by_thread_name: bool,

    /// Show ART interpreter frames
    #[arg(long = "show-art-frames")]
    show_art_frames: bool,

    /// Proguard mapping file(s)
    #[arg(long = "proguard-mapping-file")]
    proguard_mapping_files: Vec<String>,

    /// Trace off-cpu mode
    #[arg(long = "trace-offcpu")]
    trace_offcpu: Option<String>,

    /// Symbol file system directory
    #[arg(long)]
    symfs: Option<String>,

    /// Aggregate threads matching regex
    #[arg(long = "aggregate-threads")]
    aggregate_threads: Vec<String>,
}

fn find_dll_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    let exe_dir = exe.parent().unwrap_or(Path::new("."));

    // Try exe_dir/bin/windows/x86_64/
    let sub = exe_dir.join("bin").join("windows").join("x86_64");
    if sub.join("libsimpleperf_report.dll").exists() {
        return exe_dir.to_path_buf();
    }

    // Try alongside the exe
    if exe_dir.join("libsimpleperf_report.dll").exists() {
        return exe_dir.to_path_buf();
    }

    // Fallback: use working directory
    let cwd = std::env::current_dir().unwrap_or_default();
    let sub = cwd.join("bin").join("windows").join("x86_64");
    if sub.join("libsimpleperf_report.dll").exists() {
        return cwd;
    }

    cwd
}

fn apply_options(lib: &ffi::ReportLib, args: &Args) -> Result<()> {
    if args.show_art_frames {
        lib.show_art_frames(true);
    }
    for mapping_file in &args.proguard_mapping_files {
        lib.add_proguard_mapping_file(mapping_file)?;
    }
    if let Some(ref symfs) = args.symfs {
        lib.set_symfs(symfs)?;
    }
    Ok(())
}

fn apply_post_record_options(lib: &ffi::ReportLib, args: &Args) -> Result<()> {
    if let Some(ref mode) = args.trace_offcpu {
        lib.set_trace_offcpu_mode(mode)?;
    }
    if !args.aggregate_threads.is_empty() {
        lib.aggregate_threads(&args.aggregate_threads)?;
    }
    Ok(())
}

fn run(args: Args) -> Result<()> {
    let dll_dir = find_dll_dir();
    info!("DLL directory: {:?}", dll_dir);

    let mut record_data = record_data::RecordData::new();

    for record_file in &args.record_files {
        info!("Loading {}", record_file);
        let lib =
            ffi::ReportLib::new(&dll_dir).context("Failed to load libsimpleperf_report.dll")?;
        apply_options(&lib, &args)?;
        lib.show_ip_for_unknown_symbol();
        lib.set_record_file(record_file)?;
        apply_post_record_options(&lib, &args)?;
        record_data.load_record_file(&lib)?;
    }

    if args.aggregate_by_thread_name {
        record_data.aggregate_by_thread_name();
    }

    record_data.limit_percents(args.min_func_percent, args.min_callchain_percent);
    record_data.sort_call_graph_by_function_name();

    let record_info = record_data.gen_record_info();

    let output_path = PathBuf::from(&args.report_path);
    html_writer::write_html(&output_path, &record_info)?;
    info!("Report generated at '{}'", args.report_path);

    if !args.no_browser {
        let _ = open::that(&output_path);
    }

    Ok(())
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    if let Err(e) = run(args) {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

#![allow(dead_code)]

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SourceReportSummary {
    pub session_id: String,
    pub target_package: Option<String>,
    pub output_dir: PathBuf,
    pub warnings: Vec<String>,
}

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct SourceLine {
    pub file: PathBuf,
    pub line_number: u32,
    pub code: String,
}

pub fn load_source_file(path: &Path) -> Result<Vec<SourceLine>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("Failed to read '{}'", path.display()))?;
    Ok(text
        .lines()
        .enumerate()
        .map(|(index, line)| SourceLine {
            file: path.to_path_buf(),
            line_number: (index + 1) as u32,
            code: line.to_string(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_all_source_lines() {
        let file = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/source_profile/minimal/src/fixture.cpp");
        let lines = load_source_file(&file).unwrap();
        assert!(lines.len() >= 18);
        assert!(lines.iter().any(|line| line.line_number == 4));
        assert!(lines
            .iter()
            .any(|line| line.code.contains("sum += values[i] * 3")));
    }
}

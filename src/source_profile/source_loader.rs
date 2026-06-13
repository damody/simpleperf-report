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
    let bytes = fs::read(path).with_context(|| format!("Failed to read '{}'", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
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

    #[test]
    fn loads_non_utf8_source_lossily() {
        let path = std::env::temp_dir().join(format!(
            "mprofiler-non-utf8-source-{}.cpp",
            std::process::id()
        ));
        fs::write(&path, b"int ok = 1;\ninvalid \xff byte\n").unwrap();
        let lines = load_source_file(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].code, "int ok = 1;");
        assert!(lines[1].code.contains('\u{fffd}'));
    }
}

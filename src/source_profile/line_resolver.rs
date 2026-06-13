#![allow(dead_code)]

use std::path::Path;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

use super::schema::{PathRemap, ProcessMapRecord};

#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: PathBuf,
    pub line: u32,
    pub function: Option<String>,
    pub inline_stack: Vec<SourceLocationFrame>,
}

#[derive(Debug, Clone)]
pub struct SourceLocationFrame {
    pub file: PathBuf,
    pub line: u32,
    pub function: Option<String>,
}

pub trait LineResolver {
    fn resolve_ip(&self, module_id: &str, relative_address: u64) -> Option<SourceLocation>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRuntimeAddress {
    pub module_id: String,
    pub mapping_id: u64,
    pub relative_address: u64,
}

pub fn runtime_address_to_relative(
    maps: &[ProcessMapRecord],
    runtime_ip: u64,
) -> Option<ResolvedRuntimeAddress> {
    let mapping = maps
        .iter()
        .filter(|mapping| runtime_ip >= mapping.start && runtime_ip < mapping.end)
        .min_by_key(|mapping| mapping.end - mapping.start)?;

    let relative_address = if mapping.load_bias != 0 {
        if mapping.load_bias >= 0 {
            runtime_ip.checked_sub(mapping.load_bias as u64)?
        } else {
            runtime_ip.checked_add((-mapping.load_bias) as u64)?
        }
    } else {
        runtime_ip
            .checked_sub(mapping.start)?
            .checked_add(mapping.offset)?
    };

    Some(ResolvedRuntimeAddress {
        module_id: mapping.module_id.clone(),
        mapping_id: mapping.mapping_id,
        relative_address,
    })
}

pub fn resolve_source_path(
    dwarf_file: &Path,
    compile_dir: Option<&Path>,
    source_roots: &[PathBuf],
    path_remaps: &[PathRemap],
) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    candidates.push(dwarf_file.to_path_buf());

    if let Some(compile_dir) = compile_dir {
        if dwarf_file.is_relative() {
            candidates.push(compile_dir.join(dwarf_file));
        }
    }

    for remap in path_remaps {
        if let Some(remapped) = apply_path_remap(dwarf_file, remap) {
            candidates.push(remapped);
        }
    }

    for source_root in source_roots {
        if dwarf_file.is_relative() {
            candidates.push(source_root.join(dwarf_file));
        }
        if let Some(file_name) = dwarf_file.file_name() {
            candidates.push(source_root.join(file_name));
        }
    }

    candidates.into_iter().find(|candidate| candidate.exists())
}

fn apply_path_remap(path: &Path, remap: &PathRemap) -> Option<PathBuf> {
    let path_text = normalize_path_text(path);
    let from = normalize_remap_text(&remap.from);
    let to = remap.to.replace('\\', "/");
    let suffix = path_text.strip_prefix(&from)?;
    let suffix = suffix.trim_start_matches('/');
    Some(PathBuf::from(if suffix.is_empty() {
        to
    } else {
        format!("{to}/{suffix}")
    }))
}

fn normalize_path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn normalize_remap_text(path: &str) -> String {
    path.replace('\\', "/").trim_end_matches('/').to_string()
}

pub fn resolve_elf_address(
    elf_path: &Path,
    relative_address: u64,
) -> Result<Option<SourceLocation>> {
    let loader = addr2line::Loader::new(elf_path).map_err(|error| {
        anyhow!(
            "Failed to load DWARF from '{}': {error}",
            elf_path.display()
        )
    })?;
    let mut frames = loader.find_frames(relative_address).map_err(|error| {
        anyhow!(
            "Failed to resolve address 0x{relative_address:x} in '{}': {error}",
            elf_path.display()
        )
    })?;

    let mut inline_stack = Vec::new();
    while let Some(frame) = frames.next().with_context(|| {
        format!(
            "Failed to read DWARF frame for address 0x{relative_address:x} in '{}'",
            elf_path.display()
        )
    })? {
        let Some(location) = frame.location else {
            continue;
        };
        let Some(file) = location.file else {
            continue;
        };
        let line = location.line.unwrap_or(0);
        let function = frame
            .function
            .and_then(|function| function.demangle().ok().map(|name| name.into_owned()));
        inline_stack.push(SourceLocationFrame {
            file: PathBuf::from(file),
            line,
            function,
        });
    }

    let Some(first) = inline_stack.first().cloned() else {
        return Ok(None);
    };
    Ok(Some(SourceLocation {
        file: first.file,
        line: first.line,
        function: first.function,
        inline_stack,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_fixture_elf_address_to_source_line() {
        let elf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/source_profile/minimal/debug/libfixture.so");
        let location = resolve_elf_address(&elf, 0x4684).unwrap().unwrap();
        assert_eq!(location.line, 4);
        assert!(location
            .file
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with("fixture.cpp"));
    }

    #[test]
    fn converts_runtime_ip_to_elf_relative_address() {
        let mapping = ProcessMapRecord {
            mapping_id: 1,
            start: 0x4000_0000_0000,
            end: 0x4000_0001_0000,
            permissions: "r-xp".to_string(),
            offset: 0,
            device: "fd:00".to_string(),
            inode: 1,
            path: Some("/data/app/libfixture.so".to_string()),
            module_id: "libfixture.so".to_string(),
            load_bias: 0,
        };
        let resolved =
            runtime_address_to_relative(&[mapping], 0x4000_0000_4684).expect("address resolves");
        assert_eq!(resolved.module_id, "libfixture.so");
        assert_eq!(resolved.mapping_id, 1);
        assert_eq!(resolved.relative_address, 0x4684);
    }

    #[test]
    fn converts_runtime_ip_using_nonzero_load_bias() {
        let mapping = ProcessMapRecord {
            mapping_id: 1,
            start: 0x7000,
            end: 0x8000,
            permissions: "r-xp".to_string(),
            offset: 0,
            device: "fd:00".to_string(),
            inode: 1,
            path: Some("/data/app/libfixture.so".to_string()),
            module_id: "libfixture.so".to_string(),
            load_bias: 0x3000,
        };
        let resolved = runtime_address_to_relative(&[mapping], 0x7684).expect("address resolves");
        assert_eq!(resolved.relative_address, 0x4684);
    }

    #[test]
    fn resolves_source_path_by_source_root() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/source_profile/minimal/src");
        let resolved =
            resolve_source_path(Path::new("fixture.cpp"), None, &[root.clone()], &[]).unwrap();
        assert_eq!(resolved, root.join("fixture.cpp"));
    }

    #[test]
    fn resolves_source_path_by_path_remap() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/source_profile/minimal/src");
        let remap = PathRemap {
            from: "/build/source".to_string(),
            to: root.to_string_lossy().to_string(),
        };
        let resolved =
            resolve_source_path(Path::new("/build/source/fixture.cpp"), None, &[], &[remap])
                .unwrap();
        assert_eq!(resolved, root.join("fixture.cpp"));
    }
}

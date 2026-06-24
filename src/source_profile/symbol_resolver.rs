#![allow(dead_code)]

use std::path::PathBuf;
use std::{fs, io::Read, path::Path};

use anyhow::{Context, Result};
use object::{Object, ObjectSection};

use super::schema::BuildIdRecord;

#[derive(Debug, Clone)]
pub struct DebugElfCandidate {
    pub path: PathBuf,
    pub match_quality: ElfMatchQuality,
    pub has_dwarf_debug_info: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfMatchQuality {
    BuildIdExact,
    UserMapped,
    SonameAndSize,
    PathHint,
    Mismatch,
    Missing,
}

pub trait SymbolResolver {
    fn candidates(&self) -> &[DebugElfCandidate];
}

#[derive(Debug, Clone)]
pub struct ElfMatch {
    pub module_id: String,
    pub runtime_path: String,
    pub candidate_path: Option<PathBuf>,
    pub quality: ElfMatchQuality,
    pub reason: String,
    pub has_dwarf_debug_info: bool,
}

pub fn match_debug_elfs(
    modules: &[BuildIdRecord],
    candidates: &[DebugElfCandidate],
) -> Result<Vec<ElfMatch>> {
    let mut candidate_infos = Vec::new();
    for candidate in candidates {
        candidate_infos.push(CandidateInfo {
            path: candidate.path.clone(),
            build_id: read_elf_build_id(&candidate.path)?,
            file_size: fs::metadata(&candidate.path)
                .ok()
                .map(|metadata| metadata.len()),
            has_dwarf_debug_info: candidate.has_dwarf_debug_info,
        });
    }

    Ok(modules
        .iter()
        .map(|module| match_one_module(module, &candidate_infos))
        .collect())
}

pub fn discover_debug_elfs(paths: &[PathBuf]) -> Result<Vec<DebugElfCandidate>> {
    let mut candidates = Vec::new();
    for path in paths {
        if path.is_file() {
            maybe_push_elf(path, &mut candidates)?;
        } else if path.is_dir() {
            scan_dir(path, &mut candidates)?;
        }
    }
    candidates.sort_by(|a, b| a.path.cmp(&b.path));
    candidates.dedup_by(|a, b| a.path == b.path);
    Ok(candidates)
}

fn scan_dir(dir: &Path, candidates: &mut Vec<DebugElfCandidate>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("Failed to read '{}'", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, candidates)?;
        } else if path.is_file() {
            maybe_push_elf(&path, candidates)?;
        }
    }
    Ok(())
}

fn maybe_push_elf(path: &Path, candidates: &mut Vec<DebugElfCandidate>) -> Result<()> {
    if !looks_like_elf_candidate(path) {
        return Ok(());
    }
    if !has_elf_magic(path)? {
        return Ok(());
    }
    let has_dwarf_debug_info = match has_dwarf_debug_info(path) {
        Ok(has_debug_info) => has_debug_info,
        Err(err) => {
            eprintln!(
                "Warning: skipping debug ELF candidate '{}': failed to parse ELF: {err:#}",
                path.display()
            );
            return Ok(());
        }
    };
    candidates.push(DebugElfCandidate {
        path: path.to_path_buf(),
        match_quality: ElfMatchQuality::PathHint,
        has_dwarf_debug_info,
    });
    Ok(())
}

fn looks_like_elf_candidate(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    file_name.ends_with(".so")
        || file_name.ends_with(".debug")
        || file_name.contains(".so.")
        || path.components().any(|part| {
            part.as_os_str()
                .to_str()
                .is_some_and(|text| text == ".build-id" || text == "build-id")
        })
}

fn has_elf_magic(path: &Path) -> Result<bool> {
    let mut file =
        fs::File::open(path).with_context(|| format!("Failed to open '{}'", path.display()))?;
    let mut magic = [0_u8; 4];
    let read = file
        .read(&mut magic)
        .with_context(|| format!("Failed to read '{}'", path.display()))?;
    Ok(read == 4 && magic == [0x7f, b'E', b'L', b'F'])
}

#[derive(Debug)]
struct CandidateInfo {
    path: PathBuf,
    build_id: Option<String>,
    file_size: Option<u64>,
    has_dwarf_debug_info: bool,
}

fn match_one_module(module: &BuildIdRecord, candidates: &[CandidateInfo]) -> ElfMatch {
    if let Some(expected_build_id) = module.build_id.as_deref() {
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.build_id.as_deref() == Some(expected_build_id))
        {
            return make_match(
                module,
                candidate,
                ElfMatchQuality::BuildIdExact,
                "build-id exact match",
            );
        }
    }

    if let Some(candidate_path) = module.debug_elf_candidate_path.as_deref() {
        if let Some(candidate) = candidates.iter().find(|candidate| {
            candidate
                .path
                .to_string_lossy()
                .replace('\\', "/")
                .ends_with(candidate_path)
        }) {
            return make_match(
                module,
                candidate,
                ElfMatchQuality::UserMapped,
                "user/debug hint path match",
            );
        }
    }

    if let Some(soname) = module.soname.as_deref() {
        if let Some(candidate) = candidates.iter().find(|candidate| {
            candidate.path.file_name().and_then(|name| name.to_str()) == Some(soname)
                && module.file_size.is_some()
                && candidate.file_size == module.file_size
        }) {
            return make_match(
                module,
                candidate,
                ElfMatchQuality::SonameAndSize,
                "soname and file size match",
            );
        }
    }

    if let Some(candidate) = candidates.iter().find(|candidate| {
        module
            .runtime_path
            .rsplit('/')
            .next()
            .is_some_and(|file_name| {
                candidate.path.file_name().and_then(|name| name.to_str()) == Some(file_name)
            })
    }) {
        return make_match(
            module,
            candidate,
            ElfMatchQuality::PathHint,
            "runtime filename match",
        );
    }

    ElfMatch {
        module_id: module.module_id.clone(),
        runtime_path: module.runtime_path.clone(),
        candidate_path: None,
        quality: ElfMatchQuality::Missing,
        reason: "no debug ELF candidate matched".to_string(),
        has_dwarf_debug_info: false,
    }
}

fn make_match(
    module: &BuildIdRecord,
    candidate: &CandidateInfo,
    quality: ElfMatchQuality,
    reason: &str,
) -> ElfMatch {
    ElfMatch {
        module_id: module.module_id.clone(),
        runtime_path: module.runtime_path.clone(),
        candidate_path: Some(candidate.path.clone()),
        quality,
        reason: reason.to_string(),
        has_dwarf_debug_info: candidate.has_dwarf_debug_info,
    }
}

fn read_elf_build_id(path: &Path) -> Result<Option<String>> {
    let file_handle =
        fs::File::open(path).with_context(|| format!("Failed to open '{}'", path.display()))?;
    let data = unsafe {
        memmap2::MmapOptions::new()
            .map(&file_handle)
            .with_context(|| format!("Failed to mmap '{}'", path.display()))?
    };
    let file = object::File::parse(&*data)
        .with_context(|| format!("Failed to parse ELF '{}'", path.display()))?;
    Ok(file
        .build_id()
        .with_context(|| format!("Failed to read build-id from '{}'", path.display()))?
        .map(hex_lower))
}

fn has_dwarf_debug_info(path: &Path) -> Result<bool> {
    let file_handle =
        fs::File::open(path).with_context(|| format!("Failed to open '{}'", path.display()))?;
    let data = unsafe {
        memmap2::MmapOptions::new()
            .map(&file_handle)
            .with_context(|| format!("Failed to mmap '{}'", path.display()))?
    };
    let file = object::File::parse(&*data)
        .with_context(|| format!("Failed to parse ELF '{}'", path.display()))?;
    Ok(file.sections().any(|section| {
        matches!(
            section.name().ok(),
            Some(".debug_line" | ".debug_info" | ".zdebug_line" | ".zdebug_info")
        )
    }))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_fixture_debug_elf_from_file_and_dir() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/source_profile/minimal");
        let file_candidates = discover_debug_elfs(&[root.join("debug/libfixture.so")]).unwrap();
        assert_eq!(file_candidates.len(), 1);

        let dir_candidates = discover_debug_elfs(&[root.join("debug")]).unwrap();
        assert_eq!(dir_candidates.len(), 1);
        assert_eq!(
            dir_candidates[0]
                .path
                .file_name()
                .unwrap()
                .to_string_lossy(),
            "libfixture.so"
        );
    }

    #[test]
    fn matches_fixture_debug_elf_by_build_id() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/source_profile/minimal");
        let candidates = discover_debug_elfs(&[root.join("debug")]).unwrap();
        let build_ids: super::super::schema::SourceProfileBuildIds =
            serde_json::from_str(&fs::read_to_string(root.join("build_ids.json")).unwrap())
                .unwrap();
        let matches = match_debug_elfs(&build_ids.modules, &candidates).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].quality, ElfMatchQuality::BuildIdExact);
    }

    #[test]
    fn discover_debug_elfs_skips_unparseable_elf_candidates() {
        let path = std::env::temp_dir().join(format!(
            "mprofiler-discover-unparseable-elf-{}.so",
            std::process::id()
        ));
        fs::write(&path, b"\x7fELF\x02\x01\x01").unwrap();

        let candidates = discover_debug_elfs(&[path.clone()]).unwrap();

        assert!(candidates.is_empty());
        let _ = fs::remove_file(path);
    }
}

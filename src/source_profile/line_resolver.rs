#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

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
    resolve_with_loader(&loader, elf_path, relative_address)
}

pub struct CachedElfLineResolver {
    symbolizer_path: Option<PathBuf>,
    symbolizers: BTreeMap<PathBuf, SymbolizerProcess>,
    loaders: BTreeMap<PathBuf, addr2line::Loader>,
    locations: BTreeMap<(PathBuf, u64), Option<SourceLocation>>,
}

impl Default for CachedElfLineResolver {
    fn default() -> Self {
        Self {
            symbolizer_path: find_llvm_symbolizer(),
            symbolizers: BTreeMap::new(),
            loaders: BTreeMap::new(),
            locations: BTreeMap::new(),
        }
    }
}

impl CachedElfLineResolver {
    pub fn resolve(
        &mut self,
        elf_path: &Path,
        relative_address: u64,
    ) -> Result<Option<SourceLocation>> {
        let cache_key = (elf_path.to_path_buf(), relative_address);
        if let Some(location) = self.locations.get(&cache_key) {
            return Ok(location.clone());
        }

        if let Some(symbolizer_path) = self.symbolizer_path.clone() {
            let location =
                self.resolve_with_symbolizer(&symbolizer_path, elf_path, relative_address)?;
            self.locations.insert(cache_key, location.clone());
            return Ok(location);
        }

        if !self.loaders.contains_key(elf_path) {
            let loader = addr2line::Loader::new(elf_path).map_err(|error| {
                anyhow!(
                    "Failed to load DWARF from '{}': {error}",
                    elf_path.display()
                )
            })?;
            self.loaders.insert(elf_path.to_path_buf(), loader);
        }

        let loader = self
            .loaders
            .get(elf_path)
            .expect("loader inserted before lookup");
        let location = resolve_with_loader(loader, elf_path, relative_address)?;
        self.locations.insert(cache_key, location.clone());
        Ok(location)
    }

    fn resolve_with_symbolizer(
        &mut self,
        symbolizer_path: &Path,
        elf_path: &Path,
        relative_address: u64,
    ) -> Result<Option<SourceLocation>> {
        if !self.symbolizers.contains_key(elf_path) {
            let process = SymbolizerProcess::spawn(symbolizer_path, elf_path)?;
            self.symbolizers.insert(elf_path.to_path_buf(), process);
        }
        let process = self
            .symbolizers
            .get_mut(elf_path)
            .expect("symbolizer inserted before lookup");
        process.resolve(relative_address)
    }
}

struct SymbolizerProcess {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl SymbolizerProcess {
    fn spawn(symbolizer_path: &Path, elf_path: &Path) -> Result<Self> {
        let mut child = Command::new(symbolizer_path)
            .arg(format!("--obj={}", elf_path.display()))
            .arg("--functions=linkage")
            .arg("--inlining=false")
            .arg("--demangle")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                anyhow!(
                    "Failed to start llvm-symbolizer '{}' for '{}': {error}",
                    symbolizer_path.display(),
                    elf_path.display()
                )
            })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("llvm-symbolizer stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("llvm-symbolizer stdout unavailable"))?;
        Ok(Self {
            _child: child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn resolve(&mut self, relative_address: u64) -> Result<Option<SourceLocation>> {
        writeln!(self.stdin, "0x{relative_address:x}")?;
        self.stdin.flush()?;

        let function = read_symbolizer_line(&mut self.stdout)?;
        let file_line = read_symbolizer_line(&mut self.stdout)?;
        let mut separator = String::new();
        let _ = self.stdout.read_line(&mut separator)?;

        if function == "??" || file_line.starts_with("??:") {
            return Ok(None);
        }

        let Some((file, line)) = parse_symbolizer_file_line(&file_line) else {
            return Ok(None);
        };
        if line == 0 {
            return Ok(None);
        }

        Ok(Some(SourceLocation {
            file,
            line,
            function: Some(function),
            inline_stack: Vec::new(),
        }))
    }
}

fn read_symbolizer_line(stdout: &mut BufReader<ChildStdout>) -> Result<String> {
    let mut line = String::new();
    stdout.read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn parse_symbolizer_file_line(text: &str) -> Option<(PathBuf, u32)> {
    let mut parts = text.rsplitn(3, ':');
    let _column = parts.next()?;
    let line = parts.next()?.parse::<u32>().ok()?;
    let file = parts.next()?;
    Some((PathBuf::from(file), line))
}

fn find_llvm_symbolizer() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("MPROFILER_LLVM_SYMBOLIZER") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }

    for path in std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
    {
        let candidate = path.join(if cfg!(windows) {
            "llvm-symbolizer.exe"
        } else {
            "llvm-symbolizer"
        });
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    let local_app_data = std::env::var_os("LOCALAPPDATA")?;
    let ndk_root = PathBuf::from(local_app_data).join("Android/Sdk/ndk");
    let Ok(entries) = std::fs::read_dir(ndk_root) else {
        return None;
    };
    let mut candidates = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .map(|path| {
            path.join(if cfg!(windows) {
                "toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-symbolizer.exe"
            } else {
                "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-symbolizer"
            })
        })
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.pop()
}

fn resolve_with_loader(
    loader: &addr2line::Loader,
    elf_path: &Path,
    relative_address: u64,
) -> Result<Option<SourceLocation>> {
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

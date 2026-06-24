use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use object::{Object, ObjectSection, SectionKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub raw_line: String,
    pub class: InstructionClass,
    pub load_kind: Option<LoadInstructionKind>,
}

#[derive(Debug, Default, Clone)]
pub struct InstructionIndex {
    instructions: BTreeMap<u64, DecodedInstruction>,
}

impl InstructionIndex {
    pub fn parse_objdump_text(text: &str) -> Result<Self> {
        let mut index = InstructionIndex::default();
        for line in text.lines() {
            if let Some(instruction) = parse_objdump_instruction_line(line) {
                index.instructions.insert(instruction.address, instruction);
            }
        }
        Ok(index)
    }

    pub fn lookup(&self, address: u64) -> Option<&DecodedInstruction> {
        self.instructions.get(&address)
    }

    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

#[derive(Debug)]
pub struct SparseInstructionIndex {
    mmap: memmap2::Mmap,
    sections: Vec<InstructionSection>,
}

#[derive(Debug, Clone)]
struct InstructionSection {
    address: u64,
    size: u64,
    file_offset: u64,
    file_size: u64,
}

impl SparseInstructionIndex {
    pub fn lookup(&self, address: u64) -> Option<DecodedInstruction> {
        let section = self.sections.iter().find(|section| {
            let section_end = section.address.saturating_add(section.size);
            address >= section.address
                && address.checked_add(4).is_some_and(|end| end <= section_end)
        })?;
        let section_offset = address.checked_sub(section.address)?;
        if section_offset.checked_add(4)? > section.file_size {
            return None;
        }
        let file_offset = section.file_offset.checked_add(section_offset)?;
        let start = usize::try_from(file_offset).ok()?;
        let end = start.checked_add(4)?;
        let bytes = self.mmap.get(start..end)?;
        let word = u32::from_le_bytes(bytes.try_into().ok()?);
        let (class, load_kind) = classify_aarch64_instruction_word(word);
        Some(DecodedInstruction {
            address,
            mnemonic: String::new(),
            operands: String::new(),
            raw_line: format!("0x{address:x}: 0x{word:08x}"),
            class,
            load_kind,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }
}

pub fn build_sparse_instruction_index_from_elf(elf_path: &Path) -> Result<SparseInstructionIndex> {
    let file_handle =
        File::open(elf_path).with_context(|| format!("Failed to open '{}'", elf_path.display()))?;
    let mmap = unsafe {
        memmap2::MmapOptions::new()
            .map(&file_handle)
            .with_context(|| format!("Failed to mmap '{}'", elf_path.display()))?
    };
    let object = object::File::parse(&*mmap)
        .with_context(|| format!("Failed to parse ELF '{}'", elf_path.display()))?;
    let mut sections = Vec::new();
    for section in object.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let Some((file_offset, file_size)) = section.file_range() else {
            continue;
        };
        if file_size < 4 {
            continue;
        }
        sections.push(InstructionSection {
            address: section.address(),
            size: section.size().min(file_size),
            file_offset,
            file_size,
        });
    }
    sections.sort_by_key(|section| section.address);
    Ok(SparseInstructionIndex { mmap, sections })
}

pub fn build_instruction_index_from_elf(
    elf_path: &Path,
    objdump_path: Option<&Path>,
) -> Result<InstructionIndex> {
    let tool = objdump_path
        .map(Path::to_path_buf)
        .or_else(find_objdump)
        .ok_or_else(|| anyhow!("llvm-objdump/objdump was not found in PATH"))?;
    let output = Command::new(&tool)
        .arg("-d")
        .arg(elf_path)
        .output()
        .with_context(|| {
            format!(
                "Failed to run '{}' for '{}'",
                tool.display(),
                elf_path.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Disassembler '{}' failed for '{}': {}",
            tool.display(),
            elf_path.display(),
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout).with_context(|| {
        format!(
            "Disassembler output for '{}' was not UTF-8",
            elf_path.display()
        )
    })?;
    InstructionIndex::parse_objdump_text(&stdout)
}

fn classify_aarch64_instruction_word(
    instruction: u32,
) -> (InstructionClass, Option<LoadInstructionKind>) {
    if is_aarch64_barrier_or_sync(instruction) {
        return (InstructionClass::BarrierOrSync, None);
    }
    if is_aarch64_system_instruction(instruction) {
        return (InstructionClass::SystemInstruction, None);
    }
    if is_aarch64_branch(instruction) {
        return (InstructionClass::Branch, None);
    }
    if is_aarch64_prefetch(instruction) {
        return (
            InstructionClass::Prefetch,
            Some(LoadInstructionKind::Prefetch),
        );
    }
    if is_aarch64_load_store(instruction) {
        let is_vector = instruction & (1 << 26) != 0;
        let is_exclusive = (instruction & 0x3f00_0000) == 0x0800_0000;
        let is_pair = (instruction & 0x3a00_0000) == 0x2800_0000;
        let is_literal = (instruction & 0x1b00_0000) == 0x1800_0000;
        let is_load = is_literal || instruction & (1 << 22) != 0;
        if is_load {
            let kind = if is_exclusive {
                LoadInstructionKind::AtomicExclusive
            } else if is_pair && is_vector {
                LoadInstructionKind::VectorPair
            } else if is_pair {
                LoadInstructionKind::ScalarPair
            } else if is_literal {
                LoadInstructionKind::Literal
            } else if is_vector {
                LoadInstructionKind::VectorSingle
            } else if is_aarch64_sign_extending_load(instruction) {
                LoadInstructionKind::SignExtend
            } else {
                LoadInstructionKind::ScalarSingle
            };
            let class = if is_exclusive {
                InstructionClass::Atomic
            } else if is_vector {
                InstructionClass::VectorLoad
            } else {
                InstructionClass::ScalarLoad
            };
            return (class, Some(kind));
        }
        let class = if is_exclusive {
            InstructionClass::Atomic
        } else if is_vector {
            InstructionClass::VectorStore
        } else {
            InstructionClass::ScalarStore
        };
        return (class, None);
    }
    if is_aarch64_fp_simd(instruction) {
        return (InstructionClass::ComputeFpSimd, None);
    }
    (InstructionClass::ComputeInt, None)
}

fn is_aarch64_branch(instruction: u32) -> bool {
    matches!((instruction >> 26) & 0x3f, 0b000101 | 0b100101)
        || (instruction & 0x7e00_0000) == 0x3400_0000
        || (instruction & 0x7e00_0000) == 0x3600_0000
        || (instruction & 0xfe00_0000) == 0x5400_0000
        || (instruction & 0xfe00_0000) == 0xd600_0000
}

fn is_aarch64_barrier_or_sync(instruction: u32) -> bool {
    matches!(
        instruction,
        0xd503_30bf | 0xd503_31bf | 0xd503_32bf | 0xd503_33bf | 0xd503_3f9f
    ) || (instruction & 0xffff_f0ff) == 0xd503_305f
        || (instruction & 0xffff_f0ff) == 0xd503_309f
        || (instruction & 0xffff_f0ff) == 0xd503_30df
}

fn is_aarch64_system_instruction(instruction: u32) -> bool {
    (instruction & 0xffc0_0000) == 0xd500_0000
}

fn is_aarch64_load_store(instruction: u32) -> bool {
    ((instruction >> 25) & 0x7) == 0b100
}

fn is_aarch64_prefetch(instruction: u32) -> bool {
    (instruction & 0xffc0_0000) == 0xf980_0000
        || (instruction & 0xffe0_0c00) == 0xf880_0000
        || (instruction & 0xffe0_0c00) == 0xf8a0_0000
        || (instruction & 0xff00_0000) == 0xd800_0000
}

fn is_aarch64_sign_extending_load(instruction: u32) -> bool {
    matches!((instruction >> 30) & 0x3, 0b10 | 0b11) && instruction & (1 << 23) != 0
}

fn is_aarch64_fp_simd(instruction: u32) -> bool {
    matches!((instruction >> 25) & 0x7, 0b011 | 0b111)
}

fn parse_objdump_instruction_line(line: &str) -> Option<DecodedInstruction> {
    let trimmed = line.trim_start();
    let (address_text, rest) = trimmed.split_once(':')?;
    let address = u64::from_str_radix(address_text.trim(), 16).ok()?;
    let rest = rest.trim_start();
    if rest.is_empty() {
        return None;
    }

    let mut parts = rest.split_whitespace().peekable();
    while parts.peek().is_some_and(|part| is_machine_code_token(part)) {
        parts.next();
    }
    let mnemonic = parts.next()?.to_string();
    let operands = parts.collect::<Vec<_>>().join(" ");
    let class = classify_instruction(&mnemonic, &operands);
    let load_kind = classify_load_instruction(&mnemonic, &operands);

    Some(DecodedInstruction {
        address,
        mnemonic,
        operands,
        raw_line: line.to_string(),
        class,
        load_kind,
    })
}

fn is_machine_code_token(text: &str) -> bool {
    text.chars().all(|ch| ch.is_ascii_hexdigit()) && text.chars().any(|ch| ch.is_ascii_digit())
}

fn find_objdump() -> Option<PathBuf> {
    for env_name in ["MPROFILER_LLVM_OBJDUMP", "LLVM_OBJDUMP"] {
        if let Some(path) = std::env::var_os(env_name).map(PathBuf::from) {
            if path.is_file() {
                return Some(path);
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if let Some(path) = find_objdump_in_dirs([dir]) {
                return Some(path);
            }
        }
    }
    if let Some(path) = find_objdump_in_path() {
        return Some(path);
    }
    let ndk_roots = ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if let Some(path) = find_objdump_in_android_ndk_roots(ndk_roots.iter().map(PathBuf::as_path)) {
        return Some(path);
    }
    let mut sdk_roots = ["ANDROID_HOME", "ANDROID_SDK_ROOT"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        sdk_roots.push(PathBuf::from(local_app_data).join("Android/Sdk"));
    }
    if let Some(user_profile) = std::env::var_os("USERPROFILE") {
        sdk_roots.push(PathBuf::from(user_profile).join("AppData/Local/Android/Sdk"));
    }
    find_objdump_in_android_sdk_roots(sdk_roots.iter().map(PathBuf::as_path))
}

fn find_objdump_in_path() -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if let Some(path) = find_objdump_in_dirs([dir.as_path()]) {
            return Some(path);
        }
    }
    None
}

fn find_objdump_in_dirs<'a>(dirs: impl IntoIterator<Item = &'a Path>) -> Option<PathBuf> {
    for dir in dirs {
        for name in ["llvm-objdump.exe", "llvm-objdump", "objdump.exe", "objdump"] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn find_objdump_in_android_ndk_roots<'a>(
    roots: impl IntoIterator<Item = &'a Path>,
) -> Option<PathBuf> {
    let mut candidates = roots
        .into_iter()
        .flat_map(|root| {
            [
                root.join("toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-objdump.exe"),
                root.join("toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objdump"),
                root.join("toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-objdump"),
            ]
        })
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.pop()
}

fn find_objdump_in_android_sdk_roots<'a>(
    roots: impl IntoIterator<Item = &'a Path>,
) -> Option<PathBuf> {
    let mut ndk_roots = Vec::new();
    for root in roots {
        let ndk_root = root.join("ndk");
        let Ok(entries) = std::fs::read_dir(&ndk_root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                ndk_roots.push(path);
            }
        }
    }
    find_objdump_in_android_ndk_roots(ndk_roots.iter().map(PathBuf::as_path))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstructionClass {
    ComputeInt,
    ComputeFpSimd,
    ComputeCrypto,
    SystemInstruction,
    BarrierOrSync,
    ScalarLoad,
    ScalarStore,
    VectorLoad,
    VectorStore,
    Atomic,
    AcquireRelease,
    Prefetch,
    Branch,
    UnknownInstruction,
    MissingInstruction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoadInstructionKind {
    ScalarSingle,
    ScalarPair,
    SignExtend,
    VectorSingle,
    VectorPair,
    Literal,
    AtomicExclusive,
    Acquire,
    Prefetch,
    Unknown,
}

pub fn classify_instruction(mnemonic: &str, operands: &str) -> InstructionClass {
    let mnemonic = mnemonic.trim().to_ascii_lowercase();
    let operands = operands.trim().to_ascii_lowercase();
    let base = mnemonic.split('.').next().unwrap_or(mnemonic.as_str());

    if matches!(
        base,
        "dmb" | "dsb" | "isb" | "yield" | "wfe" | "wfi" | "sev" | "sevl"
    ) {
        return InstructionClass::BarrierOrSync;
    }
    if matches!(base, "mrs" | "msr" | "sys" | "sysl") {
        return InstructionClass::SystemInstruction;
    }
    if base.starts_with("aes") || base.starts_with("sha") || base == "pmull" || base == "pmull2" {
        return InstructionClass::ComputeCrypto;
    }
    if matches!(
        base,
        "b" | "bl" | "br" | "blr" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz"
    ) || mnemonic.starts_with("b.")
    {
        return InstructionClass::Branch;
    }
    if base == "prfm" {
        return InstructionClass::Prefetch;
    }
    if matches!(
        base,
        "ldxr"
            | "ldxrb"
            | "ldxrh"
            | "ldxp"
            | "stxr"
            | "stxrb"
            | "stxrh"
            | "stxp"
            | "cas"
            | "casa"
            | "casal"
            | "casl"
            | "casb"
            | "cash"
            | "swp"
            | "swpa"
            | "swpal"
            | "swpl"
            | "ldadd"
            | "ldadda"
            | "ldaddal"
            | "ldaddl"
            | "ldclr"
            | "ldeor"
            | "ldset"
            | "ldsmax"
            | "ldsmin"
            | "ldumax"
            | "ldumin"
    ) {
        return InstructionClass::Atomic;
    }
    if matches!(
        base,
        "ldar" | "ldarb" | "ldarh" | "ldapr" | "ldaprb" | "ldaprh" | "stlr" | "stlrb" | "stlrh"
    ) {
        return InstructionClass::AcquireRelease;
    }
    if is_load_mnemonic(base) {
        return if operands_start_with_vector_register(&operands) {
            InstructionClass::VectorLoad
        } else {
            InstructionClass::ScalarLoad
        };
    }
    if is_store_mnemonic(base) {
        return if operands_start_with_vector_register(&operands) {
            InstructionClass::VectorStore
        } else {
            InstructionClass::ScalarStore
        };
    }
    if base.starts_with('f')
        || base.starts_with("fc")
        || base.starts_with("scvtf")
        || base.starts_with("ucvtf")
        || base.starts_with("frec")
        || base.starts_with("frsqr")
        || operands_start_with_vector_register(&operands)
    {
        return InstructionClass::ComputeFpSimd;
    }
    if matches!(
        base,
        "add"
            | "adds"
            | "sub"
            | "subs"
            | "mul"
            | "madd"
            | "msub"
            | "smull"
            | "umull"
            | "and"
            | "ands"
            | "orr"
            | "eor"
            | "bic"
            | "lsl"
            | "lsr"
            | "asr"
            | "ror"
            | "mov"
            | "movk"
            | "movn"
            | "movz"
            | "cmp"
            | "cmn"
            | "tst"
            | "sdiv"
            | "udiv"
    ) {
        return InstructionClass::ComputeInt;
    }
    InstructionClass::UnknownInstruction
}

pub fn classify_load_instruction(mnemonic: &str, operands: &str) -> Option<LoadInstructionKind> {
    let mnemonic = mnemonic.trim().to_ascii_lowercase();
    let operands = operands.trim().to_ascii_lowercase();
    let base = mnemonic.split('.').next().unwrap_or(mnemonic.as_str());

    if base == "prfm" {
        return Some(LoadInstructionKind::Prefetch);
    }
    if matches!(
        base,
        "ldxr" | "ldxrb" | "ldxrh" | "ldxp" | "ldaxr" | "ldaxrb" | "ldaxrh" | "ldaxp"
    ) {
        return Some(LoadInstructionKind::AtomicExclusive);
    }
    if matches!(
        base,
        "ldar" | "ldarb" | "ldarh" | "ldapr" | "ldaprb" | "ldaprh"
    ) {
        return Some(LoadInstructionKind::Acquire);
    }
    if matches!(
        base,
        "ldrsb" | "ldrsh" | "ldrsw" | "ldursb" | "ldursh" | "ldursw" | "ldpsw"
    ) {
        return Some(LoadInstructionKind::SignExtend);
    }
    if matches!(base, "ldp" | "ldnp") {
        return Some(if operands_start_with_vector_register(&operands) {
            LoadInstructionKind::VectorPair
        } else {
            LoadInstructionKind::ScalarPair
        });
    }
    if base.starts_with("ldr") || base.starts_with("ldur") {
        if !operands.contains('[') {
            return Some(LoadInstructionKind::Literal);
        }
        return Some(if operands_start_with_vector_register(&operands) {
            LoadInstructionKind::VectorSingle
        } else {
            LoadInstructionKind::ScalarSingle
        });
    }
    if base.starts_with("ld") {
        return Some(LoadInstructionKind::Unknown);
    }
    None
}

fn is_load_mnemonic(base: &str) -> bool {
    base.starts_with("ldr")
        || base.starts_with("ldur")
        || base.starts_with("ldp")
        || base.starts_with("ldpsw")
        || base.starts_with("ldrs")
}

fn is_store_mnemonic(base: &str) -> bool {
    base.starts_with("str") || base.starts_with("stur") || base.starts_with("stp")
}

fn operands_start_with_vector_register(operands: &str) -> bool {
    let first = operands
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('{')
        .trim();
    matches!(
        first.chars().next(),
        Some('v' | 'q' | 'd' | 's' | 'h' | 'b')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_compute_and_system_mnemonics() {
        assert_eq!(
            classify_instruction("add", "x0, x1, x2"),
            InstructionClass::ComputeInt
        );
        assert_eq!(
            classify_instruction("fadd", "s0, s1, s2"),
            InstructionClass::ComputeFpSimd
        );
        assert_eq!(
            classify_instruction("aesd", "v0.16b, v1.16b"),
            InstructionClass::ComputeCrypto
        );
        assert_eq!(
            classify_instruction("mrs", "x0, cntvct_el0"),
            InstructionClass::SystemInstruction
        );
        assert_eq!(
            classify_instruction("dmb", "ish"),
            InstructionClass::BarrierOrSync
        );
    }

    #[test]
    fn classifies_memory_mnemonics() {
        assert_eq!(
            classify_instruction("ldr", "x0, [x1]"),
            InstructionClass::ScalarLoad
        );
        assert_eq!(
            classify_instruction("ldr", "q0, [x1]"),
            InstructionClass::VectorLoad
        );
        assert_eq!(
            classify_instruction("str", "x0, [x1]"),
            InstructionClass::ScalarStore
        );
        assert_eq!(
            classify_instruction("stp", "q0, q1, [x2]"),
            InstructionClass::VectorStore
        );
        assert_eq!(
            classify_instruction("ldxr", "x0, [x1]"),
            InstructionClass::Atomic
        );
        assert_eq!(
            classify_instruction("stlr", "x0, [x1]"),
            InstructionClass::AcquireRelease
        );
        assert_eq!(
            classify_instruction("prfm", "pldl1keep, [x0]"),
            InstructionClass::Prefetch
        );
    }

    #[test]
    fn classifies_detailed_load_instruction_kinds() {
        assert_eq!(
            classify_load_instruction("ldr", "x0, [x1]"),
            Some(LoadInstructionKind::ScalarSingle)
        );
        assert_eq!(
            classify_load_instruction("ldp", "x0, x1, [sp]"),
            Some(LoadInstructionKind::ScalarPair)
        );
        assert_eq!(
            classify_load_instruction("ldrsw", "x0, [x1]"),
            Some(LoadInstructionKind::SignExtend)
        );
        assert_eq!(
            classify_load_instruction("ldr", "q0, [x1]"),
            Some(LoadInstructionKind::VectorSingle)
        );
        assert_eq!(
            classify_load_instruction("ldp", "q0, q1, [x2]"),
            Some(LoadInstructionKind::VectorPair)
        );
        assert_eq!(
            classify_load_instruction("ldr", "x0, 0x1234"),
            Some(LoadInstructionKind::Literal)
        );
        assert_eq!(
            classify_load_instruction("ldxr", "x0, [x1]"),
            Some(LoadInstructionKind::AtomicExclusive)
        );
        assert_eq!(
            classify_load_instruction("ldapr", "x0, [x1]"),
            Some(LoadInstructionKind::Acquire)
        );
        assert_eq!(
            classify_load_instruction("prfm", "pldl1keep, [x0]"),
            Some(LoadInstructionKind::Prefetch)
        );
        assert_eq!(classify_load_instruction("add", "x0, x1, x2"), None);
    }

    #[test]
    fn classifies_branch_and_unknown() {
        assert_eq!(
            classify_instruction("b.eq", "0x1000"),
            InstructionClass::Branch
        );
        assert_eq!(classify_instruction("ret", ""), InstructionClass::Branch);
        assert_eq!(
            classify_instruction("unknown_mnemonic", "x0"),
            InstructionClass::UnknownInstruction
        );
        assert_eq!(
            InstructionClass::MissingInstruction,
            InstructionClass::MissingInstruction
        );
    }

    #[test]
    fn parses_objdump_lines_into_instruction_index() {
        let text = r#"
0000000000001000 <Tick>:
    1000: d503201f    nop
    1004: 4e20d400    fadd v0.4s, v0.4s, v0.4s
    1008: f9400020    ldr x0, [x1]
"#;
        let index = InstructionIndex::parse_objdump_text(text).unwrap();

        let inst = index.lookup(0x1004).unwrap();
        assert_eq!(inst.address, 0x1004);
        assert_eq!(inst.mnemonic, "fadd");
        assert_eq!(inst.operands, "v0.4s, v0.4s, v0.4s");
        assert_eq!(inst.class, InstructionClass::ComputeFpSimd);
    }

    #[test]
    fn instruction_index_requires_exact_lookup() {
        let text = "    2000: f9400020    ldr x0, [x1]\n";
        let index = InstructionIndex::parse_objdump_text(text).unwrap();

        assert!(index.lookup(0x2000).is_some());
        assert!(index.lookup(0x2002).is_none());
    }

    #[test]
    fn finds_android_ndk_objdump_from_sdk_root() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/source_profile_tests/fake_android_sdk");
        let bin = root.join("ndk/29.0.13113456/toolchains/llvm/prebuilt/windows-x86_64/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let objdump = bin.join("llvm-objdump.exe");
        std::fs::write(&objdump, "").unwrap();

        assert_eq!(
            find_objdump_in_android_sdk_roots([root.as_path()]),
            Some(objdump)
        );
    }
}

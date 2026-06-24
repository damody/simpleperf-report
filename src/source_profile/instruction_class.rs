use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub raw_line: String,
    pub class: InstructionClass,
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

    Some(DecodedInstruction {
        address,
        mnemonic,
        operands,
        raw_line: line.to_string(),
        class,
    })
}

fn is_machine_code_token(text: &str) -> bool {
    text.chars().all(|ch| ch.is_ascii_hexdigit()) && text.chars().any(|ch| ch.is_ascii_digit())
}

fn find_objdump() -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for name in ["llvm-objdump.exe", "llvm-objdump", "objdump.exe", "objdump"] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
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
}

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
}

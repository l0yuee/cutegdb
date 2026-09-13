//! The x64dbg "info box": what the selected instruction touches, evaluated against the paused state.

use crate::arch::Arch;
use crate::disasm::{InsnKind, Instruction};

pub struct InfoContext<'a> {
    pub arch: Arch,
    /// Full-width register value by gdb name (`rax`, `eflags`, `x0`).
    pub register: &'a dyn Fn(&str) -> Option<u64>,
    /// Little-endian value of `size` bytes at an address.
    pub memory: &'a dyn Fn(u64, usize) -> Option<u64>,
    pub label: &'a dyn Fn(u64) -> Option<String>,
}

/// Info box lines: jump condition, memory operands, registers used and the branch destination.
pub fn describe_instruction(insn: &Instruction, ctx: &InfoContext) -> Vec<String> {
    let mut lines = Vec::new();
    if insn.kind == InsnKind::ConditionalJump
        && ctx.arch != Arch::AArch64
        && let Some(flags) = (ctx.register)("eflags")
    {
        let count = register_value(ctx, if ctx.arch == Arch::X86 { "ecx" } else { "rcx" });
        if let Some(taken) = jump_taken(&insn.mnemonic, flags, count) {
            lines.push(if taken { "Jump is taken" } else { "Jump is not taken" }.to_owned());
        }
    }

    let next = insn.address.wrapping_add(insn.len() as u64);
    for operand in memory_operands(&insn.operands) {
        let Some(address) = effective_address(operand.expression, next, ctx) else { continue };
        let shown = ctx.arch.format_address(address);
        if insn.mnemonic == "lea" {
            lines.push(format!("{}={shown}", operand.text));
            continue;
        }
        let size = operand.size.unwrap_or(ctx.arch.pointer_size());
        match (ctx.memory)(address, size) {
            Some(value) => lines.push(format!("{}=[{shown}]={value:X}", operand.text)),
            None => lines.push(format!("{}=[{shown}]=???", operand.text)),
        }
    }

    let mut seen: Vec<&str> = Vec::new();
    for token in insn.operands.split(|c: char| !c.is_ascii_alphanumeric()) {
        if token.is_empty() || seen.contains(&token) {
            continue;
        }
        if let Some(value) = register_value(ctx, token) {
            seen.push(token);
            lines.push(format!("{token}={value:X}"));
        }
    }

    if let Some(target) = insn.target {
        let label = (ctx.label)(target).map(|l| format!(" {l}")).unwrap_or_default();
        lines.push(format!("Destination: {}{label}", ctx.arch.format_address(target)));
    }
    lines
}

/// Whether an x86 conditional jump is taken for the given flags (and rCX for the `j*cxz` family).
pub fn jump_taken(mnemonic: &str, flags: u64, count: Option<u64>) -> Option<bool> {
    let bit = |n: u32| (flags >> n) & 1 == 1;
    let (cf, pf, zf, sf, of) = (bit(0), bit(2), bit(6), bit(7), bit(11));
    Some(match mnemonic {
        "je" | "jz" => zf,
        "jne" | "jnz" => !zf,
        "ja" | "jnbe" => !cf && !zf,
        "jae" | "jnb" | "jnc" => !cf,
        "jb" | "jnae" | "jc" => cf,
        "jbe" | "jna" => cf || zf,
        "jg" | "jnle" => !zf && sf == of,
        "jge" | "jnl" => sf == of,
        "jl" | "jnge" => sf != of,
        "jle" | "jng" => zf || sf != of,
        "js" => sf,
        "jns" => !sf,
        "jo" => of,
        "jno" => !of,
        "jp" | "jpe" => pf,
        "jnp" | "jpo" => !pf,
        "jcxz" => count? & 0xffff == 0,
        "jecxz" => count? & 0xffff_ffff == 0,
        "jrcxz" => count? == 0,
        _ => return None,
    })
}

struct MemoryOperand<'a> {
    text: &'a str,
    size: Option<usize>,
    expression: &'a str,
}

fn memory_operands(operands: &str) -> Vec<MemoryOperand<'_>> {
    split_top_level(operands)
        .into_iter()
        .filter_map(|part| {
            let (open, close) = (part.find('[')?, part.rfind(']')?);
            let prefix = part[..open].trim();
            // Segment overrides (fs:[...]) need the segment base, which gdb does not expose here.
            if prefix.ends_with(':') {
                return None;
            }
            let size = match prefix.split_whitespace().next() {
                None => None,
                Some("byte") => Some(1),
                Some("word") => Some(2),
                Some("dword") => Some(4),
                Some("qword") => Some(8),
                Some(_) => return None,
            };
            Some(MemoryOperand { text: part.trim(), size, expression: &part[open + 1..close] })
        })
        .collect()
}

fn split_top_level(text: &str) -> Vec<&str> {
    let (mut parts, mut depth, mut start) = (Vec::new(), 0i32, 0);
    for (i, c) in text.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

fn effective_address(expression: &str, next: u64, ctx: &InfoContext) -> Option<u64> {
    let normalized = expression.replace(" - ", " + -").replace(", ", "+").replace(" + ", "+").replace('#', "");
    let mut total: u64 = 0;
    for term in normalized.split('+') {
        let term = term.trim();
        let (negative, term) = match term.strip_prefix('-') {
            Some(rest) => (true, rest.trim()),
            None => (false, term),
        };
        let value = match term.split_once('*') {
            Some((a, b)) => operand_value(a, next, ctx)?.wrapping_mul(operand_value(b, next, ctx)?),
            None => operand_value(term, next, ctx)?,
        };
        total = if negative { total.wrapping_sub(value) } else { total.wrapping_add(value) };
    }
    Some(if ctx.arch == Arch::X86 { total & 0xffff_ffff } else { total })
}

fn operand_value(term: &str, next: u64, ctx: &InfoContext) -> Option<u64> {
    let term = term.trim();
    if term.is_empty() {
        return None;
    }
    if term == "rip" || term == "eip" {
        return Some(next);
    }
    if let Some(hex) = term.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    if term.chars().all(|c| c.is_ascii_digit()) {
        return term.parse().ok();
    }
    register_value(ctx, term)
}

/// Register value including x86 sub-registers (eax, ax, al, ah, r8d, ...) and AArch64 w-registers.
fn register_value(ctx: &InfoContext, name: &str) -> Option<u64> {
    if let Some(value) = (ctx.register)(name) {
        return Some(value);
    }
    let (parent, shift, mask) = subregister(ctx.arch, name)?;
    Some(((ctx.register)(&parent)? >> shift) & mask)
}

fn subregister(arch: Arch, name: &str) -> Option<(String, u32, u64)> {
    match arch {
        Arch::AArch64 => {
            let n: u32 = name.strip_prefix('w')?.parse().ok()?;
            (n <= 30).then(|| (format!("x{n}"), 0, 0xffff_ffff))
        }
        Arch::X86 | Arch::X86_64 => {
            let wide = arch == Arch::X86_64;
            let full = |stem: &str| format!("{}{stem}", if wide { "r" } else { "e" });
            if wide && let Some(rest) = name.strip_prefix('r') {
                let digits = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
                if digits > 0 {
                    let mask = match &rest[digits..] {
                        "d" => 0xffff_ffff,
                        "w" => 0xffff,
                        "b" | "l" => 0xff,
                        _ => return None,
                    };
                    return Some((format!("r{}", &rest[..digits]), 0, mask));
                }
            }
            match name {
                "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp" if wide => {
                    Some((full(&name[1..]), 0, 0xffff_ffff))
                }
                "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp" => Some((full(name), 0, 0xffff)),
                "al" | "bl" | "cl" | "dl" => Some((full(&format!("{}x", &name[..1])), 0, 0xff)),
                "ah" | "bh" | "ch" | "dh" => Some((full(&format!("{}x", &name[..1])), 8, 0xff)),
                "sil" | "dil" | "bpl" | "spl" if wide => Some((full(&name[..2]), 0, 0xff)),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn insn(mnemonic: &str, operands: &str, kind: InsnKind, target: Option<u64>) -> Instruction {
        Instruction {
            address: 0x1000,
            bytes: vec![0; 4],
            mnemonic: mnemonic.into(),
            operands: operands.into(),
            kind,
            target,
        }
    }

    fn describe(arch: Arch, regs: &[(&str, u64)], instruction: &Instruction) -> Vec<String> {
        let regs: HashMap<&str, u64> = regs.iter().copied().collect();
        let register = |n: &str| regs.get(n).copied();
        let memory = |a: u64, size: usize| (a == 0x7fff_ffff_dff8 && size == 8).then_some(0x2a);
        let label = |a: u64| (a == 0x401000).then(|| "hello.main".to_owned());
        describe_instruction(instruction, &InfoContext { arch, register: &register, memory: &memory, label: &label })
    }

    const REGS: [(&str, u64); 4] =
        [("rax", 0x1122_3344_5566_7788), ("rbp", 0x7fff_ffff_e000), ("rcx", 2), ("eflags", 0x246)];

    #[test]
    fn memory_operands_and_registers() {
        let lines = describe(Arch::X86_64, &REGS, &insn("mov", "qword ptr [rbp - 8], rax", InsnKind::Normal, None));
        assert_eq!(lines, ["qword ptr [rbp - 8]=[00007FFFFFFFDFF8]=2A", "rbp=7FFFFFFFE000", "rax=1122334455667788"]);

        let lines = describe(Arch::X86_64, &REGS, &insn("mov", "eax, dword ptr [rcx*8 + 0x10]", InsnKind::Normal, None));
        assert_eq!(lines, ["dword ptr [rcx*8 + 0x10]=[0000000000000020]=???", "eax=55667788", "rcx=2"]);

        let lines = describe(Arch::X86_64, &REGS, &insn("lea", "rax, [rip + 0x10]", InsnKind::Normal, None));
        assert_eq!(lines, ["[rip + 0x10]=0000000000001014", "rax=1122334455667788"]);

        let lines = describe(Arch::X86_64, &REGS, &insn("mov", "byte ptr fs:[0x28], al", InsnKind::Normal, None));
        assert_eq!(lines, ["al=88"]);

        let lines = describe(Arch::X86_64, &REGS, &insn("movzx", "ecx, ah", InsnKind::Normal, None));
        assert_eq!(lines, ["ecx=2", "ah=77"]);
    }

    #[test]
    fn branches() {
        let lines = describe(Arch::X86_64, &REGS, &insn("je", "0x401000", InsnKind::ConditionalJump, Some(0x401000)));
        assert_eq!(lines, ["Jump is taken", "Destination: 0000000000401000 hello.main"]);
        let lines = describe(Arch::X86_64, &REGS, &insn("jne", "0x2000", InsnKind::ConditionalJump, Some(0x2000)));
        assert_eq!(lines, ["Jump is not taken", "Destination: 0000000000002000"]);
    }

    #[test]
    fn aarch64_operands() {
        let regs = [("sp", 0x7fff_ffff_dfe8), ("x0", 5)];
        let lines = describe(Arch::AArch64, &regs, &insn("ldr", "w0, [sp, #0x10]", InsnKind::Normal, None));
        assert_eq!(lines, ["[sp, #0x10]=[00007FFFFFFFDFF8]=2A", "w0=5", "sp=7FFFFFFFDFE8"]);
    }

    #[test]
    fn jump_conditions() {
        const ZF: u64 = 1 << 6;
        const SF: u64 = 1 << 7;
        const OF: u64 = 1 << 11;
        const CF: u64 = 1;
        assert_eq!(jump_taken("jz", ZF, None), Some(true));
        assert_eq!(jump_taken("jg", 0, None), Some(true));
        assert_eq!(jump_taken("jg", SF, None), Some(false));
        assert_eq!(jump_taken("jge", SF | OF, None), Some(true));
        assert_eq!(jump_taken("jl", SF, None), Some(true));
        assert_eq!(jump_taken("jle", ZF, None), Some(true));
        assert_eq!(jump_taken("ja", CF, None), Some(false));
        assert_eq!(jump_taken("jbe", CF, None), Some(true));
        assert_eq!(jump_taken("jrcxz", 0, Some(0)), Some(true));
        assert_eq!(jump_taken("jecxz", 0, Some(0x1_0000_0000)), Some(true));
        assert_eq!(jump_taken("jrcxz", 0, None), None);
        assert_eq!(jump_taken("jmp", 0, None), None);
    }
}

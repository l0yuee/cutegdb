//! x64dbg-style assembly ("Space" in the disassembly) on top of GNU `as`.
//!
//! The text is rewritten for GAS (hex numbers by default, labels resolved), and direct branch targets
//! become offsets from a label at the start of the code, so GAS computes displacements and picks
//! short jumps itself without a linker. The machine code is read from the object's `.text` section.

use crate::arch::Arch;
use object::{Object, ObjectSection};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AsmError {
    #[error("{0}")]
    Invalid(String),
    #[error("assembler not available: {0}")]
    Tool(String),
}

/// Assembles one instruction (or several separated by `;`) as it would be placed at `address`.
/// `resolve` maps symbol names such as `hello.add` to addresses.
pub fn assemble(arch: Arch, text: &str, address: u64, resolve: &dyn Fn(&str) -> Option<u64>) -> Result<Vec<u8>, AsmError> {
    let statements: Vec<String> = text
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| prepare_statement(arch, s, address, resolve))
        .collect::<Result<_, _>>()?;
    if statements.is_empty() {
        return Err(AsmError::Invalid("nothing to assemble".into()));
    }
    let (tool, flags, header): (&str, &[&str], &str) = match arch {
        Arch::X86_64 => ("as", &["--64"], ".intel_syntax noprefix\n.code64\n"),
        Arch::X86 => ("as", &["--32"], ".intel_syntax noprefix\n.code32\n"),
        Arch::AArch64 => ("aarch64-linux-gnu-as", &[], ""),
    };

    let dir = std::env::temp_dir().join(format!("cutegdb-asm-{}-{:x}", std::process::id(), address ^ unique()));
    std::fs::create_dir_all(&dir).map_err(|e| AsmError::Tool(e.to_string()))?;
    let source = dir.join("input.s");
    let object_path = dir.join("input.o");
    let program = format!("{header}.text\n__cutegdb_start:\n{}\n", statements.join("\n"));
    let result = (|| {
        std::fs::write(&source, program).map_err(|e| AsmError::Tool(e.to_string()))?;
        let output = Command::new(tool)
            .args(flags)
            .arg("-o")
            .arg(&object_path)
            .arg(&source)
            .output()
            .map_err(|e| AsmError::Tool(format!("{tool}: {e}")))?;
        if !output.status.success() {
            return Err(AsmError::Invalid(gas_message(&String::from_utf8_lossy(&output.stderr))));
        }
        let data = std::fs::read(&object_path).map_err(|e| AsmError::Tool(e.to_string()))?;
        let file = object::File::parse(&*data).map_err(|e| AsmError::Tool(e.to_string()))?;
        let text_section = file.section_by_name(".text").ok_or_else(|| AsmError::Tool("no .text section".into()))?;
        if file.sections().any(|s| s.relocations().next().is_some()) {
            return Err(AsmError::Invalid("unresolved symbol".into()));
        }
        let bytes = text_section.data().map_err(|e| AsmError::Tool(e.to_string()))?.to_vec();
        if bytes.is_empty() { Err(AsmError::Invalid("no code produced".into())) } else { Ok(bytes) }
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// First error line from GAS without the `file:line:` prefix.
fn gas_message(stderr: &str) -> String {
    stderr
        .lines()
        .find(|l| l.contains("Error"))
        .map(|l| l.split_once("Error: ").map_or(l, |(_, m)| m).trim().to_owned())
        .unwrap_or_else(|| stderr.trim().to_owned())
}

fn prepare_statement(arch: Arch, statement: &str, address: u64, resolve: &dyn Fn(&str) -> Option<u64>) -> Result<String, AsmError> {
    if statement.contains(['\n', '.']) && statement.trim_start().starts_with('.') {
        return Err(AsmError::Invalid("assembler directives are not allowed".into()));
    }
    let (mnemonic, operands) = match statement.split_once(char::is_whitespace) {
        Some((m, o)) => (m.to_ascii_lowercase(), o.trim()),
        None => (statement.to_ascii_lowercase(), ""),
    };
    if arch == Arch::AArch64 {
        let operands = rewrite_branch_target(arch, &mnemonic, operands, address, |word| resolve(word));
        return Ok(format!("{mnemonic} {operands}"));
    }
    let converted = convert_words(operands, resolve);
    let operands = rewrite_branch_target(arch, &mnemonic, &converted, address, |_| None);
    Ok(format!("{mnemonic} {operands}"))
}

/// x64dbg operand syntax to GAS: bare hex words become `0x` numbers, `.123` decimals lose the dot,
/// and resolvable symbols become their address. Registers never consist only of hex digits.
fn convert_words(operands: &str, resolve: &dyn Fn(&str) -> Option<u64>) -> String {
    let is_word = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '$');
    let mut out = String::with_capacity(operands.len() + 8);
    let mut rest = operands;
    while let Some(start) = rest.find(is_word) {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail.find(|c: char| !is_word(c)).unwrap_or(tail.len());
        let word = &tail[..end];
        let replacement = if let Some(decimal) = word.strip_prefix('.').filter(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit())) {
            decimal.to_owned()
        } else if word.starts_with("0x") || word.starts_with("0X") {
            word.to_owned()
        } else if let Some(address) = resolve(word) {
            format!("0x{address:x}")
        } else if word.chars().all(|c| c.is_ascii_hexdigit()) {
            format!("0x{word}")
        } else {
            word.to_owned()
        };
        out.push_str(&replacement);
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// `jmp 0x401000` → `jmp __cutegdb_start+0x...`: relative to the start label, GAS resolves the
/// displacement locally and chooses the shortest encoding.
fn rewrite_branch_target(arch: Arch, mnemonic: &str, operands: &str, address: u64, resolve: impl Fn(&str) -> Option<u64>) -> String {
    let is_branch = match arch {
        Arch::X86 | Arch::X86_64 => mnemonic.starts_with('j') || mnemonic == "call" || mnemonic.starts_with("loop"),
        Arch::AArch64 => mnemonic == "b" || mnemonic == "bl" || mnemonic.starts_with("b."),
    };
    if !is_branch {
        return operands.to_owned();
    }
    let target_text = operands.trim().trim_start_matches('#');
    let target = match target_text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None if arch == Arch::AArch64 => resolve(target_text)
            .or_else(|| u64::from_str_radix(target_text, 16).ok().filter(|_| target_text.chars().all(|c| c.is_ascii_hexdigit()))),
        None => None,
    };
    match target {
        Some(target) if target >= address => format!("__cutegdb_start+0x{:x}", target - address),
        Some(target) => format!("__cutegdb_start-0x{:x}", address - target),
        None => operands.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asm(arch: Arch, text: &str, address: u64) -> Result<Vec<u8>, AsmError> {
        let resolve = |name: &str| (name == "hello.add").then_some(0x1149);
        assemble(arch, text, address, &resolve)
    }

    #[test]
    fn x86_64_instructions() {
        assert_eq!(asm(Arch::X86_64, "mov rax, 1", 0).unwrap(), [0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(asm(Arch::X86_64, "mov eax, 10", 0).unwrap(), [0xb8, 0x10, 0x00, 0x00, 0x00], "numbers are hex");
        assert_eq!(asm(Arch::X86_64, "mov eax, .10", 0).unwrap(), [0xb8, 0x0a, 0x00, 0x00, 0x00]);
        assert_eq!(asm(Arch::X86_64, "nop; ret", 0).unwrap(), [0x90, 0xc3]);
        assert_eq!(asm(Arch::X86_64, "push rbp", 0).unwrap(), [0x55]);
        assert_eq!(asm(Arch::X86_64, "mov qword ptr ss:[rbp-8], rax", 0).unwrap(), [0x48, 0x89, 0x45, 0xf8]);
    }

    #[test]
    fn branches_use_the_placement_address() {
        assert_eq!(asm(Arch::X86_64, "call 1005", 0x1000).unwrap(), [0xe8, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(asm(Arch::X86_64, "jmp 1000", 0x1000).unwrap(), [0xeb, 0xfe], "short jump when it fits");
        assert_eq!(asm(Arch::X86_64, "je 0x1010", 0x1000).unwrap(), [0x74, 0x0e]);
        assert_eq!(asm(Arch::X86_64, "call hello.add", 0x1176).unwrap(), [0xe8, 0xce, 0xff, 0xff, 0xff]);
        assert_eq!(asm(Arch::X86_64, "jmp 401000", 0x400000).unwrap(), [0xe9, 0xfb, 0x0f, 0x00, 0x00]);
    }

    #[test]
    fn other_architectures() {
        assert_eq!(asm(Arch::X86, "mov eax, esp", 0).unwrap(), [0x89, 0xe0]);
        assert_eq!(asm(Arch::X86, "call 1000", 0x1000).unwrap(), [0xe8, 0xfb, 0xff, 0xff, 0xff]);
        assert_eq!(asm(Arch::AArch64, "ret", 0).unwrap(), [0xc0, 0x03, 0x5f, 0xd6]);
        assert_eq!(asm(Arch::AArch64, "bl #0x4000", 0x4000).unwrap(), [0x00, 0x00, 0x00, 0x94]);
        assert_eq!(asm(Arch::AArch64, "b 0x4008", 0x4000).unwrap(), [0x02, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn errors() {
        assert!(matches!(asm(Arch::X86_64, "mov rax,", 0), Err(AsmError::Invalid(_))));
        assert!(matches!(asm(Arch::X86_64, "bogus rax", 0), Err(AsmError::Invalid(_))));
        assert!(matches!(asm(Arch::X86_64, "call unknown_function", 0), Err(AsmError::Invalid(_))));
        assert!(matches!(asm(Arch::X86_64, "  ", 0), Err(AsmError::Invalid(_))));
        assert!(matches!(asm(Arch::X86_64, ".incbin \"/etc/passwd\"", 0), Err(AsmError::Invalid(_))));
    }
}

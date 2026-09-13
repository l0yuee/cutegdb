//! Target architecture facts: register naming, flag layout, address formatting.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    X86_64,
    X86,
    AArch64,
}

impl Arch {
    /// Parses the `arch` field of an MI frame ("i386:x86-64", "i386", "aarch64").
    pub fn from_gdb(name: &str) -> Option<Arch> {
        match name {
            "i386:x86-64" | "i386:x86-64:intel" => Some(Arch::X86_64),
            "i386" | "i386:intel" | "i8086" => Some(Arch::X86),
            n if n.starts_with("aarch64") => Some(Arch::AArch64),
            _ => None,
        }
    }

    /// Reads the architecture from an ELF header.
    pub fn of_file(path: &Path) -> Option<Arch> {
        use object::Object;
        let data = std::fs::read(path).ok()?;
        match object::File::parse(&*data).ok()?.architecture() {
            object::Architecture::X86_64 => Some(Arch::X86_64),
            object::Architecture::I386 => Some(Arch::X86),
            object::Architecture::Aarch64 => Some(Arch::AArch64),
            _ => None,
        }
    }

    pub fn pointer_size(self) -> usize {
        match self {
            Arch::X86 => 4,
            Arch::X86_64 | Arch::AArch64 => 8,
        }
    }

    /// Longest possible instruction encoding.
    pub fn max_instruction_len(self) -> usize {
        match self {
            Arch::X86 | Arch::X86_64 => 15,
            Arch::AArch64 => 4,
        }
    }

    pub fn pc_register(self) -> &'static str {
        match self {
            Arch::X86_64 => "rip",
            Arch::X86 => "eip",
            Arch::AArch64 => "pc",
        }
    }

    pub fn sp_register(self) -> &'static str {
        match self {
            Arch::X86_64 => "rsp",
            Arch::X86 => "esp",
            Arch::AArch64 => "sp",
        }
    }

    pub fn flags_register(self) -> &'static str {
        match self {
            Arch::X86_64 | Arch::X86 => "eflags",
            Arch::AArch64 => "cpsr",
        }
    }

    /// General purpose registers in x64dbg's register view order.
    pub fn general_registers(self) -> &'static [&'static str] {
        match self {
            Arch::X86_64 => &[
                "rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
                "r14", "r15", "rip",
            ],
            Arch::X86 => &["eax", "ebx", "ecx", "edx", "ebp", "esp", "esi", "edi", "eip"],
            Arch::AArch64 => &[
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
                "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
                "x29", "x30", "sp", "pc",
            ],
        }
    }

    /// Flag names and bit positions within the flags register, in x64dbg's display order.
    pub fn flag_bits(self) -> &'static [(&'static str, u32)] {
        match self {
            Arch::X86_64 | Arch::X86 => &[
                ("ZF", 6),
                ("PF", 2),
                ("AF", 4),
                ("OF", 11),
                ("SF", 7),
                ("DF", 10),
                ("CF", 0),
                ("TF", 8),
                ("IF", 9),
            ],
            Arch::AArch64 => &[("N", 31), ("Z", 30), ("C", 29), ("V", 28)],
        }
    }

    pub fn segment_registers(self) -> &'static [&'static str] {
        match self {
            Arch::X86_64 | Arch::X86 => &["gs", "fs", "es", "ds", "cs", "ss"],
            Arch::AArch64 => &[],
        }
    }

    /// Formats an address the way x64dbg does: fixed width, upper-case hex, no prefix.
    pub fn format_address(self, address: u64) -> String {
        match self.pointer_size() {
            4 => format!("{:08X}", address as u32),
            _ => format!("{address:016X}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gdb_arch_names() {
        assert_eq!(Arch::from_gdb("i386:x86-64"), Some(Arch::X86_64));
        assert_eq!(Arch::from_gdb("i386"), Some(Arch::X86));
        assert_eq!(Arch::from_gdb("aarch64"), Some(Arch::AArch64));
        assert_eq!(Arch::from_gdb("riscv:rv64"), None);
    }

    #[test]
    fn formats_addresses_like_x64dbg() {
        assert_eq!(Arch::X86_64.format_address(0x5555_5555_5169), "0000555555555169");
        assert_eq!(Arch::X86.format_address(0x5655_6199), "56556199");
    }
}

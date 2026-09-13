//! Instruction decoding with capstone, classified the way x64dbg colours and draws branches.

use crate::arch::Arch;
use capstone::arch::arm64::Arm64OperandType;
use capstone::arch::x86::{X86OperandType, X86Reg};
use capstone::arch::{self, ArchOperand, BuildsCapstone, BuildsCapstoneSyntax};
use capstone::{Capstone, Insn, InsnGroupType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnKind {
    Normal,
    Call,
    Jump,
    ConditionalJump,
    Ret,
    Interrupt,
    Nop,
    PushPop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub kind: InsnKind,
    /// Direct branch or call destination.
    pub target: Option<u64>,
}

impl Instruction {
    pub fn text(&self) -> String {
        if self.operands.is_empty() { self.mnemonic.clone() } else { format!("{} {}", self.mnemonic, self.operands) }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn is_branch(&self) -> bool {
        matches!(self.kind, InsnKind::Jump | InsnKind::ConditionalJump)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReferenceKind {
    Call,
    Jump,
    /// Memory operand or immediate that points into the scanned module.
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reference {
    pub from: u64,
    pub to: u64,
    pub kind: ReferenceKind,
}

pub struct Disassembler {
    cs: Capstone,
}

impl Disassembler {
    pub fn new(arch: Arch) -> Result<Self, capstone::Error> {
        let cs = match arch {
            Arch::X86_64 | Arch::X86 => Capstone::new()
                .x86()
                .mode(if arch == Arch::X86 { arch::x86::ArchMode::Mode32 } else { arch::x86::ArchMode::Mode64 })
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()?,
            Arch::AArch64 => Capstone::new().arm64().mode(arch::arm64::ArchMode::Arm).detail(true).build()?,
        };
        Ok(Self { cs })
    }

    /// Decodes up to `count` instructions, stopping at the first undecodable byte.
    pub fn disassemble(&self, code: &[u8], address: u64, count: usize) -> Vec<Instruction> {
        match self.cs.disasm_count(code, address, count) {
            Ok(insns) => insns.iter().map(|insn| self.convert(insn)).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Linear sweep over `code` (starting at `base`) collecting calls, jumps and data references
    /// whose destination lies in `within`, typically the module's address range.
    pub fn references(&self, code: &[u8], base: u64, within: std::ops::Range<u64>) -> Vec<Reference> {
        let mut references = Vec::new();
        let mut offset = 0usize;
        while offset < code.len() {
            let start = base + offset as u64;
            let decoded = match self.cs.disasm_all(&code[offset..], start) {
                Ok(insns) if !insns.is_empty() => insns,
                // Undecodable byte (data in the code section): resynchronise on the next one.
                _ => {
                    offset += 1;
                    continue;
                }
            };
            for insn in decoded.iter() {
                let address = insn.address();
                let next = address + insn.bytes().len() as u64;
                let converted = self.convert(insn);
                let mut push = |to: u64, kind| {
                    if within.contains(&to) {
                        references.push(Reference { from: address, to, kind });
                    }
                };
                match (converted.kind, converted.target) {
                    (InsnKind::Call, Some(target)) => push(target, ReferenceKind::Call),
                    (InsnKind::Jump | InsnKind::ConditionalJump, Some(target)) => push(target, ReferenceKind::Jump),
                    _ => {
                        let Ok(detail) = self.cs.insn_detail(insn) else { continue };
                        for operand in detail.arch_detail().operands() {
                            let target = match operand {
                                ArchOperand::X86Operand(op) => match op.op_type {
                                    X86OperandType::Mem(mem) if u32::from(mem.base().0) == X86Reg::X86_REG_RIP => {
                                        Some(next.wrapping_add(mem.disp() as u64))
                                    }
                                    X86OperandType::Mem(mem) if mem.base().0 == 0 && mem.index().0 == 0 => Some(mem.disp() as u64),
                                    X86OperandType::Imm(value) => Some(value as u64),
                                    _ => None,
                                },
                                ArchOperand::Arm64Operand(op) if converted.mnemonic == "adr" => match op.op_type {
                                    Arm64OperandType::Imm(value) => Some(value as u64),
                                    _ => None,
                                },
                                _ => None,
                            };
                            if let Some(target) = target {
                                push(target, ReferenceKind::Data);
                            }
                        }
                    }
                }
            }
            let last = decoded.iter().last().map_or(start, |insn| insn.address() + insn.bytes().len() as u64);
            offset = (last - base) as usize;
        }
        references
    }

    /// Start of the instruction that ends exactly at `address`, where `code` holds the bytes
    /// immediately before `address`. x86 decoding does not resynchronise, so every start offset
    /// is tried and the longest chain of instructions landing on `address` wins.
    pub fn previous_instruction(&self, code: &[u8], address: u64) -> Option<u64> {
        let base = address.checked_sub(code.len() as u64)?;
        let mut best: Option<(usize, u64)> = None;
        for offset in 0..code.len() {
            let start = base + offset as u64;
            let Ok(insns) = self.cs.disasm_all(&code[offset..], start) else { continue };
            let (mut end, mut count, mut last) = (start, 0usize, None);
            for insn in insns.iter() {
                if insn.address() != end {
                    break;
                }
                last = Some(end);
                end += insn.bytes().len() as u64;
                count += 1;
            }
            if end == address
                && let Some(last) = last
                && best.is_none_or(|(best_count, _)| count > best_count)
            {
                best = Some((count, last));
            }
        }
        best.map(|(_, last)| last)
    }

    fn convert(&self, insn: &Insn) -> Instruction {
        let mnemonic = insn.mnemonic().unwrap_or_default().to_owned();
        let mut kind = InsnKind::Normal;
        let mut target = None;
        if let Ok(detail) = self.cs.insn_detail(insn) {
            let has = |group: u32| detail.groups().iter().any(|g| u32::from(g.0) == group);
            kind = if has(InsnGroupType::CS_GRP_CALL) {
                InsnKind::Call
            } else if has(InsnGroupType::CS_GRP_RET) {
                InsnKind::Ret
            } else if has(InsnGroupType::CS_GRP_JUMP) {
                if is_unconditional_jump(&mnemonic) { InsnKind::Jump } else { InsnKind::ConditionalJump }
            } else if has(InsnGroupType::CS_GRP_INT) {
                InsnKind::Interrupt
            } else {
                InsnKind::Normal
            };
            if matches!(kind, InsnKind::Call | InsnKind::Jump | InsnKind::ConditionalJump) {
                target = detail.arch_detail().operands().iter().find_map(|op| match op {
                    ArchOperand::X86Operand(o) => match o.op_type {
                        X86OperandType::Imm(v) => Some(v as u64),
                        _ => None,
                    },
                    ArchOperand::Arm64Operand(o) => match o.op_type {
                        Arm64OperandType::Imm(v) => Some(v as u64),
                        _ => None,
                    },
                    _ => None,
                });
            }
        }
        if kind == InsnKind::Normal {
            if mnemonic.starts_with("nop") || mnemonic.starts_with("endbr") {
                kind = InsnKind::Nop;
            } else if mnemonic.starts_with("push") || mnemonic.starts_with("pop") {
                kind = InsnKind::PushPop;
            }
        }
        Instruction {
            address: insn.address(),
            bytes: insn.bytes().to_vec(),
            mnemonic,
            operands: insn.op_str().unwrap_or_default().to_owned(),
            kind,
            target,
        }
    }
}

fn is_unconditional_jump(mnemonic: &str) -> bool {
    matches!(mnemonic, "jmp" | "ljmp" | "b" | "br" | "braa" | "brab" | "braaz" | "brabz")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(arch: Arch, bytes: &[u8], address: u64) -> Instruction {
        let d = Disassembler::new(arch).unwrap();
        let mut insns = d.disassemble(bytes, address, 1);
        assert_eq!(insns.len(), 1, "failed to decode {bytes:02x?}");
        insns.remove(0)
    }

    #[test]
    fn x86_64_classification_and_targets() {
        let call = one(Arch::X86_64, &[0xe8, 0, 0, 0, 0], 0x1000);
        assert_eq!((call.kind, call.target, call.text().as_str()), (InsnKind::Call, Some(0x1005), "call 0x1005"));
        let je = one(Arch::X86_64, &[0x74, 0x02], 0x2000);
        assert_eq!((je.kind, je.target), (InsnKind::ConditionalJump, Some(0x2004)));
        let jmp = one(Arch::X86_64, &[0xeb, 0xfe], 0x3000);
        assert_eq!((jmp.kind, jmp.target), (InsnKind::Jump, Some(0x3000)));
        assert_eq!(one(Arch::X86_64, &[0xc3], 0).kind, InsnKind::Ret);
        assert_eq!(one(Arch::X86_64, &[0x90], 0).kind, InsnKind::Nop);
        assert_eq!(one(Arch::X86_64, &[0xf3, 0x0f, 0x1e, 0xfa], 0).kind, InsnKind::Nop);
        assert_eq!(one(Arch::X86_64, &[0x55], 0).kind, InsnKind::PushPop);
        assert_eq!(one(Arch::X86_64, &[0xcc], 0).kind, InsnKind::Interrupt);
        let mov = one(Arch::X86_64, &[0x48, 0x89, 0xe5], 0);
        assert_eq!((mov.kind, mov.text().as_str(), mov.len()), (InsnKind::Normal, "mov rbp, rsp", 3));
        let indirect = one(Arch::X86_64, &[0xff, 0xd0], 0);
        assert_eq!((indirect.kind, indirect.target), (InsnKind::Call, None));
    }

    #[test]
    fn x86_32_mode() {
        let call = one(Arch::X86, &[0xe8, 0xfb, 0xff, 0xff, 0xff], 0x1000);
        assert_eq!((call.kind, call.target), (InsnKind::Call, Some(0x1000)));
        assert_eq!(one(Arch::X86, &[0x89, 0xe5], 0).text(), "mov ebp, esp");
    }

    #[test]
    fn aarch64_classification() {
        assert_eq!(one(Arch::AArch64, &[0xc0, 0x03, 0x5f, 0xd6], 0).kind, InsnKind::Ret);
        let bl = one(Arch::AArch64, &[0x00, 0x00, 0x00, 0x94], 0x4000);
        assert_eq!((bl.kind, bl.target), (InsnKind::Call, Some(0x4000)));
        let b = one(Arch::AArch64, &[0x02, 0x00, 0x00, 0x14], 0x4000);
        assert_eq!((b.kind, b.target), (InsnKind::Jump, Some(0x4008)));
        let beq = one(Arch::AArch64, &[0x40, 0x00, 0x00, 0x54], 0x4000);
        assert_eq!((beq.kind, beq.target), (InsnKind::ConditionalJump, Some(0x4008)));
    }

    #[test]
    fn collects_code_and_data_references() {
        let d = Disassembler::new(Arch::X86_64).unwrap();
        let code = [
            0xe8, 0xfb, 0x0f, 0x00, 0x00, // 1000: call 0x2000
            0x48, 0x8d, 0x05, 0xf2, 0x0f, 0x00, 0x00, // 1005: lea rax, [rip + 0xff2] -> 0x1ffe
            0x74, 0x02, // 100c: je 0x1010
            0x06, // 100e: invalid in 64-bit mode
            0x90, // 100f: nop
            0xb8, 0x00, 0x20, 0x00, 0x00, // 1010: mov eax, 0x2000
            0xb8, 0x05, 0x00, 0x00, 0x00, // 1015: mov eax, 5 (outside the module)
            0x8b, 0x04, 0x25, 0x00, 0x30, 0x00, 0x00, // 101a: mov eax, dword ptr [0x3000]
        ];
        let references = d.references(&code, 0x1000, 0x1000..0x4000);
        let summary: Vec<_> = references.iter().map(|r| (r.from, r.to, r.kind)).collect();
        assert_eq!(
            summary,
            [
                (0x1000, 0x2000, ReferenceKind::Call),
                (0x1005, 0x1ffe, ReferenceKind::Data),
                (0x100c, 0x1010, ReferenceKind::Jump),
                (0x1010, 0x2000, ReferenceKind::Data),
                (0x101a, 0x3000, ReferenceKind::Data),
            ]
        );
    }

    #[test]
    fn finds_previous_instruction_boundaries() {
        let d = Disassembler::new(Arch::X86_64).unwrap();
        // push rbp; mov rbp, rsp; sub rsp, 0x10 at 0x1000
        let code = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10];
        assert_eq!(d.previous_instruction(&code, 0x1008), Some(0x1004));
        assert_eq!(d.previous_instruction(&code[..4], 0x1004), Some(0x1001));
        assert_eq!(d.previous_instruction(&code[..1], 0x1001), Some(0x1000));
        assert_eq!(d.previous_instruction(&[], 0x1000), None);
        // endbr64; push rbp; mov rbp, rsp: the aligned chain from the first byte wins.
        let code = [0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5];
        assert_eq!(d.previous_instruction(&code, 0x2008), Some(0x2005));
        assert_eq!(d.previous_instruction(&code[..5], 0x2005), Some(0x2004));
    }

    #[test]
    fn stops_at_undecodable_bytes() {
        let d = Disassembler::new(Arch::X86_64).unwrap();
        assert!(d.disassemble(&[0x06], 0, 1).is_empty());
        let insns = d.disassemble(&[0x90, 0x90, 0x06, 0x90], 0x10, 10);
        assert_eq!(insns.iter().map(|i| i.address).collect::<Vec<_>>(), [0x10, 0x11]);
    }
}

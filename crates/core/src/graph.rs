//! Control-flow graph of a function (x64dbg: G, the graph view).

use crate::disasm::{Disassembler, InsnKind, Instruction};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// Fall-through or unconditional jump (x64dbg draws it blue).
    Unconditional,
    /// Conditional jump taken (green).
    Taken,
    /// Conditional jump not taken (red).
    NotTaken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub start: u64,
    pub instructions: Vec<Instruction>,
    pub edges: Vec<(u64, EdgeKind)>,
}

impl Block {
    pub fn end(&self) -> u64 {
        self.instructions.last().map_or(self.start, |i| i.address + i.len() as u64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionGraph {
    pub entry: u64,
    /// Ordered by address.
    pub blocks: Vec<Block>,
}

/// Follows branches from `entry` without leaving `within`, decoding at most `max_instructions`.
/// `read(address, len)` returns the code bytes there (possibly fewer).
pub fn build_graph(
    disassembler: &Disassembler,
    entry: u64,
    within: Range<u64>,
    max_instructions: usize,
    read: &dyn Fn(u64, usize) -> Vec<u8>,
) -> FunctionGraph {
    let mut instructions: BTreeMap<u64, Instruction> = BTreeMap::new();
    let mut leaders: BTreeSet<u64> = BTreeSet::from([entry]);
    let mut worklist = vec![entry];

    while let Some(start) = worklist.pop() {
        let mut address = start;
        while within.contains(&address) && !instructions.contains_key(&address) && instructions.len() < max_instructions {
            let bytes = read(address, 15);
            let Some(insn) = disassembler.disassemble(&bytes, address, 1).into_iter().next() else { break };
            let next = address + insn.len() as u64;
            let (kind, target) = (insn.kind, insn.target);
            instructions.insert(address, insn);
            match kind {
                InsnKind::Ret => break,
                InsnKind::Jump => {
                    if let Some(target) = target.filter(|t| within.contains(t)) {
                        leaders.insert(target);
                        worklist.push(target);
                    }
                    break;
                }
                InsnKind::ConditionalJump => {
                    if let Some(target) = target.filter(|t| within.contains(t)) {
                        leaders.insert(target);
                        worklist.push(target);
                    }
                    leaders.insert(next);
                }
                _ => {}
            }
            address = next;
        }
    }

    let mut blocks: Vec<Block> = Vec::new();
    for (&address, insn) in &instructions {
        let continues = blocks.last().is_some_and(|block| {
            let last = block.instructions.last().unwrap();
            block.end() == address
                && !leaders.contains(&address)
                && !matches!(last.kind, InsnKind::Ret | InsnKind::Jump | InsnKind::ConditionalJump)
        });
        if continues {
            blocks.last_mut().unwrap().instructions.push(insn.clone());
        } else {
            blocks.push(Block { start: address, instructions: vec![insn.clone()], edges: Vec::new() });
        }
    }

    let starts: BTreeSet<u64> = blocks.iter().map(|b| b.start).collect();
    for block in &mut blocks {
        let last = block.instructions.last().unwrap();
        let fall_through = block.end();
        block.edges = match (last.kind, last.target) {
            (InsnKind::Ret, _) | (InsnKind::Jump, None) => Vec::new(),
            (InsnKind::Jump, Some(target)) => vec![(target, EdgeKind::Unconditional)],
            (InsnKind::ConditionalJump, target) => {
                target.map(|t| (t, EdgeKind::Taken)).into_iter().chain([(fall_through, EdgeKind::NotTaken)]).collect()
            }
            _ => vec![(fall_through, EdgeKind::Unconditional)],
        };
        block.edges.retain(|(target, _)| starts.contains(target));
    }
    FunctionGraph { entry, blocks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Arch;

    fn graph_of(code: &[u8], base: u64) -> FunctionGraph {
        let d = Disassembler::new(Arch::X86_64).unwrap();
        let read = |address: u64, len: usize| {
            let offset = (address - base) as usize;
            code[offset.min(code.len())..(offset + len).min(code.len())].to_vec()
        };
        build_graph(&d, base, base..base + code.len() as u64, 1000, &read)
    }

    /// Block start, instruction count and edges.
    type BlockSummary = (u64, usize, Vec<(u64, EdgeKind)>);

    fn summary(graph: &FunctionGraph) -> Vec<BlockSummary> {
        graph.blocks.iter().map(|b| (b.start, b.instructions.len(), b.edges.clone())).collect()
    }

    #[test]
    fn if_else_diamond() {
        let code = [
            0x55, // 1000: push rbp
            0x83, 0xff, 0x00, // 1001: cmp edi, 0
            0x74, 0x04, // 1004: je 0x100a
            0x31, 0xc0, // 1006: xor eax, eax
            0xeb, 0x05, // 1008: jmp 0x100f
            0xb8, 0x01, 0x00, 0x00, 0x00, // 100a: mov eax, 1
            0x5d, // 100f: pop rbp
            0xc3, // 1010: ret
        ];
        use EdgeKind::*;
        assert_eq!(
            summary(&graph_of(&code, 0x1000)),
            [
                (0x1000, 3, vec![(0x100a, Taken), (0x1006, NotTaken)]),
                (0x1006, 2, vec![(0x100f, Unconditional)]),
                (0x100a, 1, vec![(0x100f, Unconditional)]),
                (0x100f, 2, vec![]),
            ]
        );
    }

    #[test]
    fn loop_back_edge_splits_its_target() {
        let code = [
            0x31, 0xc9, // 2000: xor ecx, ecx
            0xff, 0xc1, // 2002: inc ecx
            0x83, 0xf9, 0x0a, // 2004: cmp ecx, 10
            0x75, 0xf9, // 2007: jne 0x2002
            0xc3, // 2009: ret
        ];
        use EdgeKind::*;
        assert_eq!(
            summary(&graph_of(&code, 0x2000)),
            [
                (0x2000, 1, vec![(0x2002, Unconditional)]),
                (0x2002, 3, vec![(0x2002, Taken), (0x2009, NotTaken)]),
                (0x2009, 1, vec![]),
            ]
        );
    }

    #[test]
    fn stays_inside_the_range_and_limit() {
        // jmp far outside the function, then an indirect jump.
        let code = [0xe9, 0x00, 0x10, 0x00, 0x00, 0xff, 0xe0];
        let graph = graph_of(&code, 0x3000);
        assert_eq!(summary(&graph), [(0x3000, 1, vec![])]);
        let d = Disassembler::new(Arch::X86_64).unwrap();
        let nops = [0x90u8; 64];
        let limited = build_graph(&d, 0, 0..64, 10, &|a, l| nops[a as usize..(a as usize + l).min(64)].to_vec());
        assert_eq!(limited.blocks.iter().map(|b| b.instructions.len()).sum::<usize>(), 10);
    }
}

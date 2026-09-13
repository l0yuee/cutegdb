//! Debugger core: target state, registers, memory, symbols and disassembly on top of GDB/MI.

mod arch;
mod assembler;
mod breakpoints;
mod database;
mod debugger;
mod disasm;
mod format;
mod graph;
mod insn_info;
mod inspect;
mod memory;
mod plugins;
mod pty;
mod registers;
mod search;
mod symbols;
mod util;

pub use arch::Arch;
pub use assembler::{AsmError, assemble};
pub use breakpoints::{Breakpoint, BreakpointKind, WatchAccess, parse_breakpoint, parse_breakpoint_table};
pub use database::{Annotation, Database, ModuleAddress, Patch, database_path, export_patched_file, file_offset};
pub use debugger::{DebugError, DebugEvent, DebugState, Debugger, Snapshot, StopReason, TraceEntry, TraceOptions};
pub use disasm::{Disassembler, InsnKind, Instruction, Reference, ReferenceKind};
pub use format::format_operands;
pub use graph::{Block, EdgeKind, FunctionGraph, build_graph};
pub use insn_info::{InfoContext, describe_instruction, jump_taken};
pub use inspect::{FileHandle, Frame, SignalInfo, ThreadInfo, parse_frames, parse_process_id, parse_signals, parse_threads};
pub use memory::{MemoryCache, PAGE_SIZE};
pub use plugins::{PluginCategory, PluginInfo, catalog as plugin_catalog, info as plugin_info};
pub use registers::{RegValue, Register, parse_value};
pub use search::{FoundString, Pattern, StringReference, find_strings};
pub use symbols::{Mapping, Module, Symbol, SymbolTable, parse_proc_mappings};

//! Loaded modules and their ELF symbols, named x64dbg-style as `module.symbol+offset`.

use object::{Object, ObjectSegment, ObjectSymbol, SymbolKind};
use std::path::Path;
use std::sync::Arc;

const PAGE_MASK: u64 = !0xfff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub perms: String,
    pub path: String,
}

/// Parses the output of gdb's `info proc mappings` (with or without the Perms column).
pub fn parse_proc_mappings(text: &str) -> Vec<Mapping> {
    let hex = |t: &str| u64::from_str_radix(t.strip_prefix("0x")?, 16).ok();
    text.lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let (start, end) = (hex(tokens.first()?)?, hex(tokens.get(1)?)?);
            hex(tokens.get(2)?)?;
            let offset = hex(tokens.get(3)?)?;
            let mut rest = &tokens[4..];
            let perms = match rest.first() {
                Some(p) if p.len() == 4 && p.chars().all(|c| "rwxps-".contains(c)) => {
                    rest = &rest[1..];
                    (*p).to_owned()
                }
                _ => String::new(),
            };
            Some(Mapping { start, end, offset, perms, path: rest.join(" ") })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub address: u64,
    pub size: u64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub path: String,
    pub base: u64,
    pub end: u64,
    pub entry: Option<u64>,
    symbols: Vec<Symbol>,
}

impl Module {
    /// Loads symbols from the ELF file at `path`, relocated so that its first segment sits at `base`.
    pub fn load(path: &str, base: u64, end: u64) -> Module {
        let mut module = Module { name: module_name(path), path: path.to_owned(), base, end, entry: None, symbols: Vec::new() };
        let Ok(data) = std::fs::read(path) else { return module };
        let Ok(file) = object::File::parse(&*data) else { return module };
        let bias = base.wrapping_sub(file.segments().map(|s| s.address()).min().unwrap_or(0) & PAGE_MASK);
        module.entry = (file.entry() != 0).then(|| file.entry().wrapping_add(bias));
        for sym in file.symbols().chain(file.dynamic_symbols()) {
            if !sym.is_definition() || sym.address() == 0 || !matches!(sym.kind(), SymbolKind::Text | SymbolKind::Data) {
                continue;
            }
            match sym.name() {
                Ok(name) if !name.is_empty() => module.symbols.push(Symbol {
                    address: sym.address().wrapping_add(bias),
                    size: sym.size(),
                    name: name.to_owned(),
                }),
                _ => {}
            }
        }
        module.symbols.extend(plt_symbols(&file, bias));
        // Stable sort keeps .symtab names ahead of their .dynsym duplicates.
        module.symbols.sort_by_key(|s| s.address);
        module.symbols.dedup_by_key(|s| s.address);
        module
    }

    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// The symbol containing `address` and the offset into it.
    pub fn symbol_at(&self, address: u64) -> Option<(&Symbol, u64)> {
        let idx = self.symbols.partition_point(|s| s.address <= address);
        let sym = self.symbols.get(idx.checked_sub(1)?)?;
        let offset = address - sym.address;
        (offset == 0 || offset < sym.size).then_some((sym, offset))
    }

    pub fn contains(&self, address: u64) -> bool {
        (self.base..self.end).contains(&address)
    }
}

/// Names for PLT stubs (`printf@plt`), which ELF symbol tables do not contain.
fn plt_symbols(file: &object::File<'_>, bias: u64) -> Vec<Symbol> {
    use object::{Architecture, ObjectSection, ObjectSymbolTable, RelocationFlags, RelocationTarget};

    if file.architecture() == Architecture::X86_64 {
        return x86_64_plt_symbols(file, bias);
    }
    // Elsewhere, stubs are laid out in the order of the jump-slot relocations.
    let (jump_slot, header): (u32, u64) = match file.architecture() {
        Architecture::X86_64 | Architecture::I386 => (7, 16),
        Architecture::Aarch64 => (1026, 32),
        _ => return Vec::new(),
    };
    const ENTRY_SIZE: u64 = 16;
    // With IBT, x86 stubs live in .plt.sec and have no header in front of them.
    let (stubs, first) = match (file.section_by_name(".plt.sec"), file.section_by_name(".plt")) {
        (Some(sec), _) if file.architecture() != Architecture::Aarch64 => (sec, 0),
        (_, Some(plt)) => (plt, header),
        _ => return Vec::new(),
    };
    let (Some(relocations), Some(dynamic_symbols)) = (file.dynamic_relocations(), file.dynamic_symbol_table()) else {
        return Vec::new();
    };
    let end = stubs.address() + stubs.size();
    relocations
        .filter(|(_, r)| matches!(r.flags(), RelocationFlags::Elf { r_type } if r_type == object::elf::RelocationType(jump_slot)))
        .enumerate()
        .filter_map(|(index, (_, relocation))| {
            let RelocationTarget::Symbol(symbol) = relocation.target() else { return None };
            let name = dynamic_symbols.symbol_by_index(symbol).ok()?.name().ok()?.to_owned();
            let address = stubs.address() + first + index as u64 * ENTRY_SIZE;
            (address + ENTRY_SIZE <= end).then(|| Symbol {
                address: address.wrapping_add(bias),
                size: ENTRY_SIZE,
                name: format!("{name}@plt"),
            })
        })
        .collect()
}

/// x86-64 stubs in .plt, .plt.sec and .plt.got all jump through `jmp [rip+disp32]` (`ff 25`) to a GOT
/// slot; the relocation filling that slot (JUMP_SLOT or GLOB_DAT) names the function.
fn x86_64_plt_symbols(file: &object::File<'_>, bias: u64) -> Vec<Symbol> {
    use object::{ObjectSection, ObjectSymbolTable, RelocationTarget};

    let (Some(relocations), Some(dynamic_symbols)) = (file.dynamic_relocations(), file.dynamic_symbol_table()) else {
        return Vec::new();
    };
    let slots: std::collections::HashMap<u64, String> = relocations
        .filter_map(|(offset, relocation)| {
            let RelocationTarget::Symbol(symbol) = relocation.target() else { return None };
            let name = dynamic_symbols.symbol_by_index(symbol).ok()?.name().ok()?;
            (!name.is_empty()).then(|| (offset, name.to_owned()))
        })
        .collect();

    let mut symbols = Vec::new();
    for (section_name, entry_size) in [(".plt", 16u64), (".plt.sec", 16), (".plt.got", 8)] {
        let Some(section) = file.section_by_name(section_name) else { continue };
        let Ok(data) = section.data() else { continue };
        for (index, entry) in data.chunks_exact(entry_size as usize).enumerate() {
            let entry_address = section.address() + index as u64 * entry_size;
            let Some(position) = entry.windows(2).position(|w| w == [0xff, 0x25]) else { continue };
            let Some(&[a, b, c, d]) = entry.get(position + 2..position + 6) else { continue };
            let displacement = i32::from_le_bytes([a, b, c, d]) as i64 as u64;
            let slot = (entry_address + position as u64 + 6).wrapping_add(displacement);
            if let Some(name) = slots.get(&slot) {
                symbols.push(Symbol {
                    address: entry_address.wrapping_add(bias),
                    size: entry_size,
                    name: format!("{name}@plt"),
                });
            }
        }
    }
    symbols
}

/// `libc.so.6` → `libc`, `/usr/bin/ls` → `ls`, `[vdso]` → `vdso`.
fn module_name(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path).trim_matches(['[', ']']);
    match file.find(".so") {
        Some(i) if i > 0 => file[..i].to_owned(),
        _ => file.to_owned(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    modules: Vec<Arc<Module>>,
}

impl SymbolTable {
    /// Builds modules from process mappings, reusing already parsed modules from `previous`.
    pub fn from_mappings(mappings: &[Mapping], previous: &SymbolTable) -> SymbolTable {
        let mut ranges: Vec<(String, u64, u64)> = Vec::new();
        for m in mappings {
            if m.path.is_empty() || (m.path.starts_with('[') && m.path != "[vdso]") {
                continue;
            }
            match ranges.iter_mut().find(|(path, ..)| *path == m.path) {
                Some((_, start, end)) => {
                    *start = (*start).min(m.start);
                    *end = (*end).max(m.end);
                }
                None => ranges.push((m.path.clone(), m.start, m.end)),
            }
        }
        let mut modules: Vec<Arc<Module>> = ranges
            .into_iter()
            .map(|(path, base, end)| {
                previous
                    .modules
                    .iter()
                    .find(|m| m.path == path && m.base == base && m.end == end)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(Module::load(&path, base, end)))
            })
            .collect();
        modules.sort_by_key(|m| m.base);
        SymbolTable { modules }
    }

    /// Symbols for an executable at its link-time addresses (before it runs, or without /proc).
    pub fn from_executable(path: &Path) -> SymbolTable {
        let Ok(data) = std::fs::read(path) else { return SymbolTable::default() };
        let Ok(file) = object::File::parse(&*data) else { return SymbolTable::default() };
        let base = file.segments().map(|s| s.address()).min().unwrap_or(0) & PAGE_MASK;
        let end = file.segments().map(|s| s.address() + s.size()).max().unwrap_or(0);
        let module = Module::load(&path.to_string_lossy(), base, end);
        SymbolTable { modules: vec![Arc::new(module)] }
    }

    pub fn from_modules(modules: Vec<Module>) -> SymbolTable {
        let mut modules: Vec<Arc<Module>> = modules.into_iter().map(Arc::new).collect();
        modules.sort_by_key(|m| m.base);
        SymbolTable { modules }
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    pub fn modules(&self) -> &[Arc<Module>] {
        &self.modules
    }

    pub fn module(&self, name: &str) -> Option<&Module> {
        self.modules.iter().find(|m| m.name == name).map(|m| &**m)
    }

    pub fn module_at(&self, address: u64) -> Option<&Module> {
        self.modules.iter().find(|m| m.contains(address)).map(|m| &**m)
    }

    /// `module.symbol` or `module.symbol+OFFSET` (upper-case hex), as x64dbg labels addresses.
    pub fn label(&self, address: u64) -> Option<String> {
        let module = self.module_at(address)?;
        let (sym, offset) = module.symbol_at(address)?;
        Some(if offset == 0 {
            format!("{}.{}", module.name, sym.name)
        } else {
            format!("{}.{}+{offset:X}", module.name, sym.name)
        })
    }

    /// Resolves `module.symbol`, `module.EntryPoint` or a bare symbol name.
    pub fn find(&self, name: &str) -> Option<u64> {
        for (dot, _) in name.match_indices('.') {
            let (module_name, symbol) = (&name[..dot], &name[dot + 1..]);
            if let Some(module) = self.module(module_name) {
                if symbol == "EntryPoint" {
                    return module.entry;
                }
                if let Some(sym) = module.symbols.iter().find(|s| s.name == symbol) {
                    return Some(sym.address);
                }
            }
        }
        self.modules.iter().flat_map(|m| m.symbols.iter()).find(|s| s.name == name).map(|s| s.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mappings_with_and_without_perms() {
        let text = "\
process 1234
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
  0x0000555555554000 0x0000555555555000     0x1000        0x0  r--p   /tmp/my prog
  0x00007ffff7fc4000 0x00007ffff7fc6000     0x2000        0x0  r-xp   [vdso]
  0x00007ffffffde000 0x00007ffffffff000    0x21000        0x0  rw-p   [stack]
  0x00007ffff7d00000 0x00007ffff7d02000     0x2000        0x0  rw-p
        0x400000           0x401000     0x1000        0x0 /bin/old
";
        let maps = parse_proc_mappings(text);
        assert_eq!(maps.len(), 5);
        assert_eq!(
            maps[0],
            Mapping { start: 0x555555554000, end: 0x555555555000, offset: 0, perms: "r--p".into(), path: "/tmp/my prog".into() }
        );
        assert_eq!(maps[3].path, "");
        assert_eq!((maps[4].perms.as_str(), maps[4].path.as_str()), ("", "/bin/old"));
    }

    #[test]
    fn module_names() {
        assert_eq!(module_name("/usr/lib/x86_64-linux-gnu/libc.so.6"), "libc");
        assert_eq!(module_name("/lib64/ld-linux-x86-64.so.2"), "ld-linux-x86-64");
        assert_eq!(module_name("/home/me/hello"), "hello");
        assert_eq!(module_name("[vdso]"), "vdso");
    }

    #[test]
    fn symbol_lookup_respects_sizes() {
        let module = Module {
            name: "m".into(),
            path: String::new(),
            base: 0x1000,
            end: 0x2000,
            entry: Some(0x1010),
            symbols: vec![
                Symbol { address: 0x1100, size: 0x20, name: "f".into() },
                Symbol { address: 0x1200, size: 0, name: "g".into() },
            ],
        };
        let table = SymbolTable { modules: vec![Arc::new(module)] };
        assert_eq!(table.label(0x1100).as_deref(), Some("m.f"));
        assert_eq!(table.label(0x111f).as_deref(), Some("m.f+1F"));
        assert_eq!(table.label(0x1120), None);
        assert_eq!(table.label(0x1200).as_deref(), Some("m.g"));
        assert_eq!(table.label(0x1201), None);
        assert_eq!(table.label(0x3000), None);
        assert_eq!(table.find("m.f"), Some(0x1100));
        assert_eq!(table.find("g"), Some(0x1200));
        assert_eq!(table.find("m.EntryPoint"), Some(0x1010));
        assert_eq!(table.find("nope"), None);
    }
}

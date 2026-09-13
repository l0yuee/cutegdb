//! Symbol loading checked against binutils (`nm`, `readelf`) as an independent oracle.

use cutegdb_core::{SymbolTable, parse_proc_mappings};
use std::path::PathBuf;
use std::process::Command;

fn tool_output(tool: &str, args: &[&str]) -> String {
    let out = Command::new(tool).args(args).output().unwrap_or_else(|e| panic!("{tool}: {e}"));
    assert!(out.status.success(), "{tool} failed");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn relocated_symbols_match_nm_and_readelf() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/hello.c");
    let exe = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("core_sym64");
    assert!(Command::new("gcc").args(["-g", "-O0", "-o"]).arg(&exe).arg(&src).status().unwrap().success());
    let exe_str = exe.to_str().unwrap();

    let nm = tool_output("nm", &[exe_str]);
    let offset_of = |name: &str| {
        nm.lines()
            .find_map(|l| {
                let parts: Vec<_> = l.split_whitespace().collect();
                (parts.len() == 3 && parts[2] == name).then(|| u64::from_str_radix(parts[0], 16).unwrap())
            })
            .unwrap_or_else(|| panic!("{name} not in nm output"))
    };
    let readelf = tool_output("readelf", &["-h", exe_str]);
    let entry = readelf
        .lines()
        .find_map(|l| l.trim().strip_prefix("Entry point address:"))
        .map(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).unwrap())
        .unwrap();

    let base = 0x5555_5555_4000;
    let mappings = parse_proc_mappings(&format!(
        "0x{base:x} 0x{:x} 0x1000 0x0 r--p {exe_str}\n\
         0x{:x} 0x{:x} 0x1000 0x1000 r-xp {exe_str}\n\
         0x7ffff7fc4000 0x7ffff7fc6000 0x2000 0x0 r-xp [vdso]\n\
         0x7ffffffde000 0x7ffffffff000 0x21000 0x0 rw-p [stack]\n",
        base + 0x1000,
        base + 0x1000,
        base + 0x2000
    ));
    let table = SymbolTable::from_mappings(&mappings, &SymbolTable::default());

    let module = table.module("core_sym64").expect("executable module");
    assert_eq!((module.base, module.end), (base, base + 0x2000));
    assert_eq!(module.entry, Some(base + entry));
    assert_eq!(table.find("core_sym64.main"), Some(base + offset_of("main")));
    assert_eq!(table.find("add"), Some(base + offset_of("add")));
    assert_eq!(table.find("counter"), Some(base + offset_of("counter")));
    assert_eq!(table.label(base + offset_of("main") + 4).as_deref(), Some("core_sym64.main+4"));
    assert_eq!(table.module_at(0x7ffff7fc5000).map(|m| m.name.as_str()), Some("vdso"));
    assert!(table.module_at(0x7ffffffe0000).is_none(), "[stack] must not be a module");

    // Unchanged modules are reused rather than re-parsed.
    let again = SymbolTable::from_mappings(&mappings, &table);
    assert!(std::ptr::eq(&*again.modules()[0], &*table.modules()[0]));

    // Before the process runs, symbols sit at link-time addresses.
    let static_table = SymbolTable::from_executable(&exe);
    assert_eq!(static_table.find("main"), Some(offset_of("main")));

    // PLT stubs get names, at the addresses objdump labels them with.
    let objdump = tool_output("objdump", &["-d", exe_str]);
    let stubs: Vec<(u64, String)> = objdump
        .lines()
        .filter_map(|l| {
            let (address, rest) = l.split_once(" <")?;
            let name = rest.strip_suffix(">:")?;
            name.ends_with("@plt").then(|| (u64::from_str_radix(address.trim(), 16).ok(), name.to_owned()))
        })
        .filter_map(|(address, name)| Some((address?, name)))
        .collect();
    assert!(stubs.iter().any(|(_, name)| name == "printf@plt"), "{stubs:?}");
    for (address, name) in &stubs {
        assert_eq!(table.find(name), Some(base + address), "{name}");
        assert_eq!(table.label(base + address), Some(format!("core_sym64.{name}")));
    }
}

//! File offsets and patch export checked against a real ELF and binutils (`nm`).

mod common;

use cutegdb_core::{ModuleAddress, Patch, export_patched_file, file_offset};
use std::process::Command;

#[test]
fn patches_land_at_the_right_file_offsets() {
    let exe = common::fixture("db_hello64", "hello.c", "gcc", &[]).unwrap();
    let nm = String::from_utf8(Command::new("nm").arg(&exe).output().unwrap().stdout).unwrap();
    let rva_of = |name: &str| {
        nm.lines()
            .find_map(|l| {
                let parts: Vec<_> = l.split_whitespace().collect();
                (parts.len() == 3 && parts[2] == name).then(|| u64::from_str_radix(parts[0], 16).unwrap())
            })
            .unwrap()
    };
    let data = std::fs::read(&exe).unwrap();
    let (add, main) = (rva_of("add"), rva_of("main"));
    let add_offset = file_offset(&data, add).unwrap() as usize;
    let main_offset = file_offset(&data, main).unwrap() as usize;
    // Both functions begin with `push rbp` at -O0.
    assert_eq!((data[add_offset], data[main_offset]), (0x55, 0x55));
    // .bss has no file data.
    assert_eq!(file_offset(&data, rva_of("counter")), None);

    let at = |rva| ModuleAddress { module: "db_hello64".into(), rva };
    let patches = [
        Patch { location: at(add), original: 0x55, patched: 0xc3 },
        Patch { location: at(main + 1), original: data[main_offset + 1], patched: 0x90 },
        Patch { location: ModuleAddress { module: "libc".into(), rva: 0 }, original: 0, patched: 1 },
    ];
    let output = exe.with_file_name("db_hello64.patched");
    assert_eq!(export_patched_file(&exe, "db_hello64", &patches, &output).unwrap(), 2);
    let patched = std::fs::read(&output).unwrap();
    assert_eq!((patched[add_offset], patched[main_offset + 1]), (0xc3, 0x90));
    let changed = data.iter().zip(&patched).filter(|(a, b)| a != b).count();
    assert_eq!(changed, 2);

    let bad = [Patch { location: at(rva_of("counter")), original: 0, patched: 1 }];
    assert!(export_patched_file(&exe, "db_hello64", &bad, &output).is_err());
}

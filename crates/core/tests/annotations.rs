//! Assembling, patching, patch export and persistent annotations against a real debuggee.
//!
//! Kept as the only test in this binary because it points XDG_DATA_HOME at a private directory.

mod common;

use common::Session;
use cutegdb_core::{DebugState, Debugger, InsnKind};
use cutegdb_mi::GdbOptions;
use std::process::Command;

#[tokio::test(flavor = "multi_thread")]
async fn assemble_patch_export_and_persistent_annotations() {
    let data_home = std::env::temp_dir().join(format!("cutegdb-annotations-{}", std::process::id()));
    // SAFETY: this binary contains a single test, so no other thread reads the environment.
    unsafe { std::env::set_var("XDG_DATA_HOME", &data_home) };

    let exe = common::fixture("anno_hello64", "hello.c", "gcc", &[]).unwrap();
    let mut s = Session::open(&exe, &[]).await;
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    s.next_pause().await;
    let symbols = s.dbg.symbols();
    let add = symbols.find("anno_hello64.add").unwrap();
    let main = symbols.find("anno_hello64.main").unwrap();

    // Annotations are keyed by module and saved immediately.
    s.dbg.set_comment(add, "adds two numbers").unwrap();
    s.dbg.set_label(add, "my_add").unwrap();
    assert!(s.dbg.toggle_bookmark(add).unwrap());
    assert_eq!(s.dbg.find_label("my_add"), Some(add));
    assert!(s.dbg.set_label(main, "my_add").is_err(), "labels are unique");
    assert!(s.dbg.set_label(main, "two words").is_err());
    assert!(s.dbg.set_comment(0x10, "nowhere").is_err());

    // Patch `mov esi, 3` in main to pass 5 instead: add(2, 5) = 7.
    let mut at = main;
    let mov = loop {
        let insn = s.dbg.instruction_at(at).await.unwrap();
        if insn.mnemonic == "mov" && insn.operands == "esi, 3" {
            break insn;
        }
        assert!(insn.kind != InsnKind::Call || at < main + 0x40, "mov esi, 3 not found");
        at += insn.len() as u64;
    };
    assert_eq!(s.dbg.assemble_at(mov.address, "mov esi, 5", true).await.unwrap(), 5);
    let gdb_view = s.dbg.gdb().console_quiet(&format!("x/5xb 0x{:x}", mov.address)).await.unwrap();
    assert!(gdb_view.contains("0xbe\t0x05\t0x00\t0x00\t0x00"), "{gdb_view}");
    assert_eq!(s.dbg.patches().len(), 1, "only the immediate byte changed");

    // A shorter instruction is padded with NOPs; restoring every byte removes the patches again.
    let push = s.dbg.instruction_at(add).await.unwrap();
    let frame_setup = s.dbg.instruction_at(add + push.len() as u64).await.unwrap();
    assert_eq!(frame_setup.len(), 3);
    assert_eq!(s.dbg.assemble_at(frame_setup.address, "nop", true).await.unwrap(), 3);
    assert_eq!(s.dbg.read_memory(frame_setup.address, 3).await, [Some(0x90); 3]);
    let replaced = frame_setup.address..frame_setup.address + 3;
    let originals: Vec<u8> = s.dbg.patches().iter().filter(|(a, _)| replaced.contains(a)).map(|(_, p)| p.original).collect();
    assert_eq!(originals, frame_setup.bytes);
    for offset in 0..3 {
        assert!(s.dbg.restore_patch(frame_setup.address + offset).await.unwrap());
    }
    assert_eq!(s.dbg.patches().len(), 1);
    assert_eq!(s.dbg.read_memory(frame_setup.address, 3).await.iter().map(|b| b.unwrap()).collect::<Vec<_>>(), frame_setup.bytes);
    assert!(s.dbg.assemble_at(mov.address, "mov esi,", false).await.is_err());

    // The exported file carries the patch on its own.
    let exported = exe.with_file_name("anno_hello64.patched");
    assert_eq!(s.dbg.export_patches(&exported).unwrap(), 1);
    std::fs::set_permissions(&exported, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let run = Command::new(&exported).output().unwrap();
    assert_eq!((String::from_utf8_lossy(&run.stdout).trim(), run.status.code()), ("x=7", Some(2)));

    // And the patched process behaves the same.
    s.dbg.run().await.unwrap();
    s.wait_state(DebugState::Terminated).await;
    assert!(s.output.iter().any(|l| l == "x=7"), "{:?}", s.output);
    assert!(s.logs.iter().any(|l| l.contains("exit code 0x2")), "{:#?}", s.logs);
    s.dbg.stop().await.ok();

    // A new session finds the annotations, before and after the process maps the executable.
    let (dbg, _events) = Debugger::spawn(GdbOptions::default()).await.unwrap();
    dbg.load(&exe, &[]).await.unwrap();
    let static_add = dbg.symbols().find("anno_hello64.add").unwrap();
    assert_eq!(dbg.comment_at(static_add).as_deref(), Some("adds two numbers"));
    assert_eq!(dbg.label_at(static_add).as_deref(), Some("my_add"));
    assert!(dbg.is_bookmarked(static_add));
    assert!(dbg.patches().is_empty(), "patches are not persisted");
    let files: Vec<_> = std::fs::read_dir(data_home.join("cutegdb/db")).unwrap().collect();
    assert_eq!(files.len(), 1);
    std::fs::remove_dir_all(&data_home).unwrap();
}

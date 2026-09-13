//! End-to-end tests of the debugger core against real gdb sessions on tests/fixtures/hello.c.

mod common;

use common::Session;
use cutegdb_core::{Arch, DebugState, InsnKind, StopReason};
use std::path::PathBuf;
use std::time::Duration;

fn fixture(name: &str, compiler: &str) -> Option<PathBuf> {
    common::fixture(name, "hello.c", compiler, &[])
}

#[tokio::test(flavor = "multi_thread")]
async fn system_then_entry_breakpoint() {
    let exe = fixture("core_entry64", "gcc").unwrap();
    let mut s = Session::open(&exe, &[]).await;

    let system = s.next_pause().await;
    assert_eq!(system.reason, StopReason::SystemBreakpoint);
    assert_eq!(system.arch, Arch::X86_64);
    let symbols = s.dbg.symbols();
    assert_eq!(symbols.module_at(system.pc).map(|m| m.name.as_str()), Some("ld-linux-x86-64"));

    s.dbg.run().await.unwrap();
    let entry = s.next_pause().await;
    assert_eq!(entry.reason, StopReason::EntryBreakpoint);
    assert_eq!(Some(entry.pc), s.dbg.symbols().find("core_entry64.EntryPoint"));
    assert!(s.logs.iter().any(|l| l == "System breakpoint reached!"));
    assert!(s.logs.iter().any(|l| l.starts_with("INT3 breakpoint \"entry breakpoint\" at <core_entry64.EntryPoint>")));
    s.dbg.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn breakpoints_stepping_memory_and_output() {
    let exe = fixture("core_hello64", "gcc").unwrap();
    let mut s = Session::open(&exe, &[]).await;
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    assert_eq!(s.next_pause().await.reason, StopReason::EntryBreakpoint);

    let symbols = s.dbg.symbols();
    let add = symbols.find("core_hello64.add").expect("add symbol");
    assert!(s.dbg.toggle_breakpoint(add).await.unwrap());
    assert_eq!(s.dbg.breakpoints(), [add]);
    s.dbg.run().await.unwrap();
    let hit = s.next_pause().await;
    assert!(matches!(hit.reason, StopReason::Breakpoint(_)), "{:?}", hit.reason);
    assert_eq!(hit.pc, add);
    assert_eq!(hit.register("rip").and_then(|v| v.as_u64()), Some(add));
    assert_eq!(symbols.label(add).as_deref(), Some("core_hello64.add"));

    // Our disassembly and memory agree with gdb's own view.
    let insn = s.dbg.instruction_at(hit.pc).await.unwrap();
    let gdb_view = s.dbg.gdb().console_quiet("x/i $pc").await.unwrap();
    assert!(gdb_view.contains(&insn.mnemonic), "{insn:?} vs {gdb_view}");
    let bytes = s.dbg.read_memory(hit.pc, 32).await;
    assert!(bytes.iter().all(Option::is_some));
    assert_eq!(bytes[..insn.len()].iter().map(|b| b.unwrap()).collect::<Vec<_>>(), insn.bytes);
    assert!(s.dbg.read_memory(0, 8).await.iter().all(Option::is_none));

    // Ctrl+F9 stops on the return instruction; F7 then lands back in main.
    s.dbg.execute_till_return().await.unwrap();
    let at_ret = s.next_pause().await;
    assert_eq!(s.dbg.instruction_at(at_ret.pc).await.unwrap().kind, InsnKind::Ret);
    // Changes are relative to the pause before Ctrl+F9, not to the last internal step:
    // rsp went down and back up (push/pop rbp), rip moved.
    let changed = |name: &str| at_ret.registers.iter().find(|r| r.name == name).map(|r| r.changed);
    assert_eq!(changed("rip"), Some(true));
    assert_eq!(changed("rsp"), Some(false));
    s.dbg.step_into().await.unwrap();
    let back = s.next_pause().await;
    assert!(symbols.label(back.pc).unwrap().starts_with("core_hello64.main+"));

    // F8 over the printf call; its output arrives through the pty.
    let call = s.step_to_call(back).await;
    s.dbg.step_over().await.unwrap();
    let after = s.next_pause().await;
    assert_eq!(after.pc, call.address + call.len() as u64);
    s.wait_output("x=5").await;

    assert!(!s.dbg.toggle_breakpoint(add).await.unwrap());
    assert!(s.dbg.breakpoints().is_empty());
    s.dbg.run().await.unwrap();
    s.wait_state(DebugState::Terminated).await;
    assert!(s.logs.iter().any(|l| l.contains("exit code 0x0")), "{:#?}", s.logs);
}

#[tokio::test(flavor = "multi_thread")]
async fn step_into_follows_call_and_run_to_user_code_returns() {
    let exe = fixture("core_step64", "gcc").unwrap();
    let mut s = Session::open(&exe, &[]).await;
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    s.next_pause().await;

    let symbols = s.dbg.symbols();
    let main = symbols.find("core_step64.main").unwrap();
    let add = symbols.find("core_step64.add").unwrap();
    s.dbg.run_to(main).await.unwrap();
    let at_main = s.next_pause().await;
    assert_eq!(at_main.pc, main);

    let call = s.step_to_call(at_main).await;
    assert_eq!(call.target, Some(add));
    s.dbg.step_into().await.unwrap();
    assert_eq!(s.next_pause().await.pc, add);

    // Step into printf through its PLT stub until execution leaves the executable, then Alt+F9 back to main.
    s.dbg.execute_till_return().await.unwrap();
    s.next_pause().await;
    s.dbg.step_into().await.unwrap();
    let back = s.next_pause().await;
    s.step_to_call(back).await;
    let mut outside = None;
    for _ in 0..16 {
        s.dbg.step_into().await.unwrap();
        let snap = s.next_pause().await;
        let module = s.dbg.symbols().module_at(snap.pc).map(|m| m.name.clone());
        if module.as_deref() != Some("core_step64") {
            outside = module;
            break;
        }
    }
    assert!(outside.is_some_and(|m| m == "libc" || m.starts_with("ld-linux")), "never left the executable");
    s.dbg.run_to_user_code().await.unwrap();
    let user = s.next_pause().await;
    let label = s.dbg.symbols().label(user.pc);
    assert!(label.as_deref().is_some_and(|l| l.starts_with("core_step64.main+")), "{label:?}; logs: {:#?}", s.logs);
    s.dbg.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn run_to_user_code_from_the_loader_reaches_the_entry_point() {
    let exe = fixture("core_rtu64", "gcc").unwrap();
    let mut s = Session::open(&exe, &[]).await;
    assert_eq!(s.next_pause().await.reason, StopReason::SystemBreakpoint);
    s.dbg.run_to_user_code().await.unwrap();
    let user = s.next_pause().await;
    assert_eq!(Some(user.pc), s.dbg.symbols().find("core_rtu64.EntryPoint"), "logs: {:#?}", s.logs);
    s.dbg.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn pause_restart_and_stop() {
    let exe = fixture("core_loop64", "gcc").unwrap();
    let mut s = Session::open(&exe, &["loop"]).await;
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    s.wait_state(DebugState::Running).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    s.dbg.pause().await.unwrap();
    let paused = s.next_pause().await;
    assert_eq!(paused.reason, StopReason::Pause);
    assert!(s.logs.iter().any(|l| l == "Program paused!"));
    assert!(s.dbg.evaluate("counter").await.unwrap() > 0);

    s.dbg.restart().await.unwrap();
    assert_eq!(s.next_pause().await.reason, StopReason::SystemBreakpoint);

    // Stop while running, then F9 starts a fresh process.
    s.dbg.run().await.unwrap();
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    s.wait_state(DebugState::Running).await;
    s.dbg.stop().await.unwrap();
    s.wait_state(DebugState::Terminated).await;
    assert_eq!(s.dbg.state(), DebugState::Terminated);
    s.dbg.run().await.unwrap();
    assert_eq!(s.next_pause().await.reason, StopReason::SystemBreakpoint);
    s.dbg.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn x86_32_target() {
    let Some(exe) = fixture("core_hello32", "i686-linux-gnu-gcc") else {
        eprintln!("i686-linux-gnu-gcc not installed; skipping");
        return;
    };
    let mut s = Session::open(&exe, &[]).await;
    assert_eq!(s.next_pause().await.reason, StopReason::SystemBreakpoint);
    s.dbg.run().await.unwrap();
    let entry = s.next_pause().await;
    assert_eq!(entry.reason, StopReason::EntryBreakpoint);
    assert_eq!(entry.arch, Arch::X86);
    assert_eq!(entry.register("eip").and_then(|v| v.as_u64()), Some(entry.pc));
    assert!(entry.pc <= u64::from(u32::MAX));
    assert!(s.dbg.symbols().find("core_hello32.main").is_some());
    assert!(!s.dbg.disassemble(entry.pc, 8).await.is_empty());
    s.dbg.stop().await.unwrap();
}

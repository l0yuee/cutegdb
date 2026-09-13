//! Remote targets (QEMU's gdb stub for AArch64, gdbserver for x86-64) and attaching to a running process.

mod common;

use common::Session;
use cutegdb_core::{Arch, DebugState, Debugger, StopReason};
use cutegdb_mi::GdbOptions;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn installed(tool: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()))
}

/// A port that was free a moment ago. Probing the server instead would consume its only connection.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn session() -> Session {
    let (dbg, rx) = Debugger::spawn(GdbOptions::default()).await.unwrap();
    Session { dbg, rx, logs: Vec::new(), output: Vec::new() }
}

#[tokio::test(flavor = "multi_thread")]
async fn aarch64_under_qemu() {
    if !installed("qemu-aarch64") || !installed("gdb-multiarch") {
        eprintln!("qemu-aarch64 or gdb-multiarch missing; skipping");
        return;
    }
    let Some(exe) = common::fixture("remote_arm64", "hello.c", "aarch64-linux-gnu-gcc", &["-static"]) else {
        eprintln!("aarch64-linux-gnu-gcc missing; skipping");
        return;
    };
    let port = free_port();
    let _qemu = KillOnDrop(
        Command::new("qemu-aarch64")
            .args(["-g", &port.to_string()])
            .arg(&exe)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut s = session().await;
    s.dbg.connect_remote(&format!("127.0.0.1:{port}"), Some(&exe)).await.unwrap();
    let first = s.next_pause().await;
    assert_eq!((first.reason.clone(), first.arch), (StopReason::Connected, Arch::AArch64));
    assert_eq!(Some(first.pc), s.dbg.symbols().find("remote_arm64._start"));
    assert!(first.register("x0").is_some() && first.register("cpsr").is_some());

    s.dbg.step_into().await.unwrap();
    assert_eq!(s.next_pause().await.pc, first.pc + 4);

    let main = s.dbg.symbols().find("remote_arm64.main").unwrap();
    assert!(s.dbg.toggle_breakpoint(main).await.unwrap());
    s.dbg.run().await.unwrap();
    let hit = s.next_pause().await;
    assert!(matches!(hit.reason, StopReason::Breakpoint(_)), "{:?}", hit.reason);
    assert_eq!(hit.pc, main);
    assert_eq!(s.dbg.call_stack(4).await.unwrap()[0].function.as_deref(), Some("main"));
    assert!(!s.dbg.instruction_at(main).await.unwrap().mnemonic.is_empty());
    assert!(s.dbg.restart().await.is_err(), "remote targets cannot be restarted");

    s.dbg.run().await.unwrap();
    s.wait_state(DebugState::Terminated).await;
    assert!(s.logs.iter().any(|l| l.contains("exit code 0x0")), "{:#?}", s.logs);
}

#[tokio::test(flavor = "multi_thread")]
async fn x86_64_under_gdbserver() {
    if !installed("gdbserver") {
        eprintln!("gdbserver missing; skipping");
        return;
    }
    let exe = common::fixture("remote_x64", "hello.c", "gcc", &[]).unwrap();
    let port = free_port();
    let _server = KillOnDrop(
        Command::new("gdbserver")
            .args(["--once", &format!("127.0.0.1:{port}")])
            .arg(&exe)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut s = session().await;
    s.dbg.connect_remote(&format!("127.0.0.1:{port}"), Some(&exe)).await.unwrap();
    let first = s.next_pause().await;
    assert_eq!((first.reason.clone(), first.arch), (StopReason::Connected, Arch::X86_64));

    // The PIE executable is relocated even though the process runs under gdbserver.
    let main = s.dbg.symbols().find("remote_x64.main").unwrap();
    assert!(main > 0x5000_0000_0000, "{main:x}");
    s.dbg.toggle_breakpoint(main).await.unwrap();
    s.dbg.run().await.unwrap();
    assert_eq!(s.next_pause().await.reason, StopReason::EntryBreakpoint);
    s.dbg.run().await.unwrap();
    assert_eq!(s.next_pause().await.pc, main);
    s.dbg.stop().await.unwrap();
    assert_eq!(s.dbg.state(), DebugState::Terminated);
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_and_detach() {
    let exe = common::fixture("remote_attach", "hello.c", "gcc", &[]).unwrap();
    let mut child = KillOnDrop(Command::new(&exe).arg("loop").stdout(Stdio::null()).spawn().unwrap());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let pid = child.0.id();

    let mut s = session().await;
    s.dbg.attach(pid).await.unwrap();
    assert_eq!(s.next_pause().await.reason, StopReason::Attach);
    assert!(s.logs.iter().any(|l| l == "Attach breakpoint reached!"));
    assert_eq!(s.dbg.executable().unwrap(), exe.canonicalize().unwrap());
    assert!(s.dbg.symbols().find("remote_attach.main").unwrap() > 0x5000_0000_0000);
    assert!(s.dbg.evaluate("counter").await.unwrap() > 0);
    assert!(s.dbg.attach(pid).await.is_err(), "already attached");

    s.dbg.detach().await.unwrap();
    assert_eq!(s.dbg.state(), DebugState::Terminated);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(child.0.try_wait().unwrap().is_none(), "the process keeps running after detaching");
    assert!(s.dbg.attach(u32::MAX).await.is_err());
}

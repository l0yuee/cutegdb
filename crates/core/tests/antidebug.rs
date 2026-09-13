//! The anti-anti-debug plugins make a target that probes for a debugger report itself as clean.

mod common;

use common::{Session, fixture};
use cutegdb_core::{DebugEvent, DebugState};
use std::time::Duration;

/// Runs `antidebug` with the given plugins active and returns its printed lines.
///
/// Plugins are installed at the entry breakpoint, where the loader has already mapped libc (so its
/// symbols resolve) but the program's own code has not run yet.
async fn run_checks(plugins: &[&str]) -> Vec<String> {
    let exe = fixture("antidebug", "antidebug.c", "gcc", &[]).expect("gcc builds the fixture");
    let mut session = Session::open(&exe, &[]).await;
    session.next_pause().await; // system breakpoint
    session.dbg.run().await.unwrap();
    session.next_pause().await; // entry breakpoint: libc is mapped

    let ids: Vec<String> = plugins.iter().map(|s| s.to_string()).collect();
    session.dbg.set_active_plugins(&ids).await.unwrap();

    session.dbg.run().await.unwrap();
    // Drive to exit, letting silent plugin breakpoints pass, and collect the fixture's output.
    loop {
        match session.next_event().await {
            DebugEvent::State(DebugState::Terminated) => break,
            DebugEvent::Paused(_) => session.dbg.run().await.unwrap(),
            _ => {}
        }
        if session.output.iter().any(|l| l.starts_with("RESULT:")) {
            break;
        }
    }
    // Drain any output still queued behind the exit notification.
    while !session.output.iter().any(|l| l.starts_with("RESULT:")) {
        match tokio::time::timeout(Duration::from_secs(2), session.rx.recv()).await {
            Ok(Some(DebugEvent::Output(l))) => session.output.push(l),
            _ => break,
        }
    }
    session.output.clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn without_plugins_the_debugger_is_detected() {
    let out = run_checks(&[]).await;
    assert!(out.iter().any(|l| l == "TRACEME: DETECTED"), "{out:?}");
    assert!(out.iter().any(|l| l == "TRACERPID: DETECTED"), "{out:?}");
    assert!(out.iter().any(|l| l == "PARENT: DETECTED"), "{out:?}");
    assert!(out.iter().any(|l| l == "RESULT: DETECTED"), "{out:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn plugins_defeat_every_check() {
    let out = run_checks(&["ptrace_guard", "procfs_cloak"]).await;
    assert!(out.iter().any(|l| l == "TRACEME: clean"), "ptrace not hidden: {out:?}");
    assert!(out.iter().any(|l| l == "TRACERPID: clean"), "TracerPid not hidden: {out:?}");
    assert!(out.iter().any(|l| l == "PARENT: clean"), "parent not hidden: {out:?}");
    assert!(out.iter().any(|l| l == "RESULT: CLEAN"), "{out:?}");
    assert!(!out.iter().any(|l| l.ends_with("DETECTED")), "a check still fired: {out:?}");
}

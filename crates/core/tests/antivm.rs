//! The anti-anti-VM plugins make a target that probes for a virtual machine report bare metal.
//!
//! These tests assume the host is itself a hypervisor guest (so the checks fire without plugins);
//! they no-op with a message otherwise.

mod common;

use common::{Session, fixture};
use cutegdb_core::{DebugEvent, DebugState};
use std::time::Duration;

async fn run_checks(plugins: &[&str]) -> Vec<String> {
    let exe = fixture("antivm", "antivm.c", "gcc", &[]).expect("gcc builds the fixture");
    let mut session = Session::open(&exe, &[]).await;
    session.next_pause().await; // system breakpoint
    session.dbg.run().await.unwrap();
    session.next_pause().await; // entry breakpoint: libc mapped, target code not run yet

    let ids: Vec<String> = plugins.iter().map(|s| s.to_string()).collect();
    session.dbg.set_active_plugins(&ids).await.unwrap();

    session.dbg.run().await.unwrap();
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
    while !session.output.iter().any(|l| l.starts_with("RESULT:")) {
        match tokio::time::timeout(Duration::from_secs(2), session.rx.recv()).await {
            Ok(Some(DebugEvent::Output(l))) => session.output.push(l),
            _ => break,
        }
    }
    session.output.clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn without_plugins_the_vm_is_detected() {
    let out = run_checks(&[]).await;
    if !out.iter().any(|l| l == "RESULT: DETECTED") {
        eprintln!("host is not a detectable VM; skipping: {out:?}");
        return;
    }
    // The x86 CPUID checks are always present on a hypervisor guest.
    assert!(out.iter().any(|l| l == "CPUID_HV: DETECTED"), "{out:?}");
    assert!(out.iter().any(|l| l == "CPUID_VENDOR: DETECTED"), "{out:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn plugins_defeat_every_vm_check() {
    let baseline = run_checks(&[]).await;
    if !baseline.iter().any(|l| l == "RESULT: DETECTED") {
        eprintln!("host is not a detectable VM; skipping: {baseline:?}");
        return;
    }
    // Every check the baseline flagged must become clean with the plugins active.
    let flagged: Vec<String> = baseline
        .iter()
        .filter(|l| l.ends_with("DETECTED") && !l.starts_with("RESULT:"))
        .map(|l| l.split(':').next().unwrap().to_owned())
        .collect();

    let out = run_checks(&["cpuid_spoof", "vm_file_cloak", "vm_syscall_cloak"]).await;
    for name in &flagged {
        assert!(
            out.iter().any(|l| l == &format!("{name}: clean")),
            "{name} still detected with plugins: {out:?}"
        );
    }
    assert!(out.iter().any(|l| l == "RESULT: CLEAN"), "{out:?}");
    assert!(!out.iter().any(|l| l.ends_with("DETECTED")), "a check still fired: {out:?}");
}

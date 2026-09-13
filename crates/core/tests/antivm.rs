//! The anti-anti-VM plugins make a target that probes for a virtual machine report bare metal.
//!
//! These tests assume the host is itself a hypervisor guest (so the checks fire without plugins);
//! they no-op with a message otherwise.

mod common;

use common::{Session, example};
use cutegdb_core::{DebugEvent, DebugState};
use std::time::Duration;

/// Runs an `examples/anti-vm/<relpath>` program with the given plugins and returns its output.
async fn run_example(name: &str, relpath: &str, plugins: &[&str]) -> Vec<String> {
    let exe = example(name, relpath, "gcc", &[]).expect("gcc builds the example");
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

/// The check names (before the ':') that reported DETECTED, excluding the RESULT summary.
fn flagged(output: &[String]) -> Vec<String> {
    output
        .iter()
        .filter(|l| l.ends_with("DETECTED") && !l.starts_with("RESULT:"))
        .map(|l| l.split(':').next().unwrap().to_owned())
        .collect()
}

/// (executable name, source under examples/anti-vm, plugins that defeat it).
const CASES: &[(&str, &str, &[&str])] = &[
    ("vm_cpuid", "anti-vm/cpuid.c", &["cpuid_spoof"]),
    ("vm_sysfiles", "anti-vm/sysfiles.c", &["vm_file_cloak", "vm_syscall_cloak"]),
];

#[tokio::test(flavor = "multi_thread")]
async fn without_plugins_the_vm_is_detected() {
    let mut detectable = false;
    for (name, source, _) in CASES {
        let out = run_example(name, source, &[]).await;
        if out.iter().any(|l| l == "RESULT: DETECTED") {
            detectable = true;
            assert!(!flagged(&out).is_empty(), "{source}: {out:?}");
        }
    }
    if !detectable {
        eprintln!("host is not a detectable VM; skipping");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn plugins_defeat_every_vm_check() {
    for (name, source, plugins) in CASES {
        let baseline = run_example(name, source, &[]).await;
        if !baseline.iter().any(|l| l == "RESULT: DETECTED") {
            eprintln!("{source}: host does not trip this check; skipping");
            continue;
        }
        let expected = flagged(&baseline);
        let out = run_example(name, source, plugins).await;
        for check in &expected {
            assert!(
                out.iter().any(|l| l == &format!("{check}: clean")),
                "{source}: {check} still detected with plugins: {out:?}"
            );
        }
        assert!(out.iter().any(|l| l == "RESULT: CLEAN"), "{source}: {out:?}");
        assert!(!out.iter().any(|l| l.ends_with("DETECTED")), "{source}: a check still fired: {out:?}");
    }
}

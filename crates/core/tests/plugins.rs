//! The plugin framework loads into a real gdb, installs a plugin against the running process, and
//! reports activity. Individual countermeasures have their own fixture-driven tests.

mod common;

use common::{Session, fixture};
use cutegdb_core::{DebugEvent, DebugState};

#[tokio::test]
async fn framework_installs_and_reports_activity() {
    let Some(exe) = fixture("hello_plugins", "hello.c", "gcc", &[]) else {
        eprintln!("gcc not installed; skipping");
        return;
    };
    let mut session = Session::open(&exe, &[]).await;
    session.next_pause().await; // system breakpoint

    // Activate the internal self-test plugin, which silently counts hits at `main`.
    session.dbg.set_active_plugins(&["_selftest".to_string()]).await.unwrap();
    session.wait_log("Countermeasures active").await;
    let before = session.dbg.plugin_stats().await.unwrap();
    assert_eq!(before, [("_selftest".to_owned(), 0)], "plugin installed with a zeroed counter");

    // Running to completion: the self-test counts `main` once and never surfaces a pause there.
    // x64dbg stops at the entry point first, so continue until the process actually exits.
    session.dbg.run().await.unwrap();
    loop {
        match session.next_event().await {
            DebugEvent::State(DebugState::Terminated) => break,
            DebugEvent::Paused(_) => session.dbg.run().await.unwrap(),
            _ => {}
        }
    }

    let after = session.dbg.plugin_stats().await.unwrap();
    assert_eq!(after, [("_selftest".to_owned(), 1)], "the silent breakpoint fired exactly once");

    // Deactivating clears the active set.
    session.dbg.set_active_plugins(&[]).await.unwrap();
    assert!(session.dbg.plugin_stats().await.unwrap().is_empty());
}

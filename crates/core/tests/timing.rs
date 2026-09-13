//! The best-effort anti-debug plugins: the timing normalizer hides an execution pause between two
//! timestamps, and the software-breakpoint cloak restores code bytes on a /proc/self/mem self-read.

mod common;

use common::{Session, fixture};
use cutegdb_core::{DebugEvent, DebugState};
use std::time::Duration;

/// Drives `session` to exit (through the entry breakpoint) and returns the target's output.
async fn drive_to_exit(session: &mut Session) -> Vec<String> {
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

async fn open_at_entry(name: &str, source: &str) -> Session {
    let exe = fixture(name, source, "gcc", &[]).expect("gcc builds the fixture");
    let mut session = Session::open(&exe, &[]).await;
    session.next_pause().await; // system breakpoint
    session.dbg.run().await.unwrap();
    session.next_pause().await; // entry breakpoint
    session
}

#[tokio::test(flavor = "multi_thread")]
async fn timing_normalizer_hides_the_pause() {
    // Baseline: the 100 ms sleeps make both deltas look like a debugger paused the process.
    let mut session = open_at_entry("timing_off", "timing.c").await;
    let out = drive_to_exit(&mut session).await;
    assert!(out.iter().any(|l| l == "RDTSC: DETECTED"), "{out:?}");
    assert!(out.iter().any(|l| l == "CLOCK: DETECTED"), "{out:?}");

    // With the plugin, both timestamp sources advance by a small fixed step.
    let mut session = open_at_entry("timing_on", "timing.c").await;
    session.dbg.set_active_plugins(&["timing_normalizer".into()]).await.unwrap();
    let out = drive_to_exit(&mut session).await;
    assert!(out.iter().any(|l| l == "RDTSC: clean"), "rdtsc not smoothed: {out:?}");
    assert!(out.iter().any(|l| l == "CLOCK: clean"), "clock_gettime not smoothed: {out:?}");
    assert!(out.iter().any(|l| l == "RESULT: CLEAN"), "{out:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn swbp_cloak_restores_code_bytes() {
    // A software breakpoint at `marker` leaves 0xCC where the program reads its own code.
    let mut session = open_at_entry("selfmod_off", "selfmod.c").await;
    session.dbg.execute_user_command("break marker").await.unwrap();
    let out = drive_to_exit(&mut session).await;
    assert!(out.iter().any(|l| l == "SWBP: DETECTED"), "breakpoint byte not seen: {out:?}");

    // With the cloak, the self-read sees the original bytes.
    let mut session = open_at_entry("selfmod_on", "selfmod.c").await;
    session.dbg.execute_user_command("break marker").await.unwrap();
    session.dbg.set_active_plugins(&["swbp_cloak".into()]).await.unwrap();
    let out = drive_to_exit(&mut session).await;
    assert!(out.iter().any(|l| l == "SWBP: clean"), "code byte not restored: {out:?}");
    assert!(out.iter().any(|l| l == "RESULT: CLEAN"), "{out:?}");
}

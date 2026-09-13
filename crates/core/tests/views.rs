//! Breakpoint kinds and the data behind the breakpoints, call stack, threads, memory map, signals
//! and handles views, against real gdb sessions.

mod common;

use common::{Session, fixture};
use cutegdb_core::{BreakpointKind, DebugState, StopReason, WatchAccess};
use std::path::Path;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn hardware_conditional_and_watch_breakpoints() {
    let exe = fixture("views_bp64", "hello.c", "gcc", &[]).unwrap();
    let mut s = Session::open(&exe, &["loop"]).await;
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    assert_eq!(s.next_pause().await.reason, StopReason::EntryBreakpoint);
    let symbols = s.dbg.symbols();
    let add = symbols.find("views_bp64.add").unwrap();
    let main = symbols.find("views_bp64.main").unwrap();

    // add(2, 3) never satisfies this condition.
    let conditional = s.dbg.set_breakpoint(add, false).await.unwrap();
    s.dbg.set_breakpoint_condition(conditional, "$rdi == 3").await.unwrap();

    let hardware = s.dbg.set_breakpoint(main, true).await.unwrap();
    let list = s.dbg.breakpoint_list();
    assert!(list.iter().any(|b| b.number == hardware && b.kind == BreakpointKind::Hardware && b.address == Some(main)));
    assert!(list.iter().any(|b| b.number == conditional && b.condition.as_deref() == Some("$rdi == 3")), "{list:?}");

    s.dbg.run().await.unwrap();
    let hit = s.next_pause().await;
    assert_eq!((hit.pc, hit.reason.clone()), (main, StopReason::Breakpoint(hardware)));
    assert!(s.logs.iter().any(|l| l.starts_with("Hardware breakpoint (execute) at <views_bp64.main>")), "{:#?}", s.logs);
    let frames = s.dbg.call_stack(16).await.unwrap();
    assert_eq!(frames[0].function.as_deref(), Some("main"));
    assert_eq!(frames[0].address, main);
    assert!(frames.len() >= 2, "{frames:?}");
    s.dbg.delete_breakpoint(hardware).await.unwrap();

    // The first stop is the watchpoint in main's loop: the conditional breakpoint never fires.
    let watch = s.dbg.set_watchpoint("counter", WatchAccess::Write).await.unwrap();
    assert!(s.dbg.breakpoint_list().iter().any(|b| b.number == watch
        && b.kind == BreakpointKind::Watchpoint(WatchAccess::Write)
        && b.location == "counter"));
    s.dbg.run().await.unwrap();
    let triggered = s.next_pause().await;
    assert_eq!(
        triggered.reason,
        StopReason::Watchpoint { number: watch, old: Some("0".into()), new: Some("1".into()) }
    );
    assert!(s.logs.iter().any(|l| l.contains(&format!("Hardware watchpoint {watch} triggered")) && l.ends_with(": 0 -> 1")));
    assert_eq!(s.dbg.call_stack(4).await.unwrap()[0].function.as_deref(), Some("main"));

    s.dbg.reload_breakpoints().await.unwrap();
    let list = s.dbg.breakpoint_list();
    assert_eq!(list.iter().find(|b| b.number == conditional).unwrap().hits, 0);
    assert!(list.iter().find(|b| b.number == watch).unwrap().hits >= 1);

    // A disabled watchpoint lets the loop run until paused.
    s.dbg.set_breakpoint_enabled(watch, false).await.unwrap();
    assert!(!s.dbg.breakpoint_list().iter().find(|b| b.number == watch).unwrap().enabled);
    s.dbg.run().await.unwrap();
    s.wait_state(DebugState::Running).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    s.dbg.pause().await.unwrap();
    assert_eq!(s.next_pause().await.reason, StopReason::Pause);

    // The breakpoint table survives a reload from gdb unchanged.
    let before = s.dbg.breakpoint_list();
    s.dbg.reload_breakpoints().await.unwrap();
    let after = s.dbg.breakpoint_list();
    assert_eq!(
        before.iter().map(|b| (b.number, b.enabled, b.condition.clone())).collect::<Vec<_>>(),
        after.iter().map(|b| (b.number, b.enabled, b.condition.clone())).collect::<Vec<_>>()
    );
    s.dbg.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn log_breakpoint_prints_and_continues() {
    let exe = fixture("views_log64", "hello.c", "gcc", &[]).unwrap();
    let mut s = Session::open(&exe, &[]).await;
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    s.next_pause().await;

    let add = s.dbg.symbols().find("views_log64.add").unwrap();
    let number = s.dbg.set_log_breakpoint(add, "add called a=%d b=%d\n", &["$rdi".into(), "$rsi".into()]).await.unwrap();
    let bp = s.dbg.breakpoint_list().into_iter().find(|b| b.number == number).unwrap();
    assert_eq!(bp.kind, BreakpointKind::Log);
    assert!(bp.log_text.as_deref().is_some_and(|t| t.contains("add called")), "{bp:?}");

    s.dbg.run().await.unwrap();
    s.wait_state(DebugState::Terminated).await;
    assert!(s.logs.iter().any(|l| l == "add called a=2 b=3"), "{:#?}", s.logs);
}

#[tokio::test(flavor = "multi_thread")]
async fn threads_signals_handles_and_memory_map() {
    let exe = fixture("views_threads", "threads.c", "gcc", &["-pthread"]).unwrap();
    let canonical = exe.canonicalize().unwrap();
    let mut s = Session::open(&exe, &["signal"]).await;
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    s.next_pause().await;

    let usr1 = s.dbg.signals().await.unwrap().into_iter().find(|x| x.name == "SIGUSR1").unwrap();
    assert!(usr1.stop && usr1.print && usr1.pass, "{usr1:?}");

    s.dbg.run().await.unwrap();
    let signalled = s.next_pause().await;
    assert_eq!(signalled.reason, StopReason::Signal("SIGUSR1".into()));

    let threads = s.dbg.threads().await.unwrap();
    assert_eq!(threads.len(), 3, "{threads:?}");
    let names: Vec<_> = threads.iter().filter_map(|t| t.name.as_deref()).collect();
    assert!(names.contains(&"worker1") && names.contains(&"worker2"), "{names:?}");
    assert_eq!(threads.iter().filter(|t| t.current).count(), 1);
    assert!(threads.iter().all(|t| t.lwp.is_some() && !t.running));

    let worker = threads.iter().find(|t| t.name.as_deref() == Some("worker1")).unwrap().id;
    s.dbg.select_thread(worker).await.unwrap();
    assert_eq!(s.next_pause().await.thread_id, Some(worker));
    assert!(s.dbg.threads().await.unwrap().iter().any(|t| t.id == worker && t.current));

    let files = s.dbg.open_files().await.unwrap();
    assert!(files.iter().any(|f| Path::new(&f.target) == canonical), "{files:?}");
    let map = s.dbg.memory_map().await.unwrap();
    assert!(map.iter().any(|m| m.path == "[stack]"));
    assert!(map.iter().any(|m| Path::new(&m.path) == canonical && m.perms.contains('x')), "{map:?}");

    // Passed silently, SIGUSR1 no longer pauses a restarted run; the handler still runs.
    s.dbg.set_signal_handling("SIGUSR1", false, false, true).await.unwrap();
    let usr1 = s.dbg.signals().await.unwrap().into_iter().find(|x| x.name == "SIGUSR1").unwrap();
    assert!(!usr1.stop && !usr1.print && usr1.pass, "{usr1:?}");
    assert!(s.dbg.set_signal_handling("SIGUSR1; shell", true, true, true).await.is_err());

    s.dbg.restart().await.unwrap();
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    s.wait_state(DebugState::Running).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(s.dbg.state(), DebugState::Running);
    s.dbg.pause().await.unwrap();
    assert_eq!(s.next_pause().await.reason, StopReason::Pause);
    assert_eq!(s.dbg.evaluate("usr1_count").await.unwrap(), 1);
    s.dbg.stop().await.unwrap();
}

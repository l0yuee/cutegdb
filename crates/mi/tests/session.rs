//! End-to-end tests against a real gdb debugging tests/fixtures/hello.c.

use cutegdb_mi::{Event, Gdb, GdbOptions, MiError, Tuple};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

fn build_fixture(name: &str, extra: &[&str]) -> PathBuf {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/hello.c");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let status = Command::new("gcc")
        .args(["-g", "-O0", "-o"])
        .arg(&out)
        .arg(&src)
        .args(extra)
        .status()
        .expect("gcc not available");
    assert!(status.success(), "failed to compile fixture");
    out
}

async fn wait_stopped(ev: &mut UnboundedReceiver<Event>) -> Tuple {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match ev.recv().await {
                Some(Event::Exec { class, results }) if class == "stopped" => return results,
                Some(Event::GdbExited) | None => panic!("gdb exited while waiting for *stopped"),
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for *stopped")
}

#[tokio::test]
async fn break_step_inspect_exit() {
    let exe = build_fixture("hello", &[]);
    let (gdb, mut ev) = Gdb::spawn(GdbOptions::default()).await.unwrap();

    gdb.execute(&format!("-file-exec-and-symbols {}", cutegdb_mi::quote(exe.to_str().unwrap())))
        .await
        .unwrap();
    let bp = gdb.execute("-break-insert main").await.unwrap();
    assert_eq!(bp.results.get("bkpt").unwrap().get_str("number"), Some("1"));

    gdb.execute("-exec-run").await.unwrap();
    let stop = wait_stopped(&mut ev).await;
    assert_eq!(stop.get_str("reason"), Some("breakpoint-hit"));
    assert_eq!(stop.get("frame").unwrap().get_str("func"), Some("main"));

    let names = gdb.execute("-data-list-register-names").await.unwrap();
    let names: Vec<_> = names.results.get("register-names").unwrap().items().filter_map(|v| v.as_str()).collect();
    let rip = names.iter().position(|n| *n == "rip").expect("rip register") as u32;
    let vals = gdb.execute(&format!("-data-list-register-values x {rip}")).await.unwrap();
    let pc = vals.results.get("register-values").unwrap().items().next().unwrap().get_str("value").unwrap().to_owned();
    assert!(pc.starts_with("0x"));

    let mem = gdb.execute("-data-read-memory-bytes $pc 16").await.unwrap();
    let contents = mem.results.get("memory").unwrap().items().next().unwrap().get_str("contents").unwrap();
    assert_eq!(contents.len(), 32);

    // Console commands return their text output.
    let mappings = gdb.console("info proc mappings").await.unwrap();
    assert!(mappings.contains("hello"), "unexpected mappings output: {mappings}");

    // Errors surface as MiError::Gdb with gdb's message.
    match gdb.execute("-data-evaluate-expression no_such_symbol").await {
        Err(MiError::Gdb(msg)) => assert!(msg.contains("no_such_symbol")),
        other => panic!("expected gdb error, got {other:?}"),
    }

    gdb.execute("-exec-next").await.unwrap();
    let stop = wait_stopped(&mut ev).await;
    assert_eq!(stop.get_str("reason"), Some("end-stepping-range"));
    let x = gdb.execute("-data-evaluate-expression x").await.unwrap();
    assert_eq!(x.results.get_str("value"), Some("5"));

    gdb.execute("-exec-continue").await.unwrap();
    let stop = wait_stopped(&mut ev).await;
    assert_eq!(stop.get_str("reason"), Some("exited-normally"));

    gdb.exit().await;
}

#[tokio::test]
async fn interrupt_running_target() {
    let exe = build_fixture("hello_loop", &[]);
    let (gdb, mut ev) = Gdb::spawn(GdbOptions::default()).await.unwrap();
    gdb.execute(&format!("-file-exec-and-symbols {}", cutegdb_mi::quote(exe.to_str().unwrap())))
        .await
        .unwrap();
    gdb.execute("-exec-arguments loop").await.unwrap();
    gdb.execute("-exec-run").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // With mi-async on, gdb accepts commands while the target runs.
    gdb.execute("-exec-interrupt").await.unwrap();
    let stop = wait_stopped(&mut ev).await;
    assert_eq!(stop.get_str("reason"), Some("signal-received"));
    let counter = gdb.execute("-data-evaluate-expression counter").await.unwrap();
    let counter: i64 = counter.results.get_str("value").unwrap().parse().unwrap();
    assert!(counter > 0);

    gdb.console("kill").await.unwrap();
    gdb.exit().await;
}

#[tokio::test]
async fn quiet_commands_do_not_emit_stream_events() {
    let (gdb, mut ev) = Gdb::spawn(GdbOptions::default()).await.unwrap();
    let text = gdb.console_quiet("show version").await.unwrap();
    assert!(text.contains("GNU gdb"));
    let leaked = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            if let Some(Event::Console(t)) = ev.recv().await {
                return t;
            }
        }
    })
    .await;
    assert!(leaked.is_err(), "quiet command emitted console output: {leaked:?}");

    gdb.console("show version").await.unwrap();
    let emitted = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(Event::Console(t)) = ev.recv().await {
                return t;
            }
        }
    })
    .await
    .expect("non-quiet console command must emit output");
    assert!(emitted.contains("GNU gdb"));
    gdb.exit().await;
}

#[tokio::test]
async fn commands_fail_after_gdb_exits() {
    let (gdb, mut ev) = Gdb::spawn(GdbOptions::default()).await.unwrap();
    gdb.exit().await;
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ev.recv()).await.unwrap() {
            Some(Event::GdbExited) | None => break,
            _ => {}
        }
    }
    assert!(gdb.execute("-gdb-version").await.is_err());
}

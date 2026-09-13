//! Conditional tracing against a real debuggee.

mod common;

use common::Session;
use cutegdb_core::TraceOptions;

#[tokio::test(flavor = "multi_thread")]
async fn conditional_trace_records_instructions() {
    let exe = common::fixture("trace_hello64", "hello.c", "gcc", &[]).unwrap();
    let mut s = Session::open(&exe, &[]).await;
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    s.next_pause().await;
    let add = s.dbg.symbols().find("trace_hello64.add").unwrap();
    s.dbg.toggle_breakpoint(add).await.unwrap();
    s.dbg.run().await.unwrap();
    assert_eq!(s.next_pause().await.pc, add);

    // Trace over until the next instruction is `ret`.
    let condition = Some("*(unsigned char*)$pc == 0xc3".to_owned());
    let steps = s.dbg.trace(TraceOptions { step_over: true, max_steps: 1000, stop_condition: condition }).await.unwrap();
    let stopped = s.next_pause().await;
    assert_eq!(s.dbg.instruction_at(stopped.pc).await.unwrap().bytes, [0xc3]);

    let entries = s.dbg.trace_entries();
    assert_eq!(entries.len(), steps);
    assert!(steps > 2, "{entries:#?}");
    assert_eq!(entries[0].address, add);
    assert!(entries[0].text.starts_with("push"), "{:?}", entries[0]);
    assert!(entries[0].changes.iter().any(|(name, _)| name == "rsp"), "{:?}", entries[0].changes);
    let last = entries.last().unwrap();
    assert_eq!(last.address + last.bytes.len() as u64, stopped.pc);
    assert!(s.logs.iter().any(|l| *l == format!("Trace finished after {steps} steps!")), "{:#?}", s.logs);

    // The step limit ends a trace as well.
    let limited = s.dbg.trace(TraceOptions { step_over: false, max_steps: 2, stop_condition: None }).await.unwrap();
    assert_eq!(limited, 2);
    s.next_pause().await;
    assert_eq!(s.dbg.trace_entries().len(), 2);

    let path = exe.with_file_name("trace_hello64.trace.txt");
    assert_eq!(s.dbg.export_trace(&path).unwrap(), 2);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert_eq!(text.lines().next().unwrap().matches(" | ").count(), 3);
    s.dbg.stop().await.unwrap();
}

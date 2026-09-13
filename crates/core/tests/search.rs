//! Pattern search, string references and cross references against a real debuggee.

mod common;

use common::Session;
use cutegdb_core::{Pattern, ReferenceKind};

#[tokio::test(flavor = "multi_thread")]
async fn pattern_search_string_references_and_xrefs() {
    let exe = common::fixture("search_hello64", "hello.c", "gcc", &[]).unwrap();
    let mut s = Session::open(&exe, &[]).await;
    s.next_pause().await;
    s.dbg.run().await.unwrap();
    s.next_pause().await;

    let symbols = s.dbg.symbols();
    let add = symbols.find("search_hello64.add").unwrap();
    let main = symbols.find("search_hello64.main").unwrap();
    let module = symbols.module("search_hello64").unwrap();

    // `push rbp; mov rbp, rsp` starts both functions at -O0.
    let prologue = Pattern::parse("55 48 89 E5").unwrap();
    let in_module = s.dbg.search_memory(&prologue, Some(module.base..module.end), 100).await.unwrap();
    assert!(in_module.contains(&add) && in_module.contains(&main), "{in_module:x?}");
    let everywhere = s.dbg.search_memory(&prologue, None, 10_000).await.unwrap();
    assert!(everywhere.contains(&add) && everywhere.len() >= in_module.len());
    assert_eq!(s.dbg.search_memory(&Pattern::parse("48").unwrap(), None, 5).await.unwrap().len(), 5);
    assert!(s.dbg.search_memory(&Pattern::parse("DE AD BE EF 13 37 C0 DE").unwrap(), Some(module.base..module.end), 10).await.unwrap().is_empty());

    let strings = s.dbg.string_references("search_hello64").await.unwrap();
    // The only string is printf's format: PLT stubs reading GOT pointers do not count.
    assert_eq!(strings.len(), 1, "{strings:x?}");
    let format = &strings[0];
    assert_eq!(format.text, "x=%d");
    assert!(symbols.label(format.from).unwrap().starts_with("search_hello64.main+"));
    assert!(!format.wide);

    let xrefs = s.dbg.references_to(add).await.unwrap();
    assert_eq!(xrefs.len(), 1, "{xrefs:x?}");
    assert_eq!(xrefs[0].kind, ReferenceKind::Call);
    assert!(symbols.label(xrefs[0].from).unwrap().starts_with("search_hello64.main+"));
    assert!(s.dbg.references_to(0x10).await.is_err());

    // Patching code invalidates the cached references.
    let call = s.dbg.instruction_at(xrefs[0].from).await.unwrap();
    s.dbg.assemble_at(call.address, "nop", true).await.unwrap();
    assert!(s.dbg.references_to(add).await.unwrap().is_empty());
    s.dbg.stop().await.unwrap();
}

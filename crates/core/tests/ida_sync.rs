//! The IDA Pro sync plugin as a ret-sync debugger client, driven against a fake
//! dispatcher (a plain TCP server) so the whole wire protocol — handshake, module
//! notice, location updates, breakpoint marks and the reverse command channel —
//! is exercised without needing a real IDA Pro.

use std::time::Duration;

use cutegdb_core::{RetSyncClient, RetSyncConfig};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::net::tcp::OwnedReadHalf;

/// The runtime load base and program counter of a PIE process under ASLR.
const BASE: u64 = 0x5555_5555_4000; // = 93824992231424
const PC1: u64 = 0x5555_5555_5129; // = base + 0x1129
const PC2: u64 = 0x5555_5555_5130; // = base + 0x1130
const BP: u64 = 0x5555_5555_5200; // = base + 0x1200

async fn line(reader: &mut BufReader<OwnedReadHalf>) -> String {
    let mut buf = String::new();
    let read = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut buf))
        .await
        .expect("timed out waiting for a ret-sync message")
        .expect("read failed");
    assert_ne!(read, 0, "connection closed unexpectedly");
    buf.trim_end().to_owned()
}

async fn next_command(inbound: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> String {
    tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .expect("timed out waiting for an inbound command")
        .expect("inbound channel closed")
}

#[tokio::test]
async fn speaks_the_ret_sync_protocol_both_ways() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (client, mut inbound) = RetSyncClient::new(RetSyncConfig { host: "127.0.0.1".into(), port });
    client.set_enabled(true);

    let (stream, _) = listener.accept().await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Handshake announces the gdb dialect.
    assert_eq!(
        line(&mut reader).await,
        "[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - cutegdb\",\"dialect\":\"gdb\"}"
    );

    // First pause: module notice (for IDB routing/rebasing) then the location.
    client.on_pause("/tmp/hello64", BASE, PC1);
    assert_eq!(
        line(&mut reader).await,
        "[notice]{\"type\":\"module\",\"path\":\"/tmp/hello64\",\"modules\":\
         [{\"base\":93824992231424,\"path\":\"/tmp/hello64\"}]}"
    );
    assert_eq!(line(&mut reader).await, "[sync]{\"type\":\"loc\",\"base\":93824992231424,\"offset\":93824992235817}");

    // Same module again: only the location, no repeated module notice.
    client.on_pause("/tmp/hello64", BASE, PC2);
    assert_eq!(line(&mut reader).await, "[sync]{\"type\":\"loc\",\"base\":93824992231424,\"offset\":93824992235824}");

    // A breakpoint is marked with a bc oneshot at its address.
    client.on_breakpoint(BASE, BP);
    assert_eq!(
        line(&mut reader).await,
        "[notice]{\"type\":\"bc\",\"msg\":\"oneshot\",\"base\":93824992231424,\"offset\":93824992236032}"
    );

    // Reverse channel: commands from IDA are delivered for the debugger to run.
    write_half.write_all(b"si\nb *0x555555555200\n").await.unwrap();
    write_half.flush().await.unwrap();
    assert_eq!(next_command(&mut inbound).await, "si");
    assert_eq!(next_command(&mut inbound).await, "b *0x555555555200");

    // Disabling says goodbye.
    client.set_enabled(false);
    assert_eq!(line(&mut reader).await, "[notice]{\"type\":\"dbg_quit\",\"msg\":\"dbg disconnected\"}");
}

#[tokio::test]
async fn nothing_is_sent_while_disabled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (client, _inbound) = RetSyncClient::new(RetSyncConfig { host: "127.0.0.1".into(), port });
    // No set_enabled(true): the client must not connect or emit anything.
    client.on_pause("/tmp/hello64", BASE, PC1);
    client.on_breakpoint(BASE, BP);

    let accept = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
    assert!(accept.is_err(), "the client connected while disabled");
    assert!(!client.is_enabled());
    assert_eq!(client.count(), 0);
}

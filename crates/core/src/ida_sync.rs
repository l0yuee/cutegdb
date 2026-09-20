//! IDA Pro sync: a [ret-sync](https://github.com/bootleg/ret-sync)-compatible
//! debugger client that mirrors the debugger into a live IDA Pro session.
//!
//! Unlike the anti-anti-debug / anti-anti-VM plugins (which run inside gdb's
//! Python to fool the target), this is a *front-end* concern: whenever the
//! debugger pauses, push the current address to IDA so its cursor follows along;
//! whenever IDA sends a command back, run it in the debugger. The debugger drives
//! it from its single `Paused` choke point, so a synthesized step-over or
//! run-to-return syncs once, at the final instruction, with no cursor flicker.
//!
//! # Wire protocol (ret-sync)
//!
//! cutegdb is a ret-sync *debugger client*. It opens a TCP connection to the
//! ret-sync **dispatcher** that the IDA plugin spawns (default `127.0.0.1:9100`;
//! set another host/port for a remote IDA). Messages are newline-terminated and
//! carry a `[notice]` (control/routing) or `[sync]` (payload) prefix followed by
//! JSON, exactly as ret-sync's own debugger plugins send:
//!
//! * on connect — `[notice]{"type":"new_dbg","msg":"dbg connect - cutegdb","dialect":"gdb"}`
//! * on module change — `[notice]{"type":"module","path":"<elf>","modules":[{"base":<b>,"path":"<elf>"}]}`
//! * on every pause — `[sync]{"type":"loc","base":<runtime_base>,"offset":<absolute_pc>}`
//! * on breakpoint set — `[notice]{"type":"bc","msg":"oneshot","base":<b>,"offset":<addr>}`
//! * on disable — `[notice]{"type":"dbg_quit","msg":"dbg disconnected"}`
//!
//! `base`/`offset` are decimal, as ret-sync formats them. IDA rebases with
//! `ea = offset - base + get_imagebase()`, so cutegdb never needs to know IDA's
//! image base; this is correct for PIE, non-PIE and shared libraries. The
//! current-line highlight is applied by the IDA side on each `loc`, so it comes
//! for free. The reverse channel is plain, newline-delimited gdb command strings
//! (`si`, `ni`, `continue`, `b *0x…`, …) that the debugger executes, plus the
//! special `syncoff`.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Where the ret-sync dispatcher lives. Read once, at gdb startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetSyncConfig {
    pub host: String,
    pub port: u16,
}

impl Default for RetSyncConfig {
    fn default() -> Self {
        Self { host: "127.0.0.1".to_owned(), port: 9100 }
    }
}

impl RetSyncConfig {
    /// The endpoint, resolved from `CUTEGDB_RETSYNC` (`host` or `host:port`),
    /// then a `.sync` INI in `$HOME`, then the ret-sync default `127.0.0.1:9100`.
    pub fn load() -> Self {
        std::env::var("CUTEGDB_RETSYNC")
            .ok()
            .and_then(|v| Self::parse_endpoint(&v))
            .or_else(Self::from_sync_file)
            .unwrap_or_default()
    }

    /// Parses `host`, `host:port`, `[v6]` or `[v6]:port`; the port defaults to ret-sync's 9100.
    fn parse_endpoint(spec: &str) -> Option<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return None;
        }
        // Bracketed IPv6, with an optional port: `[::1]` or `[::1]:9500`.
        if let Some(rest) = spec.strip_prefix('[') {
            let (host, after) = rest.split_once(']')?;
            let port = match after.strip_prefix(':') {
                Some(port) => port.trim().parse().ok()?,
                None if after.is_empty() => 9100,
                None => return None,
            };
            return Some(Self { host: host.trim().to_owned(), port });
        }
        // A bare IPv6 address has several colons and no port; keep it whole.
        if spec.matches(':').count() > 1 {
            return Some(Self { host: spec.to_owned(), ..Self::default() });
        }
        match spec.rsplit_once(':') {
            Some((host, port)) => Some(Self { host: host.trim().to_owned(), port: port.trim().parse().ok()? }),
            None => Some(Self { host: spec.to_owned(), ..Self::default() }),
        }
    }

    /// Reads `[INTERFACE] host/port` from ret-sync's own `~/.sync`, for parity
    /// with an existing ret-sync setup.
    fn from_sync_file() -> Option<Self> {
        let home = std::env::var_os("HOME")?;
        let text = std::fs::read_to_string(Path::new(&home).join(".sync")).ok()?;
        Self::parse_sync_ini(&text)
    }

    fn parse_sync_ini(text: &str) -> Option<Self> {
        let mut in_interface = false;
        let (mut host, mut port) = (None, None);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                in_interface = section.trim().eq_ignore_ascii_case("INTERFACE");
                continue;
            }
            if !in_interface {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                match key.trim().to_ascii_lowercase().as_str() {
                    "host" => host = Some(value.trim().to_owned()),
                    "port" => port = value.trim().parse().ok(),
                    _ => {}
                }
            }
        }
        // A `.sync` is only meaningful once it names a host.
        Some(Self { host: host?, port: port.unwrap_or(9100) })
    }
}

/// Control messages from the debugger to the connection worker.
enum Cmd {
    Enable,
    Disable,
    Pause { module_path: String, base: u64, pc: u64 },
    Breakpoint { base: u64, addr: u64 },
}

/// A ret-sync debugger client. Cheap to hold when disabled: every hook checks a
/// flag before touching the channel, and the worker does nothing until enabled.
pub struct RetSyncClient {
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    enabled: AtomicBool,
    count: Arc<AtomicU64>,
    config: RetSyncConfig,
}

impl RetSyncClient {
    /// Spawns the connection worker and returns the client together with the
    /// stream of inbound gdb command strings (IDA → debugger) for the caller to
    /// execute. Must be called inside a Tokio runtime.
    pub fn new(config: RetSyncConfig) -> (Arc<Self>, mpsc::UnboundedReceiver<String>) {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let count = Arc::new(AtomicU64::new(0));
        tokio::spawn(worker(config.clone(), cmd_rx, inbound_tx, count.clone()));
        let client = Arc::new(Self { cmd_tx, enabled: AtomicBool::new(false), count, config });
        (client, inbound_rx)
    }

    /// Turns syncing on or off; returns whether the state actually changed.
    pub fn set_enabled(&self, on: bool) -> bool {
        let changed = self.enabled.swap(on, Ordering::SeqCst) != on;
        if changed {
            let _ = self.cmd_tx.send(if on { Cmd::Enable } else { Cmd::Disable });
        }
        changed
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Report the current location after a pause. `base` is the runtime load base
    /// of the module containing `pc` (from the symbol table).
    pub fn on_pause(&self, module_path: &str, base: u64, pc: u64) {
        if self.is_enabled() {
            let _ = self.cmd_tx.send(Cmd::Pause { module_path: module_path.to_owned(), base, pc });
        }
    }

    /// Mark a breakpoint address in IDA (best-effort colour; ret-sync has no
    /// first-class debugger→IDA breakpoint marker, so this reuses its `bc` channel).
    pub fn on_breakpoint(&self, base: u64, addr: u64) {
        if self.is_enabled() {
            let _ = self.cmd_tx.send(Cmd::Breakpoint { base, addr });
        }
    }

    /// How many locations have been synced, for the plugin status view.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }
}

/// Why a single connection ended.
enum ServeEnd {
    /// The command channel closed (the debugger is gone): stop for good.
    ChannelClosed,
    /// The user disabled syncing: wait to be re-enabled.
    Disabled,
    /// The socket dropped: reconnect if still enabled.
    Disconnected,
}

/// Owns the connection lifecycle: connect, serve, reconnect while enabled.
async fn worker(
    config: RetSyncConfig,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    inbound_tx: mpsc::UnboundedSender<String>,
    count: Arc<AtomicU64>,
) {
    let mut enabled = false;
    // The latest location, kept while (re)connecting so a stop that happened
    // before the tunnel was up is still delivered once it is.
    let mut pending: Option<(String, u64, u64)> = None;

    loop {
        if !enabled {
            match cmd_rx.recv().await {
                None => return,
                Some(Cmd::Enable) => enabled = true,
                Some(Cmd::Pause { module_path, base, pc }) => pending = Some((module_path, base, pc)),
                Some(Cmd::Disable | Cmd::Breakpoint { .. }) => {}
            }
            continue;
        }

        let stream = match TcpStream::connect((config.host.as_str(), config.port)).await {
            Ok(stream) => stream,
            Err(_) => {
                if !idle_wait(&mut cmd_rx, &mut enabled, &mut pending, Duration::from_secs(2)).await {
                    return;
                }
                continue;
            }
        };

        match serve(stream, &mut cmd_rx, &inbound_tx, &count, &mut enabled, &mut pending).await {
            ServeEnd::ChannelClosed => return,
            ServeEnd::Disabled => {}
            ServeEnd::Disconnected => {
                if enabled && !idle_wait(&mut cmd_rx, &mut enabled, &mut pending, Duration::from_secs(1)).await {
                    return;
                }
            }
        }
    }
}

/// Waits up to `dur` while staying responsive to control commands. Returns false
/// only when the command channel has closed (the debugger is gone).
async fn idle_wait(
    cmd_rx: &mut mpsc::UnboundedReceiver<Cmd>,
    enabled: &mut bool,
    pending: &mut Option<(String, u64, u64)>,
    dur: Duration,
) -> bool {
    let sleep = tokio::time::sleep(dur);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => return true,
            cmd = cmd_rx.recv() => match cmd {
                None => return false,
                Some(Cmd::Enable) => *enabled = true,
                Some(Cmd::Disable) => *enabled = false,
                Some(Cmd::Pause { module_path, base, pc }) => *pending = Some((module_path, base, pc)),
                Some(Cmd::Breakpoint { .. }) => {}
            },
        }
    }
}

/// Serves one live connection until it drops or syncing is disabled. Reads run in
/// a separate task because [`AsyncBufReadExt::read_line`] is not cancel-safe, so
/// it must never sit in the `select!` below.
async fn serve(
    stream: TcpStream,
    cmd_rx: &mut mpsc::UnboundedReceiver<Cmd>,
    inbound_tx: &mpsc::UnboundedSender<String>,
    count: &Arc<AtomicU64>,
    enabled: &mut bool,
    pending: &mut Option<(String, u64, u64)>,
) -> ServeEnd {
    let (read_half, mut write) = stream.into_split();
    let mut last_module: Option<(String, u64)> = None;

    if write.write_all(msg_new_dbg("cutegdb").as_bytes()).await.is_err() {
        return ServeEnd::Disconnected;
    }
    let _ = write.flush().await;
    if let Some((module_path, base, pc)) = pending.take()
        && send_location(&mut write, &mut last_module, &module_path, base, pc, count).await.is_err()
    {
        *pending = Some((module_path, base, pc));
        return ServeEnd::Disconnected;
    }

    // Reader task: forwards inbound command lines and signals when the peer goes away.
    let (dead_tx, mut dead_rx) = mpsc::channel::<()>(1);
    let inbound = inbound_tx.clone();
    let reader = tokio::spawn(async move {
        let mut lines = BufReader::new(read_half);
        let mut line = String::new();
        loop {
            line.clear();
            match lines.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let command = line.trim();
                    if !command.is_empty() && inbound.send(command.to_owned()).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = dead_tx.send(()).await;
    });

    let end = loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                None => {
                    let _ = write.write_all(msg_dbg_quit().as_bytes()).await;
                    break ServeEnd::ChannelClosed;
                }
                Some(Cmd::Disable) => {
                    let _ = write.write_all(msg_dbg_quit().as_bytes()).await;
                    let _ = write.flush().await;
                    *enabled = false;
                    break ServeEnd::Disabled;
                }
                Some(Cmd::Enable) => {}
                Some(Cmd::Pause { module_path, base, pc }) => {
                    if send_location(&mut write, &mut last_module, &module_path, base, pc, count).await.is_err() {
                        *pending = Some((module_path, base, pc));
                        break ServeEnd::Disconnected;
                    }
                }
                Some(Cmd::Breakpoint { base, addr }) => {
                    if write.write_all(msg_bc_oneshot(base, addr).as_bytes()).await.is_err() {
                        break ServeEnd::Disconnected;
                    }
                    let _ = write.flush().await;
                }
            },
            _ = dead_rx.recv() => break ServeEnd::Disconnected,
        }
    };
    reader.abort();
    end
}

/// Sends a `module` notice when the module changed, then the `loc` update.
async fn send_location(
    write: &mut (impl AsyncWriteExt + Unpin),
    last_module: &mut Option<(String, u64)>,
    module_path: &str,
    base: u64,
    pc: u64,
    count: &Arc<AtomicU64>,
) -> std::io::Result<()> {
    if last_module.as_ref().is_none_or(|(path, b)| path != module_path || *b != base) {
        write.write_all(msg_module(module_path, base).as_bytes()).await?;
        *last_module = Some((module_path.to_owned(), base));
    }
    write.write_all(msg_loc(base, pc).as_bytes()).await?;
    write.flush().await?;
    count.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn msg_new_dbg(id: &str) -> String {
    format!("[notice]{{\"type\":\"new_dbg\",\"msg\":\"dbg connect - {}\",\"dialect\":\"gdb\"}}\n", json_escape(id))
}

fn msg_module(path: &str, base: u64) -> String {
    let escaped = json_escape(path);
    format!(
        "[notice]{{\"type\":\"module\",\"path\":\"{escaped}\",\"modules\":[{{\"base\":{base},\"path\":\"{escaped}\"}}]}}\n"
    )
}

fn msg_loc(base: u64, pc: u64) -> String {
    format!("[sync]{{\"type\":\"loc\",\"base\":{base},\"offset\":{pc}}}\n")
}

fn msg_bc_oneshot(base: u64, addr: u64) -> String {
    format!("[notice]{{\"type\":\"bc\",\"msg\":\"oneshot\",\"base\":{base},\"offset\":{addr}}}\n")
}

fn msg_dbg_quit() -> String {
    "[notice]{\"type\":\"dbg_quit\",\"msg\":\"dbg disconnected\"}\n".to_owned()
}

/// Minimal JSON string escaping for the few characters a module path can hold.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_match_the_ret_sync_wire_format() {
        assert_eq!(
            msg_new_dbg("cutegdb"),
            "[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - cutegdb\",\"dialect\":\"gdb\"}\n"
        );
        assert_eq!(
            msg_module("/tmp/hello64", 0x5555_5555_4000),
            "[notice]{\"type\":\"module\",\"path\":\"/tmp/hello64\",\"modules\":\
             [{\"base\":93824992231424,\"path\":\"/tmp/hello64\"}]}\n"
        );
        // base and offset are decimal, as ret-sync formats them.
        assert_eq!(msg_loc(0x400000, 0x401129), "[sync]{\"type\":\"loc\",\"base\":4194304,\"offset\":4198697}\n");
        assert_eq!(
            msg_bc_oneshot(0x400000, 0x401200),
            "[notice]{\"type\":\"bc\",\"msg\":\"oneshot\",\"base\":4194304,\"offset\":4198912}\n"
        );
        assert_eq!(msg_dbg_quit(), "[notice]{\"type\":\"dbg_quit\",\"msg\":\"dbg disconnected\"}\n");
    }

    #[test]
    fn json_escapes_paths_with_quotes_and_backslashes() {
        assert_eq!(json_escape("a\\b\"c"), "a\\\\b\\\"c");
        assert_eq!(json_escape("/plain/path"), "/plain/path");
    }

    #[test]
    fn endpoint_from_env_spec() {
        assert_eq!(RetSyncConfig::parse_endpoint("10.0.0.5:9500"), Some(RetSyncConfig { host: "10.0.0.5".into(), port: 9500 }));
        // Bare host keeps the default port.
        assert_eq!(RetSyncConfig::parse_endpoint("10.0.0.5"), Some(RetSyncConfig { host: "10.0.0.5".into(), port: 9100 }));
        assert_eq!(RetSyncConfig::parse_endpoint("  "), None);
        // A non-numeric port is rejected.
        assert_eq!(RetSyncConfig::parse_endpoint("host:nope"), None);
        // Bare IPv6 keeps the default port; brackets can carry one.
        assert_eq!(RetSyncConfig::parse_endpoint("::1"), Some(RetSyncConfig { host: "::1".into(), port: 9100 }));
        assert_eq!(RetSyncConfig::parse_endpoint("fe80::1"), Some(RetSyncConfig { host: "fe80::1".into(), port: 9100 }));
        assert_eq!(RetSyncConfig::parse_endpoint("[::1]:9500"), Some(RetSyncConfig { host: "::1".into(), port: 9500 }));
        assert_eq!(RetSyncConfig::parse_endpoint("[fe80::1]"), Some(RetSyncConfig { host: "fe80::1".into(), port: 9100 }));
    }

    #[test]
    fn endpoint_from_sync_ini() {
        let ini = "# comment\n[INTERFACE]\nhost = 192.168.1.20\nport = 9123\n[ALIASES]\nfoo=bar\n";
        assert_eq!(RetSyncConfig::parse_sync_ini(ini), Some(RetSyncConfig { host: "192.168.1.20".into(), port: 9123 }));
        // Host is required; port falls back to the default.
        assert_eq!(RetSyncConfig::parse_sync_ini("[INTERFACE]\nhost=box\n"), Some(RetSyncConfig { host: "box".into(), port: 9100 }));
        // A host outside the [INTERFACE] section does not count.
        assert_eq!(RetSyncConfig::parse_sync_ini("[OTHER]\nhost=box\n"), None);
    }
}

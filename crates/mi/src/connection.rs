//! Async GDB/MI session over a spawned gdb process.

use crate::parser::{AsyncKind, Record, ResultClass, StreamKind, Tuple, parse_line, parse_result_prefix};
use std::collections::VecDeque;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};

/// Directory in which each session writes a full transcript of MI traffic, when set.
pub const TRACE_ENV: &str = "CUTEGDB_MI_TRACE";

#[derive(Debug, Clone)]
pub struct MiResult {
    pub class: ResultClass,
    pub results: Tuple,
    /// Console stream output produced while this command was executing.
    pub console: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Event {
    Exec { class: String, results: Tuple },
    Status { class: String, results: Tuple },
    Notify { class: String, results: Tuple },
    Console(String),
    Target(String),
    Log(String),
    /// Non-MI output on gdb's stdout or stderr.
    Raw(String),
    /// A result record for a command that already has its result. gdb answers a resuming command
    /// with `^running` and, if resuming then fails (e.g. a breakpoint cannot be inserted), with a
    /// second `^error` for the same token.
    LateResult { class: ResultClass, results: Tuple },
    GdbExited,
}

#[derive(Debug, thiserror::Error)]
pub enum MiError {
    #[error("{0}")]
    Gdb(String),
    #[error("gdb process terminated")]
    Terminated,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct GdbOptions {
    pub program: String,
    pub args: Vec<String>,
}

impl Default for GdbOptions {
    fn default() -> Self {
        Self { program: default_gdb(), args: Vec::new() }
    }
}

/// Prefers `gdb-multiarch` (needed for foreign-architecture remote targets), falling back to `gdb`.
fn default_gdb() -> String {
    let found = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("gdb-multiarch").is_file()))
        .unwrap_or(false);
    if found { "gdb-multiarch".into() } else { "gdb".into() }
}

struct Pending {
    token: u64,
    console: Vec<String>,
    /// Stream output produced while this command runs is captured but not emitted as events.
    quiet: bool,
    tx: oneshot::Sender<MiResult>,
}

type PendingQueue = Arc<Mutex<VecDeque<Pending>>>;

/// Optional transcript of everything sent to and received from gdb.
#[derive(Clone)]
struct Trace {
    file: Option<Arc<Mutex<std::fs::File>>>,
    start: Instant,
}

impl Trace {
    fn from_env() -> Trace {
        static SESSION: AtomicU64 = AtomicU64::new(0);
        let file = std::env::var_os(TRACE_ENV).and_then(|dir| {
            let n = SESSION.fetch_add(1, Ordering::Relaxed);
            let path = PathBuf::from(dir).join(format!("mi-{}-{n}.log", std::process::id()));
            std::fs::File::create(path).ok().map(|f| Arc::new(Mutex::new(f)))
        });
        Trace { file, start: Instant::now() }
    }

    fn line(&self, direction: &str, text: &str) {
        if let Some(file) = &self.file {
            let ms = self.start.elapsed().as_millis();
            let _ = writeln!(file.lock().unwrap(), "{ms:>7} {direction} {}", text.trim_end());
        }
    }
}

pub struct Gdb {
    stdin: tokio::sync::Mutex<ChildStdin>,
    token: AtomicU64,
    pending: PendingQueue,
    child: tokio::sync::Mutex<Child>,
    trace: Trace,
}

impl Gdb {
    pub async fn spawn(opts: GdbOptions) -> Result<(Self, mpsc::UnboundedReceiver<Event>), MiError> {
        let mut child = Command::new(&opts.program)
            .args(["--interpreter=mi3", "--nx", "--quiet"])
            .args(&opts.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");

        let trace = Trace::from_env();
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let pending: PendingQueue = Arc::default();
        tokio::spawn(read_stdout(stdout, pending.clone(), ev_tx.clone(), trace.clone()));
        tokio::spawn(read_stderr(stderr, ev_tx, trace.clone()));

        let gdb = Gdb {
            stdin: tokio::sync::Mutex::new(stdin),
            token: AtomicU64::new(1),
            pending,
            child: tokio::sync::Mutex::new(child),
            trace,
        };
        for cmd in [
            "-gdb-set mi-async on",
            "-gdb-set pagination off",
            "-gdb-set confirm off",
            "-gdb-set width 0",
            "-gdb-set height 0",
            "-gdb-set disassembly-flavor intel",
        ] {
            gdb.execute_quiet(cmd).await?;
        }
        Ok((gdb, ev_rx))
    }

    /// Sends an MI command and waits for its result record. `^error` becomes `MiError::Gdb`.
    pub async fn execute(&self, cmd: &str) -> Result<MiResult, MiError> {
        self.run(cmd, false).await
    }

    /// Like `execute`, but stream output produced by the command is not emitted as events.
    pub async fn execute_quiet(&self, cmd: &str) -> Result<MiResult, MiError> {
        self.run(cmd, true).await
    }

    /// Sends an MI command without waiting; the receiver yields the raw result record.
    pub async fn submit(&self, cmd: &str) -> Result<oneshot::Receiver<MiResult>, MiError> {
        self.submit_with(cmd, false).await
    }

    /// Runs a CLI command through the MI console interpreter and returns its console output.
    pub async fn console(&self, cmd: &str) -> Result<String, MiError> {
        let r = self.execute(&console_command(cmd)).await?;
        Ok(r.console.concat())
    }

    /// Like `console`, but the output is only returned, not emitted as events.
    pub async fn console_quiet(&self, cmd: &str) -> Result<String, MiError> {
        let r = self.execute_quiet(&console_command(cmd)).await?;
        Ok(r.console.concat())
    }

    pub async fn exit(&self) {
        let _ = self.submit("-gdb-exit").await;
        let mut child = self.child.lock().await;
        if tokio::time::timeout(Duration::from_secs(3), child.wait()).await.is_err() {
            let _ = child.kill().await;
        }
    }

    async fn run(&self, cmd: &str, quiet: bool) -> Result<MiResult, MiError> {
        let rx = self.submit_with(cmd, quiet).await?;
        let r = rx.await.map_err(|_| MiError::Terminated)?;
        if r.class == ResultClass::Error {
            return Err(MiError::Gdb(r.results.get_str("msg").unwrap_or("unknown gdb error").to_owned()));
        }
        Ok(r)
    }

    async fn submit_with(&self, cmd: &str, quiet: bool) -> Result<oneshot::Receiver<MiResult>, MiError> {
        let token = self.token.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        // Holding the stdin lock keeps queue order identical to write order.
        let mut stdin = self.stdin.lock().await;
        self.pending.lock().unwrap().push_back(Pending { token, console: Vec::new(), quiet, tx });
        let line = format!("{token}{}\n", cmd.trim());
        self.trace.line(">>", &line);
        stdin.write_all(line.as_bytes()).await?;
        stdin.flush().await?;
        Ok(rx)
    }
}

fn console_command(cmd: &str) -> String {
    format!("-interpreter-exec console {}", quote(cmd))
}

/// Quotes a string as an MI c-string argument.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

async fn read_stdout(
    stdout: impl AsyncRead + Unpin,
    pending: PendingQueue,
    ev: mpsc::UnboundedSender<Event>,
    trace: Trace,
) {
    let mut reader = BufReader::new(stdout);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end_matches(['\r', '\n']);
        trace.line("<<", line);
        match parse_line(line) {
            Ok(Record::Result { token, class, results }) => {
                let waiting = {
                    let mut q = pending.lock().unwrap();
                    q.iter().position(|p| Some(p.token) == token).and_then(|pos| q.remove(pos))
                };
                match waiting {
                    Some(p) => {
                        let _ = p.tx.send(MiResult { class, results, console: p.console });
                    }
                    None => {
                        let _ = ev.send(Event::LateResult { class, results });
                    }
                }
            }
            Ok(Record::Async { kind, class, results, .. }) => {
                let _ = ev.send(match kind {
                    AsyncKind::Exec => Event::Exec { class, results },
                    AsyncKind::Status => Event::Status { class, results },
                    AsyncKind::Notify => Event::Notify { class, results },
                });
            }
            Ok(Record::Stream { kind, text }) => {
                // gdb executes commands in order, so stream output belongs to the oldest pending one.
                let quiet = match pending.lock().unwrap().front_mut() {
                    Some(p) => {
                        if kind == StreamKind::Console {
                            p.console.push(text.clone());
                        }
                        p.quiet
                    }
                    None => false,
                };
                if !quiet {
                    let _ = ev.send(match kind {
                        StreamKind::Console => Event::Console(text),
                        StreamKind::Target => Event::Target(text),
                        StreamKind::Log => Event::Log(text),
                    });
                }
            }
            Ok(Record::Prompt) => {}
            Err(_) if parse_result_prefix(line).is_some() => {
                // Never leave a command waiting because its result record did not parse.
                let (token, class) = parse_result_prefix(line).unwrap_or((None, ResultClass::Error));
                let waiting = {
                    let mut q = pending.lock().unwrap();
                    q.iter().position(|p| Some(p.token) == token).and_then(|pos| q.remove(pos))
                };
                if let Some(p) = waiting {
                    let _ = p.tx.send(MiResult { class, results: Tuple::default(), console: p.console });
                }
                let _ = ev.send(Event::Raw(format!("unparsed gdb result: {line}")));
            }
            Ok(Record::Other(_)) | Err(_) => {
                let _ = ev.send(Event::Raw(line.to_owned()));
            }
        }
    }
    trace.line("--", "gdb stdout closed");
    // Dropping the senders fails every outstanding command with `Terminated`.
    pending.lock().unwrap().clear();
    let _ = ev.send(Event::GdbExited);
}

async fn read_stderr(stderr: impl AsyncRead + Unpin, ev: mpsc::UnboundedSender<Event>, trace: Trace) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        trace.line("!!", &line);
        let _ = ev.send(Event::Raw(line));
    }
}

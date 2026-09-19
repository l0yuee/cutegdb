//! Debugger session with x64dbg run/step semantics on top of gdb.

use crate::arch::Arch;
use crate::disasm::{Disassembler, InsnKind, Instruction};
use crate::memory::{MemoryCache, PAGE_SIZE};
use crate::pty::InferiorTty;
use crate::registers::{RegValue, Register, parse_value};
use crate::assembler::assemble;
use crate::breakpoints::{Breakpoint, BreakpointKind, WatchAccess, parse_breakpoint, parse_breakpoint_table};
use crate::ida_sync::{RetSyncClient, RetSyncConfig};
use crate::database::{Database, ModuleAddress, Patch, database_path, export_patched_file};
use crate::disasm::Reference;
use crate::search::{Pattern, StringReference, find_strings};
use crate::inspect::{FileHandle, Frame, SignalInfo, ThreadInfo, parse_frames, parse_process_id, parse_signals, parse_threads};
use crate::symbols::{Mapping, Module, SymbolTable, parse_proc_mappings};
use crate::util::parse_hex;
use cutegdb_mi::{Event, Gdb, GdbOptions, LineBuffer, MiError, ResultClass, Tuple, quote};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Upper bound for single-step loops such as "execute till return".
const MAX_TRACE_STEPS: usize = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum DebugError {
    #[error(transparent)]
    Mi(#[from] MiError),
    #[error("pty: {0}")]
    Pty(#[from] nix::Error),
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, DebugError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DebugState {
    #[default]
    NoTarget,
    Loaded,
    Running,
    Paused,
    Terminated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// First instruction of the process (the dynamic loader's entry).
    SystemBreakpoint,
    /// Stopped by attaching to a running process.
    Attach,
    /// Initial stop after connecting to a remote target (gdbserver, QEMU).
    Connected,
    /// The executable's entry point, reached from the system breakpoint.
    EntryBreakpoint,
    Breakpoint(u32),
    Watchpoint { number: u32, old: Option<String>, new: Option<String> },
    Step,
    Pause,
    Signal(String),
    Other(String),
}

/// Upper bound for recorded trace entries.
const MAX_TRACE_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct TraceOptions {
    /// Step over calls instead of into them.
    pub step_over: bool,
    pub max_steps: usize,
    /// gdb expression that ends the trace once it is non-zero.
    pub stop_condition: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEntry {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    /// Registers whose value changed by executing the instruction.
    pub changes: Vec<(String, u64)>,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub arch: Arch,
    pub pc: u64,
    pub sp: u64,
    pub thread_id: Option<u32>,
    pub reason: StopReason,
    pub registers: Vec<Register>,
}

impl Snapshot {
    pub fn register(&self, name: &str) -> Option<&RegValue> {
        self.registers.iter().find(|r| r.name == name).map(|r| &r.value)
    }
}

#[derive(Debug, Clone)]
pub enum DebugEvent {
    Log(String),
    /// A line written by the debuggee.
    Output(String),
    State(DebugState),
    Paused(Arc<Snapshot>),
    SymbolsChanged,
    BreakpointsChanged,
    /// Comments, labels, bookmarks or patches changed.
    AnnotationsChanged,
    /// Debuggee memory was modified (patching, byte editing).
    MemoryWritten,
}

#[derive(Default)]
struct Inner {
    state: DebugState,
    arch: Option<Arch>,
    executable: Option<PathBuf>,
    memory: MemoryCache,
    symbols: Arc<SymbolTable>,
    symbols_dirty: bool,
    register_names: Vec<String>,
    last_values: HashMap<String, RegValue>,
    /// gdb's breakpoint table by number, including internal temporary breakpoints.
    breakpoints: BTreeMap<u32, Breakpoint>,
    /// Annotations of the loaded executable; `patches` only describe the current process.
    database: Database,
    database_path: Option<PathBuf>,
    /// Code references per module (path, base); cleared whenever code may have changed.
    reference_cache: HashMap<(String, u64), Arc<Vec<Reference>>>,
    /// Instructions recorded by the last trace.
    trace: Vec<TraceEntry>,
    expect_system_breakpoint: bool,
    expect_attach: bool,
    expect_connect: bool,
    /// Debugging through gdbserver or a gdb stub rather than a local child process.
    remote: bool,
    entry_breakpoint: Option<u32>,
    pause_requested: bool,
    /// gdb's message when a resume that was already reported as running failed afterwards.
    resume_error: Option<String>,
    /// Set during internal step loops: intermediate stops update state without emitting events.
    quiet: bool,
    snapshot: Option<Arc<Snapshot>>,
    /// Whether the `cutegdb` Python plugin namespace has been sourced into this gdb.
    plugins_ready: bool,
}

pub struct Debugger {
    gdb: Arc<Gdb>,
    inner: Mutex<Inner>,
    events: mpsc::UnboundedSender<DebugEvent>,
    /// Incremented after every processed stop.
    stops: watch::Sender<u64>,
    cancel: AtomicBool,
    tty: InferiorTty,
    /// ret-sync client that mirrors pauses to IDA Pro (the "IDA Pro sync" plugin).
    ida_sync: Arc<RetSyncClient>,
}

impl Debugger {
    pub async fn spawn(options: GdbOptions) -> Result<(Arc<Self>, mpsc::UnboundedReceiver<DebugEvent>)> {
        let (gdb, mi_events) = Gdb::spawn(options).await?;
        let (events, rx) = mpsc::unbounded_channel();
        let (output_tx, mut output_rx) = mpsc::unbounded_channel::<String>();
        let tty = InferiorTty::open(output_tx)?;
        gdb.execute_quiet(&format!("-inferior-tty-set {}", quote(&tty.path().to_string_lossy()))).await?;
        // Like x64dbg's call stack, show the C runtime frames that call main.
        gdb.execute_quiet("-gdb-set backtrace past-main on").await?;

        let (ida_sync, mut ida_inbound) = RetSyncClient::new(RetSyncConfig::load());
        let debugger = Arc::new(Self {
            gdb: Arc::new(gdb),
            inner: Mutex::default(),
            events: events.clone(),
            stops: watch::Sender::new(0),
            cancel: AtomicBool::new(false),
            tty,
            ida_sync,
        });
        tokio::spawn(event_loop(Arc::downgrade(&debugger), mi_events));
        // Run commands IDA sends back (step, breakpoints, …) as gdb console
        // commands, so they drive the debugger and refresh its views normally.
        tokio::spawn({
            let weak = Arc::downgrade(&debugger);
            async move {
                while let Some(command) = ida_inbound.recv().await {
                    let Some(debugger) = weak.upgrade() else { return };
                    if command == "syncoff" {
                        debugger.set_ida_sync(false);
                    } else {
                        let _ = debugger.execute_user_command(&command).await;
                    }
                }
            }
        });
        tokio::spawn(async move {
            let mut lines = LineBuffer::default();
            while let Some(chunk) = output_rx.recv().await {
                for line in lines.push(&chunk) {
                    if events.send(DebugEvent::Output(line)).is_err() {
                        return;
                    }
                }
            }
        });
        Ok((debugger, rx))
    }

    pub fn gdb(&self) -> &Arc<Gdb> {
        &self.gdb
    }

    pub fn state(&self) -> DebugState {
        self.inner.lock().unwrap().state
    }

    pub fn arch(&self) -> Option<Arch> {
        self.inner.lock().unwrap().arch
    }

    pub fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.inner.lock().unwrap().snapshot.clone()
    }

    pub fn symbols(&self) -> Arc<SymbolTable> {
        self.inner.lock().unwrap().symbols.clone()
    }

    pub fn executable(&self) -> Option<PathBuf> {
        self.inner.lock().unwrap().executable.clone()
    }

    /// Addresses of user code breakpoints (software and hardware), enabled or not.
    pub fn breakpoints(&self) -> Vec<u64> {
        self.breakpoint_list().iter().filter(|b| b.is_code()).filter_map(|b| b.address).collect()
    }

    /// User-visible breakpoints ordered by number; internal temporary ones are excluded.
    pub fn breakpoint_list(&self) -> Vec<Breakpoint> {
        self.inner.lock().unwrap().breakpoints.values().filter(|b| !b.temporary).cloned().collect()
    }

    /// The user code breakpoint at `address`.
    pub fn breakpoint_at(&self, address: u64) -> Option<Breakpoint> {
        self.breakpoint_list().into_iter().find(|b| b.is_code() && b.address == Some(address))
    }

    pub fn write_input(&self, data: &[u8]) -> std::io::Result<()> {
        self.tty.write_input(data)
    }

    /// Loads an executable (x64dbg: File → Open). Call `start` to begin debugging.
    pub async fn load(&self, path: &Path, args: &[String]) -> Result<()> {
        let path = std::fs::canonicalize(path).map_err(|e| DebugError::Invalid(format!("{}: {e}", path.display())))?;
        if matches!(self.state(), DebugState::Running | DebugState::Paused) {
            self.kill().await?;
        }
        self.gdb.execute_quiet(&format!("-file-exec-and-symbols {}", quote(&path.to_string_lossy()))).await?;
        self.gdb.execute_quiet(&format!("-exec-arguments {}", shell_join(args))).await?;
        self.gdb.execute_quiet("-break-delete").await?;
        let database_file = database_path(&path);
        let (database, database_error) = match Database::load(&database_file) {
            Ok(database) => (database, None),
            Err(e) => (Database::default(), Some(e)),
        };
        let symbols = SymbolTable::from_executable(&path);
        {
            let mut inner = self.inner.lock().unwrap();
            inner.database = database;
            inner.database.patches.clear();
            inner.reference_cache.clear();
            inner.database_path = Some(database_file.clone());
            inner.arch = Arch::of_file(&path);
            inner.executable = Some(path.clone());
            inner.register_names.clear();
            inner.last_values.clear();
            inner.breakpoints.clear();
            inner.symbols = Arc::new(symbols);
        }
        self.emit(DebugEvent::SymbolsChanged);
        self.emit(DebugEvent::BreakpointsChanged);
        self.emit(DebugEvent::AnnotationsChanged);
        self.log(format!("File loaded: {}", path.display()));
        if let Some(e) = database_error {
            self.log(format!("Failed to load database {}: {e}", database_file.display()));
        }
        self.set_state(DebugState::Loaded);
        Ok(())
    }

    /// Starts the loaded executable, pausing at the system breakpoint.
    pub async fn start(&self) -> Result<()> {
        let Some(path) = self.executable() else { return Err(DebugError::Invalid("no executable loaded".into())) };
        {
            let mut inner = self.inner.lock().unwrap();
            inner.expect_system_breakpoint = true;
            // A new process starts from the unmodified file.
            inner.database.patches.clear();
            inner.reference_cache.clear();
        }
        self.emit(DebugEvent::AnnotationsChanged);
        if let Err(e) = self.gdb.console_quiet("starti").await {
            self.inner.lock().unwrap().expect_system_breakpoint = false;
            return Err(e.into());
        }
        self.log(format!("Process started: {}", path.display()));
        Ok(())
    }

    /// Attaches to a running local process (x64dbg: File → Attach); the first pause is the attach stop.
    pub async fn attach(&self, pid: u32) -> Result<()> {
        if matches!(self.state(), DebugState::Running | DebugState::Paused) {
            return Err(DebugError::Invalid("already debugging a process".into()));
        }
        let executable = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|e| DebugError::Invalid(format!("process {pid}: {e}")))?;
        self.load(&executable, &[]).await?;
        self.inner.lock().unwrap().expect_attach = true;
        if let Err(e) = self.gdb.execute_quiet(&format!("-target-attach {pid}")).await {
            self.inner.lock().unwrap().expect_attach = false;
            return Err(e.into());
        }
        self.log(format!("Attached to process {pid}"));
        Ok(())
    }

    /// Leaves the debuggee running and stops debugging it.
    pub async fn detach(&self) -> Result<()> {
        self.require_paused()?;
        self.gdb.execute_quiet("-target-detach").await?;
        {
            let mut inner = self.inner.lock().unwrap();
            inner.memory.clear();
            inner.snapshot = None;
            inner.entry_breakpoint = None;
            inner.remote = false;
        }
        self.set_state(DebugState::Terminated);
        self.log("Detached from process");
        Ok(())
    }

    /// Connects to gdbserver or a gdb stub (QEMU) at `address` ("host:port"). `executable` provides
    /// symbols for what the target runs.
    pub async fn connect_remote(&self, address: &str, executable: Option<&Path>) -> Result<()> {
        if address.is_empty() || !address.chars().all(|c| c.is_ascii_alphanumeric() || ":.-[]_".contains(c)) {
            return Err(DebugError::Invalid(format!("invalid remote address: {address}")));
        }
        if matches!(self.state(), DebugState::Running | DebugState::Paused) {
            return Err(DebugError::Invalid("already debugging a process".into()));
        }
        if let Some(path) = executable {
            self.load(path, &[]).await?;
        }
        self.inner.lock().unwrap().expect_connect = true;
        if let Err(e) = self.gdb.execute_quiet(&format!("-target-select remote {address}")).await {
            self.inner.lock().unwrap().expect_connect = false;
            return Err(e.into());
        }
        self.inner.lock().unwrap().remote = true;
        self.log(format!("Connected to {address}"));
        Ok(())
    }

    /// F9: start when not running, otherwise continue.
    pub async fn run(&self) -> Result<()> {
        match self.state() {
            DebugState::NoTarget => Err(DebugError::Invalid("no executable loaded".into())),
            DebugState::Loaded | DebugState::Terminated => self.start().await,
            DebugState::Paused => self.resume("-exec-continue").await,
            DebugState::Running => Ok(()),
        }
    }

    /// F12. Also cancels a running step loop.
    pub async fn pause(&self) -> Result<()> {
        self.cancel.store(true, Ordering::SeqCst);
        if self.state() == DebugState::Running {
            self.inner.lock().unwrap().pause_requested = true;
            self.gdb.execute_quiet("-exec-interrupt").await?;
        }
        Ok(())
    }

    /// F7.
    pub async fn step_into(&self) -> Result<()> {
        self.require_paused()?;
        self.resume("-exec-step-instruction").await
    }

    /// F8.
    pub async fn step_over(&self) -> Result<()> {
        self.require_paused()?;
        self.resume("-exec-next-instruction").await
    }

    /// F4: run until `address` is reached.
    pub async fn run_to(&self, address: u64) -> Result<()> {
        self.require_paused()?;
        self.gdb.execute_quiet(&format!("-break-insert -t *0x{address:x}")).await?;
        self.resume("-exec-continue").await
    }

    /// Ctrl+F9: step over until the next instruction to execute is a return.
    pub async fn execute_till_return(&self) -> Result<()> {
        self.require_paused()?;
        self.begin_quiet();
        let result = async {
            for _ in 0..MAX_TRACE_STEPS {
                let Some(snap) = self.step_and_wait("-exec-next-instruction").await? else { return Ok(()) };
                if self.cancel.load(Ordering::SeqCst) || snap.reason != StopReason::Step {
                    return Ok(());
                }
                if self.instruction_at(snap.pc).await.is_some_and(|i| i.kind == InsnKind::Ret) {
                    return Ok(());
                }
            }
            Ok(())
        }
        .await;
        self.end_quiet();
        result
    }

    /// Conditional tracing (x64dbg: Ctrl+Alt+F7 / Ctrl+Alt+F8): steps into or over instructions,
    /// recording each one, until `stop_condition` holds, a breakpoint or signal stops the debuggee,
    /// the trace is paused, or `max_steps` is reached. Returns the number of steps.
    pub async fn trace(&self, options: TraceOptions) -> Result<usize> {
        self.require_paused()?;
        let command = if options.step_over { "-exec-next-instruction" } else { "-exec-step-instruction" };
        self.inner.lock().unwrap().trace.clear();
        self.begin_quiet();
        let result = async {
            let mut steps = 0;
            while steps < options.max_steps {
                let Some(before) = self.snapshot() else { break };
                let instruction = self.instruction_at(before.pc).await;
                let Some(after) = self.step_and_wait(command).await? else { break };
                steps += 1;
                let entry = TraceEntry {
                    address: before.pc,
                    bytes: instruction.as_ref().map(|i| i.bytes.clone()).unwrap_or_default(),
                    text: instruction.as_ref().map_or_else(|| "???".to_owned(), Instruction::text),
                    changes: changed_registers(&before.registers, &after.registers),
                };
                {
                    let mut inner = self.inner.lock().unwrap();
                    if inner.trace.len() < MAX_TRACE_ENTRIES {
                        inner.trace.push(entry);
                    }
                }
                if self.cancel.load(Ordering::SeqCst) || after.reason != StopReason::Step {
                    break;
                }
                if let Some(condition) = &options.stop_condition
                    && self.evaluate(condition).await.is_ok_and(|value| value != 0)
                {
                    break;
                }
            }
            Ok(steps)
        }
        .await;
        // Logged before the final pause is reported, as x64dbg does.
        if let Ok(steps) = &result {
            self.log(format!("Trace finished after {steps} steps!"));
        }
        self.end_quiet();
        result
    }

    pub fn trace_entries(&self) -> Vec<TraceEntry> {
        self.inner.lock().unwrap().trace.clone()
    }

    /// Writes the last trace as text, one instruction per line; returns the number of entries.
    pub fn export_trace(&self, path: &Path) -> Result<usize> {
        use std::fmt::Write as _;
        let (entries, arch) = {
            let inner = self.inner.lock().unwrap();
            (inner.trace.clone(), inner.arch.unwrap_or(Arch::X86_64))
        };
        let mut text = String::new();
        for entry in &entries {
            let bytes: Vec<String> = entry.bytes.iter().map(|b| format!("{b:02X}")).collect();
            let changes: Vec<String> = entry.changes.iter().map(|(name, value)| format!("{name}={value:X}")).collect();
            let _ = writeln!(
                text,
                "{} | {} | {} | {}",
                arch.format_address(entry.address),
                bytes.join(" "),
                entry.text,
                changes.join(" ")
            );
        }
        std::fs::write(path, text).map_err(|e| DebugError::Invalid(format!("{}: {e}", path.display())))?;
        Ok(entries.len())
    }

    /// Alt+F9: return from callees until execution is back inside the main executable.
    pub async fn run_to_user_code(&self) -> Result<()> {
        self.require_paused()?;
        let Some(exe) = self.executable() else { return Err(DebugError::Invalid("no executable loaded".into())) };
        self.begin_quiet();
        let result = async {
            for _ in 0..4096 {
                let Some(snap) = self.snapshot() else { return Ok(()) };
                let in_user_code = self.symbols().module_at(snap.pc).is_some_and(|m| Path::new(&m.path) == exe);
                if in_user_code || self.cancel.load(Ordering::SeqCst) {
                    return Ok(());
                }
                let stopped = match self.step_and_wait("-exec-finish").await {
                    // gdb cannot unwind here. Before the entry point (the loader's first frames have
                    // no caller) the pending entry breakpoint is the next user code; elsewhere (PLT
                    // resolvers, prologues without CFI) single-step until unwinding works.
                    Err(DebugError::Mi(MiError::Gdb(_))) => {
                        let entry_pending = self.inner.lock().unwrap().entry_breakpoint.is_some();
                        let command = if entry_pending { "-exec-continue" } else { "-exec-step-instruction" };
                        self.step_and_wait(command).await?
                    }
                    other => other?,
                };
                if stopped.is_none() {
                    return Ok(());
                }
            }
            Ok(())
        }
        .await;
        self.end_quiet();
        result
    }

    /// Ctrl+F2.
    pub async fn restart(&self) -> Result<()> {
        if self.executable().is_none() {
            return Err(DebugError::Invalid("no executable loaded".into()));
        }
        if self.inner.lock().unwrap().remote {
            return Err(DebugError::Invalid("restarting is not supported for remote targets".into()));
        }
        self.kill().await?;
        self.start().await
    }

    /// Alt+F2.
    pub async fn stop(&self) -> Result<()> {
        self.kill().await?;
        self.log("Debugging stopped!");
        Ok(())
    }

    /// F2: returns whether a breakpoint exists at `address` afterwards.
    pub async fn toggle_breakpoint(&self, address: u64) -> Result<bool> {
        match self.breakpoint_at(address) {
            Some(existing) => {
                self.delete_breakpoint(existing.number).await?;
                let shown = self.arch().unwrap_or(Arch::X86_64).format_address(address);
                self.log(format!("Breakpoint at {shown} deleted!"));
                Ok(false)
            }
            None => self.set_breakpoint(address, false).await.map(|_| true),
        }
    }

    /// Software (`int3`) or hardware execution breakpoint; returns gdb's breakpoint number.
    pub async fn set_breakpoint(&self, address: u64, hardware: bool) -> Result<u32> {
        let flag = if hardware { "-h " } else { "" };
        let r = self.gdb.execute_quiet(&format!("-break-insert {flag}*0x{address:x}")).await?;
        let number = self.store_reported_breakpoint(&r.results)?;
        let shown = self.arch().unwrap_or(Arch::X86_64).format_address(address);
        self.log(format!("{} at {shown} set!", if hardware { "Hardware breakpoint" } else { "Breakpoint" }));
        self.mark_breakpoint_in_ida(address);
        Ok(number)
    }

    /// Hardware watchpoint on an lvalue such as `counter` or `*(unsigned int*)0x4010`.
    pub async fn set_watchpoint(&self, expression: &str, access: WatchAccess) -> Result<u32> {
        let flag = match access {
            WatchAccess::Write => "",
            WatchAccess::Read => "-r ",
            WatchAccess::ReadWrite => "-a ",
        };
        let r = self.gdb.execute_quiet(&format!("-break-watch {flag}{}", quote(expression))).await?;
        let number = ["wpt", "hw-rwpt", "hw-awpt"]
            .iter()
            .find_map(|key| r.results.get(key))
            .and_then(|w| w.get_str("number"))
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| DebugError::Invalid("gdb did not report the watchpoint".into()))?;
        // The watch result carries no details; take them from the breakpoint table.
        self.reload_breakpoints().await?;
        self.log(format!("Hardware watchpoint {number} ({expression}) set!"));
        Ok(number)
    }

    /// Breakpoint that logs a printf-style `format` with `args` and continues (gdb dprintf).
    pub async fn set_log_breakpoint(&self, address: u64, format: &str, args: &[String]) -> Result<u32> {
        let mut command = format!("-dprintf-insert *0x{address:x} {}", quote(format));
        for arg in args {
            command.push(' ');
            command.push_str(&quote(arg));
        }
        let r = self.gdb.execute_quiet(&command).await?;
        let number = self.store_reported_breakpoint(&r.results)?;
        let shown = self.arch().unwrap_or(Arch::X86_64).format_address(address);
        self.log(format!("Log breakpoint at {shown} set!"));
        Ok(number)
    }

    pub async fn delete_breakpoint(&self, number: u32) -> Result<()> {
        self.gdb.execute_quiet(&format!("-break-delete {number}")).await?;
        self.inner.lock().unwrap().breakpoints.remove(&number);
        self.emit(DebugEvent::BreakpointsChanged);
        Ok(())
    }

    pub async fn set_breakpoint_enabled(&self, number: u32, enabled: bool) -> Result<()> {
        let command = if enabled { "-break-enable" } else { "-break-disable" };
        self.gdb.execute_quiet(&format!("{command} {number}")).await?;
        if let Some(bp) = self.inner.lock().unwrap().breakpoints.get_mut(&number) {
            bp.enabled = enabled;
        }
        self.emit(DebugEvent::BreakpointsChanged);
        Ok(())
    }

    /// gdb expression that must be true for the breakpoint to stop; an empty one removes the condition.
    pub async fn set_breakpoint_condition(&self, number: u32, condition: &str) -> Result<()> {
        let condition = condition.trim();
        let command = if condition.is_empty() {
            format!("-break-condition {number}")
        } else {
            format!("-break-condition {number} {}", quote(condition))
        };
        self.gdb.execute_quiet(&command).await?;
        if let Some(bp) = self.inner.lock().unwrap().breakpoints.get_mut(&number) {
            bp.condition = (!condition.is_empty()).then(|| condition.to_owned());
        }
        self.emit(DebugEvent::BreakpointsChanged);
        Ok(())
    }

    /// Replaces the breakpoint table with gdb's `-break-list`.
    pub async fn reload_breakpoints(&self) -> Result<()> {
        let r = self.gdb.execute_quiet("-break-list").await?;
        let table = parse_breakpoint_table(&r.results);
        self.inner.lock().unwrap().breakpoints = table.into_iter().map(|b| (b.number, b)).collect();
        self.emit(DebugEvent::BreakpointsChanged);
        Ok(())
    }

    fn store_reported_breakpoint(&self, results: &Tuple) -> Result<u32> {
        let bp = results
            .get("bkpt")
            .and_then(parse_breakpoint)
            .ok_or_else(|| DebugError::Invalid("gdb did not report the breakpoint".into()))?;
        let number = bp.number;
        self.inner.lock().unwrap().breakpoints.insert(number, bp);
        self.emit(DebugEvent::BreakpointsChanged);
        Ok(number)
    }

    /// Reads target memory through the page cache; unreadable bytes are `None`.
    pub async fn read_memory(&self, address: u64, len: usize) -> Vec<Option<u8>> {
        let (missing, generation) = {
            let inner = self.inner.lock().unwrap();
            (inner.memory.missing_pages(address, len), inner.memory.generation())
        };
        for base in missing.into_iter().take(256) {
            let page = match self.gdb.execute_quiet(&format!("-data-read-memory-bytes 0x{base:x} {PAGE_SIZE}")).await {
                Ok(r) => decode_memory_blocks(base, &r.results),
                Err(_) => vec![None; PAGE_SIZE],
            };
            // The debuggee ran since this read started; its pages would be stale.
            if !self.inner.lock().unwrap().memory.insert_page_if_current(generation, base, page) {
                break;
            }
        }
        self.inner.lock().unwrap().memory.read(address, len)
    }

    /// Pages of `[address, address + len)` that are not cached yet.
    pub fn missing_pages(&self, address: u64, len: usize) -> Vec<u64> {
        self.inner.lock().unwrap().memory.missing_pages(address, len)
    }

    /// Re-reads registers and memory after the user modified the paused debuggee.
    pub async fn refresh(&self) -> Result<()> {
        self.refresh_snapshot(None).await
    }

    async fn refresh_snapshot(&self, thread_id: Option<u32>) -> Result<()> {
        self.require_paused()?;
        self.inner.lock().unwrap().memory.clear();
        let registers = self.fetch_registers().await?;
        let snapshot = {
            let mut inner = self.inner.lock().unwrap();
            let Some(old) = inner.snapshot.clone() else { return Ok(()) };
            let register = |name: &str| registers.iter().find(|r| r.name == name).and_then(|r| r.value.as_u64());
            let snapshot = Arc::new(Snapshot {
                arch: old.arch,
                pc: register(old.arch.pc_register()).unwrap_or(old.pc),
                sp: register(old.arch.sp_register()).unwrap_or(old.sp),
                thread_id: thread_id.or(old.thread_id),
                reason: old.reason.clone(),
                registers,
            });
            inner.snapshot = Some(snapshot.clone());
            snapshot
        };
        self.emit(DebugEvent::Paused(snapshot));
        Ok(())
    }

    /// Frames of the current thread, innermost first.
    pub async fn call_stack(&self, depth: usize) -> Result<Vec<Frame>> {
        self.require_paused()?;
        let r = self.gdb.execute_quiet(&format!("-stack-list-frames 0 {}", depth.max(1) - 1)).await?;
        Ok(parse_frames(&r.results))
    }

    pub async fn threads(&self) -> Result<Vec<ThreadInfo>> {
        let r = self.gdb.execute_quiet("-thread-info").await?;
        Ok(parse_threads(&r.results))
    }

    /// Makes `id` the current thread; registers and the snapshot follow it.
    pub async fn select_thread(&self, id: u32) -> Result<()> {
        self.require_paused()?;
        self.gdb.execute_quiet(&format!("-thread-select {id}")).await?;
        self.refresh_snapshot(Some(id)).await
    }

    pub async fn memory_map(&self) -> Result<Vec<Mapping>> {
        Ok(parse_proc_mappings(&self.gdb.console_quiet("info proc mappings").await?))
    }

    pub async fn signals(&self) -> Result<Vec<SignalInfo>> {
        Ok(parse_signals(&self.gdb.console_quiet("info signals").await?))
    }

    /// gdb's `handle`: whether a signal pauses the debuggee, is reported, and is delivered to it.
    pub async fn set_signal_handling(&self, signal: &str, stop: bool, print: bool, pass: bool) -> Result<()> {
        if signal.is_empty() || !signal.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(DebugError::Invalid(format!("invalid signal name: {signal}")));
        }
        let command = format!(
            "handle {signal} {} {} {}",
            if stop { "stop" } else { "nostop" },
            if print { "print" } else { "noprint" },
            if pass { "pass" } else { "nopass" }
        );
        self.gdb.console_quiet(&command).await?;
        Ok(())
    }

    pub async fn process_id(&self) -> Result<Option<u32>> {
        let r = self.gdb.execute_quiet("-list-thread-groups").await?;
        Ok(parse_process_id(&r.results))
    }

    /// Open file descriptors of the (local) debuggee.
    pub async fn open_files(&self) -> Result<Vec<FileHandle>> {
        let pid = self.process_id().await?.ok_or_else(|| DebugError::Invalid("no running process".into()))?;
        tokio::task::spawn_blocking(move || crate::inspect::open_files(pid))
            .await
            .map_err(|e| DebugError::Invalid(e.to_string()))?
            .map_err(|e| DebugError::Invalid(format!("/proc/{pid}/fd: {e}")))
    }

    /// Bytes already in the cache, without talking to gdb.
    pub fn cached_memory(&self, address: u64, len: usize) -> Vec<Option<u8>> {
        self.inner.lock().unwrap().memory.read(address, len)
    }

    /// Writes bytes into the paused debuggee; changes inside modules are recorded as patches.
    pub async fn write_memory(&self, address: u64, bytes: &[u8]) -> Result<()> {
        self.require_paused()?;
        if bytes.is_empty() {
            return Ok(());
        }
        let original: Option<Vec<u8>> = self.read_memory(address, bytes.len()).await.into_iter().collect();
        let original = original
            .ok_or_else(|| DebugError::Invalid(format!("memory at {} is not readable", self.format_address(address))))?;
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        self.gdb.execute_quiet(&format!("-data-write-memory-bytes 0x{address:x} {hex}")).await?;
        {
            let mut inner = self.inner.lock().unwrap();
            inner.memory.write(address, bytes);
            inner.reference_cache.clear();
            let symbols = inner.symbols.clone();
            for (i, (&new, &old)) in bytes.iter().zip(&original).enumerate() {
                if let Some(location) = ModuleAddress::from_address(&symbols, address + i as u64) {
                    inner.database.record_patch(location, old, new);
                }
            }
        }
        self.emit(DebugEvent::MemoryWritten);
        self.emit(DebugEvent::AnnotationsChanged);
        Ok(())
    }

    /// Assembles `text` at `address` (x64dbg: Space) and writes it; returns the number of bytes written.
    /// With `fill_nops`, a shorter encoding is padded with NOPs to the end of the replaced instruction.
    pub async fn assemble_at(&self, address: u64, text: &str, fill_nops: bool) -> Result<usize> {
        let arch = self.arch().ok_or_else(|| DebugError::Invalid("no executable loaded".into()))?;
        let mut bytes = {
            let symbols = self.symbols();
            let database = self.inner.lock().unwrap().database.clone();
            let resolve =
                |name: &str| symbols.find(name).or_else(|| database.find_label(name).and_then(|l| l.resolve(&symbols)));
            assemble(arch, text, address, &resolve).map_err(|e| DebugError::Invalid(e.to_string()))?
        };
        if fill_nops
            && arch != Arch::AArch64
            && let Some(old) = self.instruction_at(address).await
            && bytes.len() < old.len()
        {
            bytes.resize(old.len(), 0x90);
        }
        self.write_memory(address, &bytes).await?;
        Ok(bytes.len())
    }

    /// Reads `[start, end)` straight from gdb in large chunks (bypassing the page cache) and returns the
    /// readable blocks, merging adjacent ones so that searches can match across chunk boundaries.
    async fn read_range(&self, start: u64, end: u64) -> Vec<(u64, Vec<u8>)> {
        const CHUNK: u64 = 0x10_0000;
        let mut blocks: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut at = start;
        while at < end {
            let len = (end - at).min(CHUNK);
            if let Ok(r) = self.gdb.execute_quiet(&format!("-data-read-memory-bytes 0x{at:x} {len}")).await {
                for block in r.results.get("memory").into_iter().flat_map(|m| m.items()) {
                    let (Some(begin), Some(contents)) = (block.get_str("begin").and_then(parse_hex), block.get_str("contents")) else {
                        continue;
                    };
                    let bytes = decode_hex(contents);
                    match blocks.last_mut() {
                        Some((previous, data)) if *previous + data.len() as u64 == begin => data.extend(bytes),
                        _ => blocks.push((begin, bytes)),
                    }
                }
            }
            at += len;
        }
        blocks
    }

    /// Byte pattern search (x64dbg: Ctrl+B) in `range`, or in all readable memory; at most `limit` hits.
    pub async fn search_memory(&self, pattern: &Pattern, range: Option<std::ops::Range<u64>>, limit: usize) -> Result<Vec<u64>> {
        self.require_paused()?;
        let ranges: Vec<(u64, u64)> = match range {
            Some(range) => vec![(range.start, range.end)],
            None => self
                .memory_map()
                .await?
                .into_iter()
                .filter(|m| (m.perms.is_empty() || m.perms.starts_with('r')) && m.path != "[vvar]" && m.path != "[vvar_vclock]")
                .map(|m| (m.start, m.end))
                .collect(),
        };
        let mut found = Vec::new();
        for (start, end) in ranges {
            for (base, bytes) in self.read_range(start, end).await {
                found.extend(pattern.find_all(&bytes, base, limit - found.len()));
                if found.len() >= limit {
                    return Ok(found);
                }
            }
        }
        Ok(found)
    }

    /// Calls, jumps and data references in the executable code of `module`, from process memory.
    pub async fn module_references(&self, module: &str) -> Result<Arc<Vec<Reference>>> {
        self.require_paused()?;
        let arch = self.arch().ok_or_else(|| DebugError::Invalid("no executable loaded".into()))?;
        let (path, base, end) = {
            let symbols = self.symbols();
            let found = symbols.module(module).ok_or_else(|| DebugError::Invalid(format!("unknown module {module}")))?;
            (found.path.clone(), found.base, found.end)
        };
        let key = (path.clone(), base);
        if let Some(cached) = self.inner.lock().unwrap().reference_cache.get(&key).cloned() {
            return Ok(cached);
        }
        let code_ranges: Vec<(u64, u64)> = self
            .memory_map()
            .await?
            .into_iter()
            .filter(|m| m.path == path && m.perms.contains('x'))
            .map(|m| (m.start, m.end))
            .collect();
        let mut code = Vec::new();
        for (start, stop) in code_ranges {
            code.extend(self.read_range(start, stop).await);
        }
        let references = tokio::task::spawn_blocking(move || {
            let disassembler = Disassembler::new(arch).ok()?;
            Some(code.iter().flat_map(|(address, bytes)| disassembler.references(bytes, *address, base..end)).collect::<Vec<_>>())
        })
        .await
        .map_err(|e| DebugError::Invalid(e.to_string()))?
        .ok_or_else(|| DebugError::Invalid("disassembler unavailable".into()))?;
        let references = Arc::new(references);
        self.inner.lock().unwrap().reference_cache.insert(key, references.clone());
        Ok(references)
    }

    /// Code in the same module that refers to `address` (x64dbg: X, cross references).
    pub async fn references_to(&self, address: u64) -> Result<Vec<Reference>> {
        let module = self
            .symbols()
            .module_at(address)
            .map(|m| m.name.clone())
            .ok_or_else(|| DebugError::Invalid(format!("{} is not inside a module", self.format_address(address))))?;
        let references = self.module_references(&module).await?;
        Ok(references.iter().filter(|r| r.to == address).copied().collect())
    }

    /// Instructions in `module` referring to strings of at least four characters.
    pub async fn string_references(&self, module: &str) -> Result<Vec<StringReference>> {
        let references = self.module_references(module).await?;
        let mut strings = Vec::new();
        for reference in references.iter().filter(|r| r.kind == crate::disasm::ReferenceKind::Data) {
            // Indirect branches (`jmp [GOT slot]` in PLT stubs) read code pointers, whose bytes can
            // look like short strings.
            if self
                .instruction_at(reference.from)
                .await
                .is_some_and(|insn| matches!(insn.kind, InsnKind::Call | InsnKind::Jump | InsnKind::ConditionalJump))
            {
                continue;
            }
            let bytes: Vec<u8> = self.read_memory(reference.to, 512).await.into_iter().map_while(|b| b).collect();
            if let Some(found) = find_strings(&bytes, reference.to, 4).into_iter().find(|s| s.address == reference.to) {
                strings.push(StringReference { from: reference.from, to: reference.to, text: found.text, wide: found.wide });
            }
        }
        Ok(strings)
    }

    /// Patched bytes of the current process, with their addresses.
    pub fn patches(&self) -> Vec<(u64, Patch)> {
        let inner = self.inner.lock().unwrap();
        inner.database.patches.iter().filter_map(|p| Some((p.location.resolve(&inner.symbols)?, p.clone()))).collect()
    }

    /// Writes back the original byte of a patch; returns whether there was one at `address`.
    pub async fn restore_patch(&self, address: u64) -> Result<bool> {
        let original = self.patches().into_iter().find(|(a, _)| *a == address).map(|(_, p)| p.original);
        match original {
            Some(byte) => {
                self.write_memory(address, &[byte]).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Saves a copy of the executable with this session's patches applied; returns the bytes changed.
    pub fn export_patches(&self, output: &Path) -> Result<usize> {
        let (executable, module, patches) = {
            let inner = self.inner.lock().unwrap();
            let executable = inner.executable.clone().ok_or_else(|| DebugError::Invalid("no executable loaded".into()))?;
            let module = inner
                .symbols
                .modules()
                .iter()
                .find(|m| Path::new(&m.path) == executable)
                .map(|m| m.name.clone())
                .ok_or_else(|| DebugError::Invalid("the executable is not mapped".into()))?;
            (executable, module, inner.database.patches.clone())
        };
        export_patched_file(&executable, &module, &patches, output).map_err(|e| DebugError::Invalid(e.to_string()))
    }

    pub fn comment_at(&self, address: u64) -> Option<String> {
        self.annotation(address, |db, location| db.comment(location).map(str::to_owned))
    }

    /// User label defined exactly at `address`.
    pub fn label_at(&self, address: u64) -> Option<String> {
        self.annotation(address, |db, location| db.label(location).map(str::to_owned))
    }

    pub fn is_bookmarked(&self, address: u64) -> bool {
        self.annotation(address, |db, location| db.is_bookmarked(location).then_some(())).is_some()
    }

    /// An empty comment removes it.
    pub fn set_comment(&self, address: u64, text: &str) -> Result<()> {
        self.update_database(address, |db, location| {
            db.set_comment(location, text);
            Ok(())
        })
    }

    /// An empty name removes the label. Names are unique and contain no whitespace.
    pub fn set_label(&self, address: u64, name: &str) -> Result<()> {
        let name = name.trim();
        if name.contains(char::is_whitespace) {
            return Err(DebugError::Invalid(format!("invalid label name: {name}")));
        }
        if !name.is_empty() && self.find_label(name).is_some_and(|existing| existing != address) {
            return Err(DebugError::Invalid(format!("label {name} already exists")));
        }
        self.update_database(address, |db, location| {
            db.set_label(location, name);
            Ok(())
        })
    }

    /// Returns whether `address` is bookmarked afterwards.
    pub fn toggle_bookmark(&self, address: u64) -> Result<bool> {
        self.update_database(address, |db, location| Ok(db.toggle_bookmark(location)))
    }

    pub fn find_label(&self, name: &str) -> Option<u64> {
        let inner = self.inner.lock().unwrap();
        inner.database.find_label(name)?.resolve(&inner.symbols)
    }

    /// All annotations; locations resolve against `symbols()`.
    pub fn database(&self) -> Database {
        self.inner.lock().unwrap().database.clone()
    }

    fn format_address(&self, address: u64) -> String {
        self.arch().unwrap_or(Arch::X86_64).format_address(address)
    }

    fn annotation<T>(&self, address: u64, get: impl FnOnce(&Database, &ModuleAddress) -> Option<T>) -> Option<T> {
        let inner = self.inner.lock().unwrap();
        let location = ModuleAddress::from_address(&inner.symbols, address)?;
        get(&inner.database, &location)
    }

    fn update_database<T>(&self, address: u64, change: impl FnOnce(&mut Database, ModuleAddress) -> Result<T>) -> Result<T> {
        let result = {
            let mut inner = self.inner.lock().unwrap();
            let location = ModuleAddress::from_address(&inner.symbols, address).ok_or_else(|| {
                let shown = inner.arch.unwrap_or(Arch::X86_64).format_address(address);
                DebugError::Invalid(format!("{shown} is not inside a module"))
            })?;
            change(&mut inner.database, location)?
        };
        self.save_database();
        Ok(result)
    }

    fn save_database(&self) {
        let (mut database, path) = {
            let inner = self.inner.lock().unwrap();
            (inner.database.clone(), inner.database_path.clone())
        };
        // Patches describe the running process and are not persisted.
        database.patches.clear();
        if let Some(path) = path
            && let Err(e) = database.save(&path)
        {
            self.log(format!("Failed to save database {}: {e}", path.display()));
        }
        self.emit(DebugEvent::AnnotationsChanged);
    }

    pub async fn disassemble(&self, address: u64, count: usize) -> Vec<Instruction> {
        let Some(arch) = self.arch() else { return Vec::new() };
        let bytes = self.read_memory(address, count * arch.max_instruction_len()).await;
        let readable: Vec<u8> = bytes.iter().map_while(|b| *b).collect();
        Disassembler::new(arch).map(|d| d.disassemble(&readable, address, count)).unwrap_or_default()
    }

    pub async fn instruction_at(&self, address: u64) -> Option<Instruction> {
        self.disassemble(address, 1).await.into_iter().next()
    }

    /// Evaluates a gdb expression to a number (addresses, registers, symbols, arithmetic).
    pub async fn evaluate(&self, expression: &str) -> Result<u64> {
        let r = self.gdb.execute_quiet(&format!("-data-evaluate-expression {}", quote(expression))).await?;
        let value = r.results.get_str("value").unwrap_or_default();
        parse_number(value).ok_or_else(|| DebugError::Invalid(format!("not a number: {value}")))
    }

    /// Runs a command typed by the user: `-mi-command` through MI, anything else as a gdb CLI command.
    pub async fn execute_user_command(&self, command: &str) -> Result<Option<String>> {
        if command.starts_with('-') {
            let r = self.gdb.execute(command).await?;
            Ok((!r.results.is_empty()).then(|| format!("{:?}", r.results)))
        } else {
            self.gdb.console(command).await?;
            Ok(None)
        }
    }

    /// Injects the `cutegdb` Python plugin namespace once per gdb lifetime.
    async fn ensure_plugins(&self) -> Result<()> {
        if self.inner.lock().unwrap().plugins_ready {
            return Ok(());
        }
        self.gdb.execute_quiet(&crate::plugins::bootstrap_command()).await?;
        self.inner.lock().unwrap().plugins_ready = true;
        Ok(())
    }

    /// Installs exactly the listed anti-anti-debug / anti-anti-VM plugins for the current process,
    /// removing any others. Call it again after each process starts, since a plugin's breakpoints
    /// are bound to the inferior's addresses.
    pub async fn set_active_plugins(&self, ids: &[String]) -> Result<()> {
        // The IDA Pro sync plugin runs in the front-end, not in gdb's Python.
        self.set_ida_sync(ids.iter().any(|id| id == "ida_sync"));
        let gdb_ids: Vec<String> = ids.iter().filter(|id| id.as_str() != "ida_sync").cloned().collect();
        self.ensure_plugins().await?;
        let output = self.gdb.console_quiet(&crate::plugins::activate_command(&gdb_ids)).await?;
        let active = crate::plugins::parse_active(&output);
        if active.is_empty() {
            self.log("Countermeasures: none active");
        } else {
            let names: Vec<&str> =
                active.iter().map(|id| crate::plugins::info(id).map_or(id.as_str(), |p| p.name)).collect();
            self.log(format!("Countermeasures active: {}", names.join(", ")));
        }
        Ok(())
    }

    /// How many checks each active plugin has neutralized so far, for the status view.
    pub async fn plugin_stats(&self) -> Result<Vec<(String, u64)>> {
        let mut stats = if self.inner.lock().unwrap().plugins_ready {
            let output = self.gdb.console_quiet(crate::plugins::STATS_COMMAND).await?;
            crate::plugins::parse_stats(&output)
        } else {
            Vec::new()
        };
        if self.ida_sync.is_enabled() {
            stats.push(("ida_sync".to_owned(), self.ida_sync.count()));
        }
        Ok(stats)
    }

    fn require_paused(&self) -> Result<()> {
        match self.state() {
            DebugState::Paused => Ok(()),
            _ => Err(DebugError::Invalid("the debuggee is not paused".into())),
        }
    }

    /// Sends a resuming command. The state becomes Running before the command is sent, so no
    /// caller can act on a stale Paused state while gdb is already running the debuggee.
    async fn resume(&self, command: &str) -> Result<()> {
        self.set_state(DebugState::Running);
        if let Err(e) = self.gdb.execute_quiet(command).await {
            // gdb rejected the command without resuming.
            self.set_state(DebugState::Paused);
            return Err(e.into());
        }
        Ok(())
    }

    fn emit(&self, event: DebugEvent) {
        // Mirror every user-visible pause to IDA. This is the single choke point
        // for the coalesced final-PC pause, so step loops sync once, not per step.
        if let DebugEvent::Paused(snapshot) = &event
            && self.ida_sync.is_enabled()
        {
            let symbols = self.symbols();
            if let Some(module) = symbols.module_at(snapshot.pc) {
                self.ida_sync.on_pause(&module.path, module.base, snapshot.pc);
            }
        }
        let _ = self.events.send(event);
    }

    /// Enables or disables the IDA Pro sync (the front-end "IDA Pro sync" plugin).
    pub fn set_ida_sync(&self, enabled: bool) {
        if self.ida_sync.set_enabled(enabled) {
            if enabled {
                self.log(format!("IDA Pro sync: connecting to {}", self.ida_sync.endpoint()));
            } else {
                self.log("IDA Pro sync: disconnected");
            }
        }
    }

    /// Marks a breakpoint address in IDA, if sync is on and the address is in a module.
    fn mark_breakpoint_in_ida(&self, address: u64) {
        if !self.ida_sync.is_enabled() {
            return;
        }
        let symbols = self.symbols();
        if let Some(module) = symbols.module_at(address) {
            self.ida_sync.on_breakpoint(module.base, address);
        }
    }

    fn log(&self, text: impl Into<String>) {
        self.emit(DebugEvent::Log(text.into()));
    }

    fn set_state(&self, state: DebugState) {
        let (changed, quiet) = {
            let mut inner = self.inner.lock().unwrap();
            (std::mem::replace(&mut inner.state, state) != state, inner.quiet)
        };
        if changed && !quiet {
            self.emit(DebugEvent::State(state));
        }
    }

    fn begin_quiet(&self) {
        self.cancel.store(false, Ordering::SeqCst);
        self.inner.lock().unwrap().quiet = true;
        self.emit(DebugEvent::State(DebugState::Running));
    }

    /// Ends a step loop and reports its final stop as a single pause.
    fn end_quiet(&self) {
        let (state, snapshot) = {
            let mut inner = self.inner.lock().unwrap();
            inner.quiet = false;
            if let Some(snap) = inner.snapshot.clone() {
                inner.last_values = snap.registers.iter().map(|r| (r.name.clone(), r.value.clone())).collect();
            }
            (inner.state, inner.snapshot.clone())
        };
        self.emit(DebugEvent::State(state));
        if state == DebugState::Paused
            && let Some(snap) = snapshot
        {
            if let Some(message) = self.stop_message(&snap) {
                self.log(message);
            }
            self.emit(DebugEvent::Paused(snap));
        }
    }

    /// Sends a resuming command and waits until the resulting stop has been processed.
    async fn step_and_wait(&self, command: &str) -> Result<Option<Arc<Snapshot>>> {
        let mut stops = self.stops.subscribe();
        self.inner.lock().unwrap().resume_error = None;
        self.resume(command).await?;
        if stops.changed().await.is_err() {
            return Ok(None);
        }
        let resume_error = self.inner.lock().unwrap().resume_error.take();
        if let Some(message) = resume_error {
            return Err(DebugError::Mi(MiError::Gdb(message)));
        }
        if self.state() != DebugState::Paused {
            return Ok(None);
        }
        Ok(self.snapshot())
    }

    /// A resume gdb had acknowledged with `^running` failed before the debuggee ran.
    fn on_resume_failed(&self, message: &str) {
        let (changed, quiet) = {
            let mut inner = self.inner.lock().unwrap();
            inner.resume_error = Some(message.to_owned());
            inner.pause_requested = false;
            (std::mem::replace(&mut inner.state, DebugState::Paused) != DebugState::Paused, inner.quiet)
        };
        // Same ordering as a stop: state, then the counter, then events.
        self.stops.send_modify(|n| *n += 1);
        if changed && !quiet {
            self.emit(DebugEvent::State(DebugState::Paused));
        }
        self.log(message.to_owned());
    }

    async fn kill(&self) -> Result<()> {
        let state = self.state();
        if state == DebugState::Running {
            let mut stops = self.stops.subscribe();
            {
                let mut inner = self.inner.lock().unwrap();
                inner.quiet = true;
                inner.pause_requested = true;
            }
            self.gdb.execute_quiet("-exec-interrupt").await?;
            let _ = tokio::time::timeout(Duration::from_secs(5), stops.changed()).await;
        }
        if matches!(state, DebugState::Running | DebugState::Paused) {
            self.gdb.console_quiet("kill").await?;
        }
        {
            let mut inner = self.inner.lock().unwrap();
            inner.quiet = false;
            inner.memory.clear();
            inner.snapshot = None;
            inner.entry_breakpoint = None;
            inner.expect_system_breakpoint = false;
            inner.pause_requested = false;
            inner.remote = false;
        }
        self.set_state(DebugState::Terminated);
        Ok(())
    }

    fn on_notify(&self, class: &str, results: &Tuple) {
        let breakpoints_changed = {
            let mut inner = self.inner.lock().unwrap();
            match class {
                "library-loaded" | "library-unloaded" | "thread-group-started" => {
                    inner.symbols_dirty = true;
                    false
                }
                // Also sent for hit-count updates while the debuggee runs.
                "breakpoint-created" | "breakpoint-modified" => match results.get("bkpt").and_then(parse_breakpoint) {
                    Some(bp) => {
                        inner.breakpoints.insert(bp.number, bp);
                        true
                    }
                    None => false,
                },
                "breakpoint-deleted" => results
                    .get_str("id")
                    .and_then(|id| id.parse::<u32>().ok())
                    .is_some_and(|id| inner.breakpoints.remove(&id).is_some()),
                _ => false,
            }
        };
        if breakpoints_changed {
            self.emit(DebugEvent::BreakpointsChanged);
        }
    }

    async fn on_stopped(&self, results: &Tuple) {
        let reason = results.get_str("reason").unwrap_or_default();
        if reason.starts_with("exited") {
            let code = results.get_str("exit-code").and_then(|c| u64::from_str_radix(c, 8).ok()).unwrap_or(0);
            let (changed, quiet) = {
                let mut inner = self.inner.lock().unwrap();
                inner.memory.clear();
                inner.snapshot = None;
                inner.entry_breakpoint = None;
                inner.expect_system_breakpoint = false;
                (std::mem::replace(&mut inner.state, DebugState::Terminated) != DebugState::Terminated, inner.quiet)
            };
            // State first, then the stop counter, then events: waiters woken by the counter and
            // consumers of the events must both see the final state.
            self.stops.send_modify(|n| *n += 1);
            self.log(format!("Process stopped with exit code 0x{code:X} ({code})"));
            if changed && !quiet {
                self.emit(DebugEvent::State(DebugState::Terminated));
            }
            return;
        }

        let frame = results.get("frame");
        let bkptno = results.get_str("bkptno").and_then(|n| n.parse::<u32>().ok());
        let (arch, stop, refresh_symbols) = {
            let mut inner = self.inner.lock().unwrap();
            let arch = frame
                .and_then(|f| f.get_str("arch"))
                .and_then(Arch::from_gdb)
                .or(inner.arch)
                .unwrap_or(Arch::X86_64);
            if inner.arch != Some(arch) {
                inner.register_names.clear();
            }
            inner.arch = Some(arch);
            inner.memory.clear();
            let pause_requested = std::mem::take(&mut inner.pause_requested);
            let stop = if std::mem::take(&mut inner.expect_system_breakpoint) {
                StopReason::SystemBreakpoint
            } else if std::mem::take(&mut inner.expect_attach) {
                StopReason::Attach
            } else if std::mem::take(&mut inner.expect_connect) {
                StopReason::Connected
            } else if bkptno.is_some() && bkptno == inner.entry_breakpoint {
                inner.entry_breakpoint = None;
                StopReason::EntryBreakpoint
            } else if pause_requested && reason == "signal-received" {
                StopReason::Pause
            } else {
                match reason {
                    "breakpoint-hit" => StopReason::Breakpoint(bkptno.unwrap_or(0)),
                    "watchpoint-trigger" | "read-watchpoint-trigger" | "access-watchpoint-trigger" => {
                        let watch = ["wpt", "hw-rwpt", "hw-awpt"].iter().find_map(|key| results.get(key));
                        let value = results.get("value");
                        StopReason::Watchpoint {
                            number: watch.and_then(|w| w.get_str("number")).and_then(|n| n.parse().ok()).unwrap_or(0),
                            old: value.and_then(|v| v.get_str("old")).map(str::to_owned),
                            new: value.and_then(|v| v.get_str("new").or_else(|| v.get_str("value"))).map(str::to_owned),
                        }
                    }
                    "end-stepping-range" | "function-finished" | "location-reached" => StopReason::Step,
                    "signal-received" => StopReason::Signal(results.get_str("signal-name").unwrap_or("?").to_owned()),
                    other => StopReason::Other(other.to_owned()),
                }
            };
            let refresh = std::mem::take(&mut inner.symbols_dirty)
                || matches!(
                    stop,
                    StopReason::SystemBreakpoint | StopReason::EntryBreakpoint | StopReason::Attach | StopReason::Connected
                );
            (arch, stop, refresh)
        };

        if refresh_symbols {
            self.refresh_symbols().await;
        }
        let registers = self.fetch_registers().await.unwrap_or_default();
        let register = |name: &str| registers.iter().find(|r| r.name == name).and_then(|r| r.value.as_u64());
        let pc = register(arch.pc_register())
            .or_else(|| frame.and_then(|f| f.get_str("addr")).and_then(parse_hex))
            .unwrap_or(0);
        let sp = register(arch.sp_register()).unwrap_or(0);
        let snapshot = Arc::new(Snapshot {
            arch,
            pc,
            sp,
            thread_id: results.get_str("thread-id").and_then(|t| t.parse().ok()),
            reason: stop.clone(),
            registers,
        });
        if matches!(stop, StopReason::SystemBreakpoint | StopReason::Connected) {
            self.set_entry_breakpoint(pc).await;
        }

        let (changed, quiet) = {
            let mut inner = self.inner.lock().unwrap();
            inner.snapshot = Some(snapshot.clone());
            (std::mem::replace(&mut inner.state, DebugState::Paused) != DebugState::Paused, inner.quiet)
        };
        // State first, then the stop counter, then events (see the exit case above).
        self.stops.send_modify(|n| *n += 1);
        if !quiet {
            if changed {
                self.emit(DebugEvent::State(DebugState::Paused));
            }
            if let Some(message) = self.stop_message(&snapshot) {
                self.log(message);
            }
            self.emit(DebugEvent::Paused(snapshot));
        }
    }

    fn stop_message(&self, snap: &Snapshot) -> Option<String> {
        let symbols = self.symbols();
        let address = snap.arch.format_address(snap.pc);
        let label = symbols.label(snap.pc).map(|l| format!("<{l}> ")).unwrap_or_default();
        Some(match &snap.reason {
            StopReason::SystemBreakpoint => "System breakpoint reached!".to_owned(),
            StopReason::EntryBreakpoint => {
                let module = symbols.module_at(snap.pc).map(|m| m.name.as_str()).unwrap_or("?");
                format!("INT3 breakpoint \"entry breakpoint\" at <{module}.EntryPoint> ({address})!")
            }
            StopReason::Breakpoint(number) => {
                let hardware = self
                    .inner
                    .lock()
                    .unwrap()
                    .breakpoints
                    .get(number)
                    .is_some_and(|b| b.kind == BreakpointKind::Hardware);
                if hardware {
                    format!("Hardware breakpoint (execute) at {label}({address})!")
                } else {
                    format!("INT3 breakpoint at {label}({address})!")
                }
            }
            StopReason::Watchpoint { number, old, new } => {
                let change = match (old, new) {
                    (Some(old), Some(new)) => format!(": {old} -> {new}"),
                    (None, Some(value)) => format!(": {value}"),
                    _ => String::new(),
                };
                format!("Hardware watchpoint {number} triggered at {label}({address}){change}")
            }
            StopReason::Attach => "Attach breakpoint reached!".to_owned(),
            StopReason::Connected => format!("Connected to remote target at {label}({address})"),
            StopReason::Pause => "Program paused!".to_owned(),
            StopReason::Signal(name) => format!("Signal {name} at {label}({address})"),
            StopReason::Other(reason) => format!("Stopped ({reason}) at {label}({address})"),
            StopReason::Step => return None,
        })
    }

    async fn refresh_symbols(&self) {
        let previous = self.symbols();
        let table = match self.gdb.console_quiet("info proc mappings").await {
            Ok(text) => {
                let mappings = parse_proc_mappings(&text);
                if mappings.is_empty() {
                    None
                } else {
                    tokio::task::spawn_blocking(move || SymbolTable::from_mappings(&mappings, &previous)).await.ok()
                }
            }
            // Remote targets without /proc access keep the executable's static symbols.
            Err(_) => None,
        };
        let table = match table {
            Some(table) => Some(table),
            None => self.relocated_executable_symbols().await,
        };
        if let Some(table) = table {
            self.inner.lock().unwrap().symbols = Arc::new(table);
            self.emit(DebugEvent::SymbolsChanged);
        }
    }

    /// Without /proc mappings (QEMU's gdb stub), places the executable's symbols at the load address
    /// gdb resolved, found by comparing a symbol's static and runtime addresses.
    async fn relocated_executable_symbols(&self) -> Option<SymbolTable> {
        let executable = self.executable()?;
        let static_table = SymbolTable::from_executable(&executable);
        let module = static_table.modules().first()?.clone();
        let probe = ["main", "_start"]
            .into_iter()
            .find_map(|name| module.symbols().iter().find(|s| s.name == name).cloned())?;
        let runtime = self.evaluate(&format!("(unsigned long)&{}", probe.name)).await.ok()?;
        let bias = runtime.wrapping_sub(probe.address);
        let relocated = Module::load(&module.path, module.base.wrapping_add(bias), module.end.wrapping_add(bias));
        Some(SymbolTable::from_modules(vec![relocated]))
    }

    async fn set_entry_breakpoint(&self, pc: u64) {
        let Some(exe) = self.executable() else { return };
        let entry = self.symbols().modules().iter().find(|m| Path::new(&m.path) == exe).and_then(|m| m.entry);
        let Some(entry) = entry else {
            self.log("Entry point not found; no entry breakpoint set");
            return;
        };
        if entry == pc {
            // Already there, e.g. a static executable started under a gdb stub.
            return;
        }
        match self.gdb.execute_quiet(&format!("-break-insert -t *0x{entry:x}")).await {
            Ok(r) => {
                let number = r.results.get("bkpt").and_then(|b| b.get_str("number")).and_then(|n| n.parse().ok());
                self.inner.lock().unwrap().entry_breakpoint = number;
            }
            Err(e) => self.log(format!("Failed to set entry breakpoint: {e}")),
        }
    }

    async fn fetch_registers(&self) -> Result<Vec<Register>> {
        if self.inner.lock().unwrap().register_names.is_empty() {
            let r = self.gdb.execute_quiet("-data-list-register-names").await?;
            let names = r
                .results
                .get("register-names")
                .map(|v| v.items().map(|n| n.as_str().unwrap_or_default().to_owned()).collect())
                .unwrap_or_default();
            self.inner.lock().unwrap().register_names = names;
        }
        let r = self.gdb.execute_quiet("-data-list-register-values --skip-unavailable x").await?;
        let mut inner = self.inner.lock().unwrap();
        let mut registers = Vec::new();
        for item in r.results.get("register-values").into_iter().flat_map(|v| v.items()) {
            let Some(number) = item.get_str("number").and_then(|n| n.parse::<usize>().ok()) else { continue };
            let Some(name) = inner.register_names.get(number).filter(|n| !n.is_empty()).cloned() else { continue };
            let value = parse_value(item.get_str("value").unwrap_or_default());
            let changed = inner.last_values.get(&name).is_some_and(|old| *old != value);
            registers.push(Register { name, value, changed });
        }
        // Inside step loops, keep comparing against the values from before the loop.
        if !inner.quiet {
            inner.last_values = registers.iter().map(|r| (r.name.clone(), r.value.clone())).collect();
        }
        Ok(registers)
    }
}

async fn event_loop(debugger: Weak<Debugger>, mut events: mpsc::UnboundedReceiver<Event>) {
    let (mut console, mut target, mut log) = (LineBuffer::default(), LineBuffer::default(), LineBuffer::default());
    while let Some(event) = events.recv().await {
        let Some(d) = debugger.upgrade() else { break };
        match event {
            Event::Exec { class, results } => match class.as_str() {
                "running" => d.set_state(DebugState::Running),
                "stopped" => d.on_stopped(&results).await,
                _ => {}
            },
            Event::Notify { class, results } => d.on_notify(&class, &results),
            Event::Console(text) => console.push(&text).into_iter().for_each(|l| d.log(l)),
            Event::Target(text) => target.push(&text).into_iter().for_each(|l| d.log(l)),
            Event::Log(text) => log.push(&text).into_iter().for_each(|l| d.log(l)),
            Event::Raw(text) => d.log(text),
            Event::LateResult { class: ResultClass::Error, results } => {
                d.on_resume_failed(results.get_str("msg").unwrap_or("resuming the debuggee failed"));
            }
            Event::LateResult { .. } | Event::Status { .. } => {}
            Event::GdbExited => {
                d.inner.lock().unwrap().quiet = false;
                d.set_state(DebugState::Terminated);
                d.stops.send_modify(|n| *n += 1);
                d.log("gdb exited");
                break;
            }
        }
    }
}

fn changed_registers(before: &[Register], after: &[Register]) -> Vec<(String, u64)> {
    after
        .iter()
        .filter_map(|register| {
            let new = register.value.as_u64()?;
            let old = before.iter().find(|r| r.name == register.name).and_then(|r| r.value.as_u64());
            (old != Some(new)).then(|| (register.name.clone(), new))
        })
        .collect()
}

fn decode_hex(contents: &str) -> Vec<u8> {
    contents
        .as_bytes()
        .chunks(2)
        .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn decode_memory_blocks(base: u64, results: &Tuple) -> Vec<Option<u8>> {
    let mut page = vec![None; PAGE_SIZE];
    for block in results.get("memory").into_iter().flat_map(|m| m.items()) {
        let (Some(begin), Some(contents)) = (block.get_str("begin").and_then(parse_hex), block.get_str("contents")) else {
            continue;
        };
        let Some(start) = begin.checked_sub(base) else { continue };
        for (i, pair) in contents.as_bytes().chunks(2).enumerate() {
            let byte = std::str::from_utf8(pair).ok().and_then(|s| u8::from_str_radix(s, 16).ok());
            if let Some(slot) = page.get_mut(start as usize + i) {
                *slot = byte;
            }
        }
    }
    page
}

/// Extracts a number from a gdb value such as `0x1139 <main>`, `{int (void)} 0x1139 <main>` or `65 'A'`.
fn parse_number(value: &str) -> Option<u64> {
    value
        .split_whitespace()
        .find_map(|t| parse_hex(t.trim_end_matches(|c: char| !c.is_ascii_hexdigit())))
        .or_else(|| value.split_whitespace().next()?.parse::<i64>().ok().map(|v| v as u64))
}

/// Joins arguments for `-exec-arguments`, which gdb passes through a shell.
fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c)) {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gdb_values_as_numbers() {
        assert_eq!(parse_number("0x555555555169 <main>"), Some(0x555555555169));
        assert_eq!(parse_number("{int (int, char **)} 0x555555555169 <main>"), Some(0x555555555169));
        assert_eq!(parse_number("(void *) 0x7fffffffe000"), Some(0x7fffffffe000));
        assert_eq!(parse_number("65 'A'"), Some(65));
        assert_eq!(parse_number("-1"), Some(u64::MAX));
        assert_eq!(parse_number("{a = 1}"), None);
    }

    #[test]
    fn decodes_partial_memory_blocks() {
        let cutegdb_mi::Record::Result { results, .. } = cutegdb_mi::parse_line(
            r#"^done,memory=[{begin="0x1002",offset="0x2",end="0x1004",contents="abcd"},{begin="0x1ffe",offset="0xffe",end="0x2000",contents="0102"}]"#,
        )
        .unwrap() else {
            panic!()
        };
        let page = decode_memory_blocks(0x1000, &results);
        assert_eq!(&page[..5], &[None, None, Some(0xab), Some(0xcd), None]);
        assert_eq!(&page[0xffe..], &[Some(1), Some(2)]);
    }

    #[test]
    fn shell_quotes_arguments() {
        let args = ["loop".to_owned(), "a b".to_owned(), "it's".to_owned(), String::new()];
        assert_eq!(shell_join(&args), r#"loop 'a b' 'it'\''s' ''"#);
    }
}

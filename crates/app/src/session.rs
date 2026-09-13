//! `DebugSession` QObject: exposes the debugger core to the Qt Widgets UI.
//!
//! Actions run asynchronously on a tokio runtime and report back through signals. Views read data
//! synchronously from the core's caches; a cache miss starts a fetch and `memoryChanged` follows.

use core::pin::Pin;
use cutegdb_cmd::{
    Command, HardwareAccess, Resolver, Script, ScriptStep, SearchScope, parse_command, translate_assignment,
    translate_expression, translate_log_text,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use cutegdb_core::{
    Arch, BreakpointKind, Database, DebugError, DebugEvent, DebugState, Debugger, Disassembler, FileHandle, Frame,
    InfoContext, InsnKind, Instruction, Mapping, ModuleAddress, PAGE_SIZE, Pattern, RegValue, SignalInfo, Snapshot,
    SymbolTable, ThreadInfo, TraceOptions, WatchAccess, EdgeKind, PluginCategory, StopReason, build_graph,
    describe_instruction, format_operands, plugin_catalog,
};
use cutegdb_mi::GdbOptions;
use cxx_qt::{CxxQtThread, CxxQtType, Threading};
use cxx_qt_lib::QString;
use std::cell::RefCell;
use std::collections::HashSet;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    unsafe extern "C++" {
        include!("app.h");
        pub fn run_app(args: Vec<String>) -> i32;
    }

    /// One line of the disassembly view.
    struct DisasmRow {
        address: u64,
        size: u32,
        bytes: String,
        mnemonic: String,
        operands: String,
        /// `InsnKind` index (see `kind_code`); 255 for undecodable bytes.
        kind: u8,
        target: u64,
        has_target: bool,
        /// Symbol starting exactly at `address`.
        label: String,
        comment: String,
    }

    /// One entry of the register view. Groups: 0 general, 1 flags register, 2 flag bits,
    /// 3 segments, 4 FPU/vector and other registers.
    struct RegisterRow {
        name: String,
        value: String,
        comment: String,
        changed: bool,
        group: u8,
    }

    /// A pointer-sized value in the stack view or the arguments pane.
    struct StackRow {
        address: u64,
        value: u64,
        readable: bool,
        name: String,
        comment: String,
    }

    struct BreakpointRow {
        number: u32,
        kind: String,
        address: u64,
        has_address: bool,
        /// Watched expression or location as written.
        location: String,
        label: String,
        enabled: bool,
        hits: u64,
        condition: String,
        log_text: String,
    }

    struct FrameRow {
        level: u32,
        address: u64,
        label: String,
        source: String,
    }

    struct ThreadRow {
        id: u32,
        lwp: u32,
        name: String,
        address: u64,
        label: String,
        current: bool,
        running: bool,
    }

    struct MapRow {
        start: u64,
        size: u64,
        perms: String,
        info: String,
    }

    struct SignalRow {
        name: String,
        stop: bool,
        print: bool,
        pass: bool,
        description: String,
    }

    struct HandleRow {
        fd: u32,
        target: String,
    }

    struct ModuleRow {
        name: String,
        path: String,
        base: u64,
        size: u64,
        entry: u64,
    }

    struct SymbolRow {
        address: u64,
        name: String,
        size: u64,
    }

    struct PatchRow {
        address: u64,
        module: String,
        original: u8,
        patched: u8,
    }

    /// A comment, label or bookmark.
    struct AnnotationRow {
        address: u64,
        module: String,
        text: String,
    }

    /// One result in the References view.
    struct ReferenceRow {
        address: u64,
        disassembly: String,
        info: String,
    }

    /// A local process for the Attach dialog.
    struct ProcessRow {
        pid: u32,
        name: String,
        path: String,
    }

    struct TraceRow {
        address: u64,
        bytes: String,
        text: String,
        changes: String,
    }

    /// A basic block of the graph view; edge kinds: 0 unconditional, 1 taken, 2 not taken.
    struct GraphBlock {
        start: u64,
        text: String,
        edge_targets: Vec<u64>,
        edge_kinds: Vec<u8>,
    }

    /// A built-in countermeasure plugin; category is 0 for anti-anti-debug, 1 for anti-anti-VM.
    struct PluginRow {
        id: String,
        name: String,
        category: i32,
        best_effort: bool,
        description: String,
    }

    /// How many checks an active plugin has neutralized.
    struct PluginStatRow {
        id: String,
        name: String,
        count: u64,
    }

    unsafe extern "RustQt" {
        #[qobject]
        type DebugSession = super::DebugSessionRust;

        #[qsignal]
        #[cxx_name = "logMessage"]
        fn log_message(self: Pin<&mut Self>, text: QString);

        /// 0 = terminated / no process, 1 = paused, 2 = running.
        #[qsignal]
        #[cxx_name = "stateChanged"]
        fn state_changed(self: Pin<&mut Self>, state: i32);

        #[qsignal]
        fn paused(self: Pin<&mut Self>, pc: u64);

        #[qsignal]
        #[cxx_name = "memoryChanged"]
        fn memory_changed(self: Pin<&mut Self>);

        #[qsignal]
        #[cxx_name = "symbolsChanged"]
        fn symbols_changed(self: Pin<&mut Self>);

        #[qsignal]
        #[cxx_name = "breakpointsChanged"]
        fn breakpoints_changed(self: Pin<&mut Self>);

        #[qsignal]
        #[cxx_name = "gdbReady"]
        fn gdb_ready(self: Pin<&mut Self>, version: QString);

        /// `view`: 0 disassembly, 1 dump, 2 stack.
        #[qsignal]
        #[cxx_name = "gotoRequested"]
        fn goto_requested(self: Pin<&mut Self>, view: i32, address: u64);

        #[qsignal]
        #[cxx_name = "clearLogRequested"]
        fn clear_log_requested(self: Pin<&mut Self>);

        /// Call stack, threads, memory map, signals or handles data was re-read.
        #[qsignal]
        #[cxx_name = "viewsChanged"]
        fn views_changed(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "deleteBreakpoint"]
        fn delete_breakpoint(self: Pin<&mut Self>, number: u32);

        #[qinvokable]
        #[cxx_name = "setBreakpointEnabled"]
        fn set_breakpoint_enabled(self: Pin<&mut Self>, number: u32, enabled: bool);

        /// `condition` is an x64dbg expression; empty removes it.
        #[qinvokable]
        #[cxx_name = "setBreakpointCondition"]
        fn set_breakpoint_condition(self: Pin<&mut Self>, number: u32, condition: &QString);

        #[qinvokable]
        #[cxx_name = "setHardwareBreakpoint"]
        fn set_hardware_breakpoint(self: Pin<&mut Self>, address: u64);

        #[qinvokable]
        #[cxx_name = "selectThread"]
        fn select_thread(self: Pin<&mut Self>, id: u32);

        #[qinvokable]
        #[cxx_name = "setSignalHandling"]
        fn set_signal_handling(self: Pin<&mut Self>, name: &QString, stop: bool, print: bool, pass: bool);

        /// 0 none, 1 enabled software, 2 disabled, 3 enabled hardware.
        #[cxx_name = "breakpointState"]
        fn breakpoint_state(self: &Self, address: u64) -> i32;

        /// gdb number of the code breakpoint at `address`, or 0.
        #[cxx_name = "breakpointNumberAt"]
        fn breakpoint_number_at(self: &Self, address: u64) -> u32;

        #[cxx_name = "breakpointRows"]
        fn breakpoint_rows(self: &Self) -> Vec<BreakpointRow>;

        #[cxx_name = "frameRows"]
        fn frame_rows(self: &Self) -> Vec<FrameRow>;

        #[cxx_name = "threadRows"]
        fn thread_rows(self: &Self) -> Vec<ThreadRow>;

        #[cxx_name = "memoryMapRows"]
        fn memory_map_rows(self: &Self) -> Vec<MapRow>;

        #[cxx_name = "signalRows"]
        fn signal_rows(self: &Self) -> Vec<SignalRow>;

        #[cxx_name = "handleRows"]
        fn handle_rows(self: &Self) -> Vec<HandleRow>;

        #[cxx_name = "moduleRows"]
        fn module_rows(self: &Self) -> Vec<ModuleRow>;

        #[cxx_name = "symbolRows"]
        fn symbol_rows(self: &Self, module: &QString) -> Vec<SymbolRow>;

        #[qinvokable]
        fn assemble(self: Pin<&mut Self>, address: u64, instruction: &QString, fill_nops: bool);

        /// An empty text removes the comment.
        #[qinvokable]
        #[cxx_name = "setComment"]
        fn set_comment(self: Pin<&mut Self>, address: u64, text: &QString);

        /// An empty name removes the label.
        #[qinvokable]
        #[cxx_name = "setLabel"]
        fn set_label(self: Pin<&mut Self>, address: u64, name: &QString);

        #[qinvokable]
        #[cxx_name = "toggleBookmark"]
        fn toggle_bookmark(self: Pin<&mut Self>, address: u64);

        /// `hex` is a byte string such as "90 90 CC".
        #[qinvokable]
        #[cxx_name = "writeBytes"]
        fn write_bytes(self: Pin<&mut Self>, address: u64, hex: &QString);

        #[qinvokable]
        #[cxx_name = "restorePatch"]
        fn restore_patch(self: Pin<&mut Self>, address: u64);

        #[qinvokable]
        #[cxx_name = "exportPatches"]
        fn export_patches(self: Pin<&mut Self>, path: &QString);

        #[cxx_name = "commentAt"]
        fn comment_at(self: &Self, address: u64) -> QString;

        #[cxx_name = "labelAt"]
        fn label_at(self: &Self, address: u64) -> QString;

        #[cxx_name = "isBookmarked"]
        fn is_bookmarked(self: &Self, address: u64) -> bool;

        #[cxx_name = "patchRows"]
        fn patch_rows(self: &Self) -> Vec<PatchRow>;

        /// `kind`: 0 comments, 1 labels, 2 bookmarks.
        #[cxx_name = "annotationRows"]
        fn annotation_rows(self: &Self, kind: i32) -> Vec<AnnotationRow>;

        /// New results for the References view.
        #[qsignal]
        #[cxx_name = "referencesChanged"]
        fn references_changed(self: Pin<&mut Self>, title: QString);

        /// Ctrl+B: in the module containing `start`, or in all readable memory.
        #[qinvokable]
        #[cxx_name = "searchPattern"]
        fn search_pattern(self: Pin<&mut Self>, start: u64, pattern: &QString, whole_memory: bool);

        #[qinvokable]
        #[cxx_name = "findStringReferences"]
        fn find_string_references(self: Pin<&mut Self>, address: u64);

        #[qinvokable]
        #[cxx_name = "findReferencesTo"]
        fn find_references_to(self: Pin<&mut Self>, address: u64);

        #[cxx_name = "referenceRows"]
        fn reference_rows(self: &Self) -> Vec<ReferenceRow>;

        #[qinvokable]
        fn attach(self: Pin<&mut Self>, pid: u32);

        #[qinvokable]
        fn detach(self: Pin<&mut Self>);

        /// `executable` may be empty.
        #[qinvokable]
        #[cxx_name = "connectRemote"]
        fn connect_remote(self: Pin<&mut Self>, address: &QString, executable: &QString);

        /// Local processes, newest first, excluding cutegdb itself.
        #[cxx_name = "processRows"]
        fn process_rows(self: &Self) -> Vec<ProcessRow>;

        #[qsignal]
        #[cxx_name = "traceChanged"]
        fn trace_changed(self: Pin<&mut Self>);

        /// `line` is the 0-based line that runs next (-1 without a script).
        #[qsignal]
        #[cxx_name = "scriptStateChanged"]
        fn script_state_changed(self: Pin<&mut Self>, line: i32, running: bool);

        /// `condition` is an x64dbg expression; empty traces until `max_steps`.
        #[qinvokable]
        fn trace(self: Pin<&mut Self>, over: bool, condition: &QString, max_steps: i32);

        #[cxx_name = "traceRows"]
        fn trace_rows(self: &Self) -> Vec<TraceRow>;

        #[qinvokable]
        #[cxx_name = "exportTrace"]
        fn export_trace(self: Pin<&mut Self>, path: &QString);

        /// Blocks of the function containing `address`, entry block first.
        #[cxx_name = "functionGraph"]
        fn function_graph(self: &Self, address: u64) -> Vec<GraphBlock>;

        /// Returns the parse error, or an empty string when the script was loaded.
        #[qinvokable]
        #[cxx_name = "loadScript"]
        fn load_script(self: Pin<&mut Self>, text: &QString) -> QString;

        #[qinvokable]
        #[cxx_name = "runScript"]
        fn run_script(self: Pin<&mut Self>, single_step: bool);

        #[qinvokable]
        #[cxx_name = "abortScript"]
        fn abort_script(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "executePython"]
        fn execute_python(self: Pin<&mut Self>, code: &QString);

        /// The built-in anti-anti-debug / anti-anti-VM plugins, for the Plugins menu.
        #[cxx_name = "pluginCatalog"]
        fn plugin_catalog(self: &Self) -> Vec<PluginRow>;

        /// Sets which plugins are enabled (comma-separated ids); applies them at once when paused,
        /// and automatically each time a new process reaches its entry point / is attached.
        #[qinvokable]
        #[cxx_name = "setEnabledPlugins"]
        fn set_enabled_plugins(self: Pin<&mut Self>, ids: &QString);

        #[qsignal]
        #[cxx_name = "pluginStatsChanged"]
        fn plugin_stats_changed(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "refreshPluginStats"]
        fn refresh_plugin_stats(self: Pin<&mut Self>);

        #[cxx_name = "pluginStatRows"]
        fn plugin_stat_rows(self: &Self) -> Vec<PluginStatRow>;

        #[qinvokable]
        fn start(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "openExecutable"]
        fn open_executable(self: Pin<&mut Self>, path: &QString, arguments: &QString);

        #[qinvokable]
        #[cxx_name = "executeCommand"]
        fn execute_command(self: Pin<&mut Self>, command: &QString);

        #[qinvokable]
        #[cxx_name = "evaluateGoto"]
        fn evaluate_goto(self: Pin<&mut Self>, view: i32, expression: &QString);

        #[qinvokable]
        fn run(self: Pin<&mut Self>);

        #[qinvokable]
        fn pause(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "stepInto"]
        fn step_into(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "stepOver"]
        fn step_over(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "executeTillReturn"]
        fn execute_till_return(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "runToUserCode"]
        fn run_to_user_code(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "runToAddress"]
        fn run_to_address(self: Pin<&mut Self>, address: u64);

        #[qinvokable]
        fn restart(self: Pin<&mut Self>);

        #[qinvokable]
        fn stop(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "toggleBreakpoint"]
        fn toggle_breakpoint(self: Pin<&mut Self>, address: u64);

        #[cxx_name = "currentAddress"]
        fn current_address(self: &Self) -> u64;

        #[cxx_name = "stackPointer"]
        fn stack_pointer(self: &Self) -> u64;

        #[cxx_name = "pointerSize"]
        fn pointer_size(self: &Self) -> i32;

        #[cxx_name = "debugState"]
        fn debug_state(self: &Self) -> i32;

        #[cxx_name = "formatAddress"]
        fn format_address(self: &Self, address: u64) -> QString;

        fn label(self: &Self, address: u64) -> QString;

        #[cxx_name = "isBreakpoint"]
        fn is_breakpoint(self: &Self, address: u64) -> bool;

        #[cxx_name = "callingConvention"]
        fn calling_convention(self: &Self) -> QString;

        fn disassemble(self: &Self, address: u64, count: i32) -> Vec<DisasmRow>;

        #[cxx_name = "previousInstruction"]
        fn previous_instruction(self: &Self, address: u64) -> u64;

        /// Bytes as 0..=255, or -1 where unreadable or not fetched yet.
        #[cxx_name = "readMemory"]
        fn read_memory(self: &Self, address: u64, length: i32) -> Vec<i16>;

        fn registers(self: &Self) -> Vec<RegisterRow>;

        #[cxx_name = "stackRows"]
        fn stack_rows(self: &Self, address: u64, count: i32) -> Vec<StackRow>;

        #[cxx_name = "argumentRows"]
        fn argument_rows(self: &Self, count: i32) -> Vec<StackRow>;

        #[cxx_name = "instructionInfo"]
        fn instruction_info(self: &Self, address: u64) -> QString;
    }

    impl cxx_qt::Threading for DebugSession {}
}

use qobject::{
    AnnotationRow, BreakpointRow, DisasmRow, FrameRow, GraphBlock, HandleRow, MapRow, ModuleRow, PatchRow, PluginRow,
    PluginStatRow, ProcessRow, ReferenceRow, RegisterRow, SignalRow, StackRow, SymbolRow, ThreadRow, TraceRow,
};

const VIEW_DISASSEMBLY: i32 = 0;
const VIEW_DUMP: i32 = 1;
const VIEW_STACK: i32 = 2;

type Thread = CxxQtThread<qobject::DebugSession>;

pub struct DebugSessionRust {
    runtime: tokio::runtime::Runtime,
    debugger: Option<Arc<Debugger>>,
    disassembler: RefCell<Option<(Arch, Disassembler)>>,
    /// Pages with a fetch in flight, so repaints do not start duplicate reads.
    fetching: Arc<Mutex<HashSet<u64>>>,
    views: Arc<Mutex<ViewCache>>,
    references: References,
    script: Arc<Mutex<Option<Script>>>,
    script_running: Arc<AtomicBool>,
    script_abort: Arc<AtomicBool>,
    /// Plugin ids the user has enabled; re-applied on each new process.
    enabled_plugins: Arc<Mutex<Vec<String>>>,
    /// Last queried per-plugin neutralization counts, for the status dialog.
    plugin_stats: Arc<Mutex<Vec<(String, u64)>>>,
}

/// Results shown in the References view: address and info text.
type References = Arc<Mutex<Vec<(u64, String)>>>;

impl Default for DebugSessionRust {
    fn default() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("cutegdb-rt")
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");
        Self {
            runtime,
            debugger: None,
            disassembler: RefCell::new(None),
            fetching: Arc::default(),
            views: Arc::default(),
            references: Arc::default(),
            script: Arc::default(),
            script_running: Arc::default(),
            script_abort: Arc::default(),
            enabled_plugins: Arc::default(),
            plugin_stats: Arc::default(),
        }
    }
}

fn log_later(thread: &Thread, text: impl Into<String>) {
    let text = text.into();
    let _ = thread.queue(move |obj| obj.log_message(QString::from(text.as_str())));
}

fn state_code(state: DebugState) -> i32 {
    match state {
        DebugState::Paused => 1,
        DebugState::Running => 2,
        DebugState::NoTarget | DebugState::Loaded | DebugState::Terminated => 0,
    }
}

fn kind_code(kind: InsnKind) -> u8 {
    match kind {
        InsnKind::Normal => 0,
        InsnKind::Call => 1,
        InsnKind::Jump => 2,
        InsnKind::ConditionalJump => 3,
        InsnKind::Ret => 4,
        InsnKind::Interrupt => 5,
        InsnKind::Nop => 6,
        InsnKind::PushPop => 7,
    }
}

struct SessionResolver {
    arch: Arch,
    symbols: Arc<SymbolTable>,
    /// User labels with their current addresses.
    labels: Vec<(String, u64)>,
}

impl SessionResolver {
    fn new(debugger: &Debugger) -> Self {
        let symbols = debugger.symbols();
        let labels = debugger
            .database()
            .labels
            .iter()
            .filter_map(|label| Some((label.text.clone(), label.location.resolve(&symbols)?)))
            .collect();
        Self { arch: debugger.arch().unwrap_or(Arch::X86_64), symbols, labels }
    }
}

impl Resolver for SessionResolver {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn symbol(&self, name: &str) -> Option<u64> {
        self.labels.iter().find(|(label, _)| label == name).map(|(_, address)| *address).or_else(|| self.symbols.find(name))
    }
}

impl qobject::DebugSession {
    fn start(self: Pin<&mut Self>) {
        let thread = self.qt_thread();
        let views = self.rust().views.clone();
        let enabled_plugins = self.rust().enabled_plugins.clone();
        self.rust().runtime.spawn(async move {
            let (debugger, mut events) = match Debugger::spawn(GdbOptions::default()).await {
                Ok(pair) => pair,
                Err(e) => return log_later(&thread, format!("Failed to start gdb: {e}")),
            };
            let version = debugger
                .gdb()
                .console_quiet("show version")
                .await
                .ok()
                .and_then(|v| v.lines().next().map(str::to_owned))
                .unwrap_or_default();
            let shared = debugger.clone();
            let _ = thread.queue(move |mut obj| {
                obj.as_mut().rust_mut().debugger = Some(shared);
                obj.as_mut().log_message(QString::from(version.as_str()));
                obj.gdb_ready(QString::from(version.as_str()));
            });
            while let Some(event) = events.recv().await {
                match &event {
                    DebugEvent::Paused(snapshot) => {
                        tokio::spawn(refresh_views(debugger.clone(), views.clone(), thread.clone()));
                        // A new process is now stopped with libc mapped but its own code not run:
                        // install the user's enabled countermeasures before it continues.
                        if matches!(
                            snapshot.reason,
                            StopReason::EntryBreakpoint | StopReason::Attach | StopReason::Connected
                        ) {
                            let ids = enabled_plugins.lock().unwrap().clone();
                            if !ids.is_empty() {
                                let (debugger, thread) = (debugger.clone(), thread.clone());
                                tokio::spawn(async move {
                                    if let Err(e) = debugger.set_active_plugins(&ids).await {
                                        log_later(&thread, format!("Failed to apply plugins: {e}"));
                                    }
                                });
                            }
                        }
                    }
                    DebugEvent::State(DebugState::Terminated) => {
                        {
                            let mut cache = views.lock().unwrap();
                            let signals = std::mem::take(&mut cache.signals);
                            *cache = ViewCache { signals, ..ViewCache::default() };
                        }
                        let _ = thread.queue(|obj| obj.views_changed());
                    }
                    _ => {}
                }
                let _ = thread.queue(move |obj| match event {
                    DebugEvent::Log(text) | DebugEvent::Output(text) => obj.log_message(QString::from(text.as_str())),
                    DebugEvent::State(state) => obj.state_changed(state_code(state)),
                    DebugEvent::Paused(snapshot) => obj.paused(snapshot.pc),
                    DebugEvent::SymbolsChanged => obj.symbols_changed(),
                    DebugEvent::BreakpointsChanged => obj.breakpoints_changed(),
                    DebugEvent::AnnotationsChanged | DebugEvent::MemoryWritten => obj.memory_changed(),
                });
            }
        });
    }

    fn open_executable(self: Pin<&mut Self>, path: &QString, arguments: &QString) {
        let path = path.to_string();
        let args: Vec<String> = arguments.to_string().split_whitespace().map(str::to_owned).collect();
        self.spawn_action(move |d| async move {
            d.load(Path::new(&path), &args).await?;
            d.start().await
        });
    }

    fn execute_command(self: Pin<&mut Self>, command: &QString) {
        let text = command.to_string();
        if text.trim().is_empty() {
            return;
        }
        let thread = self.qt_thread();
        let Some(debugger) = self.rust().debugger.clone() else { return log_later(&thread, "gdb is not running") };
        let references = self.rust().references.clone();
        self.rust().runtime.spawn(async move {
            let resolver = SessionResolver::new(&debugger);
            let command = parse_command(&text, &resolver);
            match run_command(&debugger, &resolver, command, &thread, &references).await {
                Ok(Some(message)) => log_later(&thread, message),
                Ok(None) => {}
                Err(e) => log_later(&thread, format!("Error: {e}")),
            }
            let _ = thread.queue(|obj| obj.breakpoints_changed());
        });
    }

    fn evaluate_goto(self: Pin<&mut Self>, view: i32, expression: &QString) {
        let text = expression.to_string();
        let thread = self.qt_thread();
        let Some(debugger) = self.rust().debugger.clone() else { return log_later(&thread, "gdb is not running") };
        self.rust().runtime.spawn(async move {
            let resolver = SessionResolver::new(&debugger);
            match evaluate(&debugger, &resolver, &text).await {
                Ok(address) => {
                    let _ = thread.queue(move |obj| obj.goto_requested(view, address));
                }
                Err(e) => log_later(&thread, format!("Invalid expression \"{text}\": {e}")),
            }
        });
    }

    fn run(self: Pin<&mut Self>) {
        self.spawn_action(|d| async move { d.run().await });
    }

    fn pause(self: Pin<&mut Self>) {
        self.spawn_action(|d| async move { d.pause().await });
    }

    fn step_into(self: Pin<&mut Self>) {
        self.spawn_action(|d| async move { d.step_into().await });
    }

    fn step_over(self: Pin<&mut Self>) {
        self.spawn_action(|d| async move { d.step_over().await });
    }

    fn execute_till_return(self: Pin<&mut Self>) {
        self.spawn_action(|d| async move { d.execute_till_return().await });
    }

    fn run_to_user_code(self: Pin<&mut Self>) {
        self.spawn_action(|d| async move { d.run_to_user_code().await });
    }

    fn run_to_address(self: Pin<&mut Self>, address: u64) {
        self.spawn_action(move |d| async move { d.run_to(address).await });
    }

    fn restart(self: Pin<&mut Self>) {
        self.spawn_action(|d| async move { d.restart().await });
    }

    fn stop(self: Pin<&mut Self>) {
        self.spawn_action(|d| async move { d.stop().await });
    }

    fn toggle_breakpoint(self: Pin<&mut Self>, address: u64) {
        self.spawn_action(move |d| async move { d.toggle_breakpoint(address).await.map(|_| ()) });
    }

    fn current_address(&self) -> u64 {
        self.current_snapshot().map_or(0, |s| s.pc)
    }

    fn stack_pointer(&self) -> u64 {
        self.current_snapshot().map_or(0, |s| s.sp)
    }

    fn pointer_size(&self) -> i32 {
        self.arch().pointer_size() as i32
    }

    fn debug_state(&self) -> i32 {
        self.rust().debugger.as_ref().map_or(0, |d| state_code(d.state()))
    }

    fn format_address(&self, address: u64) -> QString {
        QString::from(self.arch().format_address(address).as_str())
    }

    fn label(&self, address: u64) -> QString {
        let label = self.rust().debugger.as_ref().and_then(|d| d.symbols().label(address)).unwrap_or_default();
        QString::from(label.as_str())
    }

    fn is_breakpoint(&self, address: u64) -> bool {
        self.rust().debugger.as_ref().is_some_and(|d| d.breakpoints().contains(&address))
    }

    fn calling_convention(&self) -> QString {
        QString::from(match self.arch() {
            Arch::X86_64 => "Default (SysV x64)",
            Arch::X86 => "Default (cdecl)",
            Arch::AArch64 => "Default (AAPCS64)",
        })
    }

    fn disassemble(&self, address: u64, count: i32) -> Vec<DisasmRow> {
        let Some(debugger) = self.rust().debugger.clone() else { return Vec::new() };
        let Some(arch) = debugger.arch() else { return Vec::new() };
        let count = count.max(0) as usize;
        let max_len = arch.max_instruction_len();
        let bytes = self.bytes(&debugger, address, count * max_len);
        let symbols = debugger.symbols();
        let database = debugger.database();
        let mut rows = Vec::with_capacity(count);
        let mut offset = 0usize;
        while rows.len() < count {
            let at = address.wrapping_add(offset as u64);
            let readable: Vec<u8> =
                bytes.get(offset..).unwrap_or_default().iter().take(max_len).map_while(|b| *b).collect();
            let decoded = if readable.is_empty() {
                None
            } else {
                self.with_disassembler(arch, |d| d.disassemble(&readable, at, 1).into_iter().next()).flatten()
            };
            match decoded {
                Some(insn) => {
                    offset += insn.len();
                    rows.push(disasm_row(&insn, &symbols, &database, arch));
                }
                None => {
                    let byte = bytes.get(offset).copied().flatten();
                    offset += 1;
                    rows.push(DisasmRow {
                        address: at,
                        size: 1,
                        bytes: byte.map_or_else(|| "??".to_owned(), |b| format!("{b:02X}")),
                        mnemonic: "???".to_owned(),
                        operands: String::new(),
                        kind: 255,
                        target: 0,
                        has_target: false,
                        label: display_label(&symbols, &database, at),
                        comment: user_comment(&symbols, &database, at),
                    });
                }
            }
        }
        rows
    }

    fn previous_instruction(&self, address: u64) -> u64 {
        const WINDOW: u64 = 64;
        let Some(debugger) = self.rust().debugger.clone() else { return address.saturating_sub(1) };
        let arch = self.arch();
        if arch == Arch::AArch64 {
            return address.saturating_sub(4);
        }
        let start = address.saturating_sub(WINDOW);
        let bytes = self.bytes(&debugger, start, (address - start) as usize);
        let readable = bytes.iter().rev().take_while(|b| b.is_some()).count();
        let code: Vec<u8> = bytes[bytes.len() - readable..].iter().map(|b| b.unwrap_or_default()).collect();
        self.with_disassembler(arch, |d| d.previous_instruction(&code, address))
            .flatten()
            .unwrap_or_else(|| address.saturating_sub(1))
    }

    fn read_memory(&self, address: u64, length: i32) -> Vec<i16> {
        let Some(debugger) = self.rust().debugger.clone() else { return vec![-1; length.max(0) as usize] };
        self.bytes(&debugger, address, length.max(0) as usize).iter().map(|b| b.map_or(-1, i16::from)).collect()
    }

    fn registers(&self) -> Vec<RegisterRow> {
        let Some(debugger) = self.rust().debugger.clone() else { return Vec::new() };
        let Some(snapshot) = debugger.snapshot() else { return Vec::new() };
        let arch = snapshot.arch;
        let symbols = debugger.symbols();
        let find = |name: &str| snapshot.registers.iter().find(|r| r.name == name);
        let mut rows = Vec::new();

        for name in arch.general_registers() {
            if let Some(reg) = find(name) {
                let value = reg.value.as_u64().unwrap_or_default();
                rows.push(RegisterRow {
                    name: name.to_uppercase(),
                    value: arch.format_address(value),
                    comment: symbols.label(value).unwrap_or_default(),
                    changed: reg.changed,
                    group: 0,
                });
            }
        }
        if let Some(flags) = find(arch.flags_register()) {
            let value = flags.value.as_u64().unwrap_or_default();
            let name = if arch == Arch::X86_64 { "RFLAGS".to_owned() } else { flags.name.to_uppercase() };
            rows.push(RegisterRow {
                name,
                value: arch.format_address(value),
                comment: String::new(),
                changed: flags.changed,
                group: 1,
            });
            for (flag, bit) in arch.flag_bits() {
                rows.push(RegisterRow {
                    name: (*flag).to_owned(),
                    value: ((value >> bit) & 1).to_string(),
                    comment: String::new(),
                    changed: flags.changed,
                    group: 2,
                });
            }
        }
        for name in arch.segment_registers() {
            if let Some(reg) = find(name) {
                rows.push(RegisterRow {
                    name: name.to_uppercase(),
                    value: format!("{:04X}", reg.value.as_u64().unwrap_or_default()),
                    comment: String::new(),
                    changed: reg.changed,
                    group: 3,
                });
            }
        }
        const EXTRA_PREFIXES: [&str; 14] = [
            "st", "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop", "xmm", "mxcsr", "fs_base",
            "gs_base", "fp",
        ];
        for reg in &snapshot.registers {
            if !EXTRA_PREFIXES.iter().any(|p| reg.name.starts_with(p)) || arch.general_registers().contains(&reg.name.as_str())
            {
                continue;
            }
            let value = match &reg.value {
                RegValue::Int(v) => format!("{v:X}"),
                RegValue::Wide(v) => format!("{v:032X}"),
                RegValue::Text(t) => t.clone(),
            };
            rows.push(RegisterRow {
                name: reg.name.to_uppercase(),
                value,
                comment: String::new(),
                changed: reg.changed,
                group: 4,
            });
        }
        rows
    }

    fn stack_rows(&self, address: u64, count: i32) -> Vec<StackRow> {
        let Some(debugger) = self.rust().debugger.clone() else { return Vec::new() };
        let arch = self.arch();
        let size = arch.pointer_size();
        let symbols = debugger.symbols();
        (0..count.max(0) as u64)
            .map(|i| {
                let at = address.wrapping_add(i * size as u64);
                let value = self.read_pointer(&debugger, at, size);
                let comment = value
                    .and_then(|v| {
                        let label = symbols.label(v)?;
                        Some(if self.is_return_address(&debugger, arch, v) { format!("return to {label}") } else { label })
                    })
                    .unwrap_or_default();
                StackRow { address: at, value: value.unwrap_or(0), readable: value.is_some(), name: String::new(), comment }
            })
            .collect()
    }

    fn argument_rows(&self, count: i32) -> Vec<StackRow> {
        let Some(debugger) = self.rust().debugger.clone() else { return Vec::new() };
        let Some(snapshot) = debugger.snapshot() else { return Vec::new() };
        let symbols = debugger.symbols();
        let register = |name: &str| snapshot.register(name).and_then(RegValue::as_u64);
        (0..count.max(0) as usize)
            .map(|i| {
                let (name, value) = match snapshot.arch {
                    Arch::X86_64 => {
                        const REGS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
                        match REGS.get(i) {
                            Some(reg) => ((*reg).to_owned(), register(reg)),
                            None => {
                                // [rsp] holds the return address at function entry.
                                let offset = 8 * (i - 5) as u64;
                                (format!("[rsp+{offset:X}]"), self.read_pointer(&debugger, snapshot.sp + offset, 8))
                            }
                        }
                    }
                    Arch::X86 => {
                        let offset = 4 * (i + 1) as u64;
                        (format!("[esp+{offset:X}]"), self.read_pointer(&debugger, snapshot.sp + offset, 4))
                    }
                    Arch::AArch64 if i < 8 => (format!("x{i}"), register(&format!("x{i}"))),
                    Arch::AArch64 => {
                        let offset = 8 * (i - 8) as u64;
                        (format!("[sp+{offset:X}]"), self.read_pointer(&debugger, snapshot.sp + offset, 8))
                    }
                };
                StackRow {
                    address: i as u64 + 1,
                    value: value.unwrap_or(0),
                    readable: value.is_some(),
                    name,
                    comment: value.and_then(|v| symbols.label(v)).unwrap_or_default(),
                }
            })
            .collect()
    }

    fn instruction_info(&self, address: u64) -> QString {
        let Some(debugger) = self.rust().debugger.clone() else { return QString::default() };
        let arch = self.arch();
        let symbols = debugger.symbols();
        let bytes = self.bytes(&debugger, address, arch.max_instruction_len());
        let readable: Vec<u8> = bytes.iter().map_while(|b| *b).collect();
        let mut lines = Vec::new();
        if let Some(insn) =
            self.with_disassembler(arch, |d| d.disassemble(&readable, address, 1).into_iter().next()).flatten()
        {
            let snapshot = debugger.snapshot();
            let register = |name: &str| snapshot.as_ref().and_then(|s| s.register(name)).and_then(RegValue::as_u64);
            let memory = |at: u64, size: usize| self.read_pointer(&debugger, at, size);
            let label = |at: u64| symbols.label(at);
            lines = describe_instruction(&insn, &InfoContext { arch, register: &register, memory: &memory, label: &label });
        }
        lines.push(match symbols.label(address) {
            Some(label) => format!("{} {label}", arch.format_address(address)),
            None => arch.format_address(address),
        });
        QString::from(lines.join("\n").as_str())
    }

    fn delete_breakpoint(self: Pin<&mut Self>, number: u32) {
        self.spawn_action(move |d| async move { d.delete_breakpoint(number).await });
    }

    fn set_breakpoint_enabled(self: Pin<&mut Self>, number: u32, enabled: bool) {
        self.spawn_action(move |d| async move { d.set_breakpoint_enabled(number, enabled).await });
    }

    fn set_breakpoint_condition(self: Pin<&mut Self>, number: u32, condition: &QString) {
        let text = condition.to_string();
        self.spawn_action(move |d| async move {
            let gdb_condition = if text.trim().is_empty() {
                String::new()
            } else {
                translate_expression(&text, &SessionResolver::new(&d)).map_err(|e| DebugError::Invalid(e.to_string()))?
            };
            d.set_breakpoint_condition(number, &gdb_condition).await
        });
    }

    fn set_hardware_breakpoint(self: Pin<&mut Self>, address: u64) {
        self.spawn_action(move |d| async move { d.set_breakpoint(address, true).await.map(|_| ()) });
    }

    fn select_thread(self: Pin<&mut Self>, id: u32) {
        self.spawn_action(move |d| async move { d.select_thread(id).await });
    }

    fn set_signal_handling(self: Pin<&mut Self>, name: &QString, stop: bool, print: bool, pass: bool) {
        let name = name.to_string();
        let views = self.rust().views.clone();
        let thread = self.qt_thread();
        self.spawn_action(move |d| async move {
            d.set_signal_handling(&name, stop, print, pass).await?;
            views.lock().unwrap().signals = d.signals().await?;
            let _ = thread.queue(|obj| obj.views_changed());
            Ok(())
        });
    }

    fn breakpoint_state(&self, address: u64) -> i32 {
        match self.rust().debugger.as_ref().and_then(|d| d.breakpoint_at(address)) {
            None => 0,
            Some(bp) if !bp.enabled => 2,
            Some(bp) if bp.kind == BreakpointKind::Hardware => 3,
            Some(_) => 1,
        }
    }

    fn breakpoint_number_at(&self, address: u64) -> u32 {
        self.rust().debugger.as_ref().and_then(|d| d.breakpoint_at(address)).map_or(0, |bp| bp.number)
    }

    fn breakpoint_rows(&self) -> Vec<BreakpointRow> {
        let Some(debugger) = self.rust().debugger.clone() else { return Vec::new() };
        let symbols = debugger.symbols();
        debugger
            .breakpoint_list()
            .into_iter()
            .map(|bp| BreakpointRow {
                number: bp.number,
                kind: match &bp.kind {
                    BreakpointKind::Software => "Software".to_owned(),
                    BreakpointKind::Hardware => "Hardware".to_owned(),
                    BreakpointKind::Watchpoint(WatchAccess::Write) => "Watch (write)".to_owned(),
                    BreakpointKind::Watchpoint(WatchAccess::Read) => "Watch (read)".to_owned(),
                    BreakpointKind::Watchpoint(WatchAccess::ReadWrite) => "Watch (access)".to_owned(),
                    BreakpointKind::Log => "Log".to_owned(),
                    BreakpointKind::Other(other) => other.clone(),
                },
                address: bp.address.unwrap_or(0),
                has_address: bp.address.is_some(),
                label: bp.address.and_then(|a| symbols.label(a)).unwrap_or_default(),
                location: bp.location,
                enabled: bp.enabled,
                hits: bp.hits,
                condition: bp.condition.unwrap_or_default(),
                log_text: bp.log_text.unwrap_or_default(),
            })
            .collect()
    }

    fn frame_rows(&self) -> Vec<FrameRow> {
        let symbols = self.symbol_table();
        self.rust()
            .views
            .lock()
            .unwrap()
            .frames
            .iter()
            .map(|frame| FrameRow {
                level: frame.level,
                address: frame.address,
                label: symbols.label(frame.address).or_else(|| frame.function.clone()).unwrap_or_default(),
                source: match (&frame.file, frame.line) {
                    (Some(file), Some(line)) => format!("{}:{line}", file.rsplit('/').next().unwrap_or(file)),
                    _ => String::new(),
                },
            })
            .collect()
    }

    fn thread_rows(&self) -> Vec<ThreadRow> {
        let symbols = self.symbol_table();
        self.rust()
            .views
            .lock()
            .unwrap()
            .threads
            .iter()
            .map(|thread| ThreadRow {
                id: thread.id,
                lwp: thread.lwp.unwrap_or(0),
                name: thread.name.clone().unwrap_or_default(),
                address: thread.address.unwrap_or(0),
                label: thread.address.and_then(|a| symbols.label(a)).or_else(|| thread.function.clone()).unwrap_or_default(),
                current: thread.current,
                running: thread.running,
            })
            .collect()
    }

    fn memory_map_rows(&self) -> Vec<MapRow> {
        self.rust()
            .views
            .lock()
            .unwrap()
            .map
            .iter()
            .map(|m| MapRow { start: m.start, size: m.end - m.start, perms: m.perms.clone(), info: m.path.clone() })
            .collect()
    }

    fn signal_rows(&self) -> Vec<SignalRow> {
        self.rust()
            .views
            .lock()
            .unwrap()
            .signals
            .iter()
            .map(|s| SignalRow { name: s.name.clone(), stop: s.stop, print: s.print, pass: s.pass, description: s.description.clone() })
            .collect()
    }

    fn handle_rows(&self) -> Vec<HandleRow> {
        let views = self.rust().views.lock().unwrap();
        views.handles.iter().map(|h| HandleRow { fd: h.fd, target: h.target.clone() }).collect()
    }

    fn module_rows(&self) -> Vec<ModuleRow> {
        self.symbol_table()
            .modules()
            .iter()
            .map(|m| ModuleRow {
                name: m.name.clone(),
                path: m.path.clone(),
                base: m.base,
                size: m.end - m.base,
                entry: m.entry.unwrap_or(0),
            })
            .collect()
    }

    fn symbol_rows(&self, module: &QString) -> Vec<SymbolRow> {
        let symbols = self.symbol_table();
        let name = module.to_string();
        symbols
            .module(&name)
            .map(|m| m.symbols().iter().map(|s| SymbolRow { address: s.address, name: s.name.clone(), size: s.size }).collect())
            .unwrap_or_default()
    }

    fn assemble(self: Pin<&mut Self>, address: u64, instruction: &QString, fill_nops: bool) {
        let text = instruction.to_string();
        self.spawn_action(move |d| async move { d.assemble_at(address, &text, fill_nops).await.map(|_| ()) });
    }

    fn set_comment(self: Pin<&mut Self>, address: u64, text: &QString) {
        let text = text.to_string();
        self.spawn_action(move |d| async move { d.set_comment(address, &text) });
    }

    fn set_label(self: Pin<&mut Self>, address: u64, name: &QString) {
        let name = name.to_string();
        self.spawn_action(move |d| async move { d.set_label(address, &name) });
    }

    fn toggle_bookmark(self: Pin<&mut Self>, address: u64) {
        self.spawn_action(move |d| async move { d.toggle_bookmark(address).map(|_| ()) });
    }

    fn write_bytes(self: Pin<&mut Self>, address: u64, hex: &QString) {
        let text = hex.to_string();
        self.spawn_action(move |d| async move {
            let bytes = parse_hex_bytes(&text).ok_or_else(|| DebugError::Invalid(format!("invalid hex bytes: {text}")))?;
            d.write_memory(address, &bytes).await
        });
    }

    fn restore_patch(self: Pin<&mut Self>, address: u64) {
        self.spawn_action(move |d| async move { d.restore_patch(address).await.map(|_| ()) });
    }

    fn export_patches(self: Pin<&mut Self>, path: &QString) {
        let path = path.to_string();
        let thread = self.qt_thread();
        self.spawn_action(move |d| async move {
            let changed = d.export_patches(Path::new(&path))?;
            log_later(&thread, format!("{changed} patched byte(s) written to {path}"));
            Ok(())
        });
    }

    fn comment_at(&self, address: u64) -> QString {
        let text = self.rust().debugger.as_ref().and_then(|d| d.comment_at(address)).unwrap_or_default();
        QString::from(text.as_str())
    }

    fn label_at(&self, address: u64) -> QString {
        let text = self.rust().debugger.as_ref().and_then(|d| d.label_at(address)).unwrap_or_default();
        QString::from(text.as_str())
    }

    fn is_bookmarked(&self, address: u64) -> bool {
        self.rust().debugger.as_ref().is_some_and(|d| d.is_bookmarked(address))
    }

    fn patch_rows(&self) -> Vec<PatchRow> {
        let Some(debugger) = self.rust().debugger.clone() else { return Vec::new() };
        debugger
            .patches()
            .into_iter()
            .map(|(address, patch)| PatchRow {
                address,
                module: patch.location.module,
                original: patch.original,
                patched: patch.patched,
            })
            .collect()
    }

    fn annotation_rows(&self, kind: i32) -> Vec<AnnotationRow> {
        let Some(debugger) = self.rust().debugger.clone() else { return Vec::new() };
        let symbols = debugger.symbols();
        let database = debugger.database();
        let row = |location: &ModuleAddress, text: String| {
            Some(AnnotationRow { address: location.resolve(&symbols)?, module: location.module.clone(), text })
        };
        match kind {
            0 => database.comments.iter().filter_map(|c| row(&c.location, c.text.clone())).collect(),
            1 => database.labels.iter().filter_map(|l| row(&l.location, l.text.clone())).collect(),
            _ => database
                .bookmarks
                .iter()
                .filter_map(|location| {
                    let address = location.resolve(&symbols)?;
                    row(location, display_label(&symbols, &database, address))
                })
                .collect(),
        }
    }

    fn search_pattern(self: Pin<&mut Self>, start: u64, pattern: &QString, whole_memory: bool) {
        let text = pattern.to_string();
        let scope = if whole_memory { SearchScope::AllMemory } else { SearchScope::Module };
        let (thread, store) = (self.qt_thread(), self.rust().references.clone());
        let Some(debugger) = self.rust().debugger.clone() else { return log_later(&thread, "gdb is not running") };
        self.rust().runtime.spawn(async move {
            let resolver = SessionResolver::new(&debugger);
            match find_pattern(&debugger, &resolver, start, &text, scope).await {
                Ok(found) => log_later(&thread, publish_references(&store, &thread, found)),
                Err(e) => log_later(&thread, format!("Error: {e}")),
            }
        });
    }

    fn find_string_references(self: Pin<&mut Self>, address: u64) {
        let (thread, store) = (self.qt_thread(), self.rust().references.clone());
        let Some(debugger) = self.rust().debugger.clone() else { return log_later(&thread, "gdb is not running") };
        self.rust().runtime.spawn(async move {
            let resolver = SessionResolver::new(&debugger);
            match find_string_references(&debugger, &resolver, address).await {
                Ok(found) => log_later(&thread, publish_references(&store, &thread, found)),
                Err(e) => log_later(&thread, format!("Error: {e}")),
            }
        });
    }

    fn find_references_to(self: Pin<&mut Self>, address: u64) {
        let (thread, store) = (self.qt_thread(), self.rust().references.clone());
        let Some(debugger) = self.rust().debugger.clone() else { return log_later(&thread, "gdb is not running") };
        self.rust().runtime.spawn(async move {
            let resolver = SessionResolver::new(&debugger);
            match find_references_to(&debugger, &resolver, address).await {
                Ok(found) => log_later(&thread, publish_references(&store, &thread, found)),
                Err(e) => log_later(&thread, format!("Error: {e}")),
            }
        });
    }

    fn trace(self: Pin<&mut Self>, over: bool, condition: &QString, max_steps: i32) {
        let text = condition.to_string();
        let thread = self.qt_thread();
        self.spawn_action(move |d| async move {
            let stop_condition = if text.trim().is_empty() {
                None
            } else {
                Some(translate_expression(&text, &SessionResolver::new(&d)).map_err(|e| DebugError::Invalid(e.to_string()))?)
            };
            let options = TraceOptions { step_over: over, max_steps: max_steps.max(1) as usize, stop_condition };
            let result = d.trace(options).await.map(|_| ());
            let _ = thread.queue(|obj| obj.trace_changed());
            result
        });
    }

    fn trace_rows(&self) -> Vec<TraceRow> {
        let Some(debugger) = self.rust().debugger.clone() else { return Vec::new() };
        let arch = self.arch();
        debugger
            .trace_entries()
            .into_iter()
            .map(|entry| TraceRow {
                address: entry.address,
                bytes: entry.bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "),
                text: match entry.text.split_once(' ') {
                    Some((mnemonic, operands)) => {
                        format!("{mnemonic} {}", format_operands(operands, entry.address, entry.bytes.len(), arch))
                    }
                    None => entry.text,
                },
                changes: entry.changes.iter().map(|(name, value)| format!("{name}={value:X}")).collect::<Vec<_>>().join(" "),
            })
            .collect()
    }

    fn export_trace(self: Pin<&mut Self>, path: &QString) {
        let path = path.to_string();
        let thread = self.qt_thread();
        self.spawn_action(move |d| async move {
            let count = d.export_trace(Path::new(&path))?;
            log_later(&thread, format!("{count} trace entries written to {path}"));
            Ok(())
        });
    }

    fn function_graph(&self, address: u64) -> Vec<GraphBlock> {
        let Some(debugger) = self.rust().debugger.clone() else { return Vec::new() };
        let Some(arch) = debugger.arch() else { return Vec::new() };
        let symbols = debugger.symbols();
        let database = debugger.database();
        let Some(module) = symbols.module_at(address) else { return Vec::new() };
        let (entry, within) = match module.symbol_at(address) {
            Some((symbol, _)) if symbol.size > 0 => (symbol.address, symbol.address..symbol.address + symbol.size),
            _ => (address, module.base..module.end),
        };
        let read = |at: u64, len: usize| -> Vec<u8> { self.bytes(&debugger, at, len).into_iter().map_while(|b| b).collect() };
        let Some(graph) = self.with_disassembler(arch, |d| build_graph(d, entry, within, 5000, &read)) else {
            return Vec::new();
        };
        let mut blocks: Vec<GraphBlock> = graph
            .blocks
            .iter()
            .map(|block| {
                let mut lines = Vec::new();
                let label = display_label(&symbols, &database, block.start);
                if !label.is_empty() {
                    lines.push(format!("{label}:"));
                }
                for insn in &block.instructions {
                    let row = disasm_row(insn, &symbols, &database, arch);
                    lines.push(format!("{}  {} {}", arch.format_address(insn.address), row.mnemonic, row.operands));
                }
                GraphBlock {
                    start: block.start,
                    text: lines.join("\n"),
                    edge_targets: block.edges.iter().map(|(target, _)| *target).collect(),
                    edge_kinds: block
                        .edges
                        .iter()
                        .map(|(_, kind)| match kind {
                            EdgeKind::Unconditional => 0,
                            EdgeKind::Taken => 1,
                            EdgeKind::NotTaken => 2,
                        })
                        .collect(),
                }
            })
            .collect();
        blocks.sort_by_key(|block| block.start != graph.entry);
        blocks
    }

    fn load_script(self: Pin<&mut Self>, text: &QString) -> QString {
        if self.rust().script_running.load(Ordering::SeqCst) {
            return QString::from("a script is running");
        }
        match Script::parse(&text.to_string()) {
            Ok(script) => {
                *self.rust().script.lock().unwrap() = Some(script);
                self.script_state_changed(0, false);
                QString::default()
            }
            Err(e) => QString::from(e.to_string().as_str()),
        }
    }

    fn run_script(self: Pin<&mut Self>, single_step: bool) {
        let thread = self.qt_thread();
        let Some(debugger) = self.rust().debugger.clone() else { return log_later(&thread, "gdb is not running") };
        let script = self.rust().script.clone();
        let (running, abort) = (self.rust().script_running.clone(), self.rust().script_abort.clone());
        let references = self.rust().references.clone();
        if running.swap(true, Ordering::SeqCst) {
            return;
        }
        abort.store(false, Ordering::SeqCst);
        self.rust().runtime.spawn(async move {
            let outcome = run_script_steps(&debugger, &script, &abort, single_step, &thread, &references).await;
            running.store(false, Ordering::SeqCst);
            if let Err(message) = outcome {
                log_later(&thread, format!("Script error: {message}"));
            }
            let line = script
                .lock()
                .unwrap()
                .as_ref()
                .filter(|s| s.next_line() < s.line_count())
                .map_or(-1, |s| s.next_line() as i32);
            let _ = thread.queue(move |obj| obj.script_state_changed(line, false));
        });
    }

    fn abort_script(self: Pin<&mut Self>) {
        self.rust().script_abort.store(true, Ordering::SeqCst);
    }

    fn execute_python(self: Pin<&mut Self>, code: &QString) {
        let code = code.to_string();
        self.spawn_action(move |d| async move { d.execute_user_command(&format!("python {code}")).await.map(|_| ()) });
    }

    fn plugin_catalog(&self) -> Vec<PluginRow> {
        plugin_catalog()
            .iter()
            .map(|p| PluginRow {
                id: p.id.to_owned(),
                name: p.name.to_owned(),
                category: match p.category {
                    PluginCategory::AntiDebug => 0,
                    PluginCategory::AntiVm => 1,
                },
                best_effort: p.best_effort,
                description: p.description.to_owned(),
            })
            .collect()
    }

    fn set_enabled_plugins(self: Pin<&mut Self>, ids: &QString) {
        let ids: Vec<String> = ids.to_string().split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect();
        *self.rust().enabled_plugins.lock().unwrap() = ids.clone();
        // Apply immediately when a process is already stopped; otherwise it happens at the next start.
        let live = self.debug_state() != state_code(DebugState::NoTarget)
            && self.debug_state() != state_code(DebugState::Terminated);
        if live
            && let Some(debugger) = self.rust().debugger.clone()
        {
            let thread = self.qt_thread();
            self.rust().runtime.spawn(async move {
                if let Err(e) = debugger.set_active_plugins(&ids).await {
                    log_later(&thread, format!("Failed to apply plugins: {e}"));
                }
            });
        }
    }

    fn refresh_plugin_stats(self: Pin<&mut Self>) {
        let thread = self.qt_thread();
        let Some(debugger) = self.rust().debugger.clone() else { return };
        let store = self.rust().plugin_stats.clone();
        self.rust().runtime.spawn(async move {
            if let Ok(stats) = debugger.plugin_stats().await {
                *store.lock().unwrap() = stats;
                let _ = thread.queue(|obj| obj.plugin_stats_changed());
            }
        });
    }

    fn plugin_stat_rows(&self) -> Vec<PluginStatRow> {
        self.rust()
            .plugin_stats
            .lock()
            .unwrap()
            .iter()
            .map(|(id, count)| PluginStatRow {
                id: id.clone(),
                name: cutegdb_core::plugin_info(id).map_or_else(|| id.clone(), |p| p.name.to_owned()),
                count: *count,
            })
            .collect()
    }

    fn attach(self: Pin<&mut Self>, pid: u32) {
        self.spawn_action(move |d| async move { d.attach(pid).await });
    }

    fn detach(self: Pin<&mut Self>) {
        self.spawn_action(|d| async move { d.detach().await });
    }

    fn connect_remote(self: Pin<&mut Self>, address: &QString, executable: &QString) {
        let address = address.to_string();
        let executable = executable.to_string();
        self.spawn_action(move |d| async move {
            let executable = (!executable.trim().is_empty()).then(|| std::path::PathBuf::from(executable.trim()));
            d.connect_remote(address.trim(), executable.as_deref()).await
        });
    }

    fn process_rows(&self) -> Vec<ProcessRow> {
        let own = std::process::id();
        let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
        let mut rows: Vec<ProcessRow> = entries
            .filter_map(|entry| {
                let pid: u32 = entry.ok()?.file_name().to_str()?.parse().ok()?;
                if pid == own {
                    return None;
                }
                let name = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?.trim().to_owned();
                let path = std::fs::read_link(format!("/proc/{pid}/exe"))
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                Some(ProcessRow { pid, name, path })
            })
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row.pid));
        rows
    }

    fn reference_rows(&self) -> Vec<ReferenceRow> {
        let Some(debugger) = self.rust().debugger.clone() else { return Vec::new() };
        let Some(arch) = debugger.arch() else { return Vec::new() };
        let rows = self.rust().references.lock().unwrap().clone();
        rows.into_iter()
            .map(|(address, info)| {
                let bytes: Vec<u8> =
                    self.bytes(&debugger, address, arch.max_instruction_len()).into_iter().map_while(|b| b).collect();
                let disassembly = self
                    .with_disassembler(arch, |d| d.disassemble(&bytes, address, 1).into_iter().next())
                    .flatten()
                    .map(|insn| {
                        let operands = format_operands(&insn.operands, insn.address, insn.len(), arch);
                        if operands.is_empty() { insn.mnemonic } else { format!("{} {operands}", insn.mnemonic) }
                    })
                    .unwrap_or_else(|| "???".to_owned());
                ReferenceRow { address, disassembly, info }
            })
            .collect()
    }

    fn symbol_table(&self) -> Arc<SymbolTable> {
        self.rust().debugger.as_ref().map(|d| d.symbols()).unwrap_or_default()
    }

    fn arch(&self) -> Arch {
        self.rust().debugger.as_ref().and_then(|d| d.arch()).unwrap_or(Arch::X86_64)
    }

    fn current_snapshot(&self) -> Option<Arc<Snapshot>> {
        self.rust().debugger.as_ref().and_then(|d| d.snapshot())
    }

    fn with_disassembler<T>(&self, arch: Arch, f: impl FnOnce(&Disassembler) -> T) -> Option<T> {
        let mut slot = self.rust().disassembler.borrow_mut();
        if slot.as_ref().is_none_or(|(cached, _)| *cached != arch) {
            *slot = Disassembler::new(arch).ok().map(|d| (arch, d));
        }
        slot.as_ref().map(|(_, d)| f(d))
    }

    /// Cached bytes, starting a background fetch for pages that are not cached yet.
    fn bytes(&self, debugger: &Arc<Debugger>, address: u64, len: usize) -> Vec<Option<u8>> {
        let missing = debugger.missing_pages(address, len);
        if !missing.is_empty() {
            let fresh: Vec<u64> = {
                let mut fetching = self.rust().fetching.lock().unwrap();
                missing.into_iter().filter(|page| fetching.insert(*page)).collect()
            };
            if !fresh.is_empty() {
                let (debugger, fetching, thread) = (debugger.clone(), self.rust().fetching.clone(), self.qt_thread());
                self.rust().runtime.spawn(async move {
                    for page in &fresh {
                        debugger.read_memory(*page, PAGE_SIZE).await;
                    }
                    fetching.lock().unwrap().retain(|page| !fresh.contains(page));
                    let _ = thread.queue(|obj| obj.memory_changed());
                });
            }
        }
        debugger.cached_memory(address, len)
    }

    fn read_pointer(&self, debugger: &Arc<Debugger>, address: u64, size: usize) -> Option<u64> {
        let bytes: Option<Vec<u8>> = self.bytes(debugger, address, size).into_iter().collect();
        Some(bytes?.iter().rev().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    /// Whether the instruction just before `address` is a call, i.e. `address` is a return address.
    fn is_return_address(&self, debugger: &Arc<Debugger>, arch: Arch, address: u64) -> bool {
        if arch == Arch::AArch64 {
            return false;
        }
        let Some(start) = address.checked_sub(16) else { return false };
        let bytes = self.bytes(debugger, start, 16);
        let readable = bytes.iter().rev().take_while(|b| b.is_some()).count();
        let code: Vec<u8> = bytes[bytes.len() - readable..].iter().map(|b| b.unwrap_or_default()).collect();
        let code_start = address - code.len() as u64;
        self.with_disassembler(arch, |d| {
            let previous = d.previous_instruction(&code, address)?;
            d.disassemble(&code[(previous - code_start) as usize..], previous, 1).into_iter().next()
        })
        .flatten()
        .is_some_and(|insn| insn.kind == InsnKind::Call)
    }

    fn spawn_action<F, Fut>(&self, action: F)
    where
        F: FnOnce(Arc<Debugger>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), DebugError>> + Send + 'static,
    {
        let thread = self.qt_thread();
        let Some(debugger) = self.rust().debugger.clone() else { return log_later(&thread, "gdb is not running") };
        self.rust().runtime.spawn(async move {
            let result = action(debugger).await;
            let _ = thread.queue(move |mut obj| {
                if let Err(e) = result {
                    obj.as_mut().log_message(QString::from(e.to_string().as_str()));
                }
                obj.breakpoints_changed();
            });
        });
    }
}

/// Data behind the call stack, threads, memory map, signals and handles views.
#[derive(Default)]
struct ViewCache {
    frames: Vec<Frame>,
    threads: Vec<ThreadInfo>,
    map: Vec<Mapping>,
    signals: Vec<SignalInfo>,
    handles: Vec<FileHandle>,
}

/// Re-reads the view data after a pause. Queries fail harmlessly if the debuggee resumed meanwhile.
async fn refresh_views(debugger: Arc<Debugger>, views: Arc<Mutex<ViewCache>>, thread: Thread) {
    let cache = ViewCache {
        frames: debugger.call_stack(256).await.unwrap_or_default(),
        threads: debugger.threads().await.unwrap_or_default(),
        map: debugger.memory_map().await.unwrap_or_default(),
        signals: debugger.signals().await.unwrap_or_default(),
        handles: debugger.open_files().await.unwrap_or_default(),
    };
    *views.lock().unwrap() = cache;
    let _ = thread.queue(|obj| obj.views_changed());
}

/// User label at `address`, otherwise the symbol starting exactly there.
fn display_label(symbols: &SymbolTable, database: &Database, address: u64) -> String {
    ModuleAddress::from_address(symbols, address)
        .and_then(|location| database.label(&location).map(str::to_owned))
        .or_else(|| symbols.label(address).filter(|l| !l.contains('+')))
        .unwrap_or_default()
}

fn user_comment(symbols: &SymbolTable, database: &Database, address: u64) -> String {
    ModuleAddress::from_address(symbols, address)
        .and_then(|location| database.comment(&location).map(str::to_owned))
        .unwrap_or_default()
}

fn disasm_row(insn: &Instruction, symbols: &SymbolTable, database: &Database, arch: Arch) -> DisasmRow {
    // Direct branch destinations are shown by name, like x64dbg's "call hello.add".
    let target_label = |target: u64| {
        let user = display_label(symbols, database, target);
        if user.is_empty() { symbols.label(target) } else { Some(user) }
    };
    let operands = match insn.target.and_then(|t| target_label(t).map(|label| (t, label))) {
        Some((target, label)) => {
            insn.operands.replace(&format!("#0x{target:x}"), &label).replace(&format!("0x{target:x}"), &label)
        }
        None => insn.operands.clone(),
    };
    DisasmRow {
        address: insn.address,
        size: insn.len() as u32,
        bytes: insn.bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "),
        mnemonic: insn.mnemonic.clone(),
        operands: format_operands(&operands, insn.address, insn.len(), arch),
        kind: kind_code(insn.kind),
        target: insn.target.unwrap_or(0),
        has_target: insn.target.is_some(),
        label: display_label(symbols, database, insn.address),
        comment: user_comment(symbols, database, insn.address),
    }
}

/// "90 90 cc", "9090CC" → bytes.
fn parse_hex_bytes(text: &str) -> Option<Vec<u8>> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return None;
    }
    (0..digits.len()).step_by(2).map(|i| u8::from_str_radix(digits.get(i..i + 2)?, 16).ok()).collect()
}

async fn evaluate(debugger: &Debugger, resolver: &SessionResolver, expression: &str) -> Result<u64, String> {
    let gdb_expression = translate_expression(expression, resolver).map_err(|e| e.to_string())?;
    debugger.evaluate(&gdb_expression).await.map_err(|e| e.to_string())
}

async fn goto(debugger: &Debugger, resolver: &SessionResolver, thread: &Thread, view: i32, expression: &str) -> Result<Option<String>, String> {
    let address = evaluate(debugger, resolver, expression).await?;
    let _ = thread.queue(move |obj| obj.goto_requested(view, address));
    Ok(None)
}

/// Runs script lines until the script finishes, pauses, fails or is aborted (or after one host action
/// when `single_step`).
async fn run_script_steps(
    debugger: &Arc<Debugger>,
    script: &Arc<Mutex<Option<Script>>>,
    abort: &AtomicBool,
    single_step: bool,
    thread: &Thread,
    references: &References,
) -> Result<(), String> {
    loop {
        if abort.load(Ordering::SeqCst) {
            log_later(thread, "Script aborted");
            return Ok(());
        }
        let step = {
            let mut guard = script.lock().unwrap();
            let loaded = guard.as_mut().ok_or("no script loaded")?;
            loaded.step().map_err(|e| e.to_string())?
        };
        match step {
            ScriptStep::Finished => {
                log_later(thread, "Script finished");
                return Ok(());
            }
            ScriptStep::Paused { line } => {
                log_later(thread, format!("Script paused at line {}", line + 1));
                return Ok(());
            }
            ScriptStep::Command { line, text } => {
                let _ = thread.queue(move |obj| obj.script_state_changed(line as i32, true));
                let resolver = SessionResolver::new(debugger);
                let command = parse_command(&text, &resolver);
                match run_command(debugger, &resolver, command, thread, references).await {
                    Ok(Some(message)) => log_later(thread, message),
                    Ok(None) => {}
                    Err(e) => return Err(format!("line {}: {e}", line + 1)),
                }
                wait_until_stopped(debugger).await;
            }
            ScriptStep::Compare { line, left, right } => {
                let resolver = SessionResolver::new(debugger);
                let left = evaluate(debugger, &resolver, &left).await.map_err(|e| format!("line {}: {e}", line + 1))?;
                let right = evaluate(debugger, &resolver, &right).await.map_err(|e| format!("line {}: {e}", line + 1))?;
                if let Some(loaded) = script.lock().unwrap().as_mut() {
                    loaded.set_comparison(left, right);
                }
            }
        }
        if single_step {
            return Ok(());
        }
    }
}

/// Scripts continue once a resumed debuggee has stopped again or exited.
async fn wait_until_stopped(debugger: &Debugger) {
    for _ in 0..3000 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if debugger.state() != DebugState::Running {
            return;
        }
    }
}

/// A title such as `Pattern "55 48": 2 result(s)` and the rows for the References view.
type Found = (String, Vec<(u64, String)>);

async fn find_pattern(
    debugger: &Debugger,
    resolver: &SessionResolver,
    start: u64,
    pattern_text: &str,
    scope: SearchScope,
) -> Result<Found, String> {
    let pattern = Pattern::parse(pattern_text)?;
    let range = match scope {
        SearchScope::AllMemory => None,
        SearchScope::Module => {
            let module = resolver.symbols.module_at(start).ok_or("the start address is not inside a module")?;
            Some(module.base..module.end)
        }
        SearchScope::FirstFrom => {
            let map = debugger.memory_map().await.map_err(|e| e.to_string())?;
            let region = map.iter().find(|m| (m.start..m.end).contains(&start)).ok_or("the start address is not mapped")?;
            Some(start..region.end)
        }
    };
    let limit = if scope == SearchScope::FirstFrom { 1 } else { 10_000 };
    let hits = debugger.search_memory(&pattern, range, limit).await.map_err(|e| e.to_string())?;
    let rows: Vec<(u64, String)> = hits.iter().map(|&a| (a, resolver.symbols.label(a).unwrap_or_default())).collect();
    Ok((format!("Pattern \"{pattern_text}\": {} result(s)", rows.len()), rows))
}

async fn find_string_references(debugger: &Debugger, resolver: &SessionResolver, address: u64) -> Result<Found, String> {
    let module = resolver.symbols.module_at(address).ok_or("the address is not inside a module")?.name.clone();
    let strings = debugger.string_references(&module).await.map_err(|e| e.to_string())?;
    let rows: Vec<(u64, String)> = strings.iter().map(|r| (r.from, format!("\"{}\"", r.text))).collect();
    Ok((format!("String references in {module}: {} result(s)", rows.len()), rows))
}

async fn find_references_to(debugger: &Debugger, resolver: &SessionResolver, address: u64) -> Result<Found, String> {
    let references = debugger.references_to(address).await.map_err(|e| e.to_string())?;
    let rows: Vec<(u64, String)> = references
        .iter()
        .map(|r| (r.from, format!("{:?} {}", r.kind, resolver.symbols.label(r.from).unwrap_or_default())))
        .collect();
    Ok((format!("References to {}: {} result(s)", describe_address(resolver, address), rows.len()), rows))
}

/// Stores search results for the References view and returns their title.
fn publish_references(store: &References, thread: &Thread, (title, rows): Found) -> String {
    *store.lock().unwrap() = rows;
    let shown = title.clone();
    let _ = thread.queue(move |obj| obj.references_changed(QString::from(shown.as_str())));
    title
}

/// `0000555555555149 <hello.add>`.
fn describe_address(resolver: &SessionResolver, address: u64) -> String {
    match resolver.symbols.label(address) {
        Some(label) => format!("{} <{label}>", resolver.arch.format_address(address)),
        None => resolver.arch.format_address(address),
    }
}

/// `bpe`/`bpd`: the breakpoint at an address, or all breakpoints.
async fn set_breakpoints_enabled(
    debugger: &Debugger,
    resolver: &SessionResolver,
    target: Option<String>,
    enabled: bool,
) -> Result<Option<String>, String> {
    let numbers: Vec<u32> = match target {
        Some(expression) => {
            let address = evaluate(debugger, resolver, &expression).await?;
            let bp = debugger
                .breakpoint_at(address)
                .ok_or_else(|| format!("No breakpoint at {}", resolver.arch.format_address(address)))?;
            vec![bp.number]
        }
        None => debugger.breakpoint_list().iter().map(|b| b.number).collect(),
    };
    for number in numbers {
        debugger.set_breakpoint_enabled(number, enabled).await.map_err(|e| e.to_string())?;
    }
    Ok(None)
}

/// Execution breakpoints use a debug register directly; data access becomes a watchpoint on the
/// `size` bytes at `address`.
async fn set_hardware_breakpoint(debugger: &Debugger, address: u64, access: HardwareAccess, size: usize) -> Result<(), DebugError> {
    let data_type = match size {
        1 => "unsigned char",
        2 => "unsigned short",
        4 => "unsigned int",
        _ => "unsigned long long",
    };
    let lvalue = format!("*({data_type}*)0x{address:x}");
    match access {
        HardwareAccess::Execute => debugger.set_breakpoint(address, true).await.map(|_| ()),
        HardwareAccess::Write => debugger.set_watchpoint(&lvalue, WatchAccess::Write).await.map(|_| ()),
        HardwareAccess::ReadWrite => debugger.set_watchpoint(&lvalue, WatchAccess::ReadWrite).await.map(|_| ()),
    }
}

async fn run_command(
    debugger: &Arc<Debugger>,
    resolver: &SessionResolver,
    command: Command,
    thread: &Thread,
    references: &References,
) -> Result<Option<String>, String> {
    let done = |result: Result<(), DebugError>| result.map(|_| None).map_err(|e| e.to_string());
    match command {
        Command::Run(None) => done(debugger.run().await),
        Command::Run(Some(expression)) => {
            let address = evaluate(debugger, resolver, &expression).await?;
            done(debugger.run_to(address).await)
        }
        Command::Pause => done(debugger.pause().await),
        Command::StepInto => done(debugger.step_into().await),
        Command::StepOver => done(debugger.step_over().await),
        Command::ExecuteTillReturn => done(debugger.execute_till_return().await),
        Command::RunToUserCode => done(debugger.run_to_user_code().await),
        Command::Stop => done(debugger.stop().await),
        Command::Attach(expression) => {
            let pid = evaluate(debugger, resolver, &expression).await?;
            let pid = u32::try_from(pid).map_err(|_| format!("invalid process id {pid:#x}"))?;
            done(debugger.attach(pid).await)
        }
        Command::Detach => done(debugger.detach().await),
        Command::Trace { over, condition, max_steps } => {
            let stop_condition = translate_expression(&condition, resolver).map_err(|e| e.to_string())?;
            // x64dbg's default maximum trace count.
            let max_steps = match max_steps {
                Some(expression) => evaluate(debugger, resolver, &expression).await? as usize,
                None => 50_000,
            };
            let options = TraceOptions { step_over: over, max_steps, stop_condition: Some(stop_condition) };
            let result = debugger.trace(options).await.map(|_| ());
            let _ = thread.queue(|obj| obj.trace_changed());
            done(result)
        }
        Command::ConnectRemote { address, executable } => {
            done(debugger.connect_remote(&address, executable.as_deref().map(Path::new)).await)
        }
        Command::Restart => done(debugger.restart().await),
        Command::Start { path, arguments } => {
            let args: Vec<String> =
                arguments.map(|a| a.split_whitespace().map(str::to_owned).collect()).unwrap_or_default();
            debugger.load(Path::new(&path), &args).await.map_err(|e| e.to_string())?;
            done(debugger.start().await)
        }
        Command::SetBreakpoint(expression) => {
            let address = evaluate(debugger, resolver, &expression).await?;
            if debugger.breakpoints().contains(&address) {
                return Ok(Some(format!("Breakpoint already set at {}!", resolver.arch.format_address(address))));
            }
            done(debugger.toggle_breakpoint(address).await.map(|_| ()))
        }
        Command::DeleteBreakpoint(target) => {
            let addresses = match target {
                Some(expression) => vec![evaluate(debugger, resolver, &expression).await?],
                None => debugger.breakpoints(),
            };
            for address in addresses {
                if debugger.breakpoints().contains(&address) {
                    debugger.toggle_breakpoint(address).await.map_err(|e| e.to_string())?;
                }
            }
            Ok(None)
        }
        Command::EnableBreakpoint(target) => set_breakpoints_enabled(debugger, resolver, target, true).await,
        Command::DisableBreakpoint(target) => set_breakpoints_enabled(debugger, resolver, target, false).await,
        Command::SetHardwareBreakpoint { address, access, size } => {
            let address = evaluate(debugger, resolver, &address).await?;
            done(set_hardware_breakpoint(debugger, address, access, size).await)
        }
        Command::SetMemoryBreakpoint { address, access } => {
            let address = evaluate(debugger, resolver, &address).await?;
            done(set_hardware_breakpoint(debugger, address, access, resolver.arch.pointer_size()).await)
        }
        Command::DeleteHardwareBreakpoint(target) | Command::DeleteMemoryBreakpoint(target) => {
            let address = match target {
                Some(expression) => Some(evaluate(debugger, resolver, &expression).await?),
                None => None,
            };
            for bp in debugger.breakpoint_list() {
                let matches = match bp.kind {
                    BreakpointKind::Hardware => address.is_none_or(|a| bp.address == Some(a)),
                    BreakpointKind::Watchpoint(_) => address.is_none_or(|a| bp.location.contains(&format!("0x{a:x}"))),
                    _ => false,
                };
                if matches {
                    debugger.delete_breakpoint(bp.number).await.map_err(|e| e.to_string())?;
                }
            }
            Ok(None)
        }
        Command::SetBreakpointCondition { address, condition } => {
            let address = evaluate(debugger, resolver, &address).await?;
            let bp = debugger
                .breakpoint_at(address)
                .ok_or_else(|| format!("No breakpoint at {}", resolver.arch.format_address(address)))?;
            let condition = translate_expression(&condition, resolver).map_err(|e| e.to_string())?;
            done(debugger.set_breakpoint_condition(bp.number, &condition).await)
        }
        Command::SetBreakpointLog { address, text } => {
            let address = evaluate(debugger, resolver, &address).await?;
            let (format, args) = translate_log_text(&text, resolver).map_err(|e| e.to_string())?;
            done(debugger.set_log_breakpoint(address, &format!("{format}\n"), &args).await.map(|_| ()))
        }
        Command::SetComment { address, text } => {
            let address = evaluate(debugger, resolver, &address).await?;
            done(debugger.set_comment(address, &text))
        }
        Command::DeleteComment(address) => {
            let address = evaluate(debugger, resolver, &address).await?;
            done(debugger.set_comment(address, ""))
        }
        Command::SetLabel { address, name } => {
            let address = evaluate(debugger, resolver, &address).await?;
            done(debugger.set_label(address, &name))
        }
        Command::DeleteLabel(address) => {
            let address = evaluate(debugger, resolver, &address).await?;
            done(debugger.set_label(address, ""))
        }
        Command::SetBookmark(address) => {
            let address = evaluate(debugger, resolver, &address).await?;
            if !debugger.is_bookmarked(address) {
                debugger.toggle_bookmark(address).map_err(|e| e.to_string())?;
            }
            Ok(None)
        }
        Command::DeleteBookmark(address) => {
            let address = evaluate(debugger, resolver, &address).await?;
            if debugger.is_bookmarked(address) {
                debugger.toggle_bookmark(address).map_err(|e| e.to_string())?;
            }
            Ok(None)
        }
        Command::Assemble { address, instruction, fill_nops } => {
            let address = evaluate(debugger, resolver, &address).await?;
            done(debugger.assemble_at(address, &instruction, fill_nops).await.map(|_| ()))
        }
        Command::FindPattern { start, pattern, scope } => {
            let start = evaluate(debugger, resolver, &start).await?;
            let found = find_pattern(debugger, resolver, start, &pattern, scope).await?;
            Ok(Some(publish_references(references, thread, found)))
        }
        Command::StringReferences(target) => {
            let address = match target {
                Some(expression) => evaluate(debugger, resolver, &expression).await?,
                None => debugger.snapshot().map(|s| s.pc).ok_or("the debuggee is not paused")?,
            };
            let found = find_string_references(debugger, resolver, address).await?;
            Ok(Some(publish_references(references, thread, found)))
        }
        Command::FindReferences(expression) => {
            let address = evaluate(debugger, resolver, &expression).await?;
            let found = find_references_to(debugger, resolver, address).await?;
            Ok(Some(publish_references(references, thread, found)))
        }
        Command::GotoDisassembly(expression) => goto(debugger, resolver, thread, VIEW_DISASSEMBLY, &expression).await,
        Command::GotoDump(expression) => goto(debugger, resolver, thread, VIEW_DUMP, &expression).await,
        Command::GotoStack(expression) => goto(debugger, resolver, thread, VIEW_STACK, &expression).await,
        Command::Assign { target, value } => {
            let expression = translate_assignment(&target, &value, resolver).map_err(|e| e.to_string())?;
            debugger.evaluate(&expression).await.map_err(|e| e.to_string())?;
            done(debugger.refresh().await)
        }
        Command::Evaluate(expression) => {
            let value = evaluate(debugger, resolver, &expression).await?;
            Ok(Some(format!("{expression}: {value:X}")))
        }
        Command::ClearLog => {
            let _ = thread.queue(|obj| obj.clear_log_requested());
            Ok(None)
        }
        Command::Log(text) => Ok(Some(text)),
        Command::Gdb(line) => debugger.execute_user_command(&line).await.map_err(|e| e.to_string()),
    }
}

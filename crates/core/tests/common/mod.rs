//! Helpers shared by the integration tests: fixture builds and an event-collecting session.
#![allow(dead_code)]

use cutegdb_core::{DebugEvent, DebugState, Debugger, InsnKind, Instruction, Snapshot};
use cutegdb_mi::GdbOptions;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

pub const TIMEOUT: Duration = Duration::from_secs(20);

/// Builds `tests/fixtures/<source>` as `<name>`; `None` when `compiler` is not installed.
///
/// A per-process directory keeps concurrently running test binaries from overwriting each other's
/// fixtures while leaving file (and therefore module) names unchanged.
pub fn fixture(name: &str, source: &str, compiler: &str, flags: &[&str]) -> Option<PathBuf> {
    build(name, &workspace_path("tests/fixtures").join(source), compiler, flags)
}

/// Builds an anti-debug / anti-VM example program from `examples/<relpath>`.
pub fn example(name: &str, relpath: &str, compiler: &str, flags: &[&str]) -> Option<PathBuf> {
    build(name, &workspace_path("examples").join(relpath), compiler, flags)
}

fn workspace_path(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(sub)
}

fn build(name: &str, src: &Path, compiler: &str, flags: &[&str]) -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("fixtures-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join(name);
    let status = Command::new(compiler).args(["-g", "-O0"]).args(flags).arg("-o").arg(&out).arg(src).status().ok()?;
    assert!(status.success(), "{compiler} failed to build {name}");
    Some(out)
}

pub struct Session {
    pub dbg: Arc<Debugger>,
    pub rx: UnboundedReceiver<DebugEvent>,
    pub logs: Vec<String>,
    pub output: Vec<String>,
}

impl Session {
    /// Loads and starts `exe`; the first pause is the system breakpoint.
    pub async fn open(exe: &Path, args: &[&str]) -> Session {
        let (dbg, rx) = Debugger::spawn(GdbOptions::default()).await.unwrap();
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        dbg.load(exe, &args).await.unwrap();
        dbg.start().await.unwrap();
        Session { dbg, rx, logs: Vec::new(), output: Vec::new() }
    }

    pub async fn next_event(&mut self) -> DebugEvent {
        let event = tokio::time::timeout(TIMEOUT, self.rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out; logs: {:#?}", self.logs))
            .expect("event channel closed");
        match &event {
            DebugEvent::Log(l) => self.logs.push(l.clone()),
            DebugEvent::Output(l) => self.output.push(l.clone()),
            _ => {}
        }
        event
    }

    /// Next pause; a process that exits instead makes `next_event` time out with the logs.
    pub async fn next_pause(&mut self) -> Arc<Snapshot> {
        loop {
            if let DebugEvent::Paused(s) = self.next_event().await {
                return s;
            }
        }
    }

    pub async fn wait_state(&mut self, want: DebugState) {
        loop {
            if let DebugEvent::State(s) = self.next_event().await
                && s == want
            {
                return;
            }
        }
    }

    pub async fn wait_output(&mut self, line: &str) {
        while !self.output.iter().any(|l| l == line) {
            self.next_event().await;
        }
    }

    pub async fn wait_log(&mut self, needle: &str) {
        while !self.logs.iter().any(|l| l.contains(needle)) {
            self.next_event().await;
        }
    }

    /// Steps over until the instruction at the program counter is a call.
    pub async fn step_to_call(&mut self, mut snap: Arc<Snapshot>) -> Instruction {
        for _ in 0..64 {
            let insn = self.dbg.instruction_at(snap.pc).await.expect("decodable instruction");
            if insn.kind == InsnKind::Call {
                return insn;
            }
            self.dbg.step_over().await.unwrap();
            snap = self.next_pause().await;
        }
        panic!("no call reached");
    }
}

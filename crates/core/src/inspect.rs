//! Parsers behind the call stack, threads, signals and handles views.

use crate::util::parse_hex;
use cutegdb_mi::Tuple;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub level: u32,
    pub address: u64,
    pub function: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

/// Frames from a `-stack-list-frames` result.
pub fn parse_frames(results: &Tuple) -> Vec<Frame> {
    results
        .get("stack")
        .into_iter()
        .flat_map(|stack| stack.items())
        .filter_map(|frame| {
            Some(Frame {
                level: frame.get_str("level")?.parse().ok()?,
                address: parse_hex(frame.get_str("addr")?)?,
                function: frame.get_str("func").filter(|f| *f != "??").map(str::to_owned),
                file: frame.get_str("fullname").or_else(|| frame.get_str("file")).map(str::to_owned),
                line: frame.get_str("line").and_then(|l| l.parse().ok()),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadInfo {
    /// gdb's thread number.
    pub id: u32,
    /// Kernel thread id.
    pub lwp: Option<u32>,
    pub target_id: String,
    pub name: Option<String>,
    pub address: Option<u64>,
    pub function: Option<String>,
    pub running: bool,
    pub current: bool,
}

/// Threads from a `-thread-info` result.
pub fn parse_threads(results: &Tuple) -> Vec<ThreadInfo> {
    let current = results.get_str("current-thread-id").and_then(|c| c.parse::<u32>().ok());
    results
        .get("threads")
        .into_iter()
        .flat_map(|threads| threads.items())
        .filter_map(|thread| {
            let id = thread.get_str("id")?.parse().ok()?;
            let target_id = thread.get_str("target-id").unwrap_or_default().to_owned();
            let frame = thread.get("frame");
            Some(ThreadInfo {
                id,
                lwp: parse_lwp(&target_id),
                target_id,
                name: thread.get_str("name").map(str::to_owned),
                address: frame.and_then(|f| f.get_str("addr")).and_then(parse_hex),
                function: frame.and_then(|f| f.get_str("func")).filter(|f| *f != "??").map(str::to_owned),
                running: thread.get_str("state") == Some("running"),
                current: Some(id) == current,
            })
        })
        .collect()
}

/// `Thread 0x7ffff7da0740 (LWP 336153)` → 336153; `process 1234` → 1234.
fn parse_lwp(target_id: &str) -> Option<u32> {
    let start = target_id.find("LWP ").map(|i| i + 4).or_else(|| target_id.strip_prefix("process ").map(|_| 8))?;
    target_id[start..].split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

/// Process id from a `-list-thread-groups` result.
pub fn parse_process_id(results: &Tuple) -> Option<u32> {
    results.get("groups")?.items().find_map(|group| group.get_str("pid")?.parse().ok())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalInfo {
    pub name: String,
    /// Whether the debuggee pauses when it receives the signal.
    pub stop: bool,
    pub print: bool,
    /// Whether the signal is delivered to the debuggee.
    pub pass: bool,
    pub description: String,
}

/// Parses gdb's `info signals` table.
pub fn parse_signals(text: &str) -> Vec<SignalInfo> {
    let flag = |t: &str| match t {
        "Yes" => Some(true),
        "No" => Some(false),
        _ => None,
    };
    text.lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            Some(SignalInfo {
                name: (*tokens.first()?).to_owned(),
                stop: flag(tokens.get(1)?)?,
                print: flag(tokens.get(2)?)?,
                pass: flag(tokens.get(3)?)?,
                description: tokens[4..].join(" "),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHandle {
    pub fd: u32,
    /// Link target: a path, or e.g. `socket:[1234]`, `pipe:[5678]`.
    pub target: String,
}

/// Open file descriptors of a local process, read from `/proc/<pid>/fd`.
pub fn open_files(pid: u32) -> std::io::Result<Vec<FileHandle>> {
    let mut handles: Vec<FileHandle> = std::fs::read_dir(format!("/proc/{pid}/fd"))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let fd = entry.file_name().to_str()?.parse().ok()?;
            let target = std::fs::read_link(entry.path()).ok()?.to_string_lossy().into_owned();
            Some(FileHandle { fd, target })
        })
        .collect();
    handles.sort_by_key(|h| h.fd);
    Ok(handles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cutegdb_mi::{Record, parse_line};

    fn results(line: &str) -> Tuple {
        match parse_line(line).unwrap() {
            Record::Result { results, .. } => results,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn frames() {
        let frames = parse_frames(&results(
            r#"^done,stack=[frame={level="0",addr="0x0000555555555149",func="add",file="h.c",fullname="/src/h.c",line="7",arch="i386:x86-64"},frame={level="1",addr="0x00007ffff7dccfba",func="??",from="/lib/libc.so.6",arch="i386:x86-64"}]"#,
        ));
        assert_eq!(
            frames,
            [
                Frame { level: 0, address: 0x555555555149, function: Some("add".into()), file: Some("/src/h.c".into()), line: Some(7) },
                Frame { level: 1, address: 0x7ffff7dccfba, function: None, file: None, line: None },
            ]
        );
    }

    #[test]
    fn threads_and_process_id() {
        let threads = parse_threads(&results(
            r#"^done,threads=[{id="1",target-id="Thread 0x7ffff7da0740 (LWP 335488)",name="probe",frame={level="0",addr="0x000055555555516c",func="main",args=[]},state="stopped",core="1"},{id="2",target-id="process 42",state="running"}],current-thread-id="1""#,
        ));
        assert_eq!(threads.len(), 2);
        assert_eq!((threads[0].id, threads[0].lwp, threads[0].name.as_deref()), (1, Some(335488), Some("probe")));
        assert_eq!((threads[0].address, threads[0].function.as_deref()), (Some(0x55555555516c), Some("main")));
        assert!(threads[0].current && !threads[0].running);
        assert_eq!((threads[1].lwp, threads[1].address, threads[1].running, threads[1].current), (Some(42), None, true, false));

        let groups = results(r#"^done,groups=[{id="i1",type="process",pid="336153",executable="/tmp/p",cores=["3"]}]"#);
        assert_eq!(parse_process_id(&groups), Some(336153));
        assert_eq!(parse_process_id(&results(r#"^done,groups=[{id="i1",type="process"}]"#)), None);
    }

    #[test]
    fn signal_table() {
        let text = "Signal        Stop\tPrint\tPass to program\tDescription\n\n\
                    SIGHUP        Yes\tYes\tYes\t\tHangup\n\
                    SIGINT        Yes\tYes\tNo\t\tInterrupt\n\
                    SIGUSR1       No\tNo\tYes\t\tUser defined signal 1\n\
                    EXC_BAD_ACCESS Yes\tYes\tYes\t\tCould not access memory\n\
                    \nUse the \"handle\" command to change these tables.\n";
        let signals = parse_signals(text);
        assert_eq!(signals.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["SIGHUP", "SIGINT", "SIGUSR1", "EXC_BAD_ACCESS"]);
        assert_eq!(
            signals[2],
            SignalInfo { name: "SIGUSR1".into(), stop: false, print: false, pass: true, description: "User defined signal 1".into() }
        );
        assert!(signals[1].stop && !signals[1].pass);
    }

    #[test]
    fn open_files_of_this_process() {
        let file = std::fs::File::open(env!("CARGO_MANIFEST_DIR")).unwrap();
        let handles = open_files(std::process::id()).unwrap();
        assert!(handles.iter().any(|h| h.target == env!("CARGO_MANIFEST_DIR")), "{handles:?}");
        assert!(handles.windows(2).all(|w| w[0].fd < w[1].fd));
        drop(file);
    }
}

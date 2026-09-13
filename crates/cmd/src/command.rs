//! x64dbg commands recognised in the command bar; anything else is passed to gdb.

use crate::expr::{Resolver, looks_like_expression, translate_assignment, translate_expression};

/// A parsed command-bar line. Expression arguments stay in x64dbg syntax; translate them with
/// `translate_expression` when executing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `run [addr]`: continue, or run until `addr`.
    Run(Option<String>),
    Pause,
    StepInto,
    StepOver,
    ExecuteTillReturn,
    RunToUserCode,
    /// `ticnd condition[, maxsteps]` (into) / `tocnd condition[, maxsteps]` (over).
    Trace { over: bool, condition: String, max_steps: Option<String> },
    Start { path: String, arguments: Option<String> },
    /// `attach pid`; like every x64dbg number the pid is hex (`.1234` for decimal).
    Attach(String),
    Detach,
    /// `remote host:port[, executable]`.
    ConnectRemote { address: String, executable: Option<String> },
    Stop,
    Restart,
    SetBreakpoint(String),
    /// No address means all breakpoints.
    DeleteBreakpoint(Option<String>),
    EnableBreakpoint(Option<String>),
    DisableBreakpoint(Option<String>),
    /// `bph address[, r|w|x][, size]`.
    SetHardwareBreakpoint { address: String, access: HardwareAccess, size: usize },
    DeleteHardwareBreakpoint(Option<String>),
    /// `bpm address[, restore][, r|w|x]`.
    SetMemoryBreakpoint { address: String, access: HardwareAccess },
    DeleteMemoryBreakpoint(Option<String>),
    /// `bpcond address, condition`; the condition is an x64dbg expression.
    SetBreakpointCondition { address: String, condition: String },
    /// `bplog address, text` with `{expression}` placeholders.
    SetBreakpointLog { address: String, text: String },
    /// `cmt address, text`.
    SetComment { address: String, text: String },
    DeleteComment(String),
    /// `lbl address, name`.
    SetLabel { address: String, name: String },
    DeleteLabel(String),
    SetBookmark(String),
    DeleteBookmark(String),
    /// `asm address, "instruction"[, fillnop]`.
    Assemble { address: String, instruction: String, fill_nops: bool },
    /// `find start, pattern` / `findall start, pattern` / `findallmem start, pattern`.
    FindPattern { start: String, pattern: String, scope: SearchScope },
    /// `strref [address]`: string references in the module containing the address (default: cip).
    StringReferences(Option<String>),
    /// `reffind address`: code referring to the address.
    FindReferences(String),
    GotoDisassembly(String),
    GotoDump(String),
    GotoStack(String),
    Assign { target: String, value: String },
    Evaluate(String),
    ClearLog,
    Log(String),
    Gdb(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    /// From the start address to the end of its memory region; first match only.
    FirstFrom,
    /// The module containing the start address.
    Module,
    /// All readable memory.
    AllMemory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareAccess {
    Execute,
    Write,
    ReadWrite,
}

impl HardwareAccess {
    /// x64dbg type letters: `x` execute, `w` write, `r` or `a` read/write.
    fn parse(text: &str) -> Option<HardwareAccess> {
        match text.to_ascii_lowercase().as_str() {
            "x" | "e" => Some(HardwareAccess::Execute),
            "w" => Some(HardwareAccess::Write),
            "r" | "a" | "rw" => Some(HardwareAccess::ReadWrite),
            _ => None,
        }
    }
}

pub fn parse_command(line: &str, resolver: &impl Resolver) -> Command {
    let line = line.trim();
    let (name, rest) = match line.find(char::is_whitespace) {
        Some(i) => (&line[..i], line[i..].trim()),
        None => (line, ""),
    };
    let args = split_args(rest);
    let is_expr = |text: &str| translate_expression(text, resolver).is_ok();
    // An x64dbg command whose argument is not a valid expression is more likely a gdb command
    // of the same name (`dump memory ...`, `run arg1 arg2`).
    let with_expr = |make: fn(String) -> Command| match args.as_slice() {
        [arg] if is_expr(arg) => make(arg.clone()),
        _ => Command::Gdb(line.to_owned()),
    };
    let optional_expr = |make: fn(Option<String>) -> Command| match args.as_slice() {
        [] => make(None),
        [arg] if is_expr(arg) => make(Some(arg.clone())),
        _ => Command::Gdb(line.to_owned()),
    };

    match name.to_ascii_lowercase().as_str() {
        "run" | "go" | "r" | "g" => optional_expr(Command::Run),
        "pause" if args.is_empty() => Command::Pause,
        "stepinto" | "sti" if args.is_empty() => Command::StepInto,
        "stepover" | "sto" | "st" if args.is_empty() => Command::StepOver,
        "stepout" | "rtr" if args.is_empty() => Command::ExecuteTillReturn,
        "runtousercode" | "rtu" if args.is_empty() => Command::RunToUserCode,
        "traceintoconditional" | "ticnd" | "traceoverconditional" | "tocnd" => {
            let over = matches!(name.to_ascii_lowercase().as_str(), "traceoverconditional" | "tocnd");
            match args.as_slice() {
                [condition] if is_expr(condition) => Command::Trace { over, condition: condition.clone(), max_steps: None },
                [condition, max] if is_expr(condition) && is_expr(max) => {
                    Command::Trace { over, condition: condition.clone(), max_steps: Some(max.clone()) }
                }
                _ => Command::Gdb(line.to_owned()),
            }
        }
        "initdebug" | "initdbg" | "init" if !args.is_empty() => {
            Command::Start { path: args[0].clone(), arguments: args.get(1).cloned() }
        }
        "stopdebug" | "stop" | "dbgstop" if args.is_empty() => Command::Stop,
        "attachdebugger" | "attach" => with_expr(Command::Attach),
        "detachdebugger" | "detach" if args.is_empty() => Command::Detach,
        "remote" | "connect" => match args.as_slice() {
            [address] if address.contains(':') => Command::ConnectRemote { address: address.clone(), executable: None },
            [address, executable] if address.contains(':') => {
                Command::ConnectRemote { address: address.clone(), executable: Some(executable.clone()) }
            }
            _ => Command::Gdb(line.to_owned()),
        },
        "restart" if args.is_empty() => Command::Restart,
        "setbpx" | "bp" | "bpx" => with_expr(Command::SetBreakpoint),
        "deletebpx" | "bpc" | "bc" => optional_expr(Command::DeleteBreakpoint),
        "enablebpx" | "bpe" | "be" => optional_expr(Command::EnableBreakpoint),
        "disablebpx" | "bpd" | "bd" => optional_expr(Command::DisableBreakpoint),
        "sethardwarebreakpoint" | "bph" | "bphws" => match args.as_slice() {
            [address, rest @ ..] if is_expr(address) && rest.len() <= 2 => {
                let access = rest.first().map_or(Some(HardwareAccess::Execute), |t| HardwareAccess::parse(t));
                let size = rest.get(1).map_or(Some(1), |s| s.parse::<usize>().ok().filter(|n| matches!(n, 1 | 2 | 4 | 8)));
                match (access, size) {
                    (Some(access), Some(size)) => Command::SetHardwareBreakpoint { address: address.clone(), access, size },
                    _ => Command::Gdb(line.to_owned()),
                }
            }
            _ => Command::Gdb(line.to_owned()),
        },
        "deletehardwarebreakpoint" | "bphc" | "bphwc" => optional_expr(Command::DeleteHardwareBreakpoint),
        "setmemorybpx" | "membp" | "bpm" => match args.as_slice() {
            [address, rest @ ..] if is_expr(address) && rest.len() <= 2 => {
                // The optional restore flag (0 or 1) precedes the type.
                let is_flag = |s: &String| matches!(s.as_str(), "0" | "1");
                let kind = match rest {
                    [] => None,
                    [flag] if is_flag(flag) => None,
                    [kind] => Some(kind.as_str()),
                    [flag, kind] if is_flag(flag) => Some(kind.as_str()),
                    _ => Some(""),
                };
                match kind.map_or(Some(HardwareAccess::ReadWrite), HardwareAccess::parse) {
                    Some(access) => Command::SetMemoryBreakpoint { address: address.clone(), access },
                    None => Command::Gdb(line.to_owned()),
                }
            }
            _ => Command::Gdb(line.to_owned()),
        },
        "deletememorybpx" | "membpc" | "bpmc" => optional_expr(Command::DeleteMemoryBreakpoint),
        "setbreakpointcondition" | "bpcond" | "bpcnd" => match args.as_slice() {
            [address, condition] if is_expr(address) => {
                Command::SetBreakpointCondition { address: address.clone(), condition: condition.clone() }
            }
            _ => Command::Gdb(line.to_owned()),
        },
        "setbreakpointlog" | "bplog" | "bpl" => match args.as_slice() {
            [address, text] if is_expr(address) => Command::SetBreakpointLog { address: address.clone(), text: text.clone() },
            _ => Command::Gdb(line.to_owned()),
        },
        "commentset" | "cmt" | "cmtset" => match args.as_slice() {
            [address, text] if is_expr(address) => Command::SetComment { address: address.clone(), text: text.clone() },
            _ => Command::Gdb(line.to_owned()),
        },
        "commentdel" | "cmtc" | "cmtdel" => with_expr(Command::DeleteComment),
        "labelset" | "lbl" | "lblset" => match args.as_slice() {
            [address, name] if is_expr(address) && !name.is_empty() && !name.contains(char::is_whitespace) => {
                Command::SetLabel { address: address.clone(), name: name.clone() }
            }
            _ => Command::Gdb(line.to_owned()),
        },
        "labeldel" | "lblc" | "lbldel" => with_expr(Command::DeleteLabel),
        "bookmarkset" | "bookmark" => with_expr(Command::SetBookmark),
        "bookmarkdel" | "bookmarkc" => with_expr(Command::DeleteBookmark),
        "asm" => match args.as_slice() {
            [address, instruction] if is_expr(address) => {
                Command::Assemble { address: address.clone(), instruction: instruction.clone(), fill_nops: false }
            }
            [address, instruction, fill] if is_expr(address) => {
                Command::Assemble { address: address.clone(), instruction: instruction.clone(), fill_nops: fill != "0" }
            }
            _ => Command::Gdb(line.to_owned()),
        },
        "find" | "findall" | "findallmem" | "findmemall" => {
            let scope = match name.to_ascii_lowercase().as_str() {
                "find" => SearchScope::FirstFrom,
                "findall" => SearchScope::Module,
                _ => SearchScope::AllMemory,
            };
            // gdb's own `find start, end, value...` takes three or more arguments.
            match args.as_slice() {
                [start, pattern] if is_expr(start) && cutegdb_core::Pattern::parse(pattern).is_ok() => {
                    Command::FindPattern { start: start.clone(), pattern: pattern.clone(), scope }
                }
                _ => Command::Gdb(line.to_owned()),
            }
        }
        "strref" | "refstr" => optional_expr(Command::StringReferences),
        "reffind" | "findref" | "ref" => with_expr(Command::FindReferences),
        "disasm" | "dis" | "d" => with_expr(Command::GotoDisassembly),
        "dump" => with_expr(Command::GotoDump),
        "sdump" => with_expr(Command::GotoStack),
        "mov" | "set" if args.len() == 2 && translate_assignment(&args[0], &args[1], resolver).is_ok() => {
            Command::Assign { target: args[0].clone(), value: args[1].clone() }
        }
        "cls" | "lc" | "lclr" if args.is_empty() => Command::ClearLog,
        "log" => Command::Log(rest.trim_matches('"').to_owned()),
        _ => fallback(line, resolver),
    }
}

fn fallback(line: &str, resolver: &impl Resolver) -> Command {
    if let Some((target, value)) = split_assignment(line)
        && translate_assignment(target, value, resolver).is_ok()
    {
        return Command::Assign { target: target.trim().to_owned(), value: value.trim().to_owned() };
    }
    if looks_like_expression(line, resolver) {
        return Command::Evaluate(line.to_owned());
    }
    Command::Gdb(line.to_owned())
}

/// Splits `lhs = rhs` at a lone `=` (not part of `==`, `!=`, `<=`, `>=`).
fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    let pos = (0..bytes.len()).find(|&i| {
        bytes[i] == b'='
            && !matches!(i.checked_sub(1).map(|p| bytes[p]), Some(b'=' | b'!' | b'<' | b'>'))
            && bytes.get(i + 1) != Some(&b'=')
    })?;
    Some((&line[..pos], &line[pos + 1..]))
}

/// Splits comma-separated arguments, ignoring commas inside brackets, parentheses and quotes.
fn split_args(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut args = Vec::new();
    let (mut depth, mut quoted, mut current) = (0i32, false, String::new());
    for c in text.chars() {
        match c {
            '"' => quoted = !quoted,
            '[' | '(' if !quoted => depth += 1,
            ']' | ')' if !quoted => depth -= 1,
            ',' if !quoted && depth == 0 => {
                args.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    args.push(current);
    args.into_iter().map(|a| a.trim().trim_matches('"').to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::tests::Fake;
    use cutegdb_core::Arch;

    fn parse(line: &str) -> Command {
        parse_command(line, &Fake(Arch::X86_64))
    }

    fn some(s: &str) -> Option<String> {
        Some(s.to_owned())
    }

    #[test]
    fn debug_control() {
        assert_eq!(parse("run"), Command::Run(None));
        assert_eq!(parse("g"), Command::Run(None));
        assert_eq!(parse("run main+4"), Command::Run(some("main+4")));
        assert_eq!(parse("run arg1 arg2"), Command::Gdb("run arg1 arg2".into()));
        assert_eq!(parse("pause"), Command::Pause);
        assert_eq!(parse("sti"), Command::StepInto);
        assert_eq!(parse("StepOver"), Command::StepOver);
        assert_eq!(parse("st"), Command::StepOver);
        assert_eq!(parse("rtr"), Command::ExecuteTillReturn);
        assert_eq!(parse("rtu"), Command::RunToUserCode);
        assert_eq!(parse("stop"), Command::Stop);
        assert_eq!(parse("restart"), Command::Restart);
        assert_eq!(
            parse(r#"init "/bin/ls", "-la /tmp""#),
            Command::Start { path: "/bin/ls".into(), arguments: some("-la /tmp") }
        );
    }

    #[test]
    fn breakpoints_and_navigation() {
        assert_eq!(parse("bp main"), Command::SetBreakpoint("main".into()));
        assert_eq!(parse("bpx 401000"), Command::SetBreakpoint("401000".into()));
        assert_eq!(parse("bc"), Command::DeleteBreakpoint(None));
        assert_eq!(parse("bc main"), Command::DeleteBreakpoint(some("main")));
        assert_eq!(parse("bpe main"), Command::EnableBreakpoint(some("main")));
        assert_eq!(parse("bpd"), Command::DisableBreakpoint(None));
        assert_eq!(parse("d rip"), Command::GotoDisassembly("rip".into()));
        assert_eq!(parse("disasm [rsp]"), Command::GotoDisassembly("[rsp]".into()));
        assert_eq!(parse("dump rsp+8"), Command::GotoDump("rsp+8".into()));
        assert_eq!(parse("sdump rsp"), Command::GotoStack("rsp".into()));
        assert_eq!(parse("dump memory out.bin 0 16"), Command::Gdb("dump memory out.bin 0 16".into()));
    }

    #[test]
    fn hardware_memory_conditional_and_log_breakpoints() {
        use HardwareAccess::*;
        let hw = |address: &str, access, size| Command::SetHardwareBreakpoint { address: address.into(), access, size };
        assert_eq!(parse("bph main"), hw("main", Execute, 1));
        assert_eq!(parse("bph rsp+8, w, 8"), hw("rsp+8", Write, 8));
        assert_eq!(parse("SetHardwareBreakpoint 401000, r, 4"), hw("401000", ReadWrite, 4));
        assert_eq!(parse("bph main, z"), Command::Gdb("bph main, z".into()));
        assert_eq!(parse("bph main, w, 3"), Command::Gdb("bph main, w, 3".into()));
        assert_eq!(parse("bphc"), Command::DeleteHardwareBreakpoint(None));
        assert_eq!(parse("bphwc main"), Command::DeleteHardwareBreakpoint(some("main")));

        let mem = |address: &str, access| Command::SetMemoryBreakpoint { address: address.into(), access };
        assert_eq!(parse("bpm rsp"), mem("rsp", ReadWrite));
        assert_eq!(parse("bpm rsp, 1, w"), mem("rsp", Write));
        assert_eq!(parse("bpm rsp, 0"), mem("rsp", ReadWrite));
        assert_eq!(parse("bpm rsp, x"), mem("rsp", Execute));
        assert_eq!(parse("bpm rsp, 2, w"), Command::Gdb("bpm rsp, 2, w".into()));
        assert_eq!(parse("bpmc rsp"), Command::DeleteMemoryBreakpoint(some("rsp")));

        assert_eq!(
            parse("bpcond main, rax==5"),
            Command::SetBreakpointCondition { address: "main".into(), condition: "rax==5".into() }
        );
        assert_eq!(
            parse(r#"bplog add, "a={rdi}, b={d:rsi}""#),
            Command::SetBreakpointLog { address: "add".into(), text: "a={rdi}, b={d:rsi}".into() }
        );
        assert_eq!(parse("bplog add"), Command::Gdb("bplog add".into()));
    }

    #[test]
    fn annotations_and_assembling() {
        assert_eq!(
            parse(r#"cmt main, "entry, sort of""#),
            Command::SetComment { address: "main".into(), text: "entry, sort of".into() }
        );
        assert_eq!(parse("cmtc main"), Command::DeleteComment("main".into()));
        assert_eq!(parse("lbl rip, my_label"), Command::SetLabel { address: "rip".into(), name: "my_label".into() });
        assert_eq!(parse(r#"lbl rip, "two words""#), Command::Gdb(r#"lbl rip, "two words""#.into()));
        assert_eq!(parse("lblc rip"), Command::DeleteLabel("rip".into()));
        assert_eq!(parse("bookmark main+4"), Command::SetBookmark("main+4".into()));
        assert_eq!(parse("bookmarkc main+4"), Command::DeleteBookmark("main+4".into()));
        let asm = |instruction: &str, fill_nops| Command::Assemble { address: "rip".into(), instruction: instruction.into(), fill_nops };
        assert_eq!(parse(r#"asm rip, "mov eax, 1""#), asm("mov eax, 1", false));
        assert_eq!(parse(r#"asm rip, "nop", 1"#), asm("nop", true));
        assert_eq!(parse(r#"asm rip, "nop", 0"#), asm("nop", false));
        assert_eq!(parse("asm rip"), Command::Gdb("asm rip".into()));
    }

    #[test]
    fn conditional_tracing() {
        assert_eq!(parse("ticnd rax==5"), Command::Trace { over: false, condition: "rax==5".into(), max_steps: None });
        assert_eq!(
            parse("TraceOverConditional byte:[cip]==C3, .100"),
            Command::Trace { over: true, condition: "byte:[cip]==C3".into(), max_steps: some(".100") }
        );
        assert_eq!(parse("tocnd"), Command::Gdb("tocnd".into()));
    }

    #[test]
    fn attach_detach_and_remote() {
        assert_eq!(parse("attach 1a2b"), Command::Attach("1a2b".into()));
        assert_eq!(parse("attach .6699"), Command::Attach(".6699".into()));
        assert_eq!(parse("detach"), Command::Detach);
        assert_eq!(parse("remote localhost:1234"), Command::ConnectRemote { address: "localhost:1234".into(), executable: None });
        assert_eq!(
            parse(r#"remote 127.0.0.1:1234, "/tmp/my prog""#),
            Command::ConnectRemote { address: "127.0.0.1:1234".into(), executable: some("/tmp/my prog") }
        );
        assert_eq!(parse("remote nonsense"), Command::Gdb("remote nonsense".into()));
    }

    #[test]
    fn searches() {
        let find = |start: &str, pattern: &str, scope| Command::FindPattern { start: start.into(), pattern: pattern.into(), scope };
        assert_eq!(parse("find rip, 55 48 89 E5"), find("rip", "55 48 89 E5", SearchScope::FirstFrom));
        assert_eq!(parse("findall main, E8????????"), find("main", "E8????????", SearchScope::Module));
        assert_eq!(parse("findallmem 0, 4?"), find("0", "4?", SearchScope::AllMemory));
        assert_eq!(parse("find rip, zz"), Command::Gdb("find rip, zz".into()));
        assert_eq!(parse("find &counter, +100, 5"), Command::Gdb("find &counter, +100, 5".into()));
        assert_eq!(parse("strref"), Command::StringReferences(None));
        assert_eq!(parse("strref main"), Command::StringReferences(some("main")));
        assert_eq!(parse("reffind add"), Command::FindReferences("add".into()));
    }

    #[test]
    fn assignments_and_expressions() {
        let assign = |t: &str, v: &str| Command::Assign { target: t.into(), value: v.into() };
        assert_eq!(parse("mov rax, 5"), assign("rax", "5"));
        assert_eq!(parse("rax=5"), assign("rax", "5"));
        assert_eq!(parse("[rsp+8] = main"), assign("[rsp+8]", "main"));
        assert_eq!(parse("mov [rsp, 1"), Command::Gdb("mov [rsp, 1".into()));
        assert_eq!(parse("rax==5"), Command::Evaluate("rax==5".into()));
        assert_eq!(parse("rax"), Command::Evaluate("rax".into()));
        assert_eq!(parse("main+10"), Command::Evaluate("main+10".into()));
    }

    #[test]
    fn gdb_passthrough() {
        for line in ["info registers", "bt", "c", "x/4x $sp", "set pagination off", "set var counter = 3", "p counter"] {
            assert_eq!(parse(line), Command::Gdb(line.into()), "{line}");
        }
    }

    #[test]
    fn log_commands() {
        assert_eq!(parse("cls"), Command::ClearLog);
        assert_eq!(parse(r#"log "hello world""#), Command::Log("hello world".into()));
    }

    #[test]
    fn argument_splitting() {
        assert_eq!(split_args(r#"[rsp, 1], "a, b", c"#), ["[rsp, 1]", "a, b", "c"]);
        assert_eq!(split_assignment("rax = 1"), Some(("rax ", " 1")));
        assert_eq!(split_assignment("rax == 1"), None);
        assert_eq!(split_assignment("rax >= 1"), None);
    }
}

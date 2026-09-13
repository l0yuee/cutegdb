//! Breakpoints as gdb reports them in MI `bkpt` tuples.

use crate::util::parse_hex;
use cutegdb_mi::{Tuple, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchAccess {
    Write,
    Read,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointKind {
    /// `int3` code breakpoint.
    Software,
    /// Debug-register execution breakpoint.
    Hardware,
    Watchpoint(WatchAccess),
    /// gdb dprintf: prints `log_text` and continues.
    Log,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breakpoint {
    pub number: u32,
    pub kind: BreakpointKind,
    pub enabled: bool,
    /// Deleted by gdb when hit (entry breakpoint, run-to-address).
    pub temporary: bool,
    pub address: Option<u64>,
    /// Watched expression for watchpoints, otherwise the location as written.
    pub location: String,
    pub condition: Option<String>,
    pub hits: u64,
    pub ignore_count: u64,
    pub log_text: Option<String>,
}

impl Breakpoint {
    /// Software or hardware code breakpoint, i.e. one shown in the disassembly.
    pub fn is_code(&self) -> bool {
        matches!(self.kind, BreakpointKind::Software | BreakpointKind::Hardware)
    }
}

pub fn parse_breakpoint(bkpt: &Value) -> Option<Breakpoint> {
    // Locations of multi-location breakpoints are numbered "1.1" and are skipped.
    let number = bkpt.get_str("number")?.parse().ok()?;
    let kind = match bkpt.get_str("type").unwrap_or_default() {
        "breakpoint" => BreakpointKind::Software,
        "hw breakpoint" => BreakpointKind::Hardware,
        "dprintf" => BreakpointKind::Log,
        "watchpoint" | "hw watchpoint" => BreakpointKind::Watchpoint(WatchAccess::Write),
        "read watchpoint" => BreakpointKind::Watchpoint(WatchAccess::Read),
        "acc watchpoint" => BreakpointKind::Watchpoint(WatchAccess::ReadWrite),
        other => BreakpointKind::Other(other.to_owned()),
    };
    let count = |key: &str| bkpt.get_str(key).and_then(|v| v.parse().ok()).unwrap_or(0);
    Some(Breakpoint {
        number,
        kind,
        enabled: bkpt.get_str("enabled") != Some("n"),
        temporary: bkpt.get_str("disp") == Some("del"),
        address: bkpt.get_str("addr").and_then(parse_hex),
        location: bkpt
            .get_str("what")
            .or_else(|| bkpt.get_str("original-location"))
            .or_else(|| bkpt.get_str("exp"))
            .unwrap_or_default()
            .to_owned(),
        condition: bkpt.get_str("cond").map(str::to_owned),
        hits: count("times"),
        ignore_count: count("ignore"),
        log_text: bkpt.get("script").and_then(|s| s.items().next()).and_then(Value::as_str).map(str::to_owned),
    })
}

/// Breakpoints from a `-break-list` result.
pub fn parse_breakpoint_table(results: &Tuple) -> Vec<Breakpoint> {
    results
        .get("BreakpointTable")
        .and_then(|table| table.get("body"))
        .into_iter()
        .flat_map(|body| body.items())
        .filter_map(parse_breakpoint)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cutegdb_mi::{Record, parse_line};

    fn results(line: &str) -> Tuple {
        match parse_line(line).unwrap() {
            Record::Result { results, .. } | Record::Async { results, .. } => results,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_breakpoint_kinds() {
        let bp = |line: &str| parse_breakpoint(results(line).get("bkpt").unwrap()).unwrap();

        let soft = bp(r#"^done,bkpt={number="2",type="breakpoint",disp="keep",enabled="y",addr="0x0000555555555149",func="add",thread-groups=["i1"],cond="$rdi == 2",times="3",ignore="1",original-location="*add"}"#);
        assert_eq!(soft.kind, BreakpointKind::Software);
        assert_eq!((soft.number, soft.address, soft.hits, soft.ignore_count), (2, Some(0x555555555149), 3, 1));
        assert_eq!((soft.condition.as_deref(), soft.location.as_str()), (Some("$rdi == 2"), "*add"));
        assert!(soft.enabled && !soft.temporary && soft.is_code());

        let hw = bp(r#"^done,bkpt={number="3",type="hw breakpoint",disp="del",enabled="n",addr="0x1000",times="0"}"#);
        assert_eq!((hw.kind, hw.enabled, hw.temporary), (BreakpointKind::Hardware, false, true));

        let log = bp(r#"=breakpoint-modified,bkpt={number="4",type="dprintf",disp="keep",enabled="y",addr="0x2000",times="1",script={"printf \"a=%d\\n\",$rdi"},original-location="*add"}"#);
        assert_eq!(log.kind, BreakpointKind::Log);
        assert_eq!(log.log_text.as_deref(), Some(r#"printf "a=%d\n",$rdi"#));
        assert!(!log.is_code());

        let pending = bp(r#"=breakpoint-created,bkpt={number="5",type="breakpoint",disp="keep",enabled="y",addr="<PENDING>",times="0"}"#);
        assert_eq!(pending.address, None);
    }

    #[test]
    fn parses_breakpoint_table_with_watchpoints() {
        let table = parse_breakpoint_table(&results(
            r#"^done,BreakpointTable={nr_rows="4",nr_cols="6",hdr=[{width="7",alignment="-1",col_name="number",colhdr="Num"}],body=[bkpt={number="1",type="breakpoint",disp="keep",enabled="y",addr="0x000055555555516c",func="main",times="1",original-location="main"},bkpt={number="3",type="hw watchpoint",disp="keep",enabled="y",what="counter",times="2",original-location="counter"},bkpt={number="6",type="read watchpoint",disp="keep",enabled="y",what="*(int*)0x4010",times="0"},bkpt={number="7",type="acc watchpoint",disp="keep",enabled="y",what="x",times="0"}]}"#,
        ));
        assert_eq!(table.iter().map(|b| b.number).collect::<Vec<_>>(), [1, 3, 6, 7]);
        assert_eq!(table[1].kind, BreakpointKind::Watchpoint(WatchAccess::Write));
        assert_eq!((table[1].location.as_str(), table[1].hits, table[1].address), ("counter", 2, None));
        assert_eq!(table[2].kind, BreakpointKind::Watchpoint(WatchAccess::Read));
        assert_eq!(table[3].kind, BreakpointKind::Watchpoint(WatchAccess::ReadWrite));
    }
}

//! Parser for GDB/MI output lines.
//!
//! Grammar (from the GDB manual, "GDB/MI Output Syntax"):
//! ```text
//! result-record  → [token] "^" result-class ("," result)*
//! async-record   → [token] ("*" | "+" | "=") async-class ("," result)*
//! stream-record  → ("~" | "@" | "&") c-string
//! result         → variable "=" value
//! value          → c-string | tuple | list
//! tuple          → "{}" | "{" result ("," result)* "}"
//! list           → "[]" | "[" value ("," value)* "]" | "[" result ("," result)* "]"
//! ```

/// An ordered key/value collection. MI allows duplicate keys (e.g. `stack=[frame={..},frame={..}]`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Tuple(pub Vec<(String, Value)>);

impl Tuple {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Value::as_str)
    }

    pub fn get_all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
        self.0.iter().filter(move |(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn iter(&self) -> impl Iterator<Item = &(String, Value)> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Const(String),
    Tuple(Tuple),
    List(Vec<Value>),
    /// A list whose elements are `name=value` results.
    ResultList(Tuple),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Const(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_tuple(&self) -> Option<&Tuple> {
        match self {
            Value::Tuple(t) | Value::ResultList(t) => Some(t),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_tuple()?.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Value::as_str)
    }

    /// Iterates list elements; for result lists the keys are dropped.
    pub fn items(&self) -> Box<dyn Iterator<Item = &Value> + '_> {
        match self {
            Value::List(v) => Box::new(v.iter()),
            Value::ResultList(t) => Box::new(t.0.iter().map(|(_, v)| v)),
            _ => Box::new(std::iter::empty()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultClass {
    Done,
    Running,
    Connected,
    Error,
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncKind {
    /// `*` — execution state changes (running, stopped).
    Exec,
    /// `+` — progress of slow operations.
    Status,
    /// `=` — supplementary notifications (breakpoint-modified, library-loaded, ...).
    Notify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Console,
    Target,
    Log,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    Result { token: Option<u64>, class: ResultClass, results: Tuple },
    Async { token: Option<u64>, kind: AsyncKind, class: String, results: Tuple },
    Stream { kind: StreamKind, text: String },
    Prompt,
    /// A line that is not MI output (typically inferior output sharing gdb's stdout).
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("MI parse error at byte {pos}: {msg}")]
pub struct ParseError {
    pub pos: usize,
    pub msg: &'static str,
}

pub fn parse_line(line: &str) -> Result<Record, ParseError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.trim_end() == "(gdb)" {
        return Ok(Record::Prompt);
    }
    let bytes = line.as_bytes();
    let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    let Some(&sigil) = bytes.get(digits) else {
        return Ok(Record::Other(line.to_owned()));
    };
    let token = if digits > 0 { line[..digits].parse().ok() } else { None };
    let mut c = Cursor { s: bytes, i: digits + 1 };
    match sigil {
        b'^' => {
            let class = match c.word()? {
                "done" => ResultClass::Done,
                "running" => ResultClass::Running,
                "connected" => ResultClass::Connected,
                "error" => ResultClass::Error,
                "exit" => ResultClass::Exit,
                _ => return Err(c.err("unknown result class")),
            };
            let results = c.results_tail()?;
            c.end()?;
            Ok(Record::Result { token, class, results })
        }
        b'*' | b'+' | b'=' => {
            let kind = match sigil {
                b'*' => AsyncKind::Exec,
                b'+' => AsyncKind::Status,
                _ => AsyncKind::Notify,
            };
            let class = c.word()?.to_owned();
            let results = c.results_tail()?;
            c.end()?;
            Ok(Record::Async { token, kind, class, results })
        }
        b'~' | b'@' | b'&' if digits == 0 => {
            let kind = match sigil {
                b'~' => StreamKind::Console,
                b'@' => StreamKind::Target,
                _ => StreamKind::Log,
            };
            let text = c.cstring()?;
            c.end()?;
            Ok(Record::Stream { kind, text })
        }
        _ => Ok(Record::Other(line.to_owned())),
    }
}

/// Token and class of a result record whose body could not be parsed, so the command waiting for
/// it can still be completed.
pub fn parse_result_prefix(line: &str) -> Option<(Option<u64>, ResultClass)> {
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    let rest = line[digits..].strip_prefix('^')?;
    let class = match rest.split(',').next()? {
        "done" => ResultClass::Done,
        "running" => ResultClass::Running,
        "connected" => ResultClass::Connected,
        "error" => ResultClass::Error,
        "exit" => ResultClass::Exit,
        _ => return None,
    };
    Some(((digits > 0).then(|| line[..digits].parse().ok()).flatten(), class))
}

struct Cursor<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn err(&self, msg: &'static str) -> ParseError {
        ParseError { pos: self.i, msg }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.i += 1;
        Some(b)
    }

    fn expect(&mut self, b: u8, msg: &'static str) -> Result<(), ParseError> {
        if self.peek() == Some(b) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.err(msg))
        }
    }

    fn end(&self) -> Result<(), ParseError> {
        if self.i == self.s.len() { Ok(()) } else { Err(self.err("trailing characters")) }
    }

    fn take_until(&mut self, stop: &[u8]) -> &'a str {
        let start = self.i;
        while let Some(b) = self.peek() {
            if stop.contains(&b) {
                break;
            }
            self.i += 1;
        }
        // Stops only at ASCII bytes, so the slice boundaries are valid UTF-8 boundaries.
        std::str::from_utf8(&self.s[start..self.i]).unwrap_or("")
    }

    fn word(&mut self) -> Result<&'a str, ParseError> {
        let w = self.take_until(b",");
        if w.is_empty() { Err(self.err("expected class name")) } else { Ok(w) }
    }

    fn results_tail(&mut self) -> Result<Tuple, ParseError> {
        let mut out = Vec::new();
        while self.peek() == Some(b',') {
            self.i += 1;
            out.push(self.result()?);
        }
        Ok(Tuple(out))
    }

    fn result(&mut self) -> Result<(String, Value), ParseError> {
        let name = self.take_until(b"={}[],\"");
        if name.is_empty() {
            return Err(self.err("expected variable name"));
        }
        let name = name.to_owned();
        self.expect(b'=', "expected '='")?;
        Ok((name, self.value()?))
    }

    fn value(&mut self) -> Result<Value, ParseError> {
        match self.peek() {
            Some(b'"') => Ok(Value::Const(self.cstring()?)),
            Some(b'{') => {
                self.i += 1;
                let mut items = Vec::new();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Value::Tuple(Tuple(items)));
                }
                // gdb emits `script={"cmd1","cmd2"}`: braces holding bare values instead of results.
                if matches!(self.peek(), Some(b'"' | b'{' | b'[')) {
                    let mut values = Vec::new();
                    loop {
                        values.push(self.value()?);
                        match self.next() {
                            Some(b',') => {}
                            Some(b'}') => return Ok(Value::List(values)),
                            _ => return Err(self.err("expected ',' or '}'")),
                        }
                    }
                }
                loop {
                    items.push(self.result()?);
                    match self.next() {
                        Some(b',') => {}
                        Some(b'}') => return Ok(Value::Tuple(Tuple(items))),
                        _ => return Err(self.err("expected ',' or '}'")),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Value::List(Vec::new()));
                }
                if matches!(self.peek(), Some(b'"' | b'{' | b'[')) {
                    let mut items = Vec::new();
                    loop {
                        items.push(self.value()?);
                        match self.next() {
                            Some(b',') => {}
                            Some(b']') => return Ok(Value::List(items)),
                            _ => return Err(self.err("expected ',' or ']'")),
                        }
                    }
                } else {
                    let mut items = Vec::new();
                    loop {
                        items.push(self.result()?);
                        match self.next() {
                            Some(b',') => {}
                            Some(b']') => return Ok(Value::ResultList(Tuple(items))),
                            _ => return Err(self.err("expected ',' or ']'")),
                        }
                    }
                }
            }
            _ => Err(self.err("expected value")),
        }
    }

    fn cstring(&mut self) -> Result<String, ParseError> {
        self.expect(b'"', "expected '\"'")?;
        let mut out = Vec::new();
        loop {
            match self.next() {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => break,
                Some(b'\\') => {
                    let b = self.next().ok_or_else(|| self.err("dangling escape"))?;
                    out.push(match b {
                        b'n' => b'\n',
                        b't' => b'\t',
                        b'r' => b'\r',
                        b'a' => 0x07,
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'v' => 0x0b,
                        b'e' => 0x1b,
                        b'0'..=b'7' => {
                            let mut v = (b - b'0') as u32;
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        v = v * 8 + (d - b'0') as u32;
                                        self.i += 1;
                                    }
                                    _ => break,
                                }
                            }
                            v as u8
                        }
                        other => other,
                    });
                }
                Some(b) => out.push(b),
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(line: &str) -> (Option<u64>, ResultClass, Tuple) {
        match parse_line(line).unwrap() {
            Record::Result { token, class, results } => (token, class, results),
            r => panic!("not a result record: {r:?}"),
        }
    }

    #[test]
    fn breakpoint_insert() {
        let (tok, class, r) = result(
            r#"5^done,bkpt={number="1",type="breakpoint",disp="keep",enabled="y",addr="0x0000000000001139",func="main",file="hello.c",fullname="/x/hello.c",line="5",thread-groups=["i1"],times="0",original-location="main"}"#,
        );
        assert_eq!(tok, Some(5));
        assert_eq!(class, ResultClass::Done);
        let bkpt = r.get("bkpt").unwrap();
        assert_eq!(bkpt.get_str("number"), Some("1"));
        assert_eq!(bkpt.get_str("addr"), Some("0x0000000000001139"));
        let groups: Vec<_> = bkpt.get("thread-groups").unwrap().items().filter_map(Value::as_str).collect();
        assert_eq!(groups, ["i1"]);
    }

    #[test]
    fn stopped_event() {
        let rec = parse_line(r#"*stopped,reason="breakpoint-hit",disp="keep",bkptno="1",frame={addr="0x5555",func="main",args=[],file="h.c",line="5",arch="i386:x86-64"},thread-id="1",stopped-threads="all",core="3""#).unwrap();
        let Record::Async { token, kind, class, results } = rec else { panic!() };
        assert_eq!((token, kind, class.as_str()), (None, AsyncKind::Exec, "stopped"));
        assert_eq!(results.get_str("reason"), Some("breakpoint-hit"));
        let frame = results.get("frame").unwrap();
        assert_eq!(frame.get_str("arch"), Some("i386:x86-64"));
        assert_eq!(frame.get("args"), Some(&Value::List(vec![])));
    }

    #[test]
    fn result_list_with_duplicate_keys() {
        let (_, _, r) = result(r#"^done,stack=[frame={level="0",addr="0x1"},frame={level="1",addr="0x2"}]"#);
        let stack = r.get("stack").unwrap();
        assert!(matches!(stack, Value::ResultList(_)));
        let levels: Vec<_> = stack.items().filter_map(|f| f.get_str("level")).collect();
        assert_eq!(levels, ["0", "1"]);
    }

    #[test]
    fn list_of_tuples() {
        let (_, _, r) = result(r#"^done,memory=[{begin="0x1",offset="0x0",end="0x3",contents="9090"}]"#);
        let m: Vec<_> = r.get("memory").unwrap().items().collect();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].get_str("contents"), Some("9090"));
    }

    #[test]
    fn error_with_escaped_quotes() {
        let (tok, class, r) = result(r#"12^error,msg="No symbol \"foo\" in current context.""#);
        assert_eq!((tok, class), (Some(12), ResultClass::Error));
        assert_eq!(r.get_str("msg"), Some(r#"No symbol "foo" in current context."#));
    }

    #[test]
    fn streams_and_escapes() {
        assert_eq!(
            parse_line(r#"~"Breakpoint 1 at 0x1139: file h.c, line 5.\n""#).unwrap(),
            Record::Stream { kind: StreamKind::Console, text: "Breakpoint 1 at 0x1139: file h.c, line 5.\n".into() }
        );
        let Record::Stream { kind, text } = parse_line(r#"&"\033[0m\302\251\t""#).unwrap() else { panic!() };
        assert_eq!(kind, StreamKind::Log);
        assert_eq!(text, "\x1b[0m\u{a9}\t");
    }

    #[test]
    fn misc_records() {
        assert_eq!(parse_line("(gdb) ").unwrap(), Record::Prompt);
        assert_eq!(parse_line("(gdb)\r\n").unwrap(), Record::Prompt);
        assert_eq!(parse_line("hello world").unwrap(), Record::Other("hello world".into()));
        assert_eq!(parse_line("12345").unwrap(), Record::Other("12345".into()));
        let (_, class, r) = result("^done");
        assert_eq!(class, ResultClass::Done);
        assert!(r.is_empty());
        let (_, _, r) = result(r#"^done,a={},b=[],c="""#);
        assert_eq!(r.get("a"), Some(&Value::Tuple(Tuple::default())));
        assert_eq!(r.get_str("c"), Some(""));
        let Record::Async { kind, class, results, .. } = parse_line(r#"=thread-group-added,id="i1""#).unwrap() else { panic!() };
        assert_eq!((kind, class.as_str(), results.get_str("id")), (AsyncKind::Notify, "thread-group-added", Some("i1")));
    }

    #[test]
    fn brace_lists_of_values() {
        let (_, _, r) = result(
            r#"^done,bkpt={number="4",type="dprintf",script={"printf \"add called a=%d\\n\",$rdi"},times="1"}"#,
        );
        let bkpt = r.get("bkpt").unwrap();
        let script: Vec<_> = bkpt.get("script").unwrap().items().filter_map(Value::as_str).collect();
        assert_eq!(script, [r#"printf "add called a=%d\n",$rdi"#]);
        assert_eq!(bkpt.get_str("times"), Some("1"));
    }

    #[test]
    fn result_prefix_of_unparseable_lines() {
        assert_eq!(parse_result_prefix("12^done,x={broken"), Some((Some(12), ResultClass::Done)));
        assert_eq!(parse_result_prefix("^error,msg="), Some((None, ResultClass::Error)));
        assert_eq!(parse_result_prefix("*stopped,reason="), None);
        assert_eq!(parse_result_prefix("12^bogus"), None);
    }

    #[test]
    fn malformed_lines_error() {
        assert!(parse_line(r#"^done,x="unterminated"#).is_err());
        assert!(parse_line(r#"^done,x={a="1""#).is_err());
        assert!(parse_line("^bogus").is_err());
        assert!(parse_line(r#"^done,="1""#).is_err());
    }
}

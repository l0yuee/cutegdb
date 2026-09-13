//! x64dbg script interpreter: one command per line, `label:` definitions, `cmp` with conditional
//! jumps, `call`/`ret` and `pause`. Commands and comparisons are handed to the host to execute.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {}: {message}", line + 1)]
pub struct ScriptError {
    /// 0-based.
    pub line: usize,
    pub message: String,
}

/// What the host has to do before calling `step` again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptStep {
    /// Run a command-bar command (and wait for the debuggee if it resumes it).
    Command { line: usize, text: String },
    /// Evaluate both expressions and report them with `set_comparison`.
    Compare { line: usize, left: String, right: String },
    Paused { line: usize },
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Condition {
    Always,
    Equal,
    NotEqual,
    Above,
    AboveOrEqual,
    Below,
    BelowOrEqual,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Nothing,
    Command(String),
    Compare(String, String),
    Jump(Condition, String),
    Call(String),
    Return,
    Pause,
}

#[derive(Debug, Clone)]
pub struct Script {
    lines: Vec<Line>,
    labels: HashMap<String, usize>,
    next: usize,
    comparison: Option<(u64, u64)>,
    calls: Vec<usize>,
}

impl Script {
    pub fn parse(text: &str) -> Result<Script, ScriptError> {
        let mut lines = Vec::new();
        let mut labels = HashMap::new();
        for (index, raw) in text.lines().enumerate() {
            let code = raw.split_once("//").map_or(raw, |(code, _)| code).trim();
            let error = |message: String| ScriptError { line: index, message };
            if code.is_empty() {
                lines.push(Line::Nothing);
                continue;
            }
            if let Some(name) = code.strip_suffix(':')
                && !name.is_empty()
                && !name.contains(char::is_whitespace)
            {
                if labels.insert(name.to_owned(), index).is_some() {
                    return Err(error(format!("duplicate label \"{name}\"")));
                }
                lines.push(Line::Nothing);
                continue;
            }
            let (word, rest) = match code.split_once(char::is_whitespace) {
                Some((word, rest)) => (word.to_ascii_lowercase(), rest.trim()),
                None => (code.to_ascii_lowercase(), ""),
            };
            let line = if let Some(condition) = jump_condition(&word) {
                if rest.is_empty() {
                    return Err(error(format!("{word} needs a label")));
                }
                Line::Jump(condition, rest.to_owned())
            } else {
                match word.as_str() {
                    "cmp" => match rest.split_once(',') {
                        Some((left, right)) if !left.trim().is_empty() && !right.trim().is_empty() => {
                            Line::Compare(left.trim().to_owned(), right.trim().to_owned())
                        }
                        _ => return Err(error("cmp needs two operands".into())),
                    },
                    "call" if !rest.is_empty() => Line::Call(rest.to_owned()),
                    "ret" if rest.is_empty() => Line::Return,
                    "pause" if rest.is_empty() => Line::Pause,
                    _ => Line::Command(code.to_owned()),
                }
            };
            lines.push(line);
        }
        for (index, line) in lines.iter().enumerate() {
            if let Line::Jump(_, label) | Line::Call(label) = line
                && !labels.contains_key(label)
            {
                return Err(ScriptError { line: index, message: format!("unknown label \"{label}\"") });
            }
        }
        Ok(Script { lines, labels, next: 0, comparison: None, calls: Vec::new() })
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// 0-based line that runs next.
    pub fn next_line(&self) -> usize {
        self.next
    }

    pub fn reset(&mut self) {
        self.next = 0;
        self.comparison = None;
        self.calls.clear();
    }

    /// Result of the last `Compare` step, as evaluated by the host.
    pub fn set_comparison(&mut self, left: u64, right: u64) {
        self.comparison = Some((left, right));
    }

    /// Runs control flow until the host has something to do.
    pub fn step(&mut self) -> Result<ScriptStep, ScriptError> {
        loop {
            let index = self.next;
            let Some(line) = self.lines.get(index).cloned() else { return Ok(ScriptStep::Finished) };
            self.next += 1;
            match line {
                Line::Nothing => {}
                Line::Command(text) => return Ok(ScriptStep::Command { line: index, text }),
                Line::Compare(left, right) => return Ok(ScriptStep::Compare { line: index, left, right }),
                Line::Jump(condition, label) => {
                    if self.taken(condition, index)? {
                        self.next = self.labels[&label];
                    }
                }
                Line::Call(label) => {
                    self.calls.push(self.next);
                    self.next = self.labels[&label];
                }
                Line::Return => match self.calls.pop() {
                    Some(back) => self.next = back,
                    None => {
                        self.next = self.lines.len();
                        return Ok(ScriptStep::Finished);
                    }
                },
                Line::Pause => return Ok(ScriptStep::Paused { line: index }),
            }
        }
    }

    fn taken(&self, condition: Condition, line: usize) -> Result<bool, ScriptError> {
        if condition == Condition::Always {
            return Ok(true);
        }
        let (a, b) = self
            .comparison
            .ok_or_else(|| ScriptError { line, message: "conditional jump without a preceding cmp".into() })?;
        let (sa, sb) = (a as i64, b as i64);
        Ok(match condition {
            Condition::Always => true,
            Condition::Equal => a == b,
            Condition::NotEqual => a != b,
            Condition::Above => a > b,
            Condition::AboveOrEqual => a >= b,
            Condition::Below => a < b,
            Condition::BelowOrEqual => a <= b,
            Condition::Greater => sa > sb,
            Condition::GreaterOrEqual => sa >= sb,
            Condition::Less => sa < sb,
            Condition::LessOrEqual => sa <= sb,
        })
    }
}

/// x64dbg's jump spellings (`je`, `jz`, `ifeq`, `ife`, ...).
fn jump_condition(word: &str) -> Option<Condition> {
    Some(match word {
        "jmp" | "goto" => Condition::Always,
        "je" | "jz" | "ifeq" | "ife" | "ifz" => Condition::Equal,
        "jne" | "jnz" | "ifneq" | "ifne" | "ifnz" => Condition::NotEqual,
        "ja" | "ifa" => Condition::Above,
        "jae" | "ifae" => Condition::AboveOrEqual,
        "jb" | "ifb" => Condition::Below,
        "jbe" | "ifbe" => Condition::BelowOrEqual,
        "jg" | "ifg" | "ifgt" => Condition::Greater,
        "jge" | "ifge" => Condition::GreaterOrEqual,
        "jl" | "ifl" | "iflt" => Condition::Less,
        "jle" | "ifle" => Condition::LessOrEqual,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a script against a single variable `rax`, returning the commands seen and the final value.
    fn run(text: &str, mut rax: u64) -> (Vec<String>, u64, ScriptStep) {
        let mut script = Script::parse(text).unwrap();
        let mut seen = Vec::new();
        for _ in 0..1000 {
            match script.step().unwrap() {
                ScriptStep::Command { text, .. } => {
                    if text == "rax=rax+1" {
                        rax += 1;
                    }
                    seen.push(text);
                }
                ScriptStep::Compare { left, right, .. } => {
                    let value = |s: &str| if s == "rax" { rax } else { u64::from_str_radix(s, 16).unwrap() };
                    script.set_comparison(value(&left), value(&right));
                }
                other => return (seen, rax, other),
            }
        }
        panic!("script did not finish");
    }

    #[test]
    fn loops_with_labels_and_conditions() {
        let text = "// count up to 3\nstart:\n  cmp rax, 3\n  je done\n  rax=rax+1\n  jmp start\ndone:\n  log \"finished\"\n  ret\n  log \"never\"";
        let (seen, rax, end) = run(text, 0);
        assert_eq!(rax, 3);
        assert_eq!(seen.iter().filter(|c| *c == "rax=rax+1").count(), 3);
        assert_eq!(seen.last().map(String::as_str), Some("log \"finished\""));
        assert_eq!(end, ScriptStep::Finished);
    }

    #[test]
    fn signed_and_unsigned_comparisons() {
        // rax = -1: above 3 when unsigned, less than 3 when signed.
        let (seen, _, _) = run("cmp rax, 3\nja big\nlog small\nret\nbig:\nlog big\ncmp rax, 3\njl negative\nret\nnegative:\nlog negative", u64::MAX);
        assert_eq!(seen, ["log big", "log negative"]);
    }

    #[test]
    fn call_return_and_pause() {
        let mut script = Script::parse("call helper\nlog after\npause\nlog resumed\nret\nhelper:\nlog in helper\nret").unwrap();
        assert_eq!(script.step().unwrap(), ScriptStep::Command { line: 6, text: "log in helper".into() });
        assert_eq!(script.step().unwrap(), ScriptStep::Command { line: 1, text: "log after".into() });
        assert_eq!(script.step().unwrap(), ScriptStep::Paused { line: 2 });
        assert_eq!(script.next_line(), 3);
        assert_eq!(script.step().unwrap(), ScriptStep::Command { line: 3, text: "log resumed".into() });
        assert_eq!(script.step().unwrap(), ScriptStep::Finished);
        assert_eq!(script.step().unwrap(), ScriptStep::Finished);
        script.reset();
        assert_eq!(script.next_line(), 0);
    }

    #[test]
    fn parse_and_runtime_errors() {
        assert_eq!(Script::parse("jmp nowhere").unwrap_err(), ScriptError { line: 0, message: "unknown label \"nowhere\"".into() });
        assert_eq!(Script::parse("a:\n\na:").unwrap_err().line, 2);
        assert!(Script::parse("cmp rax").is_err());
        assert!(Script::parse("je").is_err());
        let mut script = Script::parse("x:\nje x").unwrap();
        let error = script.step().unwrap_err();
        assert_eq!((error.line, error.to_string()), (1, "line 2: conditional jump without a preceding cmp".to_owned()));
        assert_eq!(Script::parse("").unwrap().line_count(), 0);
    }
}

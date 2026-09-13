//! x64dbg expressions (hex numbers by default, `[ptr]` dereferences, `module.symbol` labels)
//! translated into gdb expressions.

use cutegdb_core::Arch;

pub trait Resolver {
    fn arch(&self) -> Arch;
    /// Resolves `module.symbol`, `module.EntryPoint` or a bare symbol name to an address.
    fn symbol(&self, name: &str) -> Option<u64>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExprError {
    #[error("empty expression")]
    Empty,
    #[error("unexpected character '{0}'")]
    BadChar(char),
    #[error("invalid number \"{0}\"")]
    BadNumber(String),
    #[error("unknown identifier \"{0}\"")]
    Unknown(String),
    #[error("unbalanced brackets")]
    Unbalanced,
    #[error("unknown size \"{0}\"")]
    BadSize(String),
    #[error("malformed expression")]
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Op(&'static str),
    Open,
    Close,
    BracketOpen,
    BracketClose,
    Colon,
}

/// Longest operators first so `<<` wins over `<`.
const OPERATORS: [&str; 20] =
    ["<<", ">>", "==", "!=", "<=", ">=", "&&", "||", "+", "-", "*", "/", "%", "&", "|", "^", "~", "!", "<", ">"];
const UNARY: [&str; 4] = ["-", "+", "~", "!"];

fn tokenize(text: &str) -> Result<Vec<Token>, ExprError> {
    let is_word = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$' | '@');
    let mut tokens = Vec::new();
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if c.is_whitespace() {
            rest = &rest[c.len_utf8()..];
            continue;
        }
        if is_word(c) {
            let end = rest.find(|ch: char| !is_word(ch)).unwrap_or(rest.len());
            tokens.push(Token::Word(rest[..end].to_owned()));
            rest = &rest[end..];
            continue;
        }
        let (token, len) = match c {
            '(' => (Token::Open, 1),
            ')' => (Token::Close, 1),
            '[' => (Token::BracketOpen, 1),
            ']' => (Token::BracketClose, 1),
            ':' => (Token::Colon, 1),
            _ => match OPERATORS.iter().find(|op| rest.starts_with(**op)) {
                Some(op) => (Token::Op(op), op.len()),
                None => return Err(ExprError::BadChar(c)),
            },
        };
        tokens.push(token);
        rest = &rest[len..];
    }
    Ok(tokens)
}

/// Translates an x64dbg expression into an equivalent gdb expression.
pub fn translate_expression(text: &str, resolver: &impl Resolver) -> Result<String, ExprError> {
    let tokens = tokenize(text)?;
    if tokens.is_empty() {
        return Err(ExprError::Empty);
    }
    let arch = resolver.arch();
    let mut out = String::new();
    let mut expect_operand = true;
    let mut open: Vec<Token> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            Token::Word(word) => {
                if !expect_operand {
                    return Err(ExprError::Malformed);
                }
                if tokens.get(i + 1) == Some(&Token::Colon) {
                    if tokens.get(i + 2) != Some(&Token::BracketOpen) {
                        return Err(ExprError::Malformed);
                    }
                    out.push_str(&format!("*({}*)(", size_type(word, arch)?));
                    open.push(Token::BracketOpen);
                    i += 3;
                    continue;
                }
                out.push_str(&translate_word(word, resolver)?);
                expect_operand = false;
            }
            Token::Op(op) => {
                if expect_operand {
                    if !UNARY.contains(op) {
                        return Err(ExprError::Malformed);
                    }
                    out.push_str(op);
                } else {
                    out.push_str(&format!(" {op} "));
                    expect_operand = true;
                }
            }
            Token::Open => {
                if !expect_operand {
                    return Err(ExprError::Malformed);
                }
                out.push('(');
                open.push(Token::Open);
            }
            Token::BracketOpen => {
                if !expect_operand {
                    return Err(ExprError::Malformed);
                }
                out.push_str(&format!("*({}*)(", pointer_type(arch)));
                open.push(Token::BracketOpen);
            }
            closing @ (Token::Close | Token::BracketClose) => {
                let matching = if *closing == Token::Close { Token::Open } else { Token::BracketOpen };
                if open.pop() != Some(matching) {
                    return Err(ExprError::Unbalanced);
                }
                if expect_operand {
                    return Err(ExprError::Malformed);
                }
                out.push(')');
            }
            Token::Colon => return Err(ExprError::Malformed),
        }
        i += 1;
    }
    if !open.is_empty() {
        return Err(ExprError::Unbalanced);
    }
    if expect_operand {
        return Err(ExprError::Malformed);
    }
    Ok(out)
}

/// Translates `target = value`; `target` must be a register or a memory dereference.
pub fn translate_assignment(target: &str, value: &str, resolver: &impl Resolver) -> Result<String, ExprError> {
    let target = target.trim();
    if register(resolver.arch(), target).is_none() && !target.ends_with(']') {
        return Err(ExprError::Malformed);
    }
    Ok(format!("{} = {}", translate_expression(target, resolver)?, translate_expression(value, resolver)?))
}

/// Whether command-bar input should be evaluated as an expression rather than sent to gdb.
///
/// A lone word made only of the letters a–f (`c`, `b`, `dead`) is a valid x64dbg hex number but far
/// more likely a gdb command, so it only counts when it names a register or symbol.
pub fn looks_like_expression(text: &str, resolver: &impl Resolver) -> bool {
    if translate_expression(text, resolver).is_err() {
        return false;
    }
    match tokenize(text).as_deref() {
        Ok([Token::Word(word)]) => {
            register(resolver.arch(), word).is_some()
                || resolver.symbol(word).is_some()
                || word.chars().any(|c| c.is_ascii_digit())
                || word.starts_with('$')
        }
        _ => true,
    }
}

fn translate_word(word: &str, resolver: &impl Resolver) -> Result<String, ExprError> {
    if let Some(reg) = register(resolver.arch(), word) {
        return Ok(format!("${reg}"));
    }
    if let Some(decimal) = word.strip_prefix('.') {
        return match decimal.parse::<u64>() {
            Ok(v) => Ok(v.to_string()),
            Err(_) => Err(ExprError::BadNumber(word.to_owned())),
        };
    }
    if let Some(hex) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")) {
        return match u64::from_str_radix(hex, 16) {
            Ok(_) => Ok(format!("0x{}", hex.to_ascii_lowercase())),
            Err(_) => Err(ExprError::BadNumber(word.to_owned())),
        };
    }
    if word.starts_with('$') {
        return Ok(word.to_owned());
    }
    if let Some(address) = resolver.symbol(word) {
        return Ok(format!("0x{address:x}"));
    }
    if word.chars().all(|c| c.is_ascii_hexdigit()) {
        return match u64::from_str_radix(word, 16) {
            Ok(_) => Ok(format!("0x{}", word.to_ascii_lowercase())),
            Err(_) => Err(ExprError::BadNumber(word.to_owned())),
        };
    }
    if word.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(ExprError::BadNumber(word.to_owned()));
    }
    Err(ExprError::Unknown(word.to_owned()))
}

fn pointer_type(arch: Arch) -> &'static str {
    if arch.pointer_size() == 4 { "unsigned int" } else { "unsigned long long" }
}

fn size_type(size: &str, arch: Arch) -> Result<&'static str, ExprError> {
    Ok(match size.to_ascii_lowercase().as_str() {
        "byte" => "unsigned char",
        "word" => "unsigned short",
        "dword" => "unsigned int",
        "qword" => "unsigned long long",
        "ptr" => pointer_type(arch),
        _ => return Err(ExprError::BadSize(size.to_owned())),
    })
}

/// Maps an x64dbg register name to gdb's name for it on `arch`.
fn register(arch: Arch, name: &str) -> Option<String> {
    const X86_COMMON: [&str; 31] = [
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "ax", "bx", "cx", "dx", "si", "di", "bp",
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "eflags", "cs", "ds", "es", "fs", "gs", "ss",
    ];
    const X86_64_ONLY: [&str; 13] =
        ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "sil", "dil", "bpl", "spl"];

    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "cip" => return Some("pc".into()),
        "csp" => return Some("sp".into()),
        _ => {}
    }
    match arch {
        Arch::X86_64 | Arch::X86 => {
            let wide = arch == Arch::X86_64;
            let generic = |r64: &str, r32: &str| Some(if wide { r64 } else { r32 }.to_owned());
            match lower.as_str() {
                "cax" => return generic("rax", "eax"),
                "cbx" => return generic("rbx", "ebx"),
                "ccx" => return generic("rcx", "ecx"),
                "cdx" => return generic("rdx", "edx"),
                "csi" => return generic("rsi", "esi"),
                "cdi" => return generic("rdi", "edi"),
                "cbp" => return generic("rbp", "ebp"),
                "cflags" | "rflags" | "flags" => return Some("eflags".into()),
                _ => {}
            }
            if X86_COMMON.contains(&lower.as_str()) || (wide && X86_64_ONLY.contains(&lower.as_str())) {
                return Some(lower);
            }
            if wide {
                // r8..r15 with d/w/b suffixes; gdb calls the byte form r8l.
                let digits = lower.strip_prefix('r')?;
                let split = digits.find(|c: char| !c.is_ascii_digit()).unwrap_or(digits.len());
                let n: u32 = digits[..split].parse().ok()?;
                if !(8..=15).contains(&n) {
                    return None;
                }
                return match &digits[split..] {
                    "" | "d" | "w" => Some(lower),
                    "b" => Some(format!("r{n}l")),
                    _ => None,
                };
            }
            None
        }
        Arch::AArch64 => match lower.as_str() {
            "sp" | "pc" | "cpsr" => Some(lower),
            "fp" => Some("x29".into()),
            "lr" => Some("x30".into()),
            _ => {
                let n: u32 = lower.strip_prefix(['x', 'w'])?.parse().ok()?;
                (n <= 30).then_some(lower)
            }
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub struct Fake(pub Arch);

    impl Resolver for Fake {
        fn arch(&self) -> Arch {
            self.0
        }

        fn symbol(&self, name: &str) -> Option<u64> {
            match name {
                "main" | "hello.main" => Some(0x401000),
                "add" => Some(0x401100),
                "hello.EntryPoint" => Some(0x400f00),
                _ => None,
            }
        }
    }

    fn tr(arch: Arch, text: &str) -> Result<String, ExprError> {
        translate_expression(text, &Fake(arch))
    }

    fn ok(text: &str) -> String {
        tr(Arch::X86_64, text).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn numbers_registers_and_operators() {
        assert_eq!(ok("rax"), "$rax");
        assert_eq!(ok("RAX"), "$rax");
        assert_eq!(ok("cip"), "$pc");
        assert_eq!(ok("csp"), "$sp");
        assert_eq!(ok("eax+1"), "$eax + 0x1");
        assert_eq!(ok("401000"), "0x401000");
        assert_eq!(ok("0X1F"), "0x1f");
        assert_eq!(ok(".100"), "100");
        assert_eq!(ok("0x10*2"), "0x10 * 0x2");
        assert_eq!(ok("-1"), "-0x1");
        assert_eq!(ok("~rax & ff"), "~$rax & 0xff");
        assert_eq!(ok("(rax+1)<<2"), "($rax + 0x1) << 0x2");
        assert_eq!(ok("r8b + r15d"), "$r8l + $r15d");
        assert_eq!(ok("$_exitcode"), "$_exitcode");
    }

    #[test]
    fn dereferences_and_symbols() {
        assert_eq!(ok("[rsp]"), "*(unsigned long long*)($rsp)");
        assert_eq!(tr(Arch::X86, "[esp+4]").unwrap(), "*(unsigned int*)($esp + 0x4)");
        assert_eq!(ok("byte:[rip+2]"), "*(unsigned char*)($rip + 0x2)");
        assert_eq!(ok("dword:[[rsp]]"), "*(unsigned int*)(*(unsigned long long*)($rsp))");
        assert_eq!(ok("main+10"), "0x401000 + 0x10");
        assert_eq!(ok("hello.main"), "0x401000");
        assert_eq!(ok("hello.EntryPoint"), "0x400f00");
        // A symbol wins over the identical hex number.
        assert_eq!(ok("add"), "0x401100");
        assert_eq!(ok("dead"), "0xdead");
    }

    #[test]
    fn architecture_specific_registers() {
        assert_eq!(tr(Arch::X86, "cax").unwrap(), "$eax");
        assert_eq!(tr(Arch::X86, "r8"), Err(ExprError::Unknown("r8".into())));
        assert_eq!(tr(Arch::X86, "rax"), Err(ExprError::Unknown("rax".into())));
        assert_eq!(tr(Arch::AArch64, "x0+w1").unwrap(), "$x0 + $w1");
        assert_eq!(tr(Arch::AArch64, "lr").unwrap(), "$x30");
        assert_eq!(tr(Arch::AArch64, "[sp]").unwrap(), "*(unsigned long long*)($sp)");
        assert_eq!(tr(Arch::AArch64, "x31"), Err(ExprError::Unknown("x31".into())));
    }

    #[test]
    fn errors() {
        assert_eq!(tr(Arch::X86_64, ""), Err(ExprError::Empty));
        assert_eq!(tr(Arch::X86_64, "rax rbx"), Err(ExprError::Malformed));
        assert_eq!(tr(Arch::X86_64, "rax +"), Err(ExprError::Malformed));
        assert_eq!(tr(Arch::X86_64, "* rax"), Err(ExprError::Malformed));
        assert_eq!(tr(Arch::X86_64, "[rax"), Err(ExprError::Unbalanced));
        assert_eq!(tr(Arch::X86_64, "rax)"), Err(ExprError::Unbalanced));
        assert_eq!(tr(Arch::X86_64, "(rax]"), Err(ExprError::Unbalanced));
        assert_eq!(tr(Arch::X86_64, "[]"), Err(ExprError::Malformed));
        assert_eq!(tr(Arch::X86_64, "foo"), Err(ExprError::Unknown("foo".into())));
        assert_eq!(tr(Arch::X86_64, "4x"), Err(ExprError::BadNumber("4x".into())));
        assert_eq!(tr(Arch::X86_64, ".1a"), Err(ExprError::BadNumber(".1a".into())));
        assert_eq!(tr(Arch::X86_64, "zmm:[rax]"), Err(ExprError::BadSize("zmm".into())));
        assert_eq!(tr(Arch::X86_64, "1#2"), Err(ExprError::BadChar('#')));
    }

    #[test]
    fn assignments() {
        let f = Fake(Arch::X86_64);
        assert_eq!(translate_assignment("rax", "5", &f).unwrap(), "$rax = 0x5");
        assert_eq!(translate_assignment("[rsp+8]", "main", &f).unwrap(), "*(unsigned long long*)($rsp + 0x8) = 0x401000");
        assert_eq!(translate_assignment("main", "1", &f), Err(ExprError::Malformed));
    }

    #[test]
    fn expression_detection_for_the_command_bar() {
        let f = Fake(Arch::X86_64);
        for expr in ["rax", "add", "1234", "0x10", "rax+1", "[rsp]", "dead+1", "$pc"] {
            assert!(looks_like_expression(expr, &f), "{expr} should be an expression");
        }
        for cmd in ["c", "b", "dead", "bt", "info registers", "x/4x $sp", "p counter", "next"] {
            assert!(!looks_like_expression(cmd, &f), "{cmd} should go to gdb");
        }
    }
}

//! x64dbg log text (`value={rax}`, `{d:rcx}`) translated to a printf format plus gdb arguments.

use crate::expr::{ExprError, Resolver, translate_expression};

/// Converts `{expression}` placeholders to printf conversions. The optional prefix selects the
/// format: `d` signed decimal, `u` unsigned decimal, `p` pointer, `s` string, `x` hex (default).
pub fn translate_log_text(text: &str, resolver: &impl Resolver) -> Result<(String, Vec<String>), ExprError> {
    let mut format = String::new();
    let mut args = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        let literal = &rest[..open];
        if literal.contains('}') {
            return Err(ExprError::Unbalanced);
        }
        format.push_str(&literal.replace('%', "%%"));
        let close = rest[open..].find('}').ok_or(ExprError::Unbalanced)? + open;
        let inner = &rest[open + 1..close];
        let (spec, expression) = match inner.split_once(':') {
            Some((spec, expression)) if matches!(spec, "d" | "u" | "x" | "p" | "s") => (spec, expression),
            _ => ("x", inner),
        };
        let gdb = translate_expression(expression, resolver)?;
        let (conversion, cast) = match spec {
            "d" => ("%lld", "long long"),
            "u" => ("%llu", "unsigned long long"),
            "p" => ("%p", "void *"),
            "s" => ("%s", "char *"),
            _ => ("%llx", "unsigned long long"),
        };
        format.push_str(conversion);
        args.push(format!("({cast})({gdb})"));
        rest = &rest[close + 1..];
    }
    if rest.contains('}') {
        return Err(ExprError::Unbalanced);
    }
    format.push_str(&rest.replace('%', "%%"));
    Ok((format, args))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::tests::Fake;
    use cutegdb_core::Arch;

    fn tr(text: &str) -> Result<(String, Vec<String>), ExprError> {
        translate_log_text(text, &Fake(Arch::X86_64))
    }

    #[test]
    fn placeholders_become_printf_arguments() {
        assert_eq!(tr("hello").unwrap(), ("hello".to_owned(), vec![]));
        assert_eq!(tr("rax={rax} 100%").unwrap(), ("rax=%llx 100%%".to_owned(), vec!["(unsigned long long)($rax)".to_owned()]));
        let (format, args) = tr("a={d:rdi} s={s:rsi} m={byte:[rsp]} p={p:main}").unwrap();
        assert_eq!(format, "a=%lld s=%s m=%llx p=%p");
        assert_eq!(
            args,
            [
                "(long long)($rdi)",
                "(char *)($rsi)",
                "(unsigned long long)(*(unsigned char*)($rsp))",
                "(void *)(0x401000)"
            ]
        );
    }

    #[test]
    fn malformed_text() {
        assert_eq!(tr("{rax"), Err(ExprError::Unbalanced));
        assert_eq!(tr("rax}"), Err(ExprError::Unbalanced));
        assert_eq!(tr("} {rax}"), Err(ExprError::Unbalanced));
        assert_eq!(tr("{nope}"), Err(ExprError::Unknown("nope".into())));
    }
}

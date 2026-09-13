//! Operand text in x64dbg's style.

use crate::arch::Arch;

/// Rewrites capstone's Intel-syntax operands the way x64dbg displays them: hex numbers in upper
/// case without `0x`, no spaces after commas or around `+`/`-`, explicit `ds:`/`ss:` segments on
/// memory operands and rip-relative references resolved to absolute addresses.
pub fn format_operands(operands: &str, address: u64, len: usize, arch: Arch) -> String {
    if arch == Arch::AArch64 {
        return operands.to_owned();
    }
    let resolved = resolve_rip_relative(operands, address.wrapping_add(len as u64));
    let segmented = add_default_segments(&resolved);
    let compact = segmented.replace(", ", ",").replace(" + ", "+").replace(" - ", "-");
    format_hex_numbers(&compact)
}

/// `[rip + 0x10]` → `[0x<next + 0x10>]`.
fn resolve_rip_relative(text: &str, next: u64) -> String {
    const PREFIX: &str = "[rip ";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(PREFIX) {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + PREFIX.len()..];
        let resolved = (|| {
            let (negative, tail) = match after.as_bytes().first()? {
                b'+' => (false, after[1..].trim_start()),
                b'-' => (true, after[1..].trim_start()),
                _ => return None,
            };
            let end = tail.find(']')?;
            let number = &tail[..end];
            let displacement = match number.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16).ok()?,
                None => number.parse().ok()?,
            };
            let target = if negative { next.wrapping_sub(displacement) } else { next.wrapping_add(displacement) };
            let consumed = after.len() - tail.len() + end + 1;
            Some((format!("[0x{target:x}]"), consumed))
        })();
        match resolved {
            Some((replacement, consumed)) => {
                out.push_str(&replacement);
                rest = &after[consumed..];
            }
            None => {
                out.push_str(PREFIX);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// `qword ptr [rbp - 8]` → `qword ptr ss:[rbp - 8]`; operands with an explicit segment are kept.
fn add_default_segments(text: &str) -> String {
    const PTR: &str = "ptr [";
    let mut out = String::with_capacity(text.len() + 8);
    let mut rest = text;
    while let Some(pos) = rest.find(PTR) {
        out.push_str(&rest[..pos + "ptr ".len()]);
        let inner = &rest[pos + PTR.len()..];
        let base: String = inner.chars().take_while(char::is_ascii_alphanumeric).collect();
        out.push_str(if matches!(base.as_str(), "rsp" | "rbp" | "esp" | "ebp") { "ss:[" } else { "ds:[" });
        rest = inner;
    }
    out.push_str(rest);
    out
}

/// `0xe2` → `E2`, leaving hex digits inside identifiers alone.
fn format_hex_numbers(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let (mut copied, mut i) = (0, 0);
    while i < bytes.len() {
        let at_boundary = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || matches!(bytes[i - 1], b'_' | b'.'));
        if at_boundary
            && bytes[i] == b'0'
            && bytes.get(i + 1) == Some(&b'x')
            && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            let end = (i + 2..bytes.len()).find(|&j| !bytes[j].is_ascii_hexdigit()).unwrap_or(bytes.len());
            out.push_str(&text[copied..i]);
            out.push_str(&text[i + 2..end].to_ascii_uppercase());
            copied = end;
            i = end;
        } else {
            i += 1;
        }
    }
    out.push_str(&text[copied..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x64dbg_operand_style() {
        let f = |ops: &str| format_operands(ops, 0x1000, 4, Arch::X86_64);
        assert_eq!(f("rbp, rsp"), "rbp,rsp");
        assert_eq!(f("rsp, 0xfffffffffffffff0"), "rsp,FFFFFFFFFFFFFFF0");
        assert_eq!(f("qword ptr [rbp - 8], rax"), "qword ptr ss:[rbp-8],rax");
        assert_eq!(f("eax, dword ptr [rcx*8 + 0x10]"), "eax,dword ptr ds:[rcx*8+10]");
        assert_eq!(f("word ptr cs:[rax + rax]"), "word ptr cs:[rax+rax]");
        assert_eq!(f("hello.add"), "hello.add");
        assert_eq!(f("hello.x0x1"), "hello.x0x1");
        assert_eq!(format_operands("byte ptr [esp + 4], 0x7f", 0, 5, Arch::X86), "byte ptr ss:[esp+4],7F");
        assert_eq!(format_operands("x0, #0x10", 0, 4, Arch::AArch64), "x0, #0x10");
    }

    #[test]
    fn resolves_rip_relative_operands() {
        assert_eq!(format_operands("rdi, [rip + 0xe2]", 0x1074, 7, Arch::X86_64), "rdi,[115D]");
        assert_eq!(format_operands("qword ptr [rip + 0x2f3f]", 0x107b, 6, Arch::X86_64), "qword ptr ds:[3FC0]");
        assert_eq!(format_operands("qword ptr [rip - 0x10]", 0x2000, 4, Arch::X86_64), "qword ptr ds:[1FF4]");
        assert_eq!(format_operands("eax, dword ptr [rip + 8]", 0x2000, 6, Arch::X86_64), "eax,dword ptr ds:[200E]");
        assert_eq!(format_operands("[rip + rax]", 0, 4, Arch::X86_64), "[rip+rax]");
    }
}

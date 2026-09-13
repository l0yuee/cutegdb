//! Small parsing helpers shared by the core modules.

/// Parses gdb's `0x`-prefixed hex numbers.
pub(crate) fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

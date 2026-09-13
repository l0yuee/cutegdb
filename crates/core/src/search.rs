//! Byte pattern and string searches over target memory (x64dbg: Ctrl+B, string references).

/// A byte pattern with nibble wildcards, e.g. `48 8B ?? 05` or `E8????????`, `4?` matching 40–4F.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// (value, mask) per byte; masked-out nibbles match anything.
    bytes: Vec<(u8, u8)>,
}

impl Pattern {
    pub fn parse(text: &str) -> Result<Pattern, String> {
        let nibbles: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
        if nibbles.is_empty() {
            return Err("empty pattern".into());
        }
        if !nibbles.len().is_multiple_of(2) {
            return Err(format!("odd number of nibbles in pattern \"{text}\""));
        }
        let nibble = |c: char| -> Result<(u8, u8), String> {
            match c {
                '?' => Ok((0, 0)),
                c => c.to_digit(16).map(|v| (v as u8, 0xf)).ok_or_else(|| format!("invalid character '{c}' in pattern")),
            }
        };
        let bytes = nibbles
            .chunks(2)
            .map(|pair| {
                let (high, high_mask) = nibble(pair[0])?;
                let (low, low_mask) = nibble(pair[1])?;
                Ok(((high << 4) | low, (high_mask << 4) | low_mask))
            })
            .collect::<Result<_, String>>()?;
        Ok(Pattern { bytes })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn matches_at(&self, haystack: &[u8], offset: usize) -> bool {
        haystack
            .get(offset..offset + self.bytes.len())
            .is_some_and(|window| window.iter().zip(&self.bytes).all(|(b, (value, mask))| b & mask == *value))
    }

    /// Addresses of up to `limit` matches in `haystack`, which starts at `base`.
    pub fn find_all(&self, haystack: &[u8], base: u64, limit: usize) -> Vec<u64> {
        if haystack.len() < self.bytes.len() {
            return Vec::new();
        }
        (0..=haystack.len() - self.bytes.len())
            .filter(|&offset| self.matches_at(haystack, offset))
            .take(limit)
            .map(|offset| base + offset as u64)
            .collect()
    }
}

/// An instruction referring to a string (x64dbg: Search for → String references).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringReference {
    pub from: u64,
    pub to: u64,
    pub text: String,
    pub wide: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundString {
    pub address: u64,
    pub text: String,
    /// UTF-16LE rather than ASCII.
    pub wide: bool,
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

/// ASCII and UTF-16LE strings of at least `min_len` printable characters in `data` (at `base`).
pub fn find_strings(data: &[u8], base: u64, min_len: usize) -> Vec<FoundString> {
    let min_len = min_len.max(1);
    let mut found = Vec::new();

    let mut start = None;
    for (i, &b) in data.iter().chain(std::iter::once(&0)).enumerate() {
        match (printable(b), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min_len {
                    found.push(FoundString {
                        address: base + s as u64,
                        text: String::from_utf8_lossy(&data[s..i]).into_owned(),
                        wide: false,
                    });
                }
                start = None;
            }
            _ => {}
        }
    }

    for parity in 0..2 {
        let mut start = None;
        let units = data[parity..].chunks_exact(2).map(|p| (p[0], p[1])).chain(std::iter::once((0, 1)));
        for (i, (low, high)) in units.enumerate() {
            let is_char = high == 0 && printable(low);
            match (is_char, start) {
                (true, None) => start = Some(i),
                (false, Some(s)) => {
                    if i - s >= min_len {
                        let offset = parity + s * 2;
                        let text: String = data[offset..parity + i * 2].chunks_exact(2).map(|p| p[0] as char).collect();
                        found.push(FoundString { address: base + offset as u64, text, wide: true });
                    }
                    start = None;
                }
                _ => {}
            }
        }
    }
    found.sort_by_key(|s| (s.address, s.wide));
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_with_wildcards() {
        let code = [0x55, 0x48, 0x89, 0xe5, 0xe8, 0x11, 0x22, 0x33, 0x44, 0x48, 0x8b, 0x05, 0x10];
        assert_eq!(Pattern::parse("48 89 E5").unwrap().find_all(&code, 0x1000, 10), [0x1001]);
        assert_eq!(Pattern::parse("48??").unwrap().find_all(&code, 0x1000, 10), [0x1001, 0x1009]);
        assert_eq!(Pattern::parse("E8 ?? ?? ?? ??").unwrap().find_all(&code, 0, 10), [4]);
        assert_eq!(Pattern::parse("4? 8?").unwrap().find_all(&code, 0, 10), [1, 9]);
        assert_eq!(Pattern::parse("48").unwrap().find_all(&code, 0, 1), [1], "limit");
        assert!(Pattern::parse("10 20 30 40 50 60 70 80 90 a0 b0 c0 d0 e0").unwrap().find_all(&code, 0, 10).is_empty());
        assert!(Pattern::parse("").is_err());
        assert!(Pattern::parse("4").is_err());
        assert!(Pattern::parse("zz").is_err());
        assert_eq!(Pattern::parse("?? ?? ??").unwrap().len(), 3);
    }

    #[test]
    fn ascii_and_wide_strings() {
        // Two NULs after "ab" keep its 'b' from pairing with the wide string as UTF-16.
        let mut data = b"\x00\x01x=%d\n\x00hello world\x00ab\x00\x00".to_vec();
        data.extend_from_slice(&[b'W', 0, b'i', 0, b'd', 0, b'e', 0, 0, 0]);
        let strings = find_strings(&data, 0x2000, 4);
        let summary: Vec<_> = strings.iter().map(|s| (s.address - 0x2000, s.text.as_str(), s.wide)).collect();
        assert_eq!(summary, [(2, "x=%d", false), (8, "hello world", false), (24, "Wide", true)]);
        assert_eq!(find_strings(b"x=%d", 0, 3)[0].text, "x=%d", "string at the end of the buffer");
        assert!(find_strings(b"abc", 0, 4).is_empty());
    }
}

//! Register values as reported by `-data-list-register-values x`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Int(u64),
    /// Values wider than 64 bits (x87 and vector registers).
    Wide(u128),
    /// Anything gdb reports in a form not understood above.
    Text(String),
}

impl RegValue {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            RegValue::Int(v) => Some(*v),
            RegValue::Wide(v) => u64::try_from(*v).ok(),
            RegValue::Text(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    pub name: String,
    pub value: RegValue,
    /// Differs from the value at the previous pause.
    pub changed: bool,
}

pub fn parse_value(raw: &str) -> RegValue {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix("0x") {
        if let Ok(v) = u64::from_str_radix(hex, 16) {
            return RegValue::Int(v);
        }
        if let Ok(v) = u128::from_str_radix(hex, 16) {
            return RegValue::Wide(v);
        }
    }
    if raw.starts_with('{')
        && let Some(pos) = raw.find("uint128 = 0x")
    {
        let hex: String = raw[pos + "uint128 = 0x".len()..].chars().take_while(char::is_ascii_hexdigit).collect();
        if let Ok(v) = u128::from_str_radix(&hex, 16) {
            return RegValue::Wide(v);
        }
    }
    if let Ok(v) = raw.parse::<i64>() {
        return RegValue::Int(v as u64);
    }
    RegValue::Text(raw.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gdb_register_formats() {
        assert_eq!(parse_value("0x7ffff7fe3d80"), RegValue::Int(0x7ffff7fe3d80));
        assert_eq!(parse_value("0x0"), RegValue::Int(0));
        assert_eq!(parse_value("0x8000000000000000ffff"), RegValue::Wide(0x8000000000000000ffff));
        assert_eq!(
            parse_value("{v8_bfloat16 = {0x0, 0x0}, v2_int64 = {0x1, 0x2}, uint128 = 0x20000000000000001}"),
            RegValue::Wide(0x20000000000000001)
        );
        assert_eq!(parse_value("-1"), RegValue::Int(u64::MAX));
        assert_eq!(parse_value("<unavailable>"), RegValue::Text("<unavailable>".into()));
        assert_eq!(RegValue::Wide(5).as_u64(), Some(5));
        assert_eq!(RegValue::Wide(u128::MAX).as_u64(), None);
    }
}

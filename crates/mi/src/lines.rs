//! Reassembles gdb stream records, which arrive in arbitrary fragments, into whole lines.

#[derive(Debug, Default)]
pub struct LineBuffer {
    partial: String,
}

impl LineBuffer {
    /// Appends `text` and returns every line it completes, without line terminators.
    pub fn push(&mut self, text: &str) -> Vec<String> {
        self.partial.push_str(text);
        let mut lines = Vec::new();
        while let Some(pos) = self.partial.find('\n') {
            let line: String = self.partial.drain(..=pos).collect();
            lines.push(line.trim_end_matches(['\n', '\r']).to_owned());
        }
        lines
    }

    /// Takes any unterminated trailing text.
    pub fn flush(&mut self) -> Option<String> {
        (!self.partial.is_empty()).then(|| std::mem::take(&mut self.partial))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_fragments_and_splits_lines() {
        let mut b = LineBuffer::default();
        assert!(b.push("Type \"").is_empty());
        assert_eq!(b.push("show copying\" for details.\nThis GDB"), ["Type \"show copying\" for details."]);
        assert_eq!(b.push(" was configured.\r\n\nnext"), ["This GDB was configured.", ""]);
        assert_eq!(b.flush().as_deref(), Some("next"));
        assert_eq!(b.flush(), None);
    }
}

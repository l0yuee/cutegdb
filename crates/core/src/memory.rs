//! Page-granular cache of target memory, invalidated whenever the target runs.

use std::collections::HashMap;

pub const PAGE_SIZE: usize = 0x1000;
const OFFSET_MASK: u64 = PAGE_SIZE as u64 - 1;

#[derive(Debug, Default)]
pub struct MemoryCache {
    /// Page base → one entry per byte; `None` marks unreadable bytes.
    pages: HashMap<u64, Vec<Option<u8>>>,
    /// Incremented by `clear`, so reads started before a clear cannot repopulate stale pages.
    generation: u64,
}

impl MemoryCache {
    pub fn clear(&mut self) {
        self.pages.clear();
        self.generation += 1;
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Page bases covering `[address, address + len)` that are not cached yet.
    pub fn missing_pages(&self, address: u64, len: usize) -> Vec<u64> {
        page_bases(address, len).filter(|base| !self.pages.contains_key(base)).collect()
    }

    pub fn insert_page(&mut self, base: u64, mut bytes: Vec<Option<u8>>) {
        bytes.resize(PAGE_SIZE, None);
        self.pages.insert(base & !OFFSET_MASK, bytes);
    }

    /// Inserts a page read while the cache was at `generation`. Returns false, dropping the page,
    /// if the cache has been cleared since.
    pub fn insert_page_if_current(&mut self, generation: u64, base: u64, bytes: Vec<Option<u8>>) -> bool {
        if generation != self.generation {
            return false;
        }
        self.insert_page(base, bytes);
        true
    }

    /// Cached bytes; missing or unreadable bytes are `None`.
    pub fn read(&self, address: u64, len: usize) -> Vec<Option<u8>> {
        (0..len as u64)
            .map(|i| {
                let a = address.checked_add(i)?;
                self.pages.get(&(a & !OFFSET_MASK))?[(a & OFFSET_MASK) as usize]
            })
            .collect()
    }

    /// Mirrors a write to the target into already cached pages.
    pub fn write(&mut self, address: u64, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            let Some(a) = address.checked_add(i as u64) else { break };
            if let Some(page) = self.pages.get_mut(&(a & !OFFSET_MASK)) {
                page[(a & OFFSET_MASK) as usize] = Some(byte);
            }
        }
    }
}

fn page_bases(address: u64, len: usize) -> impl Iterator<Item = u64> {
    let first = address & !OFFSET_MASK;
    let last = address.saturating_add((len as u64).saturating_sub(1)) & !OFFSET_MASK;
    let count = if len == 0 { 0 } else { (last - first) / PAGE_SIZE as u64 + 1 };
    (0..count).map(move |i| first + i * PAGE_SIZE as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_across_pages_and_reports_gaps() {
        let mut cache = MemoryCache::default();
        assert_eq!(cache.missing_pages(0x1ffe, 4), [0x1000, 0x2000]);
        assert!(cache.missing_pages(0x1000, 0).is_empty());

        cache.insert_page(0x1000, (0..PAGE_SIZE).map(|i| Some(i as u8)).collect());
        assert_eq!(cache.missing_pages(0x1ffe, 4), [0x2000]);
        assert_eq!(cache.read(0x1ffe, 4), [Some(0xfe), Some(0xff), None, None]);

        cache.insert_page(0x2000, vec![None; PAGE_SIZE]);
        assert!(cache.missing_pages(0x1ffe, 4).is_empty());
        assert_eq!(cache.read(0x2000, 2), [None, None]);

        cache.write(0x1fff, &[0xaa, 0xbb]);
        assert_eq!(cache.read(0x1fff, 2), [Some(0xaa), Some(0xbb)]);

        cache.clear();
        assert_eq!(cache.read(0x1000, 1), [None]);
    }

    #[test]
    fn stale_reads_are_dropped_after_clear() {
        let mut cache = MemoryCache::default();
        let before = cache.generation();
        cache.clear();
        assert!(!cache.insert_page_if_current(before, 0x1000, vec![Some(1)]));
        assert_eq!(cache.missing_pages(0x1000, 1), [0x1000]);
        assert!(cache.insert_page_if_current(cache.generation(), 0x1000, vec![Some(1)]));
        assert_eq!(cache.read(0x1000, 1), [Some(1)]);
    }

    #[test]
    fn end_of_address_space_does_not_overflow() {
        let cache = MemoryCache::default();
        assert_eq!(cache.missing_pages(u64::MAX - 1, 16), [!OFFSET_MASK]);
        assert_eq!(cache.read(u64::MAX, 3), [None, None, None]);
    }
}

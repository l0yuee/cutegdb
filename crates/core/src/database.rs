//! Per-executable annotations, like x64dbg's database: comments, labels, bookmarks and patches.
//!
//! Locations are stored relative to their module so they stay valid across ASLR and restarts.

use crate::symbols::SymbolTable;
use object::{Object, ObjectSegment};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};

const PAGE_MASK: u64 = !0xfff;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ModuleAddress {
    pub module: String,
    /// Offset from the module's load base.
    pub rva: u64,
}

impl ModuleAddress {
    pub fn from_address(symbols: &SymbolTable, address: u64) -> Option<ModuleAddress> {
        let module = symbols.module_at(address)?;
        Some(ModuleAddress { module: module.name.clone(), rva: address - module.base })
    }

    pub fn resolve(&self, symbols: &SymbolTable) -> Option<u64> {
        Some(symbols.module(&self.module)?.base + self.rva)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Annotation {
    pub location: ModuleAddress,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    pub location: ModuleAddress,
    pub original: u8,
    pub patched: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Database {
    pub comments: Vec<Annotation>,
    pub labels: Vec<Annotation>,
    pub bookmarks: Vec<ModuleAddress>,
    pub patches: Vec<Patch>,
}

impl Database {
    /// Loads a database; a missing file is an empty database.
    pub fn load(path: &Path) -> io::Result<Database> {
        match std::fs::read(path) {
            Ok(data) => serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Database::default()),
            Err(e) => Err(e),
        }
    }

    /// Writes atomically: a crash never leaves a truncated database behind.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let data = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, data)?;
        std::fs::rename(temporary, path)
    }

    pub fn comment(&self, location: &ModuleAddress) -> Option<&str> {
        find(&self.comments, location)
    }

    /// An empty comment removes it.
    pub fn set_comment(&mut self, location: ModuleAddress, text: &str) {
        set(&mut self.comments, location, text);
    }

    pub fn label(&self, location: &ModuleAddress) -> Option<&str> {
        find(&self.labels, location)
    }

    /// An empty label removes it.
    pub fn set_label(&mut self, location: ModuleAddress, text: &str) {
        set(&mut self.labels, location, text);
    }

    pub fn find_label(&self, name: &str) -> Option<&ModuleAddress> {
        self.labels.iter().find(|a| a.text == name).map(|a| &a.location)
    }

    pub fn is_bookmarked(&self, location: &ModuleAddress) -> bool {
        self.bookmarks.contains(location)
    }

    /// Returns whether the location is bookmarked afterwards.
    pub fn toggle_bookmark(&mut self, location: ModuleAddress) -> bool {
        match self.bookmarks.iter().position(|b| *b == location) {
            Some(index) => {
                self.bookmarks.remove(index);
                false
            }
            None => {
                self.bookmarks.push(location);
                self.bookmarks.sort();
                true
            }
        }
    }

    /// Records a byte change. The first original value is kept; writing it back removes the patch.
    pub fn record_patch(&mut self, location: ModuleAddress, original: u8, patched: u8) {
        match self.patches.iter().position(|p| p.location == location) {
            Some(index) if self.patches[index].original == patched => {
                self.patches.remove(index);
            }
            Some(index) => self.patches[index].patched = patched,
            None if original != patched => {
                self.patches.push(Patch { location, original, patched });
                self.patches.sort_by(|a, b| a.location.cmp(&b.location));
            }
            None => {}
        }
    }
}

fn find<'a>(list: &'a [Annotation], location: &ModuleAddress) -> Option<&'a str> {
    list.iter().find(|a| a.location == *location).map(|a| a.text.as_str())
}

fn set(list: &mut Vec<Annotation>, location: ModuleAddress, text: &str) {
    list.retain(|a| a.location != location);
    let text = text.trim();
    if !text.is_empty() {
        list.push(Annotation { location, text: text.to_owned() });
        list.sort_by(|a, b| a.location.cmp(&b.location));
    }
}

/// Where the database of `executable` lives: `$XDG_DATA_HOME/cutegdb/db/<name>-<build id>.json`
/// (falling back to a hash of the path for binaries without a build id).
pub fn database_path(executable: &Path) -> PathBuf {
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .unwrap_or_else(std::env::temp_dir);
    let name = executable.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "unknown".into());
    let build_id = std::fs::read(executable)
        .ok()
        .and_then(|data| object::File::parse(&*data).ok()?.build_id().ok().flatten().map(hex));
    let id = build_id.unwrap_or_else(|| {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        executable.hash(&mut hasher);
        format!("path{:016x}", hasher.finish())
    });
    data_home.join("cutegdb/db").join(format!("{name}-{id}.json"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// File offset of the module-relative address `rva` in an ELF file, if it is backed by file data.
pub fn file_offset(file_data: &[u8], rva: u64) -> Option<u64> {
    let file = object::File::parse(file_data).ok()?;
    let base = file.segments().map(|s| s.address()).min()? & PAGE_MASK;
    let address = base.checked_add(rva)?;
    file.segments().find_map(|segment| {
        let delta = address.checked_sub(segment.address())?;
        let (offset, size) = segment.file_range();
        (delta < size).then_some(offset + delta)
    })
}

/// Writes a copy of `executable` with the patches of `module` applied; returns how many bytes changed.
pub fn export_patched_file(executable: &Path, module: &str, patches: &[Patch], output: &Path) -> io::Result<usize> {
    let mut data = std::fs::read(executable)?;
    let mut applied = 0;
    for patch in patches.iter().filter(|p| p.location.module == module) {
        let offset = file_offset(&data, patch.location.rva).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("{}+{:X} is not backed by the file", module, patch.location.rva))
        })?;
        data[offset as usize] = patch.patched;
        applied += 1;
    }
    std::fs::write(output, data)?;
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rva: u64) -> ModuleAddress {
        ModuleAddress { module: "hello".into(), rva }
    }

    #[test]
    fn annotations_and_bookmarks() {
        let mut db = Database::default();
        db.set_comment(at(0x20), "second");
        db.set_comment(at(0x10), " first ");
        assert_eq!(db.comment(&at(0x10)), Some("first"));
        assert_eq!(db.comments.iter().map(|c| c.location.rva).collect::<Vec<_>>(), [0x10, 0x20]);
        db.set_comment(at(0x10), "");
        assert_eq!(db.comment(&at(0x10)), None);

        db.set_label(at(0x30), "decrypt");
        assert_eq!(db.find_label("decrypt"), Some(&at(0x30)));
        db.set_label(at(0x30), "decrypt_v2");
        assert_eq!((db.labels.len(), db.label(&at(0x30))), (1, Some("decrypt_v2")));

        assert!(db.toggle_bookmark(at(0x40)));
        assert!(db.is_bookmarked(&at(0x40)));
        assert!(!db.toggle_bookmark(at(0x40)));
        assert!(db.bookmarks.is_empty());
    }

    #[test]
    fn patches_keep_the_first_original_byte() {
        let mut db = Database::default();
        db.record_patch(at(1), 0x55, 0x90);
        db.record_patch(at(1), 0x90, 0xcc);
        assert_eq!(db.patches, [Patch { location: at(1), original: 0x55, patched: 0xcc }]);
        db.record_patch(at(1), 0xcc, 0x55);
        assert!(db.patches.is_empty(), "restoring the original removes the patch");
        db.record_patch(at(2), 0x10, 0x10);
        assert!(db.patches.is_empty(), "writing the same byte is not a patch");
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("cutegdb-db-test-{}", std::process::id()));
        let path = dir.join("nested/hello.json");
        assert_eq!(Database::load(&path).unwrap(), Database::default());

        let mut db = Database::default();
        db.set_comment(at(0x1149), "adds two numbers");
        db.set_label(at(0x1149), "my_add");
        db.toggle_bookmark(at(0x115d));
        db.record_patch(at(0x1150), 0x01, 0x29);
        db.save(&path).unwrap();
        assert_eq!(Database::load(&path).unwrap(), db);
        assert!(!path.with_extension("json.tmp").exists());

        std::fs::write(&path, b"{ not json").unwrap();
        assert_eq!(Database::load(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn database_paths_use_the_build_id() {
        let exe = std::env::current_exe().unwrap();
        let path = database_path(&exe);
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(&*exe.file_name().unwrap().to_string_lossy()), "{name}");
        assert!(name.ends_with(".json") && path.parent().unwrap().ends_with("cutegdb/db"));
        let missing = database_path(Path::new("/nonexistent/prog"));
        assert!(missing.file_name().unwrap().to_string_lossy().starts_with("prog-path"));
    }
}

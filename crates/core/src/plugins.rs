//! Built-in countermeasures against anti-debugging and anti-VM checks, for
//! malware analysts who need a target to run as if it were not observed.
//!
//! The behaviour lives in a gdb Python module (`plugins.py`) that the debugger
//! injects into the session; this module holds the user-facing catalog and the
//! helpers the debugger uses to drive it. Plugin ids here must match `plugins.py`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginCategory {
    /// Hides the debugger itself from the target.
    AntiDebug,
    /// Makes a virtual machine or sandbox look like bare metal.
    AntiVm,
}

impl PluginCategory {
    pub fn title(self) -> &'static str {
        match self {
            PluginCategory::AntiDebug => "Anti-anti-debug",
            PluginCategory::AntiVm => "Anti-anti-VM",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PluginInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub category: PluginCategory,
    /// True when the technique cannot be fully hidden (explained in `description`).
    pub best_effort: bool,
    pub description: &'static str,
}

/// Every built-in plugin, in display order. The source of truth for the UI.
pub fn catalog() -> &'static [PluginInfo] {
    use PluginCategory::{AntiDebug, AntiVm};
    &[
        PluginInfo {
            id: "ptrace_guard",
            name: "ptrace guard",
            category: AntiDebug,
            best_effort: false,
            description: "Fakes success for PTRACE_TRACEME/ATTACH and hides the debug registers, \
                          defeating self-ptrace and hardware-breakpoint detection.",
        },
        PluginInfo {
            id: "procfs_cloak",
            name: "procfs & environment cloak",
            category: AntiDebug,
            best_effort: false,
            description: "Zeroes TracerPid and spoofs the parent process, command line and \
                          environment in /proc, hiding the debugger from procfs and getenv checks.",
        },
        PluginInfo {
            id: "timing_normalizer",
            name: "timing normalizer",
            category: AntiDebug,
            best_effort: true,
            description: "Feeds a smoothed clock to rdtsc/rdtscp and the clock syscalls. \
                          Best-effort: large single-step slowdowns cannot be fully hidden.",
        },
        PluginInfo {
            id: "swbp_cloak",
            name: "software-breakpoint cloak",
            category: AntiDebug,
            best_effort: true,
            description: "Restores original bytes when the target reads or checksums its own code. \
                          Best-effort: use hardware breakpoints for complete stealth.",
        },
        PluginInfo {
            id: "cpuid_spoof",
            name: "CPUID spoof",
            category: AntiVm,
            best_effort: false,
            description: "Clears the hypervisor-present bit and scrubs hypervisor vendor and brand \
                          strings from CPUID results (x86/x86-64).",
        },
        PluginInfo {
            id: "vm_file_cloak",
            name: "VM file & device cloak",
            category: AntiVm,
            best_effort: false,
            description: "Rewrites DMI, /proc/cpuinfo, kernel-module and MAC-address reads and hides \
                          VM device nodes so the machine looks like bare metal.",
        },
        PluginInfo {
            id: "vm_syscall_cloak",
            name: "VM syscall cloak",
            category: AntiVm,
            best_effort: false,
            description: "Normalizes uname, memory size, CPU count, disk size, hostname and \
                          interface MACs reported through syscalls.",
        },
    ]
}

pub fn info(id: &str) -> Option<&'static PluginInfo> {
    catalog().iter().find(|p| p.id == id)
}

/// The Python module injected into gdb.
const PYTHON_MODULE: &str = include_str!("plugins.py");

/// A single gdb command that defines the `cutegdb` Python namespace.
///
/// The module is base64-encoded so the whole (multi-line) source fits on the one
/// line an MI command occupies.
pub(crate) fn bootstrap_command() -> String {
    format!(
        "python import base64, types; _m = types.ModuleType('cutegdb'); \
         exec(compile(base64.b64decode('{}').decode('utf-8'), 'cutegdb-plugins.py', 'exec'), _m.__dict__); \
         import sys as _s; _s.modules['cutegdb'] = _m; globals()['cutegdb'] = _m",
        base64_encode(PYTHON_MODULE.as_bytes())
    )
}

/// Installs exactly `ids` and logs the resulting active set.
pub(crate) fn activate_command(ids: &[String]) -> String {
    format!("python cutegdb.activate({}); print(cutegdb.active_line())", python_list(ids))
}

pub(crate) const STATS_COMMAND: &str = "python cutegdb.dump_stats()";

/// Parses the `CUTEGDB_STATS id=count ...` line printed by `dump_stats`.
pub(crate) fn parse_stats(output: &str) -> Vec<(String, u64)> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("CUTEGDB_STATS"))
        .map(|rest| {
            rest.split_whitespace()
                .filter_map(|entry| {
                    let (id, count) = entry.split_once('=')?;
                    Some((id.to_owned(), count.parse().ok()?))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The active plugin ids from the `CUTEGDB_ACTIVE ...` line printed by `activate`.
pub(crate) fn parse_active(output: &str) -> Vec<String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("CUTEGDB_ACTIVE"))
        .map(|rest| rest.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// A Python list literal of the ids, e.g. `['ptrace_guard', 'cpuid_spoof']`.
fn python_list(ids: &[String]) -> String {
    let items: Vec<String> = ids.iter().map(|id| format!("'{}'", id.replace('\'', ""))).collect();
    format!("[{}]", items.join(", "))
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let bytes = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32;
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(n & 63) as usize] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique_and_named() {
        let mut ids: Vec<&str> = catalog().iter().map(|p| p.id).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate plugin id in the catalog");
        assert!(catalog().iter().all(|p| !p.name.is_empty() && !p.description.is_empty()));
        assert!(info("cpuid_spoof").is_some() && info("nope").is_none());
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn bootstrap_round_trips_the_module() {
        // The encoded payload decodes back to the exact module source.
        let cmd = bootstrap_command();
        let b64 = cmd.split_once("b64decode('").unwrap().1.split_once('\'').unwrap().0;
        assert_eq!(decode_for_test(b64), PYTHON_MODULE.as_bytes());
    }

    #[test]
    fn activate_command_formats_a_python_list() {
        assert_eq!(
            activate_command(&["ptrace_guard".into(), "cpuid_spoof".into()]),
            "python cutegdb.activate(['ptrace_guard', 'cpuid_spoof']); print(cutegdb.active_line())"
        );
        assert_eq!(activate_command(&[]), "python cutegdb.activate([]); print(cutegdb.active_line())");
    }

    #[test]
    fn parses_stats_and_active_lines() {
        let out = "noise\nCUTEGDB_STATS ptrace_guard=3 cpuid_spoof=17\nmore";
        assert_eq!(parse_stats(out), [("ptrace_guard".to_owned(), 3), ("cpuid_spoof".to_owned(), 17)]);
        assert_eq!(parse_stats("nothing here"), []);
        assert_eq!(parse_stats("CUTEGDB_STATS"), []);
        assert_eq!(parse_active("CUTEGDB_ACTIVE ptrace_guard cpuid_spoof"), ["ptrace_guard", "cpuid_spoof"]);
    }

    fn decode_for_test(s: &str) -> Vec<u8> {
        const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let value = |c: u8| ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
        let clean: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
        let mut out = Vec::new();
        for chunk in clean.chunks(4) {
            let mut n = 0u32;
            for (i, &c) in chunk.iter().enumerate() {
                n |= value(c) << (18 - 6 * i);
            }
            out.push((n >> 16) as u8);
            if chunk.len() > 2 {
                out.push((n >> 8) as u8);
            }
            if chunk.len() > 3 {
                out.push(n as u8);
            }
        }
        out
    }
}

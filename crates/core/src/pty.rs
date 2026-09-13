//! Pseudo-terminal for the debuggee, so its I/O never mixes with gdb's MI pipes.

use nix::errno::Errno;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

pub struct InferiorTty {
    path: PathBuf,
    master: File,
    // Keeping the slave open stops reads on the master failing with EIO between runs.
    _slave: OwnedFd,
}

impl InferiorTty {
    /// Opens a pty; everything the debuggee writes is sent to `output` in raw chunks.
    pub fn open(output: mpsc::UnboundedSender<String>) -> nix::Result<Self> {
        let pty = nix::pty::openpty(None, None)?;
        let path = nix::unistd::ttyname(&pty.slave)?;
        let master = File::from(pty.master);
        let mut reader = master.try_clone().map_err(|_| Errno::last())?;
        std::thread::Builder::new()
            .name("inferior-tty".into())
            .spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if output.send(String::from_utf8_lossy(&buf[..n]).into_owned()).is_err() {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            })
            .map_err(|_| Errno::last())?;
        Ok(Self { path, master, _slave: pty.slave })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sends keyboard input to the debuggee.
    pub fn write_input(&self, data: &[u8]) -> std::io::Result<()> {
        (&self.master).write_all(data)
    }
}

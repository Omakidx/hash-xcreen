//! Asking the operator: hidden secret prompts and typed confirmations, always on `/dev/tty`.
//!
//! Secrets (a Linux password, a PIN, a pairing token) are **never** taken from argv, the
//! environment, stdin or a file: only from the controlling terminal with echo off. Reading the
//! terminal rather than stdin also means `echo secret | hx-agent ...` cannot feed one, which
//! keeps the secret out of shell history and scripts by construction.
//!
//! While a secret is read the terminal has `ECHO` and `ISIG` cleared (canonical mode stays on, so
//! backspace works). With `ISIG` off, Ctrl-C arrives as the byte `0x03`, which aborts the prompt
//! after the terminal settings are restored, so an interrupt never leaves the operator's
//! terminal with echo off.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

use rustix::termios::{LocalModes, OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

use super::error::CliError;

/// Where the CLI asks questions. The production implementation is [`TtyPrompter`]; tests script
/// the answers.
pub trait Prompter {
    /// Reads a secret of at most `max` bytes without echo. The prompt text is shown first.
    fn secret(&mut self, prompt: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, CliError>;

    /// Reads one visible line (a confirmation).
    fn line(&mut self, prompt: &str) -> Result<String, CliError>;
}

/// A terminal device: `/dev/tty` (the controlling terminal) in production; tests point it at
/// the slave side of a pseudo-terminal.
pub struct TtyPrompter {
    path: std::path::PathBuf,
}

impl TtyPrompter {
    /// The controlling terminal of the process, `/dev/tty`.
    pub fn controlling() -> Self {
        Self::at("/dev/tty")
    }

    /// A specific terminal device.
    pub fn at(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

fn no_tty(e: std::io::Error) -> CliError {
    CliError::Declined(format!(
        "no terminal to ask on ({}); run hx-agent from an interactive shell, or pass the flag that answers the question",
        e.kind()
    ))
}

fn open_tty(path: &std::path::Path) -> Result<File, CliError> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NOCTTY: opening a terminal here must never make it the controlling terminal.
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOCTTY.bits() as i32)
        .open(path)
        .map_err(no_tty)
}

/// Restores the terminal settings when dropped.
struct Restore {
    tty: File,
    saved: rustix::termios::Termios,
}

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = tcsetattr(&self.tty, OptionalActions::Flush, &self.saved);
    }
}

impl Prompter for TtyPrompter {
    fn secret(&mut self, prompt: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, CliError> {
        let mut tty = open_tty(&self.path)?;
        // Termination signals wait until the terminal is restored (declared before the guard, so
        // it is dropped after it).
        let _blocked = crate::cli::sigblock::Blocked::new();
        let saved = tcgetattr(&tty).map_err(|e| CliError::Declined(format!("terminal: {e}")))?;
        // With ISIG off the interrupt, quit and suspend characters of this terminal arrive as
        // ordinary bytes: they abort the prompt, they are never part of a secret.
        let abort: [u8; 3] = [
            saved.special_codes[SpecialCodeIndex::VINTR],
            saved.special_codes[SpecialCodeIndex::VQUIT],
            saved.special_codes[SpecialCodeIndex::VSUSP],
        ];
        let mut hidden = saved.clone();
        hidden
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ISIG);
        // The guard exists before the settings change, so every exit path restores them.
        let guard = Restore {
            tty: tty.try_clone().map_err(no_tty)?,
            saved,
        };
        // ECHONL stays as it was; the newline after the answer is written by hand below.
        tcsetattr(&tty, OptionalActions::Flush, &hidden)
            .map_err(|e| CliError::Declined(format!("terminal: {e}")))?;
        let _ = tty.write_all(prompt.as_bytes());
        let _ = tty.flush();
        // Preallocated to the bound: the buffer never reallocates, so no earlier, shorter copy
        // of the secret is left behind unwiped.
        let mut buf = Zeroizing::new(Vec::with_capacity(max.saturating_add(1)));
        let mut one = Zeroizing::new([0u8; 1]);
        let result = loop {
            match tty.read(&mut *one) {
                Ok(0) => break Ok(()),
                Ok(_) => match one[0] {
                    b'\n' | b'\r' => break Ok(()),
                    b if b == 0x03 || (b != 0 && abort.contains(&b)) => {
                        break Err(CliError::Declined("interrupted".into()));
                    }
                    // Ctrl-D with nothing typed ends the prompt; Backspace and line editing are
                    // handled by the terminal in canonical mode.
                    0x04 if buf.is_empty() => break Ok(()),
                    b => {
                        if buf.len() >= max {
                            break Err(CliError::Usage(format!(
                                "the secret is longer than {max} bytes"
                            )));
                        }
                        buf.push(b);
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => break Err(no_tty(e)),
            }
        };
        one[0] = 0;
        let _ = tty.write_all(b"\n");
        drop(guard);
        result.map(|()| buf)
    }

    fn line(&mut self, prompt: &str) -> Result<String, CliError> {
        let mut tty = open_tty(&self.path)?;
        let _ = tty.write_all(prompt.as_bytes());
        let _ = tty.flush();
        let mut line = Vec::new();
        let mut one = [0u8; 1];
        loop {
            match tty.read(&mut one) {
                Ok(0) => break,
                Ok(_) if one[0] == b'\n' => break,
                Ok(_) => {
                    if line.len() >= 256 {
                        return Err(CliError::Declined("answer too long".into()));
                    }
                    line.push(one[0]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(no_tty(e)),
            }
        }
        Ok(String::from_utf8_lossy(&line).trim().to_owned())
    }
}

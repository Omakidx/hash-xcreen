//! Secrets on stdin for `--ssh` (design C2).
//!
//! ```text
//! "HXI1" | { kind u8 | len u16 LE | bytes[len] }* | kind 0, len 0
//! 1 USER_PASSWORD    1..=1024, no \r \n NUL        required
//! 2 PIN              6..=16 ASCII digits           required
//! 3 PAIRING_TOKEN    hxt1-..., at most 1024        optional
//! 4 OWNER_PUBLIC_KEY 32 bytes                      optional
//! 5 DRIVE_TOKEN      reserved: refused in Phase 1
//! ```
//!
//! At most 8192 bytes in total, each kind at most once, all of it within 30 seconds. EOF before
//! the end record, a byte after it, an unknown kind, a bad length: all exit 2. Bytes are read
//! straight into `Zeroizing` buffers sized to the declared length (never into a `String`, never
//! grown), and after the read `/dev/null` is dup'd onto fd 0 so nothing later can read stdin.

use std::io::{self, Read};
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use zeroize::Zeroizing;

use super::error::InstallError;

/// The magic.
pub const MAGIC: &[u8; 4] = b"HXI1";
/// Most bytes of the whole stream.
pub const MAX_TOTAL: usize = 8192;
/// The time allowed for the whole read.
pub const READ_LIMIT: Duration = Duration::from_secs(30);

/// Record kinds.
pub mod kind {
    /// The Linux password.
    pub const PASSWORD: u8 = 1;
    /// The PIN.
    pub const PIN: u8 = 2;
    /// The pairing token.
    pub const TOKEN: u8 = 3;
    /// The owner public key.
    pub const OWNER_KEY: u8 = 4;
    /// Reserved.
    pub const DRIVE_TOKEN: u8 = 5;
}

/// What the stream carried.
#[derive(Default)]
pub struct Frames {
    /// The Linux password.
    pub password: Option<Zeroizing<Vec<u8>>>,
    /// The PIN.
    pub pin: Option<Zeroizing<Vec<u8>>>,
    /// The pairing token.
    pub token: Option<Zeroizing<Vec<u8>>>,
    /// The owner public key (32 bytes).
    pub owner_key: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Frames {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frames")
            .field("password", &self.password.is_some())
            .field("pin", &self.pin.is_some())
            .field("token", &self.token.is_some())
            .field("owner_key", &self.owner_key.is_some())
            .finish()
    }
}

impl Frames {
    /// Drops every buffer now (each is wiped as it drops).
    pub fn wipe(&mut self) {
        self.password = None;
        self.pin = None;
        self.token = None;
        self.owner_key = None;
    }
}

/// A reader of a file descriptor that gives up at a deadline (`poll` before every read, and
/// `read(2)` directly, so no std buffer holds a copy of a secret).
pub struct FdReader<F: AsFd> {
    fd: F,
    deadline: Instant,
}

impl<F: AsFd> FdReader<F> {
    /// Reads `fd` until `deadline`.
    pub fn new(fd: F, deadline: Instant) -> Self {
        Self { fd, deadline }
    }
}

impl<F: AsFd> Read for FdReader<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let left = self.deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
            }
            let ts = rustix::event::Timespec {
                tv_sec: i64::try_from(left.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: i64::from(left.subsec_nanos()),
            };
            let mut fds = [PollFd::new(&self.fd, PollFlags::IN)];
            match poll(&mut fds, Some(&ts)) {
                Ok(0) => continue,
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            }
            match rustix::io::read(&self.fd, &mut *buf) {
                Ok(n) => return Ok(n),
                Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
}

/// Called before the check for trailing bytes: a reader with a deadline shortens it so that a
/// quiet, still open pipe does not hold the install for the rest of the 30 seconds.
pub trait Settle {
    /// Shortens any deadline to a brief grace period.
    fn settle(&mut self) {}
}

impl<T> Settle for io::Cursor<T> {}

impl<F: AsFd> Settle for FdReader<F> {
    fn settle(&mut self) {
        let grace = Instant::now() + Duration::from_millis(50);
        if grace < self.deadline {
            self.deadline = grace;
        }
    }
}

fn bad(m: &str) -> InstallError {
    InstallError::usage(format!("the secrets on stdin are not acceptable: {m}"))
}

fn fill(r: &mut impl Read, buf: &mut [u8]) -> Result<(), InstallError> {
    let mut at = 0;
    while at < buf.len() {
        match r.read(&mut buf[at..]) {
            Ok(0) => return Err(bad("the stream ended before the end record")),
            Ok(n) => at += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                return Err(bad("not complete within 30 seconds"));
            }
            Err(_) => return Err(bad("cannot read stdin")),
        }
    }
    Ok(())
}

fn check_password(v: &[u8]) -> Result<(), InstallError> {
    if v.is_empty() || v.len() > 1024 || v.iter().any(|b| matches!(b, 0 | b'\n' | b'\r')) {
        return Err(bad(
            "a password is 1 to 1024 bytes with no newline, carriage return or NUL",
        ));
    }
    Ok(())
}

fn check_pin(v: &[u8]) -> Result<(), InstallError> {
    if !(6..=16).contains(&v.len()) || !v.iter().all(u8::is_ascii_digit) {
        return Err(bad("a PIN is 6 to 16 digits"));
    }
    Ok(())
}

fn check_token(v: &[u8]) -> Result<(), InstallError> {
    let ok = v.len() <= 1024
        && std::str::from_utf8(v).is_ok_and(|s| hx_crypto::PairingToken::parse(s).is_ok());
    if ok {
        Ok(())
    } else {
        Err(bad("that is not a pairing token (expected hxt1-...)"))
    }
}

/// Reads the framed secrets from `r` (which enforces the deadline). `require_secrets` makes the
/// password and the PIN mandatory (the `--ssh` mode).
pub fn read_frames<R: Read + Settle>(
    r: &mut R,
    require_secrets: bool,
) -> Result<Frames, InstallError> {
    let mut magic = [0u8; 4];
    fill(r, &mut magic)?;
    if &magic != MAGIC {
        return Err(bad("the magic HXI1 is missing"));
    }
    let mut total = 4usize;
    let mut out = Frames::default();
    loop {
        let mut head = [0u8; 3];
        fill(r, &mut head)?;
        total += 3;
        let (k, len) = (head[0], usize::from(u16::from_le_bytes([head[1], head[2]])));
        if k == 0 {
            if len != 0 {
                return Err(bad("the end record has a length"));
            }
            break;
        }
        if total + len + 3 > MAX_TOTAL {
            return Err(bad("more than 8192 bytes"));
        }
        let slot = match k {
            kind::PASSWORD => &mut out.password,
            kind::PIN => &mut out.pin,
            kind::TOKEN => &mut out.token,
            kind::OWNER_KEY => &mut out.owner_key,
            kind::DRIVE_TOKEN => return Err(bad("record kind 5 is reserved")),
            _ => return Err(bad("unknown record kind")),
        };
        if slot.is_some() {
            return Err(bad("a record kind appears twice"));
        }
        if len == 0 {
            return Err(bad("an empty record"));
        }
        // Exactly the declared size, filled in place: no growth, so no stale copy is left behind.
        let mut buf = Zeroizing::new(vec![0u8; len]);
        fill(r, &mut buf)?;
        total += len;
        match k {
            kind::PASSWORD => check_password(&buf)?,
            kind::PIN => check_pin(&buf)?,
            kind::TOKEN => check_token(&buf)?,
            _ => {
                if len != 32 {
                    return Err(bad("the owner public key is 32 bytes"));
                }
            }
        }
        *slot = Some(buf);
    }
    // Anything after the end record is an error. A reader that is still open and quiet is fine,
    // so only what is already queued (a short grace) is looked at.
    r.settle();
    let mut one = [0u8; 1];
    match r.read(&mut one) {
        Ok(0) => {}
        Ok(_) => return Err(bad("bytes follow the end record")),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
        Err(_) => {}
    }
    if require_secrets && (out.password.is_none() || out.pin.is_none()) {
        return Err(bad("the password and the PIN are required"));
    }
    Ok(out)
}

/// Reads fd 0 under the 30 second limit, then makes fd 0 `/dev/null`.
pub fn read_stdin(require_secrets: bool) -> Result<Frames, InstallError> {
    if rustix::termios::isatty(rustix::stdio::stdin()) {
        return Err(InstallError::usage(
            "--ssh reads its secrets from stdin, which must not be a terminal",
        ));
    }
    let deadline = Instant::now() + READ_LIMIT;
    let result = read_frames(
        &mut FdReader::new(rustix::stdio::stdin(), deadline),
        require_secrets,
    );
    redirect_stdin_to_null()?;
    result
}

/// Dup `/dev/null` onto fd 0.
pub fn redirect_stdin_to_null() -> Result<(), InstallError> {
    let null = std::fs::File::open("/dev/null")?;
    rustix::stdio::dup2_stdin(null.as_fd())
        .map_err(|e| InstallError::internal(format!("cannot redirect stdin: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    fn token_text() -> String {
        hx_crypto::PairingToken::generate()
            .unwrap()
            .to_text()
            .to_string()
    }

    fn rec(k: u8, v: &[u8]) -> Vec<u8> {
        let mut o = vec![k];
        o.extend_from_slice(&(v.len() as u16).to_le_bytes());
        o.extend_from_slice(v);
        o
    }

    fn stream(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut s = MAGIC.to_vec();
        for p in parts {
            s.extend_from_slice(p);
        }
        s
    }

    fn end() -> Vec<u8> {
        rec(0, b"")
    }

    fn parse(bytes: &[u8], require: bool) -> Result<Frames, InstallError> {
        read_frames(&mut io::Cursor::new(bytes.to_vec()), require)
    }

    fn good() -> Vec<u8> {
        stream(&[rec(1, b"pass word"), rec(2, b"123456"), end()])
    }

    #[test]
    fn a_complete_stream_is_read() {
        let f = parse(&good(), true).unwrap();
        assert_eq!(&**f.password.as_ref().unwrap(), b"pass word");
        assert_eq!(&**f.pin.as_ref().unwrap(), b"123456");
        assert!(f.token.is_none() && f.owner_key.is_none());
        let all = stream(&[
            rec(1, b"p"),
            rec(2, b"1234567890123456"),
            rec(3, token_text().as_bytes()),
            rec(4, &[7u8; 32]),
            end(),
        ]);
        let f = parse(&all, true).unwrap();
        assert!(f.token.is_some() && f.owner_key.is_some());
    }

    #[test]
    fn buffers_are_exactly_the_declared_size() {
        let f = parse(&good(), true).unwrap();
        let p = f.password.unwrap();
        assert_eq!(p.capacity(), p.len(), "no growth means no stale copy");
        let mut g = parse(&good(), true).unwrap();
        g.wipe();
        assert!(g.password.is_none() && g.pin.is_none());
    }

    #[test]
    fn truncation_is_refused_at_every_cut() {
        let full = good();
        for cut in 0..full.len() {
            let e = parse(&full[..cut], true).unwrap_err();
            assert_eq!(e.exit, 2, "cut at {cut}");
        }
    }

    #[test]
    fn duplicates_unknown_and_reserved_kinds_are_refused() {
        let dup = stream(&[rec(1, b"a"), rec(1, b"b"), end()]);
        assert!(parse(&dup, false).unwrap_err().message.contains("twice"));
        for k in [5u8, 6, 200] {
            let s = stream(&[rec(k, b"x"), end()]);
            assert_eq!(parse(&s, false).unwrap_err().exit, 2, "kind {k}");
        }
        assert!(parse(&stream(&[rec(1, b""), end()]), false).is_err());
        let mut bad_end = MAGIC.to_vec();
        bad_end.extend_from_slice(&[0, 1, 0, b'x']);
        assert!(parse(&bad_end, false).is_err());
    }

    #[test]
    fn bad_magic_is_refused() {
        let mut s = good();
        s[0] = b'X';
        assert!(parse(&s, true).is_err());
        assert!(parse(b"", true).is_err());
    }

    #[test]
    fn field_rules_are_enforced() {
        let case = |k: u8, v: &[u8]| parse(&stream(&[rec(k, v), end()]), false).is_err();
        assert!(case(1, b"a\nb"));
        assert!(case(1, b"a\rb"));
        assert!(case(1, b"a\0b"));
        assert!(case(1, &vec![b'a'; 1025]));
        assert!(!case(1, &vec![b'a'; 1024]));
        assert!(case(2, b"12345"));
        assert!(case(2, b"12345678901234567"));
        assert!(case(2, b"12345a"));
        assert!(case(3, b"nope"));
        assert!(case(4, &[0u8; 31]));
        assert!(case(4, &[0u8; 33]));
    }

    #[test]
    fn required_secrets_are_required_only_when_asked() {
        let s = stream(&[rec(1, b"p"), end()]);
        assert!(parse(&s, true).unwrap_err().message.contains("required"));
        assert!(parse(&s, false).is_ok());
        assert!(parse(&stream(&[end()]), true).is_err());
    }

    #[test]
    fn oversize_streams_are_refused() {
        // Four records of 2500 bytes each pass the per-field size of a token only if valid, so
        // use owner-key-sized lies: the total cap fires on the declared length first.
        let mut s = MAGIC.to_vec();
        s.extend_from_slice(&[1, 0xff, 0xff]);
        let e = parse(&s, false).unwrap_err();
        assert!(e.message.contains("8192"), "{}", e.message);
    }

    #[test]
    fn bytes_after_the_end_record_are_refused() {
        let mut s = good();
        s.push(0);
        assert!(parse(&s, true).unwrap_err().message.contains("follow"));
    }

    #[test]
    fn the_thirty_second_limit_is_a_deadline_on_a_stuck_writer() {
        let (a, mut b) = UnixStream::pair().unwrap();
        b.write_all(MAGIC).unwrap();
        // Nothing more: the reader must give up at its deadline (shortened here).
        let mut r = FdReader::new(a, Instant::now() + Duration::from_millis(150));
        let t = Instant::now();
        let e = read_frames(&mut r, true).unwrap_err();
        assert!(e.message.contains("30 seconds"), "{}", e.message);
        assert!(t.elapsed() < Duration::from_secs(5));
        drop(b);
    }

    #[test]
    fn a_closed_writer_is_eof_not_a_hang() {
        let (a, mut b) = UnixStream::pair().unwrap();
        b.write_all(&good()[..9]).unwrap();
        drop(b);
        let mut r = FdReader::new(a, Instant::now() + Duration::from_secs(5));
        assert!(read_frames(&mut r, true).is_err());
    }

    #[test]
    fn a_quiet_open_pipe_after_the_end_record_is_accepted() {
        let (a, mut b) = UnixStream::pair().unwrap();
        b.write_all(&good()).unwrap();
        let mut r = FdReader::new(a, Instant::now() + Duration::from_millis(200));
        assert!(read_frames(&mut r, true).is_ok());
        drop(b);
    }

    #[test]
    fn fd0_becomes_dev_null() {
        redirect_stdin_to_null().unwrap();
        let t = std::fs::read_link("/proc/self/fd/0").unwrap();
        assert_eq!(t, std::path::Path::new("/dev/null"));
    }

    #[test]
    fn frames_never_print() {
        let f = parse(&good(), true).unwrap();
        let s = format!("{f:?}");
        assert!(!s.contains("pass word") && !s.contains("123456"));
    }
}

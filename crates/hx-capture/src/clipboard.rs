//! X11 selections (clipboard) in both directions.
//!
//! A worker thread owns a private X connection and an invisible window and does everything
//! an ICCCM selection owner and requestor must:
//!
//! * **Local owner changes are watched** with XFixes selection notifications. When a local
//!   application takes the clipboard, the worker asks it for `TARGETS` and reports the
//!   formats as MIME types ([`ClipboardEvent::LocalOffer`]). Nothing is read until someone
//!   asks ([`Clipboard::fetch_local`]), so copying a large image costs nothing until it is
//!   pasted on the other side.
//! * **Reading** converts the selection to the best matching target (`UTF8_STRING`,
//!   `image/png`, `text/uri-list`), receives `INCR` transfers, and enforces a size limit and
//!   a per-step timeout. A hostile owner can neither exhaust memory nor hang the worker.
//! * **Serving**: when the client owns the clipboard ([`Clipboard::offer_remote`]) the worker
//!   takes the X selection and answers `TARGETS` and conversion requests from a
//!   [`RemoteProvider`], using `INCR` above the chunk size. Data is requested from the
//!   provider lazily, once per format per offer.
//! * **PRIMARY** is off unless [`ClipboardConfig::primary`] is set.
//!
//! MIME types used here: [`MIME_TEXT`], [`MIME_PNG`], [`MIME_URI_LIST`].

use crate::CaptureError;
use crossbeam_channel::{Receiver, Sender, bounded};
use rustix::event::{EventfdFlags, PollFd, PollFlags, eventfd, poll};
use rustix::io::Errno;
use rustix::time::Timespec;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use thiserror::Error;
use x11rb::connection::{Connection, RequestConnection};
use x11rb::protocol::Event;
use x11rb::protocol::xfixes::{self, ConnectionExt as _, SelectionEventMask};
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ChangeWindowAttributesAux, ConnectionExt as _, CreateWindowAux, EventMask,
    PropMode, Property, SELECTION_NOTIFY_EVENT, SelectionNotifyEvent, Window, WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::{CURRENT_TIME, NONE};

pub const MIME_TEXT: &str = "text/plain;charset=utf-8";
pub const MIME_PNG: &str = "image/png";
pub const MIME_URI_LIST: &str = "text/uri-list";

/// Largest chunk written to a property in one request (and the `INCR` chunk size).
const MAX_CHUNK: usize = 256 * 1024;
/// Concurrent `INCR` sends to local applications.
const MAX_INCR_OUT: usize = 8;
/// Largest number of conversion jobs waiting behind the active one.
const MAX_QUEUED_JOBS: usize = 32;
const EVENT_QUEUE: usize = 32;

/// Which X selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Selection {
    Clipboard,
    Primary,
}

/// What the worker reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClipboardEvent {
    /// A local application took the selection and offers these MIME types.
    LocalOffer {
        selection: Selection,
        formats: Vec<String>,
    },
    /// The selection has no owner any more.
    LocalCleared { selection: Selection },
    /// A local application took the selection from the client's offer.
    OwnershipLost { selection: Selection },
}

/// Source of the data for an offer made on behalf of the client. Called on the worker
/// thread when a local application asks for a format; it may block, but must return within
/// [`ClipboardConfig::provider_timeout`] or the requester gets a refusal.
pub trait RemoteProvider: Send + Sync {
    /// The bytes of `mime`, at most `max` of them, or `None` if they cannot be had.
    fn fetch(&self, mime: &str, max: u64) -> Option<Vec<u8>>;
}

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("display: {0}")]
    Display(#[from] CaptureError),
    #[error("nobody owns the selection")]
    NoOwner,
    #[error("the selection is owned by the client's own offer")]
    OwnedByClient,
    #[error("the owner offers no usable {0}")]
    Unsupported(String),
    #[error("data exceeds the limit of {0} bytes")]
    TooLarge(u64),
    #[error("timed out")]
    Timeout,
    #[error("the owner refused the conversion")]
    Refused,
    #[error("another job is queued too deep")]
    Busy,
    #[error("the clipboard worker has stopped")]
    Closed,
}

impl From<x11rb::errors::ConnectionError> for ClipboardError {
    fn from(e: x11rb::errors::ConnectionError) -> Self {
        CaptureError::from(e).into()
    }
}

impl From<x11rb::errors::ReplyError> for ClipboardError {
    fn from(e: x11rb::errors::ReplyError) -> Self {
        CaptureError::from(e).into()
    }
}

impl From<x11rb::errors::ReplyOrIdError> for ClipboardError {
    fn from(e: x11rb::errors::ReplyOrIdError) -> Self {
        CaptureError::from_reply_or_id(e).into()
    }
}

#[derive(Clone, Debug)]
pub struct ClipboardConfig {
    /// Display name; `None` uses `$DISPLAY`.
    pub display: Option<String>,
    /// Also watch and serve PRIMARY (select-to-copy). Off by default.
    pub primary: bool,
    /// Largest payload in either direction. Protocol: 64 MiB.
    pub max_bytes: u64,
    /// How long a local owner may take to start, and between `INCR` chunks.
    pub step_timeout: Duration,
    /// How long the provider may take to produce data for a local requester.
    pub provider_timeout: Duration,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            display: None,
            primary: false,
            max_bytes: 64 * 1024 * 1024,
            step_timeout: Duration::from_secs(5),
            provider_timeout: Duration::from_secs(5),
        }
    }
}

enum Cmd {
    Fetch {
        selection: Selection,
        mime: String,
        reply: Sender<Result<Vec<u8>, ClipboardError>>,
    },
    Offer {
        selection: Selection,
        formats: Vec<String>,
        provider: Arc<dyn RemoteProvider>,
        reply: Sender<Result<(), ClipboardError>>,
    },
    Clear {
        selection: Selection,
    },
    Stop,
}

/// Handle to the clipboard worker. Dropping it stops the thread.
pub struct Clipboard {
    cmds: Sender<Cmd>,
    wake: Arc<OwnedFd>,
    events: Receiver<ClipboardEvent>,
    thread: Option<JoinHandle<()>>,
    step_timeout: Duration,
}

impl fmt::Debug for Clipboard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Clipboard").finish_non_exhaustive()
    }
}

impl Clipboard {
    pub fn start(cfg: ClipboardConfig) -> Result<Self, ClipboardError> {
        let wake = Arc::new(
            eventfd(0, EventfdFlags::NONBLOCK | EventfdFlags::CLOEXEC)
                .map_err(CaptureError::from)?,
        );
        let (cmd_tx, cmd_rx) = bounded(64);
        let (ev_tx, ev_rx) = bounded(EVENT_QUEUE);
        let step_timeout = cfg.step_timeout;
        let worker = Worker::new(cfg, cmd_rx, ev_tx, wake.clone())?;
        let thread = std::thread::Builder::new()
            .name("hx-clipboard".into())
            .spawn(move || worker.run())
            .map_err(CaptureError::from)?;
        Ok(Self {
            cmds: cmd_tx,
            wake,
            events: ev_rx,
            thread: Some(thread),
            step_timeout,
        })
    }

    /// Owner changes of the local clipboard.
    pub fn events(&self) -> &Receiver<ClipboardEvent> {
        &self.events
    }

    fn send(&self, cmd: Cmd) -> Result<(), ClipboardError> {
        self.cmds.try_send(cmd).map_err(|_| ClipboardError::Busy)?;
        let _ = rustix::io::write(&*self.wake, &1u64.to_ne_bytes());
        Ok(())
    }

    /// Read `mime` from the local owner of `selection`. Blocks until the data is complete,
    /// the limit is hit, or the owner stalls.
    pub fn fetch_local(&self, selection: Selection, mime: &str) -> Result<Vec<u8>, ClipboardError> {
        let (tx, rx) = bounded(1);
        self.send(Cmd::Fetch {
            selection,
            mime: mime.to_owned(),
            reply: tx,
        })?;
        // The worker enforces per-step deadlines; this only guards against a dead worker.
        match rx.recv_timeout(Duration::from_secs(600).max(self.step_timeout)) {
            Ok(r) => r,
            Err(_) => Err(ClipboardError::Closed),
        }
    }

    /// Make the client the owner of `selection`, offering `formats` (MIME types), with data
    /// coming from `provider` on demand. Replaces an earlier offer.
    pub fn offer_remote(
        &self,
        selection: Selection,
        formats: Vec<String>,
        provider: Arc<dyn RemoteProvider>,
    ) -> Result<(), ClipboardError> {
        let (tx, rx) = bounded(1);
        self.send(Cmd::Offer {
            selection,
            formats,
            provider,
            reply: tx,
        })?;
        rx.recv_timeout(self.step_timeout * 2)
            .map_err(|_| ClipboardError::Closed)?
    }

    /// Drop the client's offer, if it is still the owner.
    pub fn clear_remote(&self, selection: Selection) -> Result<(), ClipboardError> {
        self.send(Cmd::Clear { selection })
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        let _ = self.cmds.try_send(Cmd::Stop);
        let _ = rustix::io::write(&*self.wake, &1u64.to_ne_bytes());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ---------------------------------------------------------------------------------------

struct Atoms {
    clipboard: Atom,
    targets: Atom,
    utf8: Atom,
    text: Atom,
    text_utf8: Atom,
    text_plain: Atom,
    png: Atom,
    uri_list: Atom,
    gnome_files: Atom,
    incr: Atom,
    prop: Atom,
}

impl Atoms {
    fn load(conn: &RustConnection) -> Result<Self, ClipboardError> {
        let names: [&[u8]; 10] = [
            b"CLIPBOARD",
            b"TARGETS",
            b"UTF8_STRING",
            b"TEXT",
            b"text/plain;charset=utf-8",
            b"text/plain",
            b"image/png",
            b"text/uri-list",
            b"x-special/gnome-copied-files",
            b"INCR",
        ];
        let cookies: Vec<_> = names
            .iter()
            .map(|n| conn.intern_atom(false, n))
            .collect::<Result<_, _>>()?;
        let prop = conn.intern_atom(false, b"HX_CLIPBOARD_DATA")?;
        let mut a = Vec::new();
        for c in cookies {
            a.push(c.reply()?.atom);
        }
        Ok(Self {
            clipboard: a[0],
            targets: a[1],
            utf8: a[2],
            text: a[3],
            text_utf8: a[4],
            text_plain: a[5],
            png: a[6],
            uri_list: a[7],
            gnome_files: a[8],
            incr: a[9],
            prop: prop.reply()?.atom,
        })
    }

    fn selection(&self, s: Selection) -> Atom {
        match s {
            Selection::Clipboard => self.clipboard,
            Selection::Primary => AtomEnum::PRIMARY.into(),
        }
    }

    fn which(&self, atom: Atom) -> Option<Selection> {
        if atom == self.clipboard {
            Some(Selection::Clipboard)
        } else if atom == u32::from(AtomEnum::PRIMARY) {
            Some(Selection::Primary)
        } else {
            None
        }
    }

    /// Targets that deliver `mime`, best first.
    fn read_targets(&self, mime: &str) -> Vec<Atom> {
        match mime {
            MIME_TEXT => vec![
                self.utf8,
                self.text_utf8,
                AtomEnum::STRING.into(),
                self.text,
            ],
            MIME_PNG => vec![self.png],
            MIME_URI_LIST => vec![self.uri_list],
            _ => Vec::new(),
        }
    }

    /// MIME types offered by a TARGETS list.
    fn mimes_of(&self, targets: &[Atom]) -> Vec<String> {
        let has = |a: Atom| targets.contains(&a);
        let mut out = Vec::new();
        if has(self.utf8) || has(self.text_utf8) || has(AtomEnum::STRING.into()) || has(self.text) {
            out.push(MIME_TEXT.to_owned());
        }
        if has(self.png) {
            out.push(MIME_PNG.to_owned());
        }
        if has(self.uri_list) {
            out.push(MIME_URI_LIST.to_owned());
        }
        out
    }

    /// The MIME type a request for `target` is served from, with the conversion needed.
    fn serve_mime(&self, target: Atom) -> Option<(&'static str, Conv)> {
        if target == self.utf8 || target == self.text_utf8 || target == self.text_plain {
            Some((MIME_TEXT, Conv::None))
        } else if target == u32::from(AtomEnum::STRING) || target == self.text {
            Some((MIME_TEXT, Conv::Latin1))
        } else if target == self.png {
            Some((MIME_PNG, Conv::None))
        } else if target == self.uri_list {
            Some((MIME_URI_LIST, Conv::None))
        } else if target == self.gnome_files {
            Some((MIME_URI_LIST, Conv::GnomeFiles))
        } else {
            None
        }
    }

    /// Target atoms announced for an offered MIME type.
    fn announce(&self, mime: &str) -> Vec<Atom> {
        match mime {
            MIME_TEXT => vec![
                self.utf8,
                self.text_utf8,
                self.text_plain,
                AtomEnum::STRING.into(),
                self.text,
            ],
            MIME_PNG => vec![self.png],
            MIME_URI_LIST => vec![self.uri_list, self.gnome_files],
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Conv {
    None,
    Latin1,
    GnomeFiles,
}

fn utf8_to_latin1(data: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(data)
        .chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
        .collect()
}

fn latin1_to_utf8(data: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|b| char::from(*b))
        .collect::<String>()
        .into_bytes()
}

/// `text/uri-list` (CRLF lines, `#` comments) to the file-manager "copied files" format.
fn uri_list_to_gnome(list: &[u8]) -> Vec<u8> {
    let mut out = b"copy".to_vec();
    for line in String::from_utf8_lossy(list).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(b'\n');
        out.extend_from_slice(line.as_bytes());
    }
    out
}

enum JobKind {
    Probe,
    Data {
        mime: String,
        reply: Sender<Result<Vec<u8>, ClipboardError>>,
    },
}

struct Job {
    selection: Selection,
    kind: JobKind,
}

struct Active {
    job: Job,
    /// Targets still to try, front first.
    targets: VecDeque<Atom>,
    target: Atom,
    incr: bool,
    buf: Vec<u8>,
    deadline: Instant,
}

struct Owned {
    formats: Vec<String>,
    provider: Arc<dyn RemoteProvider>,
    cache: HashMap<String, Arc<Vec<u8>>>,
}

struct IncrOut {
    requestor: Window,
    property: Atom,
    target: Atom,
    data: Arc<Vec<u8>>,
    offset: usize,
    /// All data and the closing empty chunk have been written.
    finished: bool,
    deadline: Instant,
}

struct Worker {
    cfg: ClipboardConfig,
    conn: RustConnection,
    win: Window,
    atoms: Atoms,
    cmds: Receiver<Cmd>,
    events: Sender<ClipboardEvent>,
    wake: Arc<OwnedFd>,
    selections: Vec<Selection>,
    /// TARGETS last seen per selection.
    targets: HashMap<Selection, Vec<Atom>>,
    owned: HashMap<Selection, Owned>,
    queue: VecDeque<Job>,
    active: Option<Active>,
    incr_out: Vec<IncrOut>,
    max_chunk: usize,
    stop: bool,
}

impl Worker {
    fn new(
        cfg: ClipboardConfig,
        cmds: Receiver<Cmd>,
        events: Sender<ClipboardEvent>,
        wake: Arc<OwnedFd>,
    ) -> Result<Self, ClipboardError> {
        let (conn, num) =
            RustConnection::connect(cfg.display.as_deref()).map_err(CaptureError::from)?;
        let root = conn.setup().roots[num].root;
        if conn
            .extension_information(xfixes::X11_EXTENSION_NAME)?
            .is_none()
        {
            return Err(CaptureError::MissingExtension("XFIXES", "2.0").into());
        }
        conn.xfixes_query_version(5, 0)?.reply()?;
        let win = conn.generate_id()?;
        conn.create_window(
            0,
            win,
            root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_ONLY,
            0,
            &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        )?
        .check()?;
        let atoms = Atoms::load(&conn)?;
        let mut selections = vec![Selection::Clipboard];
        if cfg.primary {
            selections.push(Selection::Primary);
        }
        let mask = SelectionEventMask::SET_SELECTION_OWNER
            | SelectionEventMask::SELECTION_WINDOW_DESTROY
            | SelectionEventMask::SELECTION_CLIENT_CLOSE;
        for s in &selections {
            conn.xfixes_select_selection_input(win, atoms.selection(*s), mask)?
                .check()?;
        }
        let max_chunk = conn
            .maximum_request_bytes()
            .saturating_sub(1024)
            .clamp(4096, MAX_CHUNK);
        conn.flush()?;
        let mut w = Self {
            cfg,
            conn,
            win,
            atoms,
            cmds,
            events,
            wake,
            selections,
            targets: HashMap::new(),
            owned: HashMap::new(),
            queue: VecDeque::new(),
            active: None,
            incr_out: Vec::new(),
            max_chunk,
            stop: false,
        };
        // Whoever owns the clipboard at startup is an offer too.
        for s in w.selections.clone() {
            if w.owner_of(s).is_some_and(|o| o != NONE && o != w.win) {
                w.enqueue(Job {
                    selection: s,
                    kind: JobKind::Probe,
                });
            }
        }
        Ok(w)
    }

    fn owner_of(&self, s: Selection) -> Option<Window> {
        self.conn
            .get_selection_owner(self.atoms.selection(s))
            .ok()?
            .reply()
            .ok()
            .map(|r| r.owner)
    }

    fn emit(&self, ev: ClipboardEvent) {
        let _ = self.events.try_send(ev);
    }

    fn run(mut self) {
        loop {
            self.drain_commands();
            if self.stop {
                break;
            }
            if self.pump_events().is_err() {
                break;
            }
            self.expire();
            self.start_next();
            let timeout = self.next_deadline();
            if self.block(timeout).is_err() {
                break;
            }
        }
        // Fail whatever is still waiting so no caller hangs.
        if let Some(a) = self.active.take() {
            finish_job(a.job, Err(ClipboardError::Closed));
        }
        for j in self.queue.drain(..) {
            finish_job(j, Err(ClipboardError::Closed));
        }
    }

    fn block(&self, timeout: Option<Duration>) -> Result<(), ClipboardError> {
        self.conn.flush()?;
        let ts = timeout.map(|d| Timespec {
            tv_sec: d.as_secs().min(i64::MAX as u64) as i64,
            tv_nsec: i64::from(d.subsec_nanos()),
        });
        let mut fds = [
            PollFd::new(self.conn.stream(), PollFlags::IN),
            PollFd::new(&*self.wake, PollFlags::IN),
        ];
        match poll(&mut fds, ts.as_ref()) {
            Ok(_) | Err(Errno::INTR) => {}
            Err(e) => return Err(CaptureError::from(e).into()),
        }
        if fds[1].revents().contains(PollFlags::IN) {
            let mut buf = [0u8; 8];
            let _ = rustix::io::read(&*self.wake, &mut buf);
        }
        Ok(())
    }

    fn next_deadline(&self) -> Option<Duration> {
        let now = Instant::now();
        self.active
            .iter()
            .map(|a| a.deadline)
            .chain(self.incr_out.iter().map(|i| i.deadline))
            .min()
            .map(|d| d.saturating_duration_since(now))
    }

    // ---- commands ----

    fn drain_commands(&mut self) {
        while let Ok(cmd) = self.cmds.try_recv() {
            match cmd {
                Cmd::Stop => self.stop = true,
                Cmd::Fetch {
                    selection,
                    mime,
                    reply,
                } => {
                    if !self.selections.contains(&selection) {
                        let _ = reply.send(Err(ClipboardError::Unsupported("selection".into())));
                    } else if self.owned.contains_key(&selection) {
                        let _ = reply.send(Err(ClipboardError::OwnedByClient));
                    } else {
                        self.enqueue(Job {
                            selection,
                            kind: JobKind::Data { mime, reply },
                        });
                    }
                }
                Cmd::Offer {
                    selection,
                    formats,
                    provider,
                    reply,
                } => {
                    let r = self.take_selection(selection, formats, provider);
                    let _ = reply.send(r);
                }
                Cmd::Clear { selection } => self.release_selection(selection),
            }
        }
    }

    fn enqueue(&mut self, job: Job) {
        if let JobKind::Probe = job.kind {
            // One pending probe per selection is enough: the newest owner wins.
            if self
                .queue
                .iter()
                .any(|j| j.selection == job.selection && matches!(j.kind, JobKind::Probe))
            {
                return;
            }
        }
        if self.queue.len() >= MAX_QUEUED_JOBS {
            finish_job(job, Err(ClipboardError::Busy));
            return;
        }
        self.queue.push_back(job);
    }

    fn take_selection(
        &mut self,
        selection: Selection,
        formats: Vec<String>,
        provider: Arc<dyn RemoteProvider>,
    ) -> Result<(), ClipboardError> {
        if !self.selections.contains(&selection) {
            return Err(ClipboardError::Unsupported("selection".into()));
        }
        let formats: Vec<String> = formats
            .into_iter()
            .filter(|f| !self.atoms.announce(f).is_empty())
            .collect();
        if formats.is_empty() {
            return Err(ClipboardError::Unsupported("format".into()));
        }
        let atom = self.atoms.selection(selection);
        self.conn
            .set_selection_owner(self.win, atom, CURRENT_TIME)?;
        self.conn.flush()?;
        if self.owner_of(selection) != Some(self.win) {
            return Err(ClipboardError::Refused);
        }
        self.owned.insert(
            selection,
            Owned {
                formats,
                provider,
                cache: HashMap::new(),
            },
        );
        Ok(())
    }

    fn release_selection(&mut self, selection: Selection) {
        if self.owned.remove(&selection).is_some() {
            let atom = self.atoms.selection(selection);
            let _ = self.conn.set_selection_owner(NONE, atom, CURRENT_TIME);
        }
    }

    // ---- X events ----

    fn pump_events(&mut self) -> Result<(), ClipboardError> {
        while let Some(ev) = self.conn.poll_for_event()? {
            match ev {
                Event::XfixesSelectionNotify(e) => self.on_owner_change(e.selection, e.owner),
                Event::SelectionNotify(e) => self.on_selection_notify(&e),
                Event::SelectionRequest(e) => self.on_request(&e)?,
                Event::SelectionClear(e) => {
                    if e.owner == self.win
                        && let Some(s) = self.atoms.which(e.selection)
                        && self.owned.remove(&s).is_some()
                    {
                        self.emit(ClipboardEvent::OwnershipLost { selection: s });
                    }
                }
                Event::PropertyNotify(e) => self.on_property(&e)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn on_owner_change(&mut self, selection: Atom, owner: Window) {
        let Some(s) = self.atoms.which(selection) else {
            return;
        };
        if owner == self.win {
            return; // our own offer
        }
        // Someone else owns it now: the client's offer, if any, is gone.
        if self.owned.remove(&s).is_some() {
            self.emit(ClipboardEvent::OwnershipLost { selection: s });
        }
        if owner == NONE {
            self.targets.remove(&s);
            self.emit(ClipboardEvent::LocalCleared { selection: s });
        } else {
            self.enqueue(Job {
                selection: s,
                kind: JobKind::Probe,
            });
        }
    }

    // ---- reading ----

    fn start_next(&mut self) {
        while self.active.is_none() {
            let Some(job) = self.queue.pop_front() else {
                return;
            };
            let targets: VecDeque<Atom> = match &job.kind {
                JobKind::Probe => VecDeque::from([self.atoms.targets]),
                JobKind::Data { mime, .. } => {
                    let known = self.targets.get(&job.selection);
                    let wanted = self.atoms.read_targets(mime);
                    // Prefer targets the owner announced; with no TARGETS knowledge, try all.
                    let mut t: VecDeque<Atom> = match known {
                        Some(k) => wanted.iter().copied().filter(|a| k.contains(a)).collect(),
                        None => wanted.iter().copied().collect(),
                    };
                    if t.is_empty() {
                        let what = mime.clone();
                        finish_job(job, Err(ClipboardError::Unsupported(what)));
                        continue;
                    }
                    let first = t.pop_front();
                    first.into_iter().chain(t).collect()
                }
            };
            let mut active = Active {
                job,
                targets,
                target: 0,
                incr: false,
                buf: Vec::new(),
                deadline: Instant::now() + self.cfg.step_timeout,
            };
            if self.convert_next(&mut active) {
                self.active = Some(active);
            } else {
                finish_job(active.job, Err(ClipboardError::Refused));
            }
        }
    }

    /// Ask the owner for the next candidate target. False when none are left.
    fn convert_next(&self, a: &mut Active) -> bool {
        let Some(target) = a.targets.pop_front() else {
            return false;
        };
        a.target = target;
        a.incr = false;
        a.buf.clear();
        a.deadline = Instant::now() + self.cfg.step_timeout;
        let sel = self.atoms.selection(a.job.selection);
        let ok = self.conn.delete_property(self.win, self.atoms.prop).is_ok()
            && self
                .conn
                .convert_selection(self.win, sel, target, self.atoms.prop, CURRENT_TIME)
                .is_ok();
        ok && self.conn.flush().is_ok()
    }

    fn on_selection_notify(&mut self, e: &x11rb::protocol::xproto::SelectionNotifyEvent) {
        let Some(mut a) = self.active.take() else {
            return;
        };
        if e.requestor != self.win
            || self.atoms.selection(a.job.selection) != e.selection
            || e.target != a.target
        {
            self.active = Some(a);
            return;
        }
        if e.property == NONE {
            // Refused: try the next candidate target.
            if self.convert_next(&mut a) {
                self.active = Some(a);
            } else {
                finish_job(a.job, Err(ClipboardError::Refused));
            }
            return;
        }
        match self.read_property(&mut a, false) {
            Step::More => self.active = Some(a),
            Step::Done(r) => self.complete(a, r),
        }
    }

    fn on_property(
        &mut self,
        e: &x11rb::protocol::xproto::PropertyNotifyEvent,
    ) -> Result<(), ClipboardError> {
        if e.window == self.win && e.atom == self.atoms.prop && e.state == Property::NEW_VALUE {
            if let Some(mut a) = self.active.take() {
                if a.incr {
                    match self.read_property(&mut a, true) {
                        Step::More => self.active = Some(a),
                        Step::Done(r) => self.complete(a, r),
                    }
                } else {
                    self.active = Some(a);
                }
            }
        } else if e.state == Property::DELETE {
            self.advance_incr_out(e.window, e.atom)?;
        }
        Ok(())
    }

    /// Read the property after a notification. `chunk` is a follow-up INCR chunk.
    fn read_property(&self, a: &mut Active, chunk: bool) -> Step {
        let limit = self.cfg.max_bytes;
        let long_len = (limit / 4 + 2).min(u64::from(u32::MAX / 4)) as u32;
        let reply = match self
            .conn
            .get_property(false, self.win, self.atoms.prop, AtomEnum::ANY, 0, long_len)
            .map_err(ClipboardError::from)
            .and_then(|c| c.reply().map_err(ClipboardError::from))
        {
            Ok(r) => r,
            Err(e) => return Step::Done(Err(e)),
        };
        let _ = self.conn.delete_property(self.win, self.atoms.prop);
        let _ = self.conn.flush();
        if !chunk && reply.type_ == self.atoms.incr {
            a.incr = true;
            a.deadline = Instant::now() + self.cfg.step_timeout;
            return Step::More;
        }
        if reply.bytes_after > 0 {
            return Step::Done(Err(ClipboardError::TooLarge(limit)));
        }
        if chunk {
            if reply.value.is_empty() {
                return Step::Done(Ok(std::mem::take(&mut a.buf)));
            }
            if (a.buf.len() + reply.value.len()) as u64 > limit {
                return Step::Done(Err(ClipboardError::TooLarge(limit)));
            }
            a.buf.extend_from_slice(&reply.value);
            a.deadline = Instant::now() + self.cfg.step_timeout;
            return Step::More;
        }
        if reply.value.len() as u64 > limit {
            return Step::Done(Err(ClipboardError::TooLarge(limit)));
        }
        Step::Done(Ok(reply.value))
    }

    fn complete(&mut self, a: Active, result: Result<Vec<u8>, ClipboardError>) {
        let sel = a.job.selection;
        match (a.job.kind, result) {
            (JobKind::Probe, Ok(raw)) => {
                let atoms: Vec<Atom> = raw
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| u32::from_ne_bytes(*c))
                    .collect();
                let formats = self.atoms.mimes_of(&atoms);
                self.targets.insert(sel, atoms);
                self.emit(ClipboardEvent::LocalOffer {
                    selection: sel,
                    formats,
                });
            }
            (JobKind::Probe, Err(_)) => {
                // A silent or broken owner: treat as no usable offer.
                self.targets.remove(&sel);
                self.emit(ClipboardEvent::LocalOffer {
                    selection: sel,
                    formats: Vec::new(),
                });
            }
            (JobKind::Data { reply, .. }, r) => {
                let r = r.map(|d| {
                    if a.target == u32::from(AtomEnum::STRING) || a.target == self.atoms.text {
                        // Legacy targets are Latin-1 (or unspecified); normalise to UTF-8.
                        if std::str::from_utf8(&d).is_ok() {
                            d
                        } else {
                            latin1_to_utf8(&d)
                        }
                    } else {
                        d
                    }
                });
                let _ = reply.send(r);
            }
        }
    }

    fn expire(&mut self) {
        let now = Instant::now();
        if self.active.as_ref().is_some_and(|a| a.deadline <= now)
            && let Some(a) = self.active.take()
        {
            let _ = self.conn.delete_property(self.win, self.atoms.prop);
            self.complete(a, Err(ClipboardError::Timeout));
        }
        self.incr_out.retain(|i| i.deadline > now);
    }

    // ---- serving ----

    fn on_request(
        &mut self,
        e: &x11rb::protocol::xproto::SelectionRequestEvent,
    ) -> Result<(), ClipboardError> {
        let property = if e.property == NONE {
            e.target
        } else {
            e.property
        };
        let granted = self.serve(e, property);
        let notify = SelectionNotifyEvent {
            response_type: SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: e.time,
            requestor: e.requestor,
            selection: e.selection,
            target: e.target,
            property: if granted { property } else { NONE },
        };
        self.conn
            .send_event(false, e.requestor, EventMask::NO_EVENT, notify)?;
        self.conn.flush()?;
        Ok(())
    }

    /// Fill `property` on the requestor. False means refuse.
    fn serve(
        &mut self,
        e: &x11rb::protocol::xproto::SelectionRequestEvent,
        property: Atom,
    ) -> bool {
        let Some(sel) = self.atoms.which(e.selection) else {
            return false;
        };
        if e.owner != self.win || !self.owned.contains_key(&sel) {
            return false;
        }
        if e.target == self.atoms.targets {
            let owned = &self.owned[&sel];
            let mut list = vec![self.atoms.targets];
            for f in &owned.formats {
                list.extend(self.atoms.announce(f));
            }
            return self
                .conn
                .change_property32(
                    PropMode::REPLACE,
                    e.requestor,
                    property,
                    AtomEnum::ATOM,
                    &list,
                )
                .is_ok();
        }
        let Some((mime, conv)) = self.atoms.serve_mime(e.target) else {
            return false;
        };
        let Some(owned) = self.owned.get_mut(&sel) else {
            return false;
        };
        if !owned.formats.iter().any(|f| f == mime) {
            return false;
        }
        let raw = match owned.cache.get(mime) {
            Some(d) => d.clone(),
            None => {
                let provider = owned.provider.clone();
                let Some(d) = provider.fetch(mime, self.cfg.max_bytes) else {
                    return false;
                };
                if d.len() as u64 > self.cfg.max_bytes {
                    return false;
                }
                let d = Arc::new(d);
                if let Some(o) = self.owned.get_mut(&sel) {
                    o.cache.insert(mime.to_owned(), d.clone());
                }
                d
            }
        };
        let data: Arc<Vec<u8>> = match conv {
            Conv::None => raw,
            Conv::Latin1 => Arc::new(utf8_to_latin1(&raw)),
            Conv::GnomeFiles => Arc::new(uri_list_to_gnome(&raw)),
        };
        let type_: Atom = e.target;
        if data.len() <= self.max_chunk {
            return self
                .conn
                .change_property8(PropMode::REPLACE, e.requestor, property, type_, &data)
                .is_ok();
        }
        // INCR: announce the size, then feed chunks as the requestor deletes the property.
        if self.incr_out.len() >= MAX_INCR_OUT {
            return false;
        }
        let ok = self
            .conn
            .change_window_attributes(
                e.requestor,
                &ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE),
            )
            .is_ok()
            && self
                .conn
                .change_property32(
                    PropMode::REPLACE,
                    e.requestor,
                    property,
                    self.atoms.incr,
                    &[u32::try_from(data.len()).unwrap_or(u32::MAX)],
                )
                .is_ok();
        if ok {
            self.incr_out.push(IncrOut {
                requestor: e.requestor,
                property,
                target: type_,
                data,
                offset: 0,
                finished: false,
                deadline: Instant::now() + self.cfg.step_timeout,
            });
        }
        ok
    }

    fn advance_incr_out(&mut self, window: Window, property: Atom) -> Result<(), ClipboardError> {
        let Some(i) = self
            .incr_out
            .iter()
            .position(|t| t.requestor == window && t.property == property)
        else {
            return Ok(());
        };
        if self.incr_out[i].finished {
            self.incr_out.swap_remove(i);
            return Ok(());
        }
        let step = self.cfg.step_timeout;
        let max_chunk = self.max_chunk;
        let t = &mut self.incr_out[i];
        let end = (t.offset + max_chunk).min(t.data.len());
        let chunk = &t.data[t.offset..end];
        self.conn
            .change_property8(PropMode::REPLACE, t.requestor, t.property, t.target, chunk)?;
        if chunk.is_empty() {
            t.finished = true;
        }
        t.offset = end;
        t.deadline = Instant::now() + step;
        self.conn.flush()?;
        Ok(())
    }
}

enum Step {
    More,
    Done(Result<Vec<u8>, ClipboardError>),
}

fn finish_job(job: Job, err: Result<Vec<u8>, ClipboardError>) {
    if let JobKind::Data { reply, .. } = job.kind {
        let _ = reply.send(err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latin1_round_trip_and_replacement() {
        assert_eq!(utf8_to_latin1("caf\u{e9}".as_bytes()), b"caf\xe9");
        assert_eq!(utf8_to_latin1("\u{20ac}".as_bytes()), b"?");
        assert_eq!(latin1_to_utf8(b"caf\xe9"), "caf\u{e9}".as_bytes());
    }

    #[test]
    fn uri_list_becomes_the_copied_files_format() {
        let list = b"# comment\r\nfile:///a/b%20c.txt\r\nfile:///d\r\n";
        assert_eq!(
            uri_list_to_gnome(list),
            b"copy\nfile:///a/b%20c.txt\nfile:///d".to_vec()
        );
    }
}

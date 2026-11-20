//! Clipboard engine against a private Xvfb, with an independent minimal X client written
//! here as the "other application" (owner and requester, with INCR in both directions).

mod common;

use common::Xvfb;
use crossbeam_channel::RecvTimeoutError;
use hx_capture::clipboard::{
    Clipboard, ClipboardConfig, ClipboardError, ClipboardEvent, MIME_PNG, MIME_TEXT, MIME_URI_LIST,
    RemoteProvider, Selection,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ChangeWindowAttributesAux, ConnectionExt as _, CreateWindowAux, EventMask,
    PropMode, Property, SELECTION_NOTIFY_EVENT, SelectionNotifyEvent, WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::{CURRENT_TIME, NONE};

const W: u32 = 320;
const H: u32 = 200;
const INCR_THRESHOLD: usize = 100_000;
const SECOND: Duration = Duration::from_secs(5);

struct App {
    conn: RustConnection,
    win: u32,
}

fn atom(conn: &RustConnection, name: &str) -> Atom {
    conn.intern_atom(false, name.as_bytes())
        .unwrap()
        .reply()
        .unwrap()
        .atom
}

fn selection_atom(conn: &RustConnection, sel: Selection) -> Atom {
    match sel {
        Selection::Clipboard => atom(conn, "CLIPBOARD"),
        Selection::Primary => AtomEnum::PRIMARY.into(),
    }
}

impl App {
    fn new(x: &Xvfb) -> Self {
        let (conn, n) = RustConnection::connect(Some(&x.display)).unwrap();
        let root = conn.setup().roots[n].root;
        let win = conn.generate_id().unwrap();
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
        )
        .unwrap()
        .check()
        .unwrap();
        Self { conn, win }
    }

    fn own(&self, sel: Selection) {
        let s = selection_atom(&self.conn, sel);
        self.conn
            .set_selection_owner(self.win, s, CURRENT_TIME)
            .unwrap();
        self.conn.flush().unwrap();
        assert_eq!(
            self.conn
                .get_selection_owner(s)
                .unwrap()
                .reply()
                .unwrap()
                .owner,
            self.win
        );
    }

    fn disown(&self, sel: Selection) {
        let s = selection_atom(&self.conn, sel);
        self.conn
            .set_selection_owner(NONE, s, CURRENT_TIME)
            .unwrap();
        self.conn.flush().unwrap();
    }

    /// Request `target` of `sel` from its owner, following INCR. Returns (type name, data).
    fn request(&self, sel: Selection, target: &str) -> Result<(Atom, Vec<u8>), &'static str> {
        let s = selection_atom(&self.conn, sel);
        let t = atom(&self.conn, target);
        let prop = atom(&self.conn, "APP_RECV");
        let incr = atom(&self.conn, "INCR");
        self.conn
            .convert_selection(self.win, s, t, prop, CURRENT_TIME)
            .unwrap();
        self.conn.flush().unwrap();
        let end = Instant::now() + SECOND;
        let mut out = Vec::new();
        let mut in_incr = false;
        let mut type_ = 0;
        while Instant::now() < end {
            let Some(ev) = self.conn.poll_for_event().unwrap() else {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            };
            match ev {
                Event::SelectionNotify(e) if !in_incr => {
                    if e.property == NONE {
                        return Err("refused");
                    }
                    let r = self
                        .conn
                        .get_property(true, self.win, prop, AtomEnum::ANY, 0, u32::MAX / 4)
                        .unwrap()
                        .reply()
                        .unwrap();
                    type_ = r.type_;
                    if r.type_ == incr {
                        in_incr = true;
                    } else {
                        return Ok((r.type_, r.value));
                    }
                }
                Event::PropertyNotify(e)
                    if in_incr && e.atom == prop && e.state == Property::NEW_VALUE =>
                {
                    let r = self
                        .conn
                        .get_property(true, self.win, prop, AtomEnum::ANY, 0, u32::MAX / 4)
                        .unwrap()
                        .reply()
                        .unwrap();
                    if r.value.is_empty() {
                        return Ok((type_, out));
                    }
                    type_ = r.type_;
                    out.extend_from_slice(&r.value);
                }
                _ => {}
            }
        }
        Err("timeout")
    }

    /// Become the owner of `sel`, answering requests from `items` (target name -> bytes)
    /// until the returned handle is dropped. `silent` ignores every request.
    fn serve(self, sel: Selection, items: Vec<(&'static str, Vec<u8>)>, silent: bool) -> Server {
        self.own(sel);
        let stop = Arc::new(AtomicBool::new(false));
        let log = Arc::new(Mutex::new(Vec::new()));
        let (stop2, log2) = (stop.clone(), log.clone());
        let thread = std::thread::spawn(move || {
            let conn = &self.conn;
            let table: Vec<(Atom, &'static str, Vec<u8>)> = items
                .into_iter()
                .map(|(n, d)| (atom(conn, n), n, d))
                .collect();
            let targets = atom(conn, "TARGETS");
            let incr = atom(conn, "INCR");
            struct Out {
                requestor: u32,
                prop: Atom,
                type_: Atom,
                data: Vec<u8>,
                off: usize,
                done: bool,
            }
            let mut outs: Vec<Out> = Vec::new();
            while !stop2.load(SeqCst) {
                let Some(ev) = conn.poll_for_event().unwrap() else {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                };
                match ev {
                    Event::SelectionRequest(e) if !silent => {
                        let prop = if e.property == NONE {
                            e.target
                        } else {
                            e.property
                        };
                        log2.lock().unwrap().push(
                            String::from_utf8(
                                conn.get_atom_name(e.target).unwrap().reply().unwrap().name,
                            )
                            .unwrap(),
                        );
                        let mut ok = false;
                        if e.target == targets {
                            let mut list = vec![targets];
                            list.extend(table.iter().map(|t| t.0));
                            conn.change_property32(
                                PropMode::REPLACE,
                                e.requestor,
                                prop,
                                AtomEnum::ATOM,
                                &list,
                            )
                            .unwrap();
                            ok = true;
                        } else if let Some((a, _, d)) = table.iter().find(|t| t.0 == e.target) {
                            if d.len() > INCR_THRESHOLD {
                                conn.change_window_attributes(
                                    e.requestor,
                                    &ChangeWindowAttributesAux::new()
                                        .event_mask(EventMask::PROPERTY_CHANGE),
                                )
                                .unwrap();
                                conn.change_property32(
                                    PropMode::REPLACE,
                                    e.requestor,
                                    prop,
                                    incr,
                                    &[d.len() as u32],
                                )
                                .unwrap();
                                outs.push(Out {
                                    requestor: e.requestor,
                                    prop,
                                    type_: *a,
                                    data: d.clone(),
                                    off: 0,
                                    done: false,
                                });
                            } else {
                                conn.change_property8(PropMode::REPLACE, e.requestor, prop, *a, d)
                                    .unwrap();
                            }
                            ok = true;
                        }
                        let n = SelectionNotifyEvent {
                            response_type: SELECTION_NOTIFY_EVENT,
                            sequence: 0,
                            time: e.time,
                            requestor: e.requestor,
                            selection: e.selection,
                            target: e.target,
                            property: if ok { prop } else { NONE },
                        };
                        conn.send_event(false, e.requestor, EventMask::NO_EVENT, n)
                            .unwrap();
                        conn.flush().unwrap();
                    }
                    Event::PropertyNotify(e) if e.state == Property::DELETE => {
                        if let Some(i) = outs
                            .iter()
                            .position(|o| o.requestor == e.window && o.prop == e.atom)
                        {
                            if outs[i].done {
                                outs.remove(i);
                            } else {
                                let o = &mut outs[i];
                                let end = (o.off + 65_536).min(o.data.len());
                                conn.change_property8(
                                    PropMode::REPLACE,
                                    o.requestor,
                                    o.prop,
                                    o.type_,
                                    &o.data[o.off..end],
                                )
                                .unwrap();
                                if end == o.off {
                                    o.done = true;
                                }
                                o.off = end;
                                conn.flush().unwrap();
                            }
                        }
                    }
                    _ => {}
                }
            }
        });
        Server {
            stop,
            log,
            thread: Some(thread),
        }
    }
}

struct Server {
    stop: Arc<AtomicBool>,
    log: Arc<Mutex<Vec<String>>>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn clipboard(x: &Xvfb, tweak: impl FnOnce(&mut ClipboardConfig)) -> Clipboard {
    let mut cfg = ClipboardConfig {
        display: Some(x.display.clone()),
        step_timeout: Duration::from_millis(1500),
        ..ClipboardConfig::default()
    };
    tweak(&mut cfg);
    Clipboard::start(cfg).expect("start clipboard")
}

fn next_event(c: &Clipboard) -> Option<ClipboardEvent> {
    c.events().recv_timeout(SECOND).ok()
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

struct Provider {
    items: HashMap<&'static str, Vec<u8>>,
    calls: AtomicUsize,
}

impl Provider {
    fn new(items: Vec<(&'static str, Vec<u8>)>) -> Arc<Self> {
        Arc::new(Self {
            items: items.into_iter().collect(),
            calls: AtomicUsize::new(0),
        })
    }
}

impl RemoteProvider for Provider {
    fn fetch(&self, mime: &str, _max: u64) -> Option<Vec<u8>> {
        self.calls.fetch_add(1, SeqCst);
        self.items.get(mime).cloned()
    }
}

const TEXT: &str = "h\u{e9}llo w\u{f6}rld \u{2713} \u{1f600}";

#[test]
fn local_text_is_offered_and_read() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |_| {});
    let srv = App::new(&x).serve(
        Selection::Clipboard,
        vec![("UTF8_STRING", TEXT.as_bytes().to_vec())],
        false,
    );
    assert_eq!(
        next_event(&c),
        Some(ClipboardEvent::LocalOffer {
            selection: Selection::Clipboard,
            formats: vec![MIME_TEXT.to_owned()],
        })
    );
    assert_eq!(
        c.fetch_local(Selection::Clipboard, MIME_TEXT).unwrap(),
        TEXT.as_bytes()
    );
    // One TARGETS probe when the owner changed, one conversion for the read: nothing else.
    assert_eq!(srv.requests(), vec!["TARGETS", "UTF8_STRING"]);
    // Not offered: refused without hanging.
    assert!(matches!(
        c.fetch_local(Selection::Clipboard, MIME_PNG),
        Err(ClipboardError::Unsupported(_))
    ));
}

#[test]
fn legacy_string_target_is_converted_to_utf8() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |_| {});
    let _srv = App::new(&x).serve(
        Selection::Clipboard,
        vec![("STRING", b"caf\xe9".to_vec())],
        false,
    );
    assert!(next_event(&c).is_some());
    assert_eq!(
        c.fetch_local(Selection::Clipboard, MIME_TEXT).unwrap(),
        "caf\u{e9}".as_bytes()
    );
}

#[test]
fn local_image_round_trips_including_incr() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |_| {});
    let png = {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend(pattern(3 * 1024 * 1024));
        v
    };
    let _srv = App::new(&x).serve(
        Selection::Clipboard,
        vec![("image/png", png.clone()), ("UTF8_STRING", b"x".to_vec())],
        false,
    );
    let Some(ClipboardEvent::LocalOffer { formats, .. }) = next_event(&c) else {
        panic!("no offer")
    };
    assert_eq!(formats, vec![MIME_TEXT.to_owned(), MIME_PNG.to_owned()]);
    assert_eq!(c.fetch_local(Selection::Clipboard, MIME_PNG).unwrap(), png);
}

#[test]
fn local_file_list_is_read() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |_| {});
    let list = b"file:///tmp/a.txt\r\nfile:///tmp/b%20c.png\r\n".to_vec();
    let _srv = App::new(&x).serve(
        Selection::Clipboard,
        vec![("text/uri-list", list.clone())],
        false,
    );
    let Some(ClipboardEvent::LocalOffer { formats, .. }) = next_event(&c) else {
        panic!("no offer")
    };
    assert_eq!(formats, vec![MIME_URI_LIST.to_owned()]);
    assert_eq!(
        c.fetch_local(Selection::Clipboard, MIME_URI_LIST).unwrap(),
        list
    );
}

#[test]
fn oversized_data_is_refused_for_plain_and_incr() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |cfg| cfg.max_bytes = 1024 * 1024);
    let _srv = App::new(&x).serve(
        Selection::Clipboard,
        vec![
            ("image/png", pattern(3 * 1024 * 1024)),
            ("UTF8_STRING", pattern(90_000)),
        ],
        false,
    );
    assert!(next_event(&c).is_some());
    assert!(matches!(
        c.fetch_local(Selection::Clipboard, MIME_PNG),
        Err(ClipboardError::TooLarge(_))
    ));
    // The engine is still usable afterwards.
    assert_eq!(
        c.fetch_local(Selection::Clipboard, MIME_TEXT)
            .unwrap()
            .len(),
        90_000
    );
}

#[test]
fn a_silent_owner_times_out_and_does_not_wedge_the_worker() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |cfg| cfg.step_timeout = Duration::from_millis(300));
    let silent = App::new(&x).serve(
        Selection::Clipboard,
        vec![("UTF8_STRING", b"a".to_vec())],
        true,
    );
    // The probe gets no answer: an offer with no formats is reported.
    assert_eq!(
        next_event(&c),
        Some(ClipboardEvent::LocalOffer {
            selection: Selection::Clipboard,
            formats: vec![],
        })
    );
    assert!(matches!(
        c.fetch_local(Selection::Clipboard, MIME_TEXT),
        Err(ClipboardError::Timeout | ClipboardError::Unsupported(_))
    ));
    drop(silent);
    let _good = App::new(&x).serve(
        Selection::Clipboard,
        vec![("UTF8_STRING", b"ok".to_vec())],
        false,
    );
    while let Some(ClipboardEvent::LocalOffer { formats, .. }) = next_event(&c) {
        if !formats.is_empty() {
            break;
        }
    }
    assert_eq!(
        c.fetch_local(Selection::Clipboard, MIME_TEXT).unwrap(),
        b"ok"
    );
}

#[test]
fn owner_leaving_is_reported() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |_| {});
    let app = App::new(&x);
    app.own(Selection::Clipboard);
    // No server loop: the probe times out quickly with a short step timeout elsewhere, so
    // only look for the clear.
    app.disown(Selection::Clipboard);
    let mut cleared = false;
    while let Some(ev) = next_event(&c) {
        if ev
            == (ClipboardEvent::LocalCleared {
                selection: Selection::Clipboard,
            })
        {
            cleared = true;
            break;
        }
    }
    assert!(cleared);
}

#[test]
fn primary_is_ignored_unless_enabled() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let _srv = App::new(&x).serve(
        Selection::Primary,
        vec![("UTF8_STRING", b"p".to_vec())],
        false,
    );
    {
        let c = clipboard(&x, |_| {});
        assert_eq!(
            c.events().recv_timeout(Duration::from_millis(600)),
            Err(RecvTimeoutError::Timeout)
        );
        assert!(c.fetch_local(Selection::Primary, MIME_TEXT).is_err());
    }
    let c = clipboard(&x, |cfg| cfg.primary = true);
    // The owner from before is picked up at startup.
    let Some(ClipboardEvent::LocalOffer { selection, .. }) = next_event(&c) else {
        panic!("no offer")
    };
    assert_eq!(selection, Selection::Primary);
    assert_eq!(c.fetch_local(Selection::Primary, MIME_TEXT).unwrap(), b"p");
}

#[test]
fn client_text_is_served_to_local_applications() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |_| {});
    let p = Provider::new(vec![(MIME_TEXT, TEXT.as_bytes().to_vec())]);
    c.offer_remote(Selection::Clipboard, vec![MIME_TEXT.to_owned()], p.clone())
        .unwrap();
    let app = App::new(&x);
    let (_, targets) = app.request(Selection::Clipboard, "TARGETS").unwrap();
    let ids: Vec<u32> = targets
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_ne_bytes(*c))
        .collect();
    for name in [
        "TARGETS",
        "UTF8_STRING",
        "STRING",
        "text/plain;charset=utf-8",
    ] {
        assert!(ids.contains(&atom(&app.conn, name)), "{name} missing");
    }
    assert!(!ids.contains(&atom(&app.conn, "image/png")));
    let (t, d) = app.request(Selection::Clipboard, "UTF8_STRING").unwrap();
    assert_eq!(t, atom(&app.conn, "UTF8_STRING"));
    assert_eq!(d, TEXT.as_bytes());
    // Legacy STRING gets Latin-1 (unrepresentable characters become '?').
    let (_, d) = app.request(Selection::Clipboard, "STRING").unwrap();
    assert_eq!(d, b"h\xe9llo w\xf6rld ? ?");
    // Formats that were not offered are refused.
    assert_eq!(
        app.request(Selection::Clipboard, "image/png"),
        Err("refused")
    );
    assert_eq!(
        app.request(Selection::Clipboard, "MULTIPLE"),
        Err("refused")
    );
    // One provider call for the text format, however many targets read it.
    assert_eq!(p.calls.load(SeqCst), 1);
}

#[test]
fn client_image_is_served_with_incr() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |_| {});
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend(pattern(2_500_000));
    let p = Provider::new(vec![(MIME_PNG, png.clone())]);
    c.offer_remote(Selection::Clipboard, vec![MIME_PNG.to_owned()], p)
        .unwrap();
    let app = App::new(&x);
    let (_, d) = app.request(Selection::Clipboard, "image/png").unwrap();
    assert_eq!(d.len(), png.len());
    assert!(d == png);
    // A second paste works too (cached, new transfer).
    let (_, d) = app.request(Selection::Clipboard, "image/png").unwrap();
    assert!(d == png);
}

#[test]
fn client_files_are_served_as_uri_list_and_copied_files() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |_| {});
    let list = b"file:///stage/a.txt\r\nfile:///stage/b.png\r\n".to_vec();
    let p = Provider::new(vec![(MIME_URI_LIST, list.clone())]);
    c.offer_remote(Selection::Clipboard, vec![MIME_URI_LIST.to_owned()], p)
        .unwrap();
    let app = App::new(&x);
    assert_eq!(
        app.request(Selection::Clipboard, "text/uri-list")
            .unwrap()
            .1,
        list
    );
    assert_eq!(
        app.request(Selection::Clipboard, "x-special/gnome-copied-files")
            .unwrap()
            .1,
        b"copy\nfile:///stage/a.txt\nfile:///stage/b.png"
    );
}

#[test]
fn provider_failures_and_oversize_are_refused() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |cfg| cfg.max_bytes = 1000);
    let p = Provider::new(vec![(MIME_PNG, pattern(5000))]);
    c.offer_remote(
        Selection::Clipboard,
        vec![MIME_TEXT.to_owned(), MIME_PNG.to_owned()],
        p,
    )
    .unwrap();
    let app = App::new(&x);
    assert_eq!(
        app.request(Selection::Clipboard, "UTF8_STRING"),
        Err("refused")
    ); // no data
    assert_eq!(
        app.request(Selection::Clipboard, "image/png"),
        Err("refused")
    ); // too big
    // Offers with no servable format are rejected up front.
    let p = Provider::new(vec![]);
    assert!(matches!(
        c.offer_remote(Selection::Clipboard, vec!["application/x-evil".into()], p),
        Err(ClipboardError::Unsupported(_))
    ));
}

#[test]
fn taking_the_clipboard_away_reports_lost_ownership() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |_| {});
    let p = Provider::new(vec![(MIME_TEXT, b"mine".to_vec())]);
    c.offer_remote(Selection::Clipboard, vec![MIME_TEXT.to_owned()], p)
        .unwrap();
    // Reading our own offer through the engine is refused rather than deadlocking.
    assert!(matches!(
        c.fetch_local(Selection::Clipboard, MIME_TEXT),
        Err(ClipboardError::OwnedByClient)
    ));
    let _srv = App::new(&x).serve(
        Selection::Clipboard,
        vec![("UTF8_STRING", b"theirs".to_vec())],
        false,
    );
    let mut lost = false;
    let mut offered = false;
    while let Some(ev) = next_event(&c) {
        match ev {
            ClipboardEvent::OwnershipLost { .. } => lost = true,
            ClipboardEvent::LocalOffer { formats, .. } if !formats.is_empty() => {
                offered = true;
            }
            _ => {}
        }
        if lost && offered {
            break;
        }
    }
    assert!(lost && offered);
    assert_eq!(
        c.fetch_local(Selection::Clipboard, MIME_TEXT).unwrap(),
        b"theirs"
    );
}

#[test]
fn dropping_the_handle_stops_the_worker_promptly() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let c = clipboard(&x, |_| {});
    let t = Instant::now();
    drop(c);
    assert!(t.elapsed() < Duration::from_secs(2));
}

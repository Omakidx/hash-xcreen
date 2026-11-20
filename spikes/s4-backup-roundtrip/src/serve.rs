//! Host-side bridge: serves a rustic backend (here the Drive backend) over the restic REST protocol.
//!
//! Why: the backup worker container must never hold the Drive refresh token. It talks to this bridge with
//! rustic's built-in `rest:` backend and a throw-away bridge password; the bridge, running on the host with
//! the token, forwards to Drive. In production hx-privd plays this role (the sandboxed worker gets a
//! repository handle, not Google credentials).
//!
//! Protocol subset: `POST /?create=true`, `HEAD|GET /config`, `GET /<type>/` (v2 list), `GET|POST|DELETE
//! /<type>/<id>`, `Range` on GET, plus `GET /_stats` and `POST /_stats/reset` for the spike's accounting.

use anyhow::{Result, anyhow};
use base64::Engine;
use bytes::Bytes;
use rustic_core::{BytesList, FileType, Id, WriteBackend};
use std::sync::Arc;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

fn tpe_of(s: &str) -> Option<FileType> {
    Some(match s {
        "data" => FileType::Pack,
        "index" => FileType::Index,
        "keys" => FileType::Key,
        "snapshots" => FileType::Snapshot,
        _ => return None,
    })
}

fn text(code: u16, msg: impl Into<String>) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(msg.into()).with_status_code(StatusCode(code))
}

fn handle(
    be: &Arc<dyn WriteBackend>,
    stats: &serde_json::Value,
    rq: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let url = rq.url().to_string();
    let path = url
        .split('?')
        .next()
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
    let query = url.split_once('?').map(|x| x.1).unwrap_or("");
    let method = rq.method().clone();
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let json = |v: serde_json::Value| {
        Response::from_string(v.to_string()).with_header(
            Header::from_bytes("Content-Type", "application/vnd.x.restic.rest.v2").unwrap(),
        )
    };
    let err = |e: Box<rustic_core::RusticError>| -> Response<std::io::Cursor<Vec<u8>>> {
        let m = format!("{e}");
        // not-found is a clean 404 so rustic can tell "absent" from "failed"
        let low = m.to_lowercase();
        if low.contains("notfound") || low.contains("not found") || low.contains("path not found") {
            text(404, m)
        } else {
            text(500, m)
        }
    };

    match (&method, parts.as_slice()) {
        (Method::Post, []) if query.contains("create=true") => match be.create() {
            Ok(()) => text(200, "ok"),
            Err(e) => err(e),
        },
        (Method::Get | Method::Head, ["config"]) => match be.list_with_size(FileType::Config) {
            Ok(v) if v.is_empty() => text(404, "no config"),
            Ok(_) => match be.read_full(FileType::Config, &Id::default()) {
                Ok(b) => Response::from_data(b.to_vec()),
                Err(e) => err(e),
            },
            Err(e) => err(e),
        },
        (Method::Post, ["config"]) => {
            let mut v = vec![];
            if rq.as_reader().read_to_end(&mut v).is_err() {
                return text(400, "read body");
            }
            match be.write_bytes(
                FileType::Config,
                &Id::default(),
                false,
                BytesList::from(Bytes::from(v)),
            ) {
                Ok(()) => text(200, "ok"),
                Err(e) => err(e),
            }
        }
        (Method::Get, ["_stats"]) => json(stats.clone()),
        (Method::Get, [t]) if tpe_of(t).is_some() => match be.list_with_size(tpe_of(t).unwrap()) {
            Ok(v) => json(serde_json::Value::Array(
                v.into_iter()
                    .map(
                        |(id, sz)| serde_json::json!({"name": id.to_hex().to_string(), "size": sz}),
                    )
                    .collect(),
            )),
            Err(e) => err(e),
        },
        (m, [t, id]) if tpe_of(t).is_some() => {
            let tpe = tpe_of(t).unwrap();
            let Ok(id) = id.parse::<Id>() else {
                return text(400, "bad id");
            };
            match m {
                Method::Get | Method::Head => {
                    let range = rq
                        .headers()
                        .iter()
                        .find(|h| h.field.equiv("Range"))
                        .map(|h| h.value.to_string());
                    if let Some(r) = range {
                        let (a, b) = r
                            .trim_start_matches("bytes=")
                            .split_once('-')
                            .and_then(|(a, b)| {
                                Some((a.parse::<u32>().ok()?, b.parse::<u32>().ok()?))
                            })
                            .unwrap_or((0, 0));
                        match be.read_partial(tpe, &id, false, a, b - a + 1) {
                            Ok(b) => {
                                Response::from_data(b.to_vec()).with_status_code(StatusCode(206))
                            }
                            Err(e) => err(e),
                        }
                    } else {
                        match be.read_full(tpe, &id) {
                            Ok(b) => Response::from_data(b.to_vec()),
                            Err(e) => err(e),
                        }
                    }
                }
                Method::Post => {
                    let mut v = vec![];
                    if rq.as_reader().read_to_end(&mut v).is_err() {
                        return text(400, "read body");
                    }
                    match be.write_bytes(tpe, &id, false, BytesList::from(Bytes::from(v))) {
                        Ok(()) => text(200, "ok"),
                        Err(e) => err(e),
                    }
                }
                Method::Delete => match be.remove(tpe, &id, false) {
                    Ok(()) => text(200, "ok"),
                    Err(e) => err(e),
                },
                _ => text(405, "method"),
            }
        }
        _ => text(404, "unknown route"),
    }
}

/// Serve until killed. `stats` is called for `GET /_stats`.
pub fn serve(
    listen: &str,
    user: &str,
    password: &str,
    be: Arc<dyn WriteBackend>,
    stats: Arc<dyn Fn() -> serde_json::Value + Send + Sync>,
    threads: usize,
) -> Result<()> {
    let server = Arc::new(Server::http(listen).map_err(|e| anyhow!("bind {listen}: {e}"))?);
    let want = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    );
    eprintln!("hx bridge listening on {listen} ({threads} threads)");
    let mut hs = vec![];
    for _ in 0..threads {
        let (server, be, want, stats) = (server.clone(), be.clone(), want.clone(), stats.clone());
        hs.push(std::thread::spawn(move || {
            while let Ok(mut rq) = server.recv() {
                let ok = rq
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("Authorization") && h.value.as_str() == want);
                let t = std::time::Instant::now();
                let line = format!("{} {}", rq.method(), rq.url());
                let resp = if ok {
                    handle(&be, &stats(), &mut rq)
                } else {
                    text(401, "unauthorized")
                };
                let code = resp.status_code().0;
                let _ = rq.respond(resp);
                if code >= 400 || t.elapsed().as_secs() >= 5 {
                    eprintln!("{line} -> {code} in {:.1}s", t.elapsed().as_secs_f64());
                }
            }
        }));
    }
    for h in hs {
        let _ = h.join();
    }
    Ok(())
}

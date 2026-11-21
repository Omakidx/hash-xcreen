//! The in-container session units of every recipe (ipc.md 6.11, 11, 21 item 3): file contents and
//! agreement with the Rust constants. Their behaviour in a real unprivileged container is checked
//! by the ignored test in `incus_real_session.rs`.

use std::collections::BTreeMap;

use hx_provision::incus::{SESSION_LINK_CONNECT, SessionLink};
use hx_provision::session::{
    SESSION_BINARY, SESSION_SERVICE_UNIT, SESSION_SOCKET, SESSION_SOCKET_DIR, SESSION_SOCKET_UNIT,
    XSESSION_UNIT,
};
use hx_provision::{Addon, Catalog, Plan, RecipeId, Step};

fn files(p: &Plan) -> BTreeMap<String, (String, String)> {
    p.build
        .iter()
        .filter_map(|s| match s {
            Step::WriteFile(f) => Some((f.path.clone(), (f.content.clone(), f.mode.clone()))),
            _ => None,
        })
        .collect()
}

/// `[Section]` -> every `Key=Value` line in order (a key may repeat).
fn unit(text: &str) -> BTreeMap<String, Vec<(String, String)>> {
    let mut out: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut cur = String::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.starts_with('#') {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            cur = s.to_string();
        } else if let Some((k, v)) = line.split_once('=') {
            out.entry(cur.clone())
                .or_default()
                .push((k.to_string(), v.to_string()));
        }
    }
    out
}

fn get<'a>(u: &'a BTreeMap<String, Vec<(String, String)>>, sec: &str, key: &str) -> Vec<&'a str> {
    u.get(sec)
        .map(|v| {
            v.iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
                .collect()
        })
        .unwrap_or_default()
}

fn has_key(u: &BTreeMap<String, Vec<(String, String)>>, key: &str) -> bool {
    u.values().flatten().any(|(k, _)| k == key)
}

fn each_recipe(mut f: impl FnMut(RecipeId, &Plan)) {
    for rid in RecipeId::all() {
        let p = Catalog::embedded().resolve(rid, &[Addon::Docker]).unwrap();
        f(rid, &p);
    }
}

#[test]
fn the_xfce_unit_is_renamed_everywhere() {
    each_recipe(|rid, p| {
        let f = files(p);
        assert!(
            !f.contains_key("/etc/systemd/user/hx-session.service"),
            "{rid:?}: the old user unit is still written"
        );
        let (text, _) = &f["/etc/systemd/user/hx-xsession.service"];
        assert!(text.contains("ExecStart=/usr/bin/xfce4-session"));
        for step in p.build.iter() {
            if let Step::EnableServices { services, .. } = step {
                assert!(
                    services
                        .user_enable_global
                        .contains(&XSESSION_UNIT.to_string())
                );
                assert!(
                    !services
                        .user_enable_global
                        .contains(&SESSION_SERVICE_UNIT.to_string()),
                    "hx-session.service is a system unit and is not enabled for user managers"
                );
                assert!(
                    services
                        .system_enable
                        .contains(&SESSION_SOCKET_UNIT.to_string())
                );
                assert!(
                    !services
                        .system_enable
                        .contains(&SESSION_SERVICE_UNIT.to_string()),
                    "the service is started by the socket and has no [Install]"
                );
            }
        }
    });
    // No xfce hx-session.service is left anywhere in recipes/ (an `hx-session.service` as the
    // streaming daemon is fine: it is under /etc/systemd/system and never runs xfce4-session).
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../recipes");
    for e in walk(&root) {
        let t = std::fs::read_to_string(&e).unwrap();
        assert!(!t.contains("systemd/user/hx-session.service"), "{e:?}");
        assert!(!t.contains("user_enable_global = [\"hx-session"), "{e:?}");
    }
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            v.extend(walk(&p));
        } else if p.extension().is_some_and(|x| x == "toml") {
            v.push(p);
        }
    }
    v
}

#[test]
fn the_socket_unit_is_as_specified() {
    each_recipe(|_, p| {
        let f = files(p);
        let (text, mode) = &f["/etc/systemd/system/hx-session.socket"];
        assert_eq!(mode, "0644");
        let u = unit(text);
        assert_eq!(get(&u, "Socket", "ListenStream"), [SESSION_SOCKET]);
        assert_eq!(get(&u, "Socket", "SocketUser"), ["1000"]);
        assert_eq!(get(&u, "Socket", "SocketMode"), ["0600"]);
        assert_eq!(get(&u, "Socket", "DirectoryMode"), ["0755"]);
        assert_eq!(get(&u, "Socket", "Accept"), ["no"]);
        assert_eq!(get(&u, "Install", "WantedBy"), ["sockets.target"]);
        // The directory comes from tmpfiles, root-owned, so the desktop user cannot replace the
        // socket path.
        let (tmp, _) = &f["/etc/tmpfiles.d/hx-session.conf"];
        assert!(
            tmp.lines().any(|l| l.split_whitespace().collect::<Vec<_>>()
                == ["d", SESSION_SOCKET_DIR, "0755", "root", "root", "-"]),
            "{tmp}"
        );
        // The writable received-files directory is owned by the desktop uid.
        assert!(
            tmp.lines().any(|l| l.split_whitespace().collect::<Vec<_>>()
                == [
                    "d",
                    "/var/lib/hx-session/received",
                    "0700",
                    "1000",
                    "-",
                    "-"
                ]),
            "{tmp}"
        );
    });
}

#[test]
fn the_service_unit_is_as_specified() {
    each_recipe(|_, p| {
        let f = files(p);
        let (text, mode) = &f["/etc/systemd/system/hx-session.service"];
        assert_eq!(mode, "0644");
        let u = unit(text);

        // Runs the installed binary as the desktop user, started by the socket.
        assert_eq!(get(&u, "Service", "ExecStart"), [SESSION_BINARY]);
        assert_eq!(get(&u, "Service", "User"), ["1000"]);
        assert_eq!(get(&u, "Unit", "Requires"), ["hx-session.socket"]);
        assert!(!u.contains_key("Install"), "started by the socket only");

        // Explicit environment (no PAM session).
        let env = get(&u, "Service", "Environment");
        assert!(env.contains(&"DISPLAY=:0"));
        assert!(env.contains(&"XAUTHORITY=/run/hx-xorg/Xauthority"));
        assert!(env.contains(&"XDG_RUNTIME_DIR=/run/user/1000"));
        assert!(
            get(&u, "Unit", "After")
                .join(" ")
                .contains("user@1000.service")
        );

        // The hardening list of ipc.md 21 item 3.
        let one = |k: &str| get(&u, "Service", k);
        assert_eq!(one("NoNewPrivileges"), ["yes"]);
        assert_eq!(one("CapabilityBoundingSet"), [""]);
        assert_eq!(one("RestrictAddressFamilies"), ["AF_UNIX"]);
        assert_eq!(one("ProtectSystem"), ["strict"]);
        assert_eq!(one("ProtectHome"), ["read-only"]);
        assert_eq!(one("ReadWritePaths"), ["/var/lib/hx-session/received"]);
        assert_eq!(one("LockPersonality"), ["yes"]);
        assert_eq!(one("SystemCallFilter"), ["@system-service"]);
        assert!(!one("TasksMax").is_empty() && !one("MemoryMax").is_empty());

        // Things that must not be there: they break Xorg's abstract socket or hide the X11 socket
        // directory.
        assert!(!has_key(&u, "PrivateNetwork"));
        assert!(!has_key(&u, "PrivateTmp"));
        assert!(!has_key(&u, "PrivateDevices"));

        // Kills everything it started; restart policy that does not trip the start limit fast.
        assert_eq!(one("KillMode"), ["control-group"]);
        assert_eq!(one("Restart"), ["on-failure"]);
        let restart_sec: u32 = one("RestartSec")[0].parse().unwrap();
        let interval: u32 = get(&u, "Unit", "StartLimitIntervalSec")[0].parse().unwrap();
        let burst: u32 = get(&u, "Unit", "StartLimitBurst")[0].parse().unwrap();
        assert!(restart_sec >= 3);
        // A permanent crash loop makes at most interval/restart_sec starts per window; the burst
        // must be well below that, but it takes at least half a minute to reach it.
        assert!(burst * restart_sec >= 30, "limit would trip within 30 s");
        assert!(interval >= 60);
    });
}

#[test]
fn rust_constants_agree_with_the_proxy_device_and_the_recipe() {
    // The proxy device connects to the socket the unit creates.
    assert_eq!(SESSION_LINK_CONNECT, SESSION_SOCKET);
    assert_eq!(
        SessionLink::new("main", (990, 990), (1000, 1000))
            .unwrap()
            .device()["connect"],
        format!("unix:{SESSION_SOCKET}")
    );
    assert_eq!(SESSION_SOCKET, format!("{SESSION_SOCKET_DIR}/link.sock"));
    assert_eq!(SESSION_SOCKET_UNIT, "hx-session.socket");
    assert_eq!(SESSION_SERVICE_UNIT, "hx-session.service");
    assert_eq!(XSESSION_UNIT, "hx-xsession.service");
    assert!(SESSION_BINARY.starts_with("/usr/lib/hx-session/"));
}

#[test]
fn the_received_files_link_is_a_build_step_as_the_user() {
    each_recipe(|_, p| {
        let step = p
            .build
            .iter()
            .find_map(|s| match s {
                Step::Command(c) if c.name == "received-link" => Some(c),
                _ => None,
            })
            .expect("received-link step");
        assert_eq!(step.as_user.as_deref(), Some("desk"));
        assert!(step.run.contains("/var/lib/hx-session/received"));
    });
}

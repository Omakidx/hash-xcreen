//! The real installer, end to end, as root, inside a nested Incus system container (design D8 a).
//!
//! ```text
//! test process (host, unprivileged, group incus-admin)
//!   |  incus exec / file push            +--- CONNECT proxy on the bridge gateway (apt, images)
//!   v                                    |
//!  L1 = hx1e-host-<distro>  (unprivileged system container, systemd as PID 1, root inside)
//!   |  sh install.sh --release-dir ... --ssh   (C2 frames on stdin, C3 JSON Lines on stdout)
//!   |  hx-agent install -> real units (hx-privd, hx-gatewayd, sockets) -> inner Incus
//!   v
//!  inner Incus: pool hx-pool, bridge hxbr0, the desktop container hx-main
//! ```
//!
//! Run it with (the test is `#[ignore]` and does nothing without `HX1E_LOCAL=1`):
//!
//! ```text
//! HX1E_LOCAL=1 sg incus-admin -c 'cargo nextest run -p hx-agent --run-ignored only \
//!     --test install_nested_incus --no-capture'
//! ```
//!
//! Also: `HX1E_DISTROS` (default `ubuntu-24.04`; `ubuntu-24.04,debian-13` runs both),
//! `HX1E_KEEP=1` (leave the `hx1e-` objects for a post-mortem; clean them by hand with
//! `incus delete --force`, `profile delete`, `network delete`, `storage delete`). The test
//! starts by removing the leftovers of an earlier run, and ends by asserting that none is left.
//!
//! # What is real
//!
//! The real `install.sh` (test-keyed copy), the real `hx-agent install`, the real units under real
//! systemd, real privd and gatewayd, `systemd-creds`, the inner Incus the installer installs from
//! the distro, and the desktop build (`CreateDesktop`, recipe `ubuntu-24.04-xfce-basic`). The
//! client is `hx_crypto` and `hx_transport` from this test, over the bridge to `L1-IP:443`.
//!
//! # Safety (this runs on a shared machine)
//!
//! Nothing runs as root on the host, and the harness never runs `nft`, `iptables` or `sysctl`
//! there. Every object is `hx1e-...` with `user.hx1e-test=1`; the `default` profile, `incusbr0`,
//! the `default` pool and every Docker object are only read, and the run asserts they are
//! unchanged. The test bridge has `ipv4.nat=false`, `ipv4.firewall=false`, `ipv4.routing=false`,
//! `ipv6.address=none`, `ipv6.firewall=false` and no ACL: incusd's bridge driver (Incus 6.0.0)
//! then builds no firewall options (FeaturesV4 needs `ipv4.firewall`, SNATV4 needs `ipv4.nat`,
//! ACL needs `security.acls`) and writes no `ip_forward` sysctl (needs `ipv4.routing`), so it
//! adds no host rule at all. The CONNECT proxy on the bridge gateway is L1's only way out.
//!
//! # Deviations from a production host (each is the test's, none changes the product)
//!
//! 1. L1 is a container, so the installer runs with `--test-allow-container`.
//! 2. No loop devices in an unprivileged container: the run stops after stage `incus`, creates
//!    the inner `hx-pool` as a `dir` pool with the hash-xcreen marker (`ensure_host` and the
//!    uninstall's teardown leave or remove it by that marker), then resumes.
//! 3. `vm.max_map_count` and `fs.inotify.*` are not namespaced: privd is built with
//!    `privd-test-hooks`, which turns the sysctl EPERM into a warning.
//! 4. Incus writes `/run/systemd/system/service.d/zzz-lxc-service.conf` into every container,
//!    with `LoadCredential=` (which also clears `LoadCredentialEncrypted=`) and
//!    `NoNewPrivileges=no`. A drop-in `zzzz-hx1e-test.conf` on `hx-privd` and `hx-gatewayd` puts
//!    back the sealed credential and `NoNewPrivileges=yes`. The other keys that file relaxes
//!    (`ProtectProc`, `ProtectKernelTunables`, `ProtectControlGroups`, `ProcSubset`) stay relaxed.
//! 5. `systemd-creds` cannot create its host secret in an unprivileged container (`linkat` with
//!    `AT_EMPTY_PATH` gets ENOENT): the secret is made once with
//!    `setpriv --bounding-set=-dac_read_search systemd-creds setup`, which takes systemd's
//!    temporary-file path instead.
//! 6. The inner Incus's `/etc/subuid` names a range above L1's id map, so unpacking the desktop
//!    image fails (`Failed chown: Invalid argument`): both files are set to `root:100000:900000`.
//! 7. The inner Incus and the desktop's apt reach the internet through the proxy:
//!    `core.proxy_http(s)` on the inner server and `environment.*proxy` on the `hx-desktop`
//!    profile; the installer runs with `--allow-private-networks` so the desktop's ACL lets it
//!    reach the proxy's private address.
//! 8. apt in L1 has a proxy file (`/etc/apt/apt.conf.d/99hx1e-proxy`); `curl`, `openssl`, `acl`
//!    are installed before the run (a real host has them).
//! 9. The session package is real for Ubuntu 24.04 only (the other three are placeholders in the
//!    tarball: their FFmpeg sonames differ and `build-deb.sh` must run on the distro itself).
//! 10. The release is signed with a test key (kept in `target/hx1e/keys` between runs) that the
//!     agent embeds through `test-release-key`; `release-keys/*.pub` are untouched.
//! 11. Not reproduced: TPM sealing, a real reboot (L1 is restarted instead), a loop-file pool,
//!     the Zabbly repository (its key is `UNPROVISIONED`: only L1 distros whose own Incus is
//!     new enough are used, so no `--docker`), cloud firewalls, GitHub downloads.
#![cfg(target_os = "linux")]

mod e2e_common;
mod gateway_common;
mod install_harness;
mod relay_common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use hx_crypto::{PairingToken, PublicKey};
use hx_transport::TransportPreference;
use install_harness::incus::{self as inc, Out};
use install_harness::progress::{RunOut, run_in};
use install_harness::{Artifacts, client, frames, pass, random_hex, random_pin};
use serde_json::Value;

const REL: &str = "/root/release";
const AGENT: &str = "/usr/lib/hx/current/hx-agent";
const PAT: &str = "/root/hx1e-canary.pat";
const HITS: &str = "/root/hx1e-canary.hits";
const USER: &str = "alice";

struct Distro {
    id: &'static str,
    image: &'static str,
    name: &'static str,
    apparmor_signal: bool,
}

const DISTROS: &[Distro] = &[
    Distro {
        id: "ubuntu-24.04",
        image: "images:ubuntu/24.04",
        name: "hx1e-host-u2404",
        apparmor_signal: false,
    },
    Distro {
        id: "debian-13",
        image: "images:debian/13",
        name: "hx1e-host-d13",
        apparmor_signal: true,
    },
];

/// The secrets of one run. They live only here, on L1's stdin pipe and in the pattern file the
/// canary scan reads; none is ever in an argument or an environment variable.
struct Secrets {
    password: String,
    pin: String,
    token: String,
}

impl Secrets {
    fn new() -> Self {
        Self {
            password: format!("Pw-{}", random_hex(10)),
            pin: random_pin(14),
            token: PairingToken::generate()
                .expect("token")
                .to_text()
                .to_string(),
        }
    }

    /// Development only (HX1E_KEEP=1 writes, HX1E_REUSE=1 reads): a kept L1 container has the
    /// secrets of the run that made it, and an attached run needs the same ones. The file is in
    /// the git-ignored target directory, mode 0600, and holds throwaway test values.
    fn for_run(keep: bool, reuse: bool) -> Self {
        let path = install_harness::work_dir().join("kept-secrets");
        if reuse {
            let t =
                std::fs::read_to_string(&path).expect("kept-secrets (run with HX1E_KEEP=1 first)");
            let mut l = t.lines();
            return Self {
                password: l.next().expect("password").to_owned(),
                pin: l.next().expect("pin").to_owned(),
                token: l.next().expect("token").to_owned(),
            };
        }
        let s = Self::new();
        if keep {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .expect("kept-secrets");
            writeln!(f, "{}\n{}\n{}", s.password, s.pin, s.token).expect("write");
        }
        s
    }

    fn frames(&self) -> Vec<u8> {
        frames::stream(&self.password, &self.pin, Some(&self.token), None)
    }

    fn patterns(&self) -> String {
        let body = self.token.strip_prefix("hxt1-").unwrap_or(&self.token);
        format!(
            "{}\n{}\n{}\n{}\n",
            self.password, self.pin, self.token, body
        )
    }

    fn leaks(&self, text: &str) -> bool {
        text.contains(&self.password) || text.contains(&self.pin) || text.contains(&self.token)
    }
}

struct World {
    rt: tokio::runtime::Runtime,
    art: Artifacts,
    proxy_port: u16,
    defaults_before: Vec<(String, String)>,
}

fn env_on(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == "1")
}

#[test]
#[ignore = "needs HX1E_LOCAL=1, Incus and the incus-admin group; see the module docs"]
fn the_real_installer_runs_end_to_end_in_a_nested_incus_container() {
    if !env_on("HX1E_LOCAL") {
        eprintln!("HX1E_LOCAL=1 is not set: nothing to do");
        return;
    }
    let want: Vec<String> = std::env::var("HX1E_DISTROS")
        .unwrap_or_else(|_| "ubuntu-24.04".into())
        .split(',')
        .map(|s| s.trim().to_owned())
        .collect();
    let distros: Vec<&Distro> =
        want.iter()
            .map(|w| {
                DISTROS.iter().find(|d| d.id == w).unwrap_or_else(|| {
                    panic!("unknown distro {w} (known: ubuntu-24.04, debian-13)")
                })
            })
            .collect();

    // Leftovers of an earlier run first, then the objects that must not change. (HX1E_REUSE=1
    // is a development switch: it attaches to the L1 container a HX1E_KEEP=1 run left behind.)
    let reuse = env_on("HX1E_REUSE");
    if !reuse {
        let left = inc::cleanup();
        assert!(left.is_empty(), "cannot clean old hx1e- objects: {left:?}");
    }
    let defaults_before = inc::default_objects();

    let art = install_harness::build_artifacts();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let world = World {
        rt,
        art,
        proxy_port: 0,
        defaults_before,
    };

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut world = world;
        if !reuse {
            inc::create_host_objects();
        }
        let (port, _proxy) = world.rt.block_on(e2e_common::start_proxy(IpAddr::V4(
            inc::BRIDGE_ADDR.parse::<Ipv4Addr>().unwrap(),
        )));
        world.proxy_port = port;
        pass(
            "host",
            "setup",
            format!(
                "pool {}, bridge {} (no NAT, no firewall, no routing, no IPv6), profile {}, CONNECT proxy {}:{port}",
                inc::POOL,
                inc::BRIDGE,
                inc::PROFILE,
                inc::BRIDGE_ADDR
            ),
        );
        for d in &distros {
            run_distro(&world, d);
        }
        world
    }));

    let keep = env_on("HX1E_KEEP");
    if !keep {
        let left = inc::cleanup();
        assert!(left.is_empty(), "objects left after cleanup: {left:?}");
    }
    match outcome {
        Ok(world) => {
            let after = inc::default_objects();
            assert_eq!(
                world.defaults_before, after,
                "the default profile, incusbr0 and the default pool must be unchanged"
            );
            pass(
                "host",
                "default objects",
                "profile default, network incusbr0, storage default unchanged (used_by lists excluded: other sessions share this machine)",
            );
            if !keep {
                pass(
                    "host",
                    "cleanup",
                    "no hx1e- instance, profile, network, storage pool or ACL left",
                );
            }
            install_harness::print_rows();
        }
        Err(e) => std::panic::resume_unwind(e),
    }
}

// ----- one host distro ------------------------------------------------------------------------------------

struct L1<'a> {
    w: &'a World,
    d: &'a Distro,
    secrets: Secrets,
    ip: String,
}

impl L1<'_> {
    fn exec(&self, script: &str) -> Out {
        inc::exec(self.d.name, script)
    }

    fn exec_ok(&self, script: &str) -> String {
        inc::exec_ok(self.d.name, script)
    }

    /// `install.sh` as the app would call it over SSH.
    fn install(&self, port: u16, extra: &[&str]) -> RunOut {
        self.install_with(port, extra, |_| {})
    }

    fn install_with(
        &self,
        port: u16,
        extra: &[&str],
        on_line: impl Fn(&Value) + Send + Sync + 'static,
    ) -> RunOut {
        let port = port.to_string();
        let script = format!("{REL}/install.sh");
        let mut argv: Vec<&str> = vec![
            "sh",
            &script,
            "--release-dir",
            REL,
            "--progress",
            "json",
            "--ssh",
            "--test-allow-container",
            "--user",
            USER,
            "--allow-private-networks",
            "--port",
            &port,
        ];
        argv.extend_from_slice(extra);
        let out = run_in(self.d.name, &argv, &self.secrets.frames(), on_line);
        // The harness is also a consumer of the contract: nothing but JSON on stdout, and no
        // secret on either stream.
        assert!(
            out.nonjson.is_empty(),
            "non-JSON stdout lines: {:?}",
            out.nonjson
        );
        let all = format!("{:?}{}", out.lines, out.stderr);
        assert!(
            !self.secrets.leaks(&all),
            "a secret reached the installer's output"
        );
        out
    }

    fn state(&self) -> Value {
        let raw =
            inc::pull(self.d.name, "/var/lib/hx/install-state.json").expect("install-state.json");
        serde_json::from_slice(&raw).expect("state json")
    }

    fn addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.ip.parse().unwrap(), port)
    }
}

fn run_distro(w: &World, d: &Distro) {
    let t_all = Instant::now();
    let id = d.id;

    let reuse = env_on("HX1E_REUSE");
    let keep = env_on("HX1E_KEEP");
    // ---- launch L1 ----
    if !reuse {
        inc::configure_profile(d.apparmor_signal);
        inc::incus_ok(&[
            "launch",
            d.image,
            d.name,
            "--no-profiles",
            "--profile",
            inc::PROFILE,
        ]);
    }
    let ip = wait_ready(d);
    let l1 = L1 {
        w,
        d,
        secrets: Secrets::for_run(keep, reuse),
        ip,
    };
    let timings = if reuse {
        // Attach: the sampler of the canary starts again; the install is already done.
        l1.exec_ok(&format!(
            "systemctl stop hx1e-canary.service 2>/dev/null; : > {HITS}; systemd-run --unit=hx1e-canary --collect -q sh -c 'while :; do grep -l -a -F -f {PAT} /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null; sleep 0.05; done >> {HITS}'"
        ));
        dropins(&l1);
        Vec::new()
    } else {
        let cfg = inc::incus_ok(&["config", "show", d.name, "--expanded"]);
        for bad in ["security.privileged: \"true\"", "raw.lxc"] {
            assert!(
                !cfg.contains(bad),
                "L1 must not be privileged or use raw.lxc: {cfg}"
            );
        }
        for want in [
            "security.nesting: \"true\"",
            "security.idmap.isolated: \"true\"",
            "limits.kernel.memlock: unlimited",
        ] {
            assert!(cfg.contains(want), "{want} missing: {cfg}");
        }
        pass(
            id,
            "L1 launched",
            format!(
                "{} at {} ({}), unprivileged, nesting, isolated idmap",
                d.name, l1.ip, d.image
            ),
        );

        prelude(&l1);
        pass(
            id,
            "L1 prelude",
            "apt proxy, curl/openssl/acl, systemd-creds host secret, unit drop-ins (deviations 4, 5, 8)",
        );

        // The canary: patterns for the secrets, and a sampler that records any process whose
        // command line or environment holds one, for the whole run.
        inc::push_bytes(d.name, l1.secrets.patterns().as_bytes(), PAT, "0600");
        l1.exec_ok(&format!(
            ": > {HITS}; systemd-run --unit=hx1e-canary --collect -q sh -c 'while :; do grep -l -a -F -f {PAT} /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null; sleep 0.05; done >> {HITS}'"
        ));

        push_release(&l1);
        pass(
            id,
            "release pushed",
            format!(
                "{} files, root-owned, in {REL}",
                l1.exec_ok(&format!("ls {REL} | wc -l")).trim()
            ),
        );

        // ---- clean-host refusals (nothing may change) ----
        refusals(&l1);

        // ---- the resume chain: fail after every stage, then resume ----
        resume_chain(&l1)
    };

    // ---- the finished install ----
    let fin = l1.install(443, &[]);
    assert_eq!(
        fin.exit,
        0,
        "final run: {:?}\n{}",
        fin.lines.last(),
        fin.stderr
    );
    let res = fin.result().expect("result").clone();
    assert_eq!(res["ok"], true, "{res}");
    let server_hex = res["server_public_key"]
        .as_str()
        .expect("server key")
        .to_owned();
    assert_eq!(server_hex.len(), 64, "{res}");
    assert_eq!(res["pairing"]["kind"], "token", "{res}");
    assert_eq!(res["port"], 443);
    pass(
        id,
        "install complete",
        format!(
            "exit 0, server key {}..., desktop {}, port rule {}",
            &server_hex[..12],
            res["desktop"]["path_taken"],
            res["port_rule"]
        ),
    );
    let st = l1.state();
    assert_eq!(st["complete"], true, "{st}");
    assert_eq!(st["mode"], "ssh");
    let order: Vec<String> = fin
        .stages()
        .iter()
        .filter(|s| s.1 == "skip" || s.1 == "done")
        .map(|s| s.0.clone())
        .collect();
    assert!(
        order.starts_with(&["bootstrap-preflight".to_owned()]),
        "{order:?}"
    );

    // ---- units, credentials ----
    units_and_credentials(&l1, &server_hex);

    // ---- pairing and PIN login from the host ----
    let server = client::hex_to_key(&server_hex);
    client_checks(&l1, server, 443, true);

    // ---- secrets canary (Gate 1) ----
    canary(&l1);

    // ---- idempotence ----
    idempotence(&l1);

    // ---- lock ----
    lock_contention(&l1);

    // ---- port change ----
    port_change(&l1, server);

    // ---- rescue ----
    rescue(&l1);

    // ---- restart of L1 ----
    restart(&l1, server);

    // ---- uninstall, both modes ----
    uninstall_both(&l1);

    // ---- measurements ----
    eprintln!("\n==== install duration per stage [{id}] (ms, the run that did the work) ====");
    let mut total = 0u64;
    for (stage, ms) in &timings {
        eprintln!("| {id} | {stage} | {ms} |");
        total += ms;
    }
    eprintln!("| {id} | sum of stages | {total} |");
    eprintln!(
        "| {id} | whole distro run | {} s |",
        t_all.elapsed().as_secs()
    );
    pass(
        id,
        "distro done",
        format!("{} s", t_all.elapsed().as_secs()),
    );
}

// ----- L1 plumbing ------------------------------------------------------------------------------------------

fn wait_ready(d: &Distro) -> String {
    let end = Instant::now() + Duration::from_secs(120);
    loop {
        let o = inc::incus(&["list", d.name, "-c", "4", "--format", "csv"]);
        // One address per line, quoted when there are several ("10.77.0.9 (eth0)" and, once the
        // inner Incus runs, "10.x.y.1 (hxbr0)"): take the one of eth0.
        let ip = o
            .stdout
            .lines()
            .map(|l| l.trim().trim_matches('"'))
            .find(|l| l.ends_with("(eth0)"))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_default()
            .to_owned();
        if ip.parse::<Ipv4Addr>().is_ok() {
            let s = inc::exec(d.name, "systemctl is-system-running --wait 2>&1; true");
            let st = s.stdout.trim().to_owned();
            if st == "running" || st == "degraded" {
                return ip;
            }
        }
        assert!(Instant::now() < end, "L1 {} did not come up: {o:?}", d.name);
        std::thread::sleep(Duration::from_secs(2));
    }
}

const DROPIN: &str = "zzzz-hx1e-test.conf";

/// The drop-ins that put back what Incus's `zzz-lxc-service.conf` removes (deviation 4).
fn dropins(l1: &L1) {
    l1.exec_ok(&format!(
        "for u in hx-gatewayd:identity hx-privd:pepper; do n=${{u%%:*}}; c=${{u##*:}}; mkdir -p /etc/systemd/system/$n.service.d; \
         printf '[Service]\\nLoadCredentialEncrypted=%s:/etc/hx/creds/%s.cred\\nNoNewPrivileges=yes\\n' $c $c > /etc/systemd/system/$n.service.d/{DROPIN}; done; systemctl daemon-reload"
    ));
}

fn prelude(l1: &L1) {
    let p = l1.w.proxy_port;
    let proxy = format!("http://{}:{p}", inc::BRIDGE_ADDR);
    l1.exec_ok(&format!(
        "printf 'Acquire::http::Proxy \"{proxy}\";\\nAcquire::https::Proxy \"{proxy}\";\\n' > /etc/apt/apt.conf.d/99hx1e-proxy; \
         export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq curl openssl ca-certificates acl >/dev/null"
    ));
    // The host secret of systemd-creds (deviation 5).
    l1.exec_ok("setpriv --bounding-set=-dac_read_search systemd-creds setup");
    dropins(l1);
}

fn push_release(l1: &L1) {
    l1.exec_ok(&format!("install -d -m 0755 -o 0 -g 0 {REL}"));
    let dir = &l1.w.art.release_dir;
    for e in std::fs::read_dir(dir).expect("release dir") {
        let e = e.expect("entry");
        if !e.file_type().unwrap().is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let mode = if name == "install.sh" { "0755" } else { "0644" };
        inc::push(l1.d.name, &e.path(), &format!("{REL}/{name}"), mode);
    }
    let own = l1.exec_ok(&format!("stat -c '%U:%G %a' {REL}"));
    assert_eq!(
        own.trim(),
        "root:root 755",
        "install.sh insists on a root-owned release dir"
    );
}

// ----- phases ---------------------------------------------------------------------------------------------

/// A bad invocation changes nothing and exits with the documented code.
fn refusals(l1: &L1) {
    let id = l1.d.id;
    // Not an ssh-mode stdin: no frames at all is a usage error (2) and nothing is installed.
    let out = run_in(
        l1.d.name,
        &[
            "sh",
            &format!("{REL}/install.sh"),
            "--release-dir",
            REL,
            "--progress",
            "json",
            "--ssh",
            "--test-allow-container",
            "--user",
            USER,
        ],
        b"",
        |_| {},
    );
    assert_eq!(
        out.exit, 2,
        "empty stdin must be a usage error: {:?} {}",
        out.lines, out.stderr
    );
    // The agent refuses a port it must not use (22), before changing anything.
    let out = l1.install(22, &[]);
    assert_ne!(out.exit, 0, "port 22 must be refused");
    assert!(
        !l1.exec(&format!("test -e /var/lib/hx/install-state.json"))
            .ok(),
        "a refused run must leave no state"
    );
    let port22 = out.exit;
    // The prebuilt image path and an image file are "not in this release": exit 6, at preflight.
    let pre = l1.install(443, &["--image", "prebuilt"]);
    assert_eq!(
        pre.exit, 6,
        "--image prebuilt: {:?}\n{}",
        pre.lines, pre.stderr
    );
    let file = l1.install(443, &["--image-file", "/root/none.img"]);
    assert_eq!(
        file.exit, 6,
        "--image-file: {:?}\n{}",
        file.lines, file.stderr
    );
    assert!(
        !l1.exec("test -e /var/lib/hx/install-state.json").ok(),
        "a refused run must leave no state"
    );
    assert!(
        !l1.exec("test -e /usr/lib/hx || dpkg -s incus >/dev/null 2>&1")
            .ok(),
        "a refused run must install nothing"
    );
    pass(
        id,
        "refusals change nothing",
        format!(
            "empty stdin exit 2, --port 22 exit {port22}, --image prebuilt exit 6, --image-file exit 6; no state file, no /usr/lib/hx, no incus package"
        ),
    );
}

const CHAIN: &[&str] = &[
    "preflight",
    "packages",
    "incus",
    "release",
    "system-files",
    "credentials",
    "config",
    "units",
    "setup-window",
    "host",
    "firewall-port",
    "desktop",
    "verifiers",
    "backup",
    "pairing",
    "finish",
];

/// Runs the installer with `--test-fail-after <stage>` for each stage in turn; every run resumes
/// where the one before stopped. Returns `(stage, ms)` of the run in which each stage did work.
fn resume_chain(l1: &L1) -> Vec<(String, u64)> {
    let id = l1.d.id;
    let mut timings: Vec<(String, u64)> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for &stage in CHAIN {
        if stage == "release" {
            // Deviation 2, 6, 7: the inner Incus is installed now.
            after_incus(l1);
        }
        dropins(l1);
        let out = if stage == "desktop" {
            desktop_run_with_lock_race(l1)
        } else {
            l1.install(443, &["--test-fail-after", stage])
        };
        assert_eq!(
            out.exit,
            1,
            "after {stage}: {:?}\n{}",
            out.lines.last(),
            out.stderr
        );
        let res = out.result().expect("result");
        assert_eq!(res["ok"], false);
        assert_eq!(
            res["code"], "TEST_HOOK",
            "stage {stage} must stop at the hook, not fail: {res}"
        );
        assert_eq!(res["stage"], stage);
        // Everything earlier is skipped or was done in an earlier run; the hook stage did work or
        // was converged, and nothing after it started.
        for s in &seen {
            let st = out.state_of(s).unwrap_or_default();
            assert!(
                matches!(st.as_str(), "skip" | "done" | "deferred"),
                "{s} after {stage}: {st}"
            );
        }
        let after: Vec<String> = out
            .stages()
            .into_iter()
            .map(|s| s.0)
            .filter(|n| CHAIN.iter().position(|c| c == n) > CHAIN.iter().position(|c| *c == stage))
            .collect();
        assert!(
            after.is_empty(),
            "stages ran past the hook {stage}: {after:?}"
        );
        let ms = out.ms_of(stage).unwrap_or(0);
        timings.push((stage.to_owned(), ms));
        let st = l1.state();
        // `backup` is recorded as deferred (Phase 2: SetBackupSchedule is UNIMPLEMENTED).
        let want = if stage == "backup" {
            "deferred"
        } else {
            "done"
        };
        assert_eq!(st["stages"][stage]["state"], want, "{stage} recorded: {st}");
        assert_eq!(st["complete"], false);
        seen.push(stage);
        pass(
            id,
            &format!("resume: stop after {stage}"),
            format!("exit 1 TEST_HOOK, recorded {want}, {ms} ms; the next run resumes"),
        );
    }
    timings
}

/// After stage `incus`: the dir pool with the marker (no loop devices in a container), the proxy
/// for the inner server, and an id range inside L1's map. Idempotent.
fn after_incus(l1: &L1) {
    let proxy = format!("http://{}:{}", inc::BRIDGE_ADDR, l1.w.proxy_port);
    l1.exec_ok(&format!(
        "printf 'root:100000:900000\\n' > /etc/subuid; printf 'root:100000:900000\\n' > /etc/subgid; systemctl restart incus.service; \
         for i in 1 2 3 4 5 6 7 8 9 10; do incus info >/dev/null 2>&1 && break; sleep 1; done; \
         incus config set core.proxy_http {proxy}; incus config set core.proxy_https {proxy}; \
         if ! incus storage show hx-pool >/dev/null 2>&1; then incus storage create hx-pool dir >/dev/null && \
            incus storage show hx-pool | sed 's/^description:.*/description: hash-xcreen test pool (dir on the btrfs of the L1 container)/' | incus storage edit hx-pool; fi"
    ));
    // The profile exists once stage `host` has run; set its proxy as soon as it does.
}

/// The `hx-desktop` profile's proxy environment (deviation 7); needs stage `host` done.
fn desktop_profile_proxy(l1: &L1) {
    let proxy = format!("http://{}:{}", inc::BRIDGE_ADDR, l1.w.proxy_port);
    l1.exec_ok(&format!(
        "incus profile set hx-desktop environment.http_proxy={proxy} environment.https_proxy={proxy} environment.HTTP_PROXY={proxy} environment.HTTPS_PROXY={proxy}"
    ));
}

/// The `desktop` stage takes minutes: start a second installer while it runs; it must give up
/// with exit 11 and change nothing.
fn desktop_run_with_lock_race(l1: &L1) -> RunOut {
    desktop_profile_proxy(l1);
    let (tx, rx) = mpsc::channel::<()>();
    let tx = std::sync::Mutex::new(tx);
    let name = l1.d.name;
    let race = std::thread::spawn(move || {
        // Wait for the first run to be inside the desktop stage, then race it.
        if rx.recv_timeout(Duration::from_secs(600)).is_err() {
            return None;
        }
        std::thread::sleep(Duration::from_secs(3));
        Some(run_in(
            name,
            &[
                "sh",
                &format!("{REL}/install.sh"),
                "--release-dir",
                REL,
                "--progress",
                "json",
                "--ssh",
                "--test-allow-container",
                "--user",
                USER,
            ],
            b"HXI1\0\0\0",
            |_| {},
        ))
    });
    let out = l1.install_with(443, &["--test-fail-after", "desktop"], move |v| {
        if v["t"] == "stage" && v["id"] == "desktop" && v["state"] == "start" {
            let _ = tx.lock().unwrap().send(());
        }
    });
    let second = race
        .join()
        .expect("race thread")
        .expect("the first run reached the desktop stage");
    assert_eq!(
        second.exit, 11,
        "a second installer must exit 11: {:?} {}",
        second.lines, second.stderr
    );
    pass(
        l1.d.id,
        "lock",
        format!(
            "second installer during stage desktop: exit 11 ({})",
            second.stderr.trim().lines().last().unwrap_or("")
        ),
    );
    out
}

fn units_and_credentials(l1: &L1, server_hex: &str) {
    let id = l1.d.id;
    let act = l1.exec_ok("systemctl is-active hx-privd.socket hx-gatewayd-admin.socket hx-gatewayd-public.socket incus.socket");
    assert!(act.lines().all(|l| l == "active"), "units: {act}");
    let fw = l1.exec_ok("systemctl is-enabled hx-host-firewall.service");
    assert_eq!(
        fw.trim(),
        "enabled",
        "hx-host-firewall.service must be enabled for the next boot"
    );
    // The public socket is socket-activated: a connection starts gatewayd (checked below by the
    // client); here the sockets listen on 443 for both protocols.
    let ss = l1.exec_ok("ss -H -ltnu");
    assert!(ss.contains("*:443"), "{ss}");
    assert!(
        ss.lines().filter(|l| l.contains(":443")).count() >= 2,
        "tcp and udp: {ss}"
    );
    pass(
        id,
        "units active",
        "hx-privd.socket, hx-gatewayd-{admin,public}.socket, incus.socket (active) and hx-host-firewall.service (enabled; it only reloads the ruleset at boot, privd loaded it now); 443 tcp+udp listening",
    );

    // The whole boot transaction, not just our units: an ordering cycle through an hx unit makes
    // systemd delete a start job at boot (it deleted systemd-tmpfiles-setup.service once).
    let dt = l1.exec("systemd-analyze verify default.target 2>&1");
    let cyc: Vec<String> = format!("{}{}", dt.stdout, dt.stderr)
        .lines()
        .filter(|l| l.contains("ordering cycle") || l.contains("deleted to break"))
        .map(str::to_owned)
        .collect();
    assert!(
        cyc.is_empty(),
        "ordering cycle in the boot transaction: {cyc:?}"
    );
    let v = l1.exec("systemd-analyze verify /usr/local/lib/systemd/system/hx-privd.service /usr/local/lib/systemd/system/hx-privd.socket /usr/local/lib/systemd/system/hx-gatewayd.service /usr/local/lib/systemd/system/hx-gatewayd-admin.socket /usr/local/lib/systemd/system/hx-gatewayd-public.socket /usr/local/lib/systemd/system/hx-host-firewall.service /usr/local/lib/systemd/system/hx-privd-rescue.service 2>&1");
    let text = format!("{}{}", v.stdout, v.stderr);
    let bad: Vec<&str> = text
        .lines()
        .filter(|l| {
            l.to_lowercase().contains("error")
                || l.contains("Failed")
                || l.contains("not found")
                || l.contains("Unknown")
        })
        .collect();
    assert!(bad.is_empty(), "systemd-analyze verify: {text}");
    pass(
        id,
        "systemd-analyze verify",
        format!(
            "exit {}, {} warning lines, no error",
            v.code,
            text.lines().count()
        ),
    );

    // Sealed credentials, no plaintext pepper.
    let ls = l1.exec_ok("ls -l /etc/hx/creds");
    assert!(
        ls.contains("pepper.cred") && ls.contains("identity.cred"),
        "{ls}"
    );
    assert!(
        ls.lines()
            .filter(|l| l.contains(".cred"))
            .all(|l| l.starts_with("-rw-------") && l.contains("root root")),
        "{ls}"
    );
    assert!(
        !l1.exec("ls /var/lib/hx/pepper.key 2>/dev/null").ok()
            || l1.exec("test -e /var/lib/hx/pepper.key").code != 0,
        "pepper.key must not exist"
    );
    let key = l1.exec("test -e /var/lib/hx/pepper.key");
    assert_ne!(key.code, 0, "pepper.key exists");
    let head = l1.exec_ok("head -c 24 /etc/hx/creds/identity.cred | od -An -c | head -1");
    // A sealed credential is not the seed: it must not decrypt without systemd (no plaintext hex).
    assert!(!head.contains(server_hex), "{head}");
    // The gateway process runs with its credential directory.
    let gw = l1.exec("systemctl is-active hx-gatewayd.service; ls -l /run/credentials/hx-gatewayd.service/ 2>&1; getfacl -p /run/credentials/hx-gatewayd.service/identity 2>&1");
    pass(
        id,
        "credentials sealed",
        format!(
            "pepper.cred + identity.cred 0600 root, no pepper.key; gatewayd credential dir: {}",
            gw.stdout
                .replace('\n', " | ")
                .chars()
                .take(400)
                .collect::<String>()
        ),
    );
}

/// Pairs (when `cred` is given) and logs in with the PIN, from the host to `L1-IP:port`.
fn token_pair_and_login(
    l1: &L1,
    server: PublicKey,
    port: u16,
    pref: TransportPreference,
    name: &str,
    cred: Option<&str>,
) -> hx_transport::Connection {
    l1.w.rt.block_on(client::pair_and_login(
        l1.addr(port),
        server,
        pref,
        name,
        &l1.secrets.pin,
        cred,
    ))
}

/// A fresh pairing code, made by the CLI on L1 (what the user would read out to the app).
fn new_code(l1: &L1) -> String {
    let code = l1.exec_ok(&format!(
        "{AGENT} pairing code 2>&1 | grep -Eo '[0-9A-Z]{{4}}-[0-9A-Z]{{4}}' | head -1"
    ));
    let code = code.trim().to_owned();
    assert_eq!(code.len(), 9, "pairing code: {code:?}");
    code
}

/// Pairing with the app's token (the install's last frame) and the PIN login, over QUIC and over
/// WebSocket, against `L1-IP:port`; then, if the desktop runs, the first frame.
fn client_checks(l1: &L1, server: PublicKey, port: u16, first_pair: bool) {
    let id = l1.d.id;
    if first_pair {
        let t0 = Instant::now();
        let conn = token_pair_and_login(
            l1,
            server,
            port,
            TransportPreference::Quic,
            "hx1e-quic",
            Some(&l1.secrets.token),
        );
        let quic_ms = t0.elapsed().as_millis();
        pass(
            id,
            "pair + PIN login over QUIC",
            format!("the app's token paired, server key pinned, PIN accepted in {quic_ms} ms"),
        );
        stream_check(l1, conn);
        // A token is single use.
        let refused = l1.w.rt.block_on(client::pairing_is_refused(
            l1.addr(port),
            TransportPreference::Quic,
            &l1.secrets.token,
        ));
        assert!(refused, "a used token must not pair again");
        pass(
            id,
            "token is single use",
            "a second pairing with the same token is refused",
        );
    }
    // WebSocket: pair with a fresh code created on L1 through the CLI, then log in with the PIN.
    let code = new_code(l1);
    let t0 = Instant::now();
    let _c = token_pair_and_login(
        l1,
        server,
        port,
        TransportPreference::WebSocket,
        "hx1e-ws",
        Some(&code),
    );
    pass(
        id,
        "pair + PIN login over WebSocket",
        format!(
            "pairing code from hx-agent, PIN accepted in {} ms",
            t0.elapsed().as_millis()
        ),
    );
}

/// If the desktop and its session run: ViewConfig, then an IDR of the real desktop.
fn stream_check(l1: &L1, conn: hx_transport::Connection) {
    let id = l1.d.id;
    let session = l1
        .exec("incus exec hx-main -- systemctl is-active hx-session.socket")
        .stdout
        .trim()
        .to_owned();
    if session != "active" {
        pass(
            id,
            "stream: first frame",
            format!("skipped: hx-session.socket in the desktop is {session:?}"),
        );
        return;
    }
    match l1.w.rt.block_on(client::first_frame(conn, 90)) {
        Some((bytes, ms)) => pass(
            id,
            "stream: first frame",
            format!(
                "an IDR of {bytes} bytes {ms} ms after ViewConfig, from the desktop built inside L1"
            ),
        ),
        None => panic!("no IDR within 90 s although hx-session.socket is active"),
    }
}

fn canary(l1: &L1) {
    let id = l1.d.id;
    l1.exec_ok("systemctl stop hx1e-canary.service || true");
    let hits = l1.exec_ok(&format!("sort -u {HITS} | head -20; true"));
    assert!(
        hits.trim().is_empty(),
        "a secret was in /proc/<pid>/cmdline or environ while the sampler ran: {hits}"
    );
    let j = l1.exec_ok(&format!(
        "journalctl -a --no-pager 2>/dev/null | grep -a -F -c -f {PAT}; true"
    ));
    assert_eq!(j.trim(), "0", "a secret is in the journal");
    let files = l1.exec_ok(&format!(
        "grep -r -a -F -l -f {PAT} /var/log/hx /var/log/hx-install.log /etc/hx /var/lib/hx /var/lib/hx-gatewayd /run/hx /run/credentials /usr/lib/hx /usr/local/lib/systemd /etc/systemd 2>/dev/null; true"
    ));
    assert!(files.trim().is_empty(), "a secret is on disk: {files}");
    let n = l1
        .exec_ok("journalctl -a --no-pager 2>/dev/null | wc -l")
        .trim()
        .to_owned();
    pass(
        id,
        "secrets canary (Gate 1)",
        format!(
            "password, PIN, token (and its body) absent from /proc/*/cmdline and environ (sampled every 50 ms for the whole run), the journal ({n} lines), /var/log/hx*, the state file, /etc/hx, /var/lib/hx*, /run/hx, /run/credentials, the units"
        ),
    );
}

const HASHES: &str = "cd / && find etc/hx usr/local/lib/systemd/system etc/systemd/system usr/local/lib/sysusers.d usr/local/lib/tmpfiles.d etc/logrotate.d usr/lib/hx usr/lib/hx-rescue -xdev \\( -type f -o -type l \\) 2>/dev/null | sort | while read f; do case \"$f\" in */install-state.json|etc/hx/host-firewall.nft) ;; *) if [ -L \"$f\" ]; then echo \"L $f $(readlink \"$f\")\"; else echo \"$(sha256sum \"$f\" | cut -d' ' -f1) $(stat -c '%a %U:%G %Y' \"$f\") $f\"; fi;; esac; done";

fn idempotence(l1: &L1) {
    let id = l1.d.id;
    let before = l1.exec_ok(HASHES);
    let st_before = l1.state();
    let out = l1.install(443, &[]);
    assert_eq!(out.exit, 0, "{:?}\n{}", out.lines.last(), out.stderr);
    let after = l1.exec_ok(HASHES);
    assert_eq!(
        before, after,
        "a second run changed files (sha256, mode, owner, mtime)"
    );
    let st_after = l1.state();
    for k in ["install_id", "server_public_key", "mode", "agent_version"] {
        assert_eq!(st_before[k], st_after[k], "{k} changed");
    }
    let skipped: Vec<String> = out
        .stages()
        .into_iter()
        .filter(|s| s.1 == "skip")
        .map(|s| s.0)
        .collect();
    for s in [
        "packages",
        "incus",
        "release",
        "system-files",
        "credentials",
        "config",
        "units",
        "desktop",
    ] {
        assert!(
            skipped.iter().any(|x| x == s),
            "{s} must be skipped on a complete install: {skipped:?}"
        );
    }
    pass(
        id,
        "idempotence",
        format!(
            "second run exit 0 in {} s; {} files hashed (sha256, mode, owner, mtime) identical; stages skipped: {}",
            out.wall.as_secs(),
            before.lines().count(),
            skipped.join(",")
        ),
    );
}

fn lock_contention(l1: &L1) {
    // The in-flight race was done during the desktop build; this is the plain lock check: a
    // holder of /run/hx-install.lock makes install.sh and hx-agent exit 11 at once.
    let id = l1.d.id;
    l1.exec_ok(
        "systemd-run --unit=hx1e-lockholder --collect -q flock /run/hx-install.lock sleep 25",
    );
    std::thread::sleep(Duration::from_secs(1));
    let out = run_in(
        l1.d.name,
        &[
            "sh",
            &format!("{REL}/install.sh"),
            "--release-dir",
            REL,
            "--progress",
            "json",
            "--ssh",
            "--test-allow-container",
            "--user",
            USER,
        ],
        b"HXI1\0\0\0",
        |_| {},
    );
    assert_eq!(out.exit, 11, "{:?} {}", out.lines, out.stderr);
    l1.exec_ok("systemctl stop hx1e-lockholder.service || true");
    pass(
        id,
        "lock (held lock file)",
        format!(
            "install.sh exit 11: {}",
            out.stderr.trim().lines().last().unwrap_or("")
        ),
    );
}

fn port_change(l1: &L1, server: PublicKey) {
    let id = l1.d.id;
    let out = l1.install(8443, &[]);
    assert_eq!(out.exit, 0, "{:?}\n{}", out.lines.last(), out.stderr);
    let dropin = l1.exec_ok("cat /etc/systemd/system/hx-gatewayd-public.socket.d/50-port.conf");
    assert!(
        dropin.contains("8443") && !dropin.contains(":443\n"),
        "{dropin}"
    );
    let toml = l1.exec_ok("cat /etc/hx/gatewayd.toml");
    assert!(toml.contains("8443"), "{toml}");
    let ss = l1.exec_ok("ss -H -ltnu");
    assert!(ss.contains("*:8443"), "{ss}");
    assert!(!ss.contains("*:443"), "443 must be closed: {ss}");
    let code = new_code(l1);
    let _c = token_pair_and_login(
        l1,
        server,
        8443,
        TransportPreference::Quic,
        "hx1e-quic-8443",
        Some(&code),
    );
    // 443 refuses TCP.
    assert!(
        std::net::TcpStream::connect_timeout(&l1.addr(443), Duration::from_secs(3)).is_err(),
        "443 must refuse"
    );
    pass(
        id,
        "port change 443 -> 8443",
        "socket drop-in, gatewayd.toml and the listeners follow; PIN login over QUIC on 8443 works; 443 refuses",
    );
    // Back to 443 for the checks that follow.
    let back = l1.install(443, &[]);
    assert_eq!(back.exit, 0, "{:?}\n{}", back.lines.last(), back.stderr);
    let ss = l1.exec_ok("ss -H -ltnu");
    assert!(ss.contains("*:443") && !ss.contains("*:8443"), "{ss}");
    let code = new_code(l1);
    let _c = token_pair_and_login(
        l1,
        server,
        443,
        TransportPreference::WebSocket,
        "hx1e-ws-back",
        Some(&code),
    );
    pass(
        id,
        "port change back to 443",
        "listeners follow; PIN login over WebSocket works",
    );
}

fn rescue(l1: &L1) {
    let id = l1.d.id;
    let v = l1.exec_ok("readlink /usr/lib/hx/current").trim().to_owned();
    // A "new release" whose hx-privd cannot start, and a pending record for it.
    l1.exec_ok(&format!(
        "set -e; rm -rf /usr/lib/hx/9.9.9; cp -a /usr/lib/hx/{v} /usr/lib/hx/9.9.9; printf '#!/bin/sh\\nexit 1\\n' > /usr/lib/hx/9.9.9/hx-privd; chmod 0755 /usr/lib/hx/9.9.9/hx-privd; \
         printf '9.9.9\\n' > /usr/lib/hx/9.9.9/VERSION; ln -sfn {v} /usr/lib/hx/previous; ln -sfn 9.9.9 /usr/lib/hx/current"
    ));
    let mut state: Value = inc::pull(l1.d.name, "/var/lib/hx/updates-state")
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    state["pending"] = serde_json::json!({"version": "9.9.9", "previous": v, "started_unix": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), "attempts": 0, "gateway_pid": 1});
    inc::push_bytes(
        l1.d.name,
        &serde_json::to_vec(&state).unwrap(),
        "/var/lib/hx/updates-state",
        "0600",
    );
    let t0 = Instant::now();
    l1.exec_ok("systemctl restart hx-privd.service || true");
    // The new privd fails to start five times (RestartSec=2s, StartLimitBurst=5); then
    // OnFailure runs the rescue helper, which restores `current` and starts the old privd.
    let end = Instant::now() + Duration::from_secs(150);
    loop {
        let cur = l1.exec_ok("readlink /usr/lib/hx/current").trim().to_owned();
        let act = l1
            .exec("systemctl is-active hx-privd.service")
            .stdout
            .trim()
            .to_owned();
        if cur == v && act == "active" {
            break;
        }
        assert!(
            Instant::now() < end,
            "no rollback after 150 s: current={cur} privd={act}\n{}",
            l1.exec("journalctl -u hx-privd.service -u hx-privd-rescue.service --no-pager -n 30")
                .stdout
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    let took = t0.elapsed().as_secs();
    let j = l1.exec_ok("journalctl -u hx-privd-rescue.service --no-pager 2>/dev/null | grep -a 'hx-privd-rescue' | tail -3");
    assert!(
        j.contains("restarted hx-privd") || j.contains("hx-privd-rescue"),
        "rescue helper log: {j}"
    );
    // The restarted old privd runs rollback_now: the pending record goes away.
    let end = Instant::now() + Duration::from_secs(60);
    let pending = loop {
        let s: Value = inc::pull(l1.d.name, "/var/lib/hx/updates-state")
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if s["pending"].is_null() {
            break s;
        }
        assert!(
            Instant::now() < end,
            "pending still set after the rollback: {s}"
        );
        std::thread::sleep(Duration::from_secs(2));
    };
    let audit = l1.exec_ok(
        "grep -a -c 'UPDATE_ROLLED_BACK\\|rolled_back\\|rollback' /var/log/hx/audit.log; true",
    );
    pass(
        id,
        "rescue: OnFailure rolls a bad privd back",
        format!(
            "current 9.9.9 -> {v} in {took} s via hx-privd-rescue; pending cleared (rolled_back={}); audit rollback lines: {}",
            pending["rolled_back"],
            audit.trim()
        ),
    );
    l1.exec_ok(
        "rm -rf /usr/lib/hx/9.9.9; systemctl reset-failed hx-privd.service hx-privd.socket || true",
    );
}

fn restart(l1: &L1, server: PublicKey) {
    let id = l1.d.id;
    let t0 = Instant::now();
    inc::incus_ok(&["restart", l1.d.name]);
    let _ = wait_ready(l1.d);
    let took = t0.elapsed().as_secs();
    let act = l1.exec_ok("systemctl is-active hx-privd.socket hx-gatewayd-admin.socket hx-gatewayd-public.socket incus.socket");
    assert!(act.lines().all(|l| l == "active"), "after restart: {act}");
    // The boot-time oneshot ran: it is what loads `table inet hx` before Incus after a reboot.
    let fw = l1.exec_ok("systemctl is-active hx-host-firewall.service");
    assert_eq!(
        fw.trim(),
        "active",
        "hx-host-firewall.service did not run at boot"
    );
    let tables = l1.exec_ok("nft list tables");
    assert!(
        tables.contains("table inet hx"),
        "inet hx must be loaded again after a restart: {tables}"
    );
    let code = new_code(l1);
    let _c = token_pair_and_login(
        l1,
        server,
        443,
        TransportPreference::Quic,
        "hx1e-quic-restart",
        Some(&code),
    );
    let inner = l1.exec_ok("incus list -f csv -c ns");
    pass(
        id,
        "restart of L1",
        format!(
            "incus restart in {took} s; sockets active, table inet hx loaded, PIN login works (gatewayd and privd started on demand); inner instances: {}",
            inner.trim().replace('\n', ", ")
        ),
    );
}

const ABSENT: &[&str] = &[
    "/usr/lib/hx",
    "/usr/lib/hx-rescue",
    "/var/lib/hx",
    "/var/log/hx",
    "/run/hx",
    "/var/lib/hx-gatewayd",
    "/usr/local/lib/systemd/system/hx-privd.service",
    "/usr/local/lib/systemd/system/hx-privd.socket",
    "/usr/local/lib/systemd/system/hx-gatewayd.service",
    "/usr/local/lib/systemd/system/hx-gatewayd-admin.socket",
    "/usr/local/lib/systemd/system/hx-gatewayd-public.socket",
    "/usr/local/lib/systemd/system/hx-privd-rescue.service",
    "/usr/local/lib/sysusers.d/hx-gatewayd.conf",
    "/usr/local/lib/tmpfiles.d/hx.conf",
    "/etc/logrotate.d/hx-audit",
    "/etc/systemd/system/hx-gatewayd-public.socket.d",
    "/var/lib/hx-uninstall.json",
];

fn leftover_paths(l1: &L1, extra_absent: &[&str]) -> Vec<String> {
    let mut v = Vec::new();
    for p in ABSENT.iter().chain(extra_absent) {
        if l1.exec(&format!("test -e {p} || test -L {p}")).ok() {
            v.push((*p).to_owned());
        }
    }
    if l1.exec("getent passwd hx-gatewayd").ok() {
        v.push("user hx-gatewayd".into());
    }
    let units =
        l1.exec_ok("systemctl list-unit-files 'hx-*' --no-legend 2>/dev/null | awk '{print $1}'");
    for u in units.lines().filter(|u| !u.is_empty()) {
        v.push(format!("unit file {u}"));
    }
    v
}

fn uninstall_both(l1: &L1) {
    let id = l1.d.id;
    // The harness's own drop-ins go first (they are not the installer's).
    let rm_dropins = || {
        l1.exec_ok(&format!("rm -f /etc/systemd/system/hx-gatewayd.service.d/{DROPIN} /etc/systemd/system/hx-privd.service.d/{DROPIN}; rmdir /etc/systemd/system/hx-gatewayd.service.d /etc/systemd/system/hx-privd.service.d 2>/dev/null; systemctl daemon-reload"))
    };
    rm_dropins();

    // ---- keep mode ----
    let t0 = Instant::now();
    let k = l1.exec(&format!("{AGENT} uninstall --keep-desktop --yes 2>&1"));
    assert_eq!(
        k.code, 0,
        "uninstall --keep-desktop: {} {}",
        k.stdout, k.stderr
    );
    let left = leftover_paths(l1, &[]);
    assert!(
        left.is_empty(),
        "leftovers after uninstall --keep-desktop: {left:?}\n{}",
        k.stdout
    );
    let inner = l1.exec_ok("incus list -f csv -c n");
    assert!(
        inner.lines().any(|l| l == "hx-main"),
        "keep mode keeps the desktop: {inner}"
    );
    let kept_fw = l1.exec_ok("ls /etc/hx 2>&1; true");
    pass(
        id,
        "uninstall --keep-desktop",
        format!(
            "{} s, no leftover (units, files, state, user); desktop kept (inner instances: {}); /etc/hx keeps: {}",
            t0.elapsed().as_secs(),
            inner.trim().replace('\n', ","),
            kept_fw.trim().replace('\n', ",")
        ),
    );

    // ---- install again over the kept desktop, then destroy mode ----
    dropins(l1);
    let re = l1.install(443, &[]);
    assert_eq!(
        re.exit,
        0,
        "reinstall over a kept desktop: {:?}\n{}",
        re.lines.last(),
        re.stderr
    );
    pass(
        id,
        "reinstall over a kept desktop",
        format!(
            "exit 0 in {} s ({} stages did work)",
            re.wall.as_secs(),
            re.stages().iter().filter(|s| s.1 == "done").count()
        ),
    );
    rm_dropins();
    let t0 = Instant::now();
    let dd = l1.exec(&format!("{AGENT} uninstall --destroy-desktop --yes 2>&1"));
    assert_eq!(
        dd.code, 0,
        "uninstall --destroy-desktop: {} {}",
        dd.stdout, dd.stderr
    );
    let left = leftover_paths(l1, &["/etc/hx"]);
    assert!(
        left.is_empty(),
        "leftovers after uninstall --destroy-desktop: {left:?}\n{}",
        dd.stdout
    );
    let inner: String = [
        "list",
        "profile list",
        "network list",
        "storage list",
        "network acl list",
    ]
    .iter()
    .map(|c| l1.exec_ok(&format!("incus {c} -f csv -c n 2>&1")))
    .collect::<Vec<_>>()
    .join("\n");
    let ours: Vec<&str> = inner
        .lines()
        .filter(|l| l.starts_with("hx-") || l.starts_with("hxbr"))
        .collect();
    assert!(
        ours.is_empty(),
        "inner Incus objects left after destroy: {ours:?}"
    );
    let nft = l1.exec_ok("nft list tables 2>&1; true");
    assert!(
        !nft.contains("table inet hx"),
        "table inet hx must be gone: {nft}"
    );
    pass(
        id,
        "uninstall --destroy-desktop",
        format!(
            "{} s, no leftover; no hx-* instance, profile, network, pool or ACL in the inner Incus; table inet hx gone",
            t0.elapsed().as_secs()
        ),
    );
}

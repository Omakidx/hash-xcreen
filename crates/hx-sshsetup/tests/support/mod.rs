//! An in-process SSH server (russh's server API) over a `tokio::io::duplex` pipe: a host key,
//! password and public-key authentication, `exec` with stdin, stdout, stderr and exit status,
//! and scripted behaviour (delays, abrupt disconnects, hangs). No sshd, no sockets.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::{HashAlg, LineEnding};
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet};
use tokio::io::DuplexStream;

pub fn key_from_seed(seed: u8) -> PrivateKey {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).expect("random");
    s[0] ^= seed; // distinct even with a broken RNG
    PrivateKey::from(Ed25519Keypair::from_seed(&s))
}

pub fn fingerprint(k: &PrivateKey) -> String {
    k.public_key().fingerprint(HashAlg::Sha256).to_string()
}

pub fn pem(k: &PrivateKey) -> zeroize::Zeroizing<String> {
    k.to_openssh(LineEnding::LF).expect("pem")
}

/// One command the client ran.
#[derive(Debug, Clone)]
pub struct Exec {
    pub command: String,
    pub stdin: Vec<u8>,
}

/// What the fake does for a command.
#[derive(Debug, Clone)]
pub enum Action {
    Out(Vec<u8>),
    Err(Vec<u8>),
    Exit(u32),
    Delay(u64),
    /// Close the whole SSH connection with no exit status (a lost connection).
    Disconnect,
    /// Never answer.
    Hang,
}

pub fn out(s: &str) -> Action {
    Action::Out(s.as_bytes().to_vec())
}

pub fn err(s: &str) -> Action {
    Action::Err(s.as_bytes().to_vec())
}

pub type Plan = Arc<dyn Fn(&Exec) -> Vec<Action> + Send + Sync>;

#[derive(Default)]
pub struct Counters {
    pub auth_attempts: usize,
    pub execs: Vec<Exec>,
}

#[derive(Clone)]
pub struct Fake {
    pub host_key: PrivateKey,
    pub user: String,
    pub password: Option<String>,
    pub client_key: Option<PublicKey>,
    pub plan: Plan,
    pub state: Arc<Mutex<Counters>>,
}

impl Fake {
    pub fn new(plan: Plan) -> Self {
        Self {
            host_key: key_from_seed(1),
            user: "alice".into(),
            password: Some("right-pw".into()),
            client_key: None,
            plan,
            state: Arc::default(),
        }
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.host_key)
    }

    pub fn auth_attempts(&self) -> usize {
        self.state.lock().unwrap().auth_attempts
    }

    pub fn execs(&self) -> Vec<Exec> {
        self.state.lock().unwrap().execs.clone()
    }

    /// Starts a server and returns the client end of the pipe.
    pub fn connect(&self) -> DuplexStream {
        let (c, s) = tokio::io::duplex(1 << 20);
        let mut cfg = server::Config::default();
        cfg.keys.push(self.host_key.clone());
        cfg.auth_rejection_time = Duration::from_millis(5);
        cfg.auth_rejection_time_initial = Some(Duration::ZERO);
        cfg.inactivity_timeout = None;
        let mut methods = MethodSet::empty();
        methods.push(MethodKind::Password);
        methods.push(MethodKind::PublicKey);
        cfg.methods = methods;
        let h = Handler {
            fake: self.clone(),
            chans: HashMap::new(),
        };
        tokio::spawn(async move {
            if let Ok(rs) = server::run_stream(Arc::new(cfg), s, h).await {
                let _ = rs.await;
            }
        });
        c
    }
}

struct Handler {
    fake: Fake,
    chans: HashMap<ChannelId, (String, Vec<u8>)>,
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.fake.state.lock().unwrap().auth_attempts += 1;
        if user == self.fake.user && self.fake.password.as_deref() == Some(password) {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        self.fake.state.lock().unwrap().auth_attempts += 1;
        if user == self.fake.user && self.fake.client_key.as_ref() == Some(key.public_key) {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.chans.insert(channel.id(), (String::new(), Vec::new()));
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(c) = self.chans.get_mut(&channel) {
            c.0 = String::from_utf8_lossy(data).into_owned();
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(c) = self.chans.get_mut(&channel) {
            c.1.extend_from_slice(data);
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some((command, stdin)) = self.chans.remove(&channel) else {
            return Ok(());
        };
        let exec = Exec { command, stdin };
        self.fake.state.lock().unwrap().execs.push(exec.clone());
        for a in (self.fake.plan)(&exec) {
            match a {
                Action::Out(b) => session.data(channel, b)?,
                Action::Err(b) => session.extended_data(channel, 1, b)?,
                Action::Exit(c) => session.exit_status_request(channel, c)?,
                Action::Delay(ms) => tokio::time::sleep(Duration::from_millis(ms)).await,
                Action::Disconnect => {
                    session.disconnect(Disconnect::ByApplication, "bye", "en")?;
                    return Ok(());
                }
                Action::Hang => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    return Ok(());
                }
            }
        }
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

/// How the fake account gets root.
#[derive(Clone)]
pub enum Sudo {
    Root,
    Passwordless,
    Password(&'static str),
    None,
}

/// The standard fake server shell: knows the engine's fixed commands. `install_run` is what the
/// installer run itself does (after the sudo password line, if any, was checked and removed).
pub fn shell(sudo: Sudo, preflight_out: String, install_run: Plan) -> Plan {
    Arc::new(move |e: &Exec| {
        let c = e.command.as_str();
        if c == "sh -s" {
            let s = String::from_utf8_lossy(&e.stdin);
            if s.contains("@uid") {
                return vec![out(&preflight_out), Action::Exit(0)];
            }
            let ans = match sudo {
                Sudo::Root => "root",
                Sudo::Passwordless => "passwordless",
                Sudo::Password(_) => "password",
                Sudo::None => "none",
            };
            return vec![out(&format!("{ans}\n")), Action::Exit(0)];
        }
        if c.starts_with("sudo -S -k -p '' true") {
            let want = match sudo {
                Sudo::Password(p) => p,
                _ => "",
            };
            let got = String::from_utf8_lossy(&e.stdin);
            return if got.trim_end_matches('\n') == want {
                vec![Action::Exit(0)]
            } else {
                vec![err("sudo: 1 incorrect password attempt\n"), Action::Exit(1)]
            };
        }
        if c.contains("mktemp -d /tmp/hx-setup.XXXXXX") {
            return vec![out("/tmp/hx-setup.AbC123\n"), Action::Exit(0)];
        }
        if c.contains("cat > \"$1/install.sh\"") {
            return vec![out(&format!("{}\n", e.stdin.len())), Action::Exit(0)];
        }
        if c.contains("rm -rf --") {
            return vec![Action::Exit(0)];
        }
        if c.contains("install.sh") && c.contains("--ssh") {
            return install_run(e);
        }
        vec![err("unknown command\n"), Action::Exit(127)]
    })
}

pub const HEALTHY_PREFLIGHT: &str = "@uid\n1000\n@os\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n\
@arch\nx86_64\n@systemd\nyes\n@systemd-version\nsystemd 255 (255.4)\n@virt\nnone\n\
@mem\nMemTotal:        8123456 kB\n@cpus\n4\n@disk\nFilesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 100000000 1000 62914560 2% /\n\
@ss\nyes\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n@sudo\npresent\n@sudo-n\nno\n@end\n";

pub const KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The C3 lines of a full successful `--ssh` run, shortened.
pub fn ok_lines(key_hex: &str) -> String {
    let id = "a".repeat(32);
    let result = format!(
        r#"{{"v":1,"t":"result","ok":true,"exit":0,"install_id":"{id}","agent_version":"0.1.0","server_public_key":"{key_hex}","addresses":["203.0.113.9"],"port":443,"desktop":{{"id":"main","path_taken":"BUILD","reason":"prebuilt image unavailable","warnings":["slow mirror"]}},"pairing":{{"kind":"token","expires_at_unix_s":900}},"port_rule":"ufw"}}"#
    );
    let lines = [
        r#"{"v":1,"t":"stage","id":"bootstrap-preflight","state":"start"}"#,
        r#"{"v":1,"t":"stage","id":"bootstrap-preflight","state":"done"}"#,
        r#"{"v":1,"t":"stage","id":"preflight","n":1,"of":19,"state":"start","ms":0}"#,
        r#"{"v":1,"t":"stage","id":"preflight","n":1,"of":19,"state":"done","ms":120}"#,
        r#"{"v":1,"t":"step","id":"desktop","privd_stage":"BUILD","index":3,"total":12,"step":"Installing XFCE","percent":255}"#,
        r#"{"v":1,"t":"warn","id":"desktop","message":"apt-get update was slow"}"#,
        result.as_str(),
    ];
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

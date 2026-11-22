//! The SSH connection: host-key confirmation, authentication, bounded command execution.
//!
//! The flow the "Add server" wizard needs is two steps:
//!
//! 1. [`probe_host_key`] connects, reads the server's host key and disconnects **before any
//!    authentication**, returning its fingerprint (`SHA256:...`, OpenSSH format) for the user to
//!    confirm. Known-hosts storage is the app's concern.
//! 2. [`Connection::connect`] connects again with the trusted fingerprint as `expected` and
//!    authenticates. A different key is [`SshSetupError::HostKeyChanged`] and nothing is sent.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, Handle, Msg};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg, Disconnect};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::error::{Result, SshSetupError};
use crate::text::sanitize;

/// Where to connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    /// Host name or IP address.
    pub host: String,
    /// TCP port (22 by default).
    pub port: u16,
}

impl SshTarget {
    /// `host:port`.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

/// The server's host key, as shown to the user for confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    /// `SHA256:<base64 without padding>`, the format of `ssh-keygen -l` and OpenSSH prompts.
    pub fingerprint: String,
    /// The key algorithm (`ssh-ed25519`, `rsa-sha2-512`, ...).
    pub algorithm: String,
}

/// Where a private key comes from.
pub enum KeySource {
    /// An OpenSSH or PKCS#8 file (ed25519, RSA, ECDSA).
    Path(PathBuf),
    /// The text of the key.
    Pem(Zeroizing<String>),
}

/// How to authenticate.
pub enum Auth {
    /// A one-time password. Never stored.
    Password(Zeroizing<String>),
    /// A private key, with its passphrase when it has one.
    Key {
        /// The key.
        source: KeySource,
        /// Passphrase of an encrypted key.
        passphrase: Option<Zeroizing<String>>,
    },
    /// The first key of the running ssh-agent (`SSH_AUTH_SOCK`) that the server accepts.
    Agent,
}

/// User and method.
pub struct Credentials {
    /// The account on the server.
    pub user: String,
    /// The method.
    pub auth: Auth,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = match self.auth {
            Auth::Password(_) => "password",
            Auth::Key { .. } => "key",
            Auth::Agent => "agent",
        };
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("method", &m)
            .finish()
    }
}

/// Bounds on the connection.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// TCP connect.
    pub connect_timeout: Duration,
    /// SSH version exchange, key exchange and host-key check.
    pub handshake_timeout: Duration,
    /// Authentication.
    pub auth_timeout: Duration,
    /// How often a quiet connection is probed. A dead peer is noticed after
    /// `keepalive_interval * (keepalive_max + 1)`.
    pub keepalive_interval: Duration,
    /// Unanswered probes before the connection is dropped.
    pub keepalive_max: usize,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            handshake_timeout: Duration::from_secs(30),
            auth_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(15),
            keepalive_max: 3,
        }
    }
}

/// Most bytes of stdout or stderr that [`Connection::exec`] collects.
pub const MAX_EXEC_OUTPUT: usize = 1024 * 1024;

type Seen = Arc<Mutex<Option<HostKey>>>;

struct Hand {
    expected: Option<String>,
    seen: Seen,
}

impl client::Handler for Hand {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let pk = key.public_key();
        let hk = HostKey {
            fingerprint: pk.fingerprint(HashAlg::Sha256).to_string(),
            algorithm: pk.algorithm().to_string(),
        };
        let ok = self.expected.as_deref() == Some(hk.fingerprint.as_str());
        if let Ok(mut g) = self.seen.lock() {
            *g = Some(hk);
        }
        // With no expected fingerprint (a probe) the connection is dropped right after the key
        // exchange: no credential is ever offered to an unconfirmed host.
        Ok(ok)
    }
}

fn config(o: &ConnectOptions) -> Arc<client::Config> {
    Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(o.keepalive_interval),
        keepalive_max: o.keepalive_max,
        nodelay: true,
        ..Default::default()
    })
}

async fn tcp(target: &SshTarget, o: &ConnectOptions) -> Result<TcpStream> {
    let s = tokio::time::timeout(
        o.connect_timeout,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    .map_err(|_| SshSetupError::Timeout("connecting to the server"))?
    .map_err(|e| SshSetupError::Connect(sanitize(&e.to_string(), 200)))?;
    let _ = s.set_nodelay(true);
    Ok(s)
}

/// Reads the server's host key without authenticating.
pub async fn probe_host_key(target: &SshTarget, opts: &ConnectOptions) -> Result<HostKey> {
    let s = tcp(target, opts).await?;
    probe_host_key_stream(s, opts).await
}

/// [`probe_host_key`] over a stream the caller opened (a proxy, a test transport).
pub async fn probe_host_key_stream<S>(stream: S, opts: &ConnectOptions) -> Result<HostKey>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let seen: Seen = Arc::default();
    let hand = Hand {
        expected: None,
        seen: seen.clone(),
    };
    let r = tokio::time::timeout(
        opts.handshake_timeout,
        client::connect_stream(config(opts), stream, hand),
    )
    .await;
    let got = seen.lock().ok().and_then(|g| g.clone());
    match (got, r) {
        (Some(k), Ok(Err(russh::Error::UnknownKey))) => Ok(k),
        (Some(k), Ok(Ok(h))) => {
            // Cannot happen (the handler refuses), but never keep an open session.
            let _ = h.disconnect(Disconnect::ByApplication, "", "en").await;
            Ok(k)
        }
        (_, Err(_)) => Err(SshSetupError::Timeout("the SSH handshake")),
        (_, Ok(Err(e))) => Err(SshSetupError::Connect(sanitize(&e.to_string(), 200))),
        (None, Ok(Ok(_))) => Err(SshSetupError::Protocol("no host key was offered".into())),
    }
}

enum Prepared {
    Password(Zeroizing<String>),
    Key(Arc<PrivateKey>),
    Agent,
}

async fn prepare(auth: &Auth) -> Result<Prepared> {
    match auth {
        Auth::Password(p) => {
            if p.is_empty() || p.contains(['\0', '\n', '\r']) {
                return Err(SshSetupError::InvalidInput(
                    "the SSH password is empty or has a line break".into(),
                ));
            }
            Ok(Prepared::Password(p.clone()))
        }
        Auth::Agent => Ok(Prepared::Agent),
        Auth::Key { source, passphrase } => {
            let text: Zeroizing<String> = match source {
                KeySource::Pem(t) => t.clone(),
                KeySource::Path(p) => {
                    let p = p.clone();
                    let read = tokio::task::spawn_blocking(move || std::fs::read_to_string(p))
                        .await
                        .map_err(|_| {
                            SshSetupError::KeyUnusable("cannot read the key file".into())
                        })?;
                    Zeroizing::new(read.map_err(|e| {
                        SshSetupError::KeyUnusable(format!(
                            "cannot read the key file ({})",
                            sanitize(&e.kind().to_string(), 60)
                        ))
                    })?)
                }
            };
            let pass = passphrase.as_ref().map(|p| p.as_str());
            match russh::keys::decode_secret_key(&text, pass) {
                Ok(k) => Ok(Prepared::Key(Arc::new(k))),
                Err(russh::keys::Error::KeyIsEncrypted) => {
                    Err(SshSetupError::KeyPassphraseRequired)
                }
                // A wrong passphrase surfaces as a decryption or format error.
                Err(_) if pass.is_some() => Err(SshSetupError::KeyPassphraseRequired),
                Err(e) => Err(SshSetupError::KeyUnusable(sanitize(&e.to_string(), 120))),
            }
        }
    }
}

/// An authenticated SSH connection. Cheap to clone.
#[derive(Clone)]
pub struct Connection {
    handle: Arc<Handle<Hand>>,
    host_key: HostKey,
    user: String,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("user", &self.user)
            .field("host_key", &self.host_key.fingerprint)
            .finish()
    }
}

impl Connection {
    /// Connects and authenticates. `expected_fingerprint` is the `SHA256:...` the user
    /// confirmed (or the one stored from an earlier visit); a different host key stops the
    /// connection before any credential is sent.
    pub async fn connect(
        target: &SshTarget,
        expected_fingerprint: &str,
        creds: &Credentials,
        opts: &ConnectOptions,
    ) -> Result<Self> {
        let prepared = prepare(&creds.auth).await?;
        let s = tcp(target, opts).await?;
        Self::establish(s, expected_fingerprint, creds, prepared, opts).await
    }

    /// [`connect`](Self::connect) over a stream the caller opened.
    pub async fn connect_stream<S>(
        stream: S,
        expected_fingerprint: &str,
        creds: &Credentials,
        opts: &ConnectOptions,
    ) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let prepared = prepare(&creds.auth).await?;
        Self::establish(stream, expected_fingerprint, creds, prepared, opts).await
    }

    async fn establish<S>(
        stream: S,
        expected: &str,
        creds: &Credentials,
        prepared: Prepared,
        opts: &ConnectOptions,
    ) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let seen: Seen = Arc::default();
        let hand = Hand {
            expected: Some(expected.trim().to_owned()),
            seen: seen.clone(),
        };
        let r = tokio::time::timeout(
            opts.handshake_timeout,
            client::connect_stream(config(opts), stream, hand),
        )
        .await;
        let mut handle = match r {
            Err(_) => return Err(SshSetupError::Timeout("the SSH handshake")),
            Ok(Ok(h)) => h,
            Ok(Err(russh::Error::UnknownKey)) => {
                let actual = seen
                    .lock()
                    .ok()
                    .and_then(|g| g.as_ref().map(|k| k.fingerprint.clone()))
                    .unwrap_or_default();
                return Err(SshSetupError::HostKeyChanged {
                    expected: expected.trim().to_owned(),
                    actual,
                });
            }
            Ok(Err(e)) => return Err(SshSetupError::Connect(sanitize(&e.to_string(), 200))),
        };
        let host_key = seen
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .ok_or_else(|| SshSetupError::Protocol("no host key was seen".into()))?;
        let authed = tokio::time::timeout(
            opts.auth_timeout,
            authenticate(&mut handle, &creds.user, prepared),
        )
        .await
        .map_err(|_| SshSetupError::Timeout("authentication"))??;
        if !authed {
            let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
            return Err(SshSetupError::AuthFailed);
        }
        Ok(Self {
            handle: Arc::new(handle),
            host_key,
            user: creds.user.clone(),
        })
    }

    /// The server's host key as verified.
    pub fn host_key(&self) -> &HostKey {
        &self.host_key
    }

    /// The account name.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// True once the connection is gone.
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// Closes the connection.
    pub async fn disconnect(&self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
    }

    /// Opens a session channel and starts `command` (a command line for the account's shell:
    /// every argument must already be quoted, see [`crate::text::quote`]).
    pub(crate) async fn open_exec(&self, command: &str) -> Result<Channel<Msg>> {
        let lost = |_| SshSetupError::ConnectionLost { last_stage: None };
        let ch = self.handle.channel_open_session().await.map_err(lost)?;
        ch.exec(true, command).await.map_err(lost)?;
        Ok(ch)
    }

    /// Runs `command`, optionally writing `stdin` and then EOF, and collects its output (at
    /// most [`MAX_EXEC_OUTPUT`] bytes per stream) within `timeout`.
    pub async fn exec(
        &self,
        command: &str,
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<ExecOutput> {
        tokio::time::timeout(timeout, self.exec_inner(command, stdin))
            .await
            .map_err(|_| SshSetupError::Timeout("a command on the server"))?
    }

    async fn exec_inner(&self, command: &str, stdin: Option<&[u8]>) -> Result<ExecOutput> {
        let mut ch = self.open_exec(command).await?;
        let lost = |_| SshSetupError::ConnectionLost { last_stage: None };
        if let Some(data) = stdin {
            ch.data(data).await.map_err(lost)?;
        }
        ch.eof().await.map_err(lost)?;
        let mut out = ExecOutput::default();
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::Data { data } => push_capped(&mut out.stdout, &data)?,
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    push_capped(&mut out.stderr, &data)?;
                }
                ChannelMsg::ExitStatus { exit_status } => out.exit = Some(exit_status),
                ChannelMsg::ExitSignal { .. } => out.signalled = true,
                _ => {}
            }
        }
        if out.exit.is_none() && !out.signalled {
            return Err(SshSetupError::ConnectionLost { last_stage: None });
        }
        Ok(out)
    }
}

fn push_capped(buf: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    if buf.len() + data.len() > MAX_EXEC_OUTPUT {
        return Err(SshSetupError::Protocol(
            "a command printed more than 1 MiB".into(),
        ));
    }
    buf.extend_from_slice(data);
    Ok(())
}

/// What a finished command produced.
#[derive(Debug, Default, Clone)]
pub struct ExecOutput {
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
    /// The exit status, when the command exited normally.
    pub exit: Option<u32>,
    /// True when the command was killed by a signal.
    pub signalled: bool,
}

impl ExecOutput {
    /// True for exit status 0.
    pub fn success(&self) -> bool {
        self.exit == Some(0)
    }

    /// Standard output as text (lossy).
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Standard error as text (lossy).
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

async fn authenticate(handle: &mut Handle<Hand>, user: &str, prepared: Prepared) -> Result<bool> {
    let conn_err = |e: russh::Error| SshSetupError::Connect(sanitize(&e.to_string(), 200));
    match prepared {
        Prepared::Password(pw) => {
            // russh takes an owned String; its copy is outside our control.
            let r = handle
                .authenticate_password(user, pw.as_str())
                .await
                .map_err(conn_err)?;
            if r.success() {
                return Ok(true);
            }
            // Some servers offer only keyboard-interactive for passwords.
            let try_kbd = matches!(
                &r,
                russh::client::AuthResult::Failure { remaining_methods, .. }
                    if remaining_methods.contains(&russh::MethodKind::KeyboardInteractive)
            );
            if !try_kbd {
                return Ok(false);
            }
            keyboard_interactive(handle, user, &pw)
                .await
                .map_err(conn_err)
        }
        Prepared::Key(key) => {
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .map_err(conn_err)?
                .flatten();
            let r = handle
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(key, hash))
                .await
                .map_err(conn_err)?;
            Ok(r.success())
        }
        Prepared::Agent => agent_auth(handle, user).await,
    }
}

async fn keyboard_interactive(
    handle: &mut Handle<Hand>,
    user: &str,
    pw: &Zeroizing<String>,
) -> std::result::Result<bool, russh::Error> {
    use russh::client::KeyboardInteractiveAuthResponse as R;
    let mut r = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await?;
    // A few rounds at most; every prompt is answered with the password.
    for _ in 0..4 {
        match r {
            R::Success => return Ok(true),
            R::Failure { .. } => return Ok(false),
            R::InfoRequest { prompts, .. } => {
                let answers = prompts.iter().map(|_| pw.to_string()).collect();
                r = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Ok(false)
}

#[cfg(unix)]
async fn agent_auth(handle: &mut Handle<Hand>, user: &str) -> Result<bool> {
    use russh::keys::agent::AgentIdentity;
    use russh::keys::agent::client::AgentClient;
    let mut agent = AgentClient::connect_env()
        .await
        .map_err(|_| SshSetupError::KeyUnusable("no ssh-agent is running".into()))?;
    let ids = agent
        .request_identities()
        .await
        .map_err(|_| SshSetupError::KeyUnusable("the ssh-agent did not answer".into()))?;
    for id in ids {
        let AgentIdentity::PublicKey { key, .. } = id else {
            continue;
        };
        let hash = handle
            .best_supported_rsa_hash()
            .await
            .map_err(|e| SshSetupError::Connect(sanitize(&e.to_string(), 200)))?
            .flatten();
        match handle
            .authenticate_publickey_with(user, key, hash, &mut agent)
            .await
        {
            Ok(r) if r.success() => return Ok(true),
            Ok(_) => {}
            Err(_) => {}
        }
    }
    Ok(false)
}

#[cfg(not(unix))]
async fn agent_auth(_: &mut Handle<Hand>, _: &str) -> Result<bool> {
    Err(SshSetupError::KeyUnusable(
        "ssh-agent is supported on Unix only".into(),
    ))
}

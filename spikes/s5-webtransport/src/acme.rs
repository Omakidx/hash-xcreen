//! Let's Encrypt IP-address certificates through `instant-acme` (spike S5 follow-up).
//!
//! Subcommands (wired in `main.rs`):
//!   acme --env staging|production --ip IP[,IP] --dir DIR [--bind ADDR:80] [--replaces PEM]
//!   acme-info --env staging|production --cert PEM
//!
//! Challenge: `http-01` on TCP 80. `tls-alpn-01` would need the ACME client to own TCP 443 and
//! speak a special TLS handshake there, which collides with the HTTPS/WebSocket listener of the
//! server that is being renewed. `http-01` needs only a tiny listener that can run next to a
//! live server on 443.
//!
//! State layout under DIR/<env>/: `account.json` (ACME account key, 0600), `key.pem` (certificate
//! private key, 0600), `fullchain.pem`, `fullchain.prev.pem`. Private keys are never printed.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier, ChallengeType, Identifier,
    LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;

const PROFILE: &str = "shortlived";
type Tokens = Arc<Mutex<HashMap<String, String>>>;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn directory_url(env: &str) -> Result<String> {
    Ok(match env {
        "staging" => LetsEncrypt::Staging.url().to_owned(),
        "production" => LetsEncrypt::Production.url().to_owned(),
        other => bail!("--env must be staging or production, got {other}"),
    })
}

/// Write a secret file with mode 0600 from the first byte (no world-readable window), then rename.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

async fn load_or_create_account(env_dir: &Path, url: &str) -> Result<Account> {
    let path = env_dir.join("account.json");
    if let Ok(raw) = std::fs::read(&path) {
        let creds: AccountCredentials = serde_json::from_slice(&raw).context("account.json")?;
        info!("reusing ACME account from {}", path.display());
        return Ok(Account::builder()?.from_credentials(creds).await?);
    }
    // Creating an account means agreeing to the CA's subscriber agreement; no contact address is
    // registered on purpose.
    let (account, creds) = Account::builder()?
        .create(
            &NewAccount { contact: &[], terms_of_service_agreed: true, only_return_existing: false },
            url.to_owned(),
            None,
        )
        .await?;
    write_private(&path, &serde_json::to_vec(&creds)?)?;
    info!("created ACME account {}", account.id());
    Ok(account)
}

/// Minimal http-01 responder. Logs every request so validation vantage points are visible.
async fn challenge_server(listener: TcpListener, tokens: Tokens) {
    loop {
        let Ok((mut s, peer)) = listener.accept().await else { continue };
        let tokens = tokens.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                _ => return,
            };
            let head = String::from_utf8_lossy(&buf[..n]);
            let path = head.lines().next().unwrap_or("").split(' ').nth(1).unwrap_or("").to_owned();
            let body = path
                .strip_prefix("/.well-known/acme-challenge/")
                .and_then(|t| tokens.lock().unwrap().get(t).cloned());
            info!(%peer, %path, served = body.is_some(), "http-01 request");
            let resp = match body {
                Some(b) => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                    b.len()
                ),
                None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
            };
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.shutdown().await;
        });
    }
}

fn parse_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_slice_iter(pem).collect::<Result<Vec<_>, _>>().context("parse PEM chain")
}

fn describe(chain: &[CertificateDer<'_>]) -> Result<()> {
    use x509_parser::prelude::*;
    for (i, der) in chain.iter().enumerate() {
        let (_, c) = parse_x509_certificate(der.as_ref())?;
        let v = c.validity();
        let span = v.not_after.timestamp() - v.not_before.timestamp();
        println!("cert[{i}] subject : {}", c.subject());
        println!("cert[{i}] issuer  : {}", c.issuer());
        println!("cert[{i}] serial  : {}", c.raw_serial_as_string());
        println!(
            "cert[{i}] validity: {} -> {}  ({} s = {:.1} h)",
            v.not_before.to_rfc2822().unwrap_or_default(),
            v.not_after.to_rfc2822().unwrap_or_default(),
            span,
            span as f64 / 3600.0
        );
        println!("cert[{i}] sig alg : {}", c.signature_algorithm.algorithm);
        println!("cert[{i}] key alg : {}", c.public_key().algorithm.algorithm);
        if i == 0
            && let Ok(Some(san)) = c.subject_alternative_name()
        {
            println!("cert[0] SAN     : {:?}", san.value.general_names);
        }
    }
    Ok(())
}

async fn print_ari(account: &Account, leaf: &CertificateDer<'_>) {
    let id = match CertificateIdentifier::try_from(leaf) {
        Ok(id) => id,
        Err(e) => return println!("ARI: cannot build certificate id: {e}"),
    };
    match account.renewal_info(&id).await {
        Ok((ri, retry_after)) => println!(
            "ARI: id={id} suggestedWindow {} -> {}  explanationURL={:?}  retry-after={}s",
            ri.suggested_window.start,
            ri.suggested_window.end,
            ri.explanation_url,
            retry_after.as_secs()
        ),
        Err(e) => println!("ARI: not available: {e}"),
    }
}

pub async fn run_acme(args: &[String]) -> Result<()> {
    let env = arg(args, "--env").context("--env staging|production")?;
    let ips: Vec<IpAddr> = arg(args, "--ip")
        .context("--ip IP[,IP]")?
        .split(',')
        .map(|s| s.trim().parse().with_context(|| format!("bad IP {s}")))
        .collect::<Result<_>>()?;
    let root = PathBuf::from(arg(args, "--dir").context("--dir DIR")?);
    let bind: SocketAddr = arg(args, "--bind").unwrap_or_else(|| "0.0.0.0:80".into()).parse()?;
    let env_dir = root.join(&env);
    std::fs::create_dir_all(&env_dir)?;
    let url = directory_url(&env)?;
    let t0 = Instant::now();

    let account = load_or_create_account(&env_dir, &url).await?;
    let profiles: Vec<_> = account.profiles().map(|p| format!("{}: {}", p.name, p.description)).collect();
    info!(?profiles, "directory profiles");

    // Renewal: tell the CA which certificate this order replaces (ARI `replaces`).
    let replaces = match arg(args, "--replaces") {
        Some(p) => {
            let chain = parse_chain(&std::fs::read(&p)?)?;
            print_ari(&account, &chain[0]).await;
            Some(CertificateIdentifier::try_from(&chain[0]).map_err(anyhow::Error::msg)?.into_owned())
        }
        None => None,
    };

    let identifiers: Vec<Identifier> = ips.iter().map(|ip| Identifier::Ip(*ip)).collect();
    let mut new_order = NewOrder::new(&identifiers).profile(PROFILE);
    if let Some(r) = replaces {
        new_order = new_order.replaces(r);
    }
    let mut order = account.new_order(&new_order).await?;
    info!(status = ?order.state().status, "order created ({} ms)", t0.elapsed().as_millis());

    // Bind port 80 before telling the CA we are ready.
    let listener = TcpListener::bind(bind).await.with_context(|| format!("bind {bind} (needs CAP_NET_BIND_SERVICE)"))?;
    let tokens: Tokens = Arc::default();
    let server = tokio::spawn(challenge_server(listener, tokens.clone()));

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => bail!("authorization status {other:?}"),
        }
        let mut ch = authz.challenge(ChallengeType::Http01).context("no http-01 challenge offered")?;
        let key_auth = ch.key_authorization();
        let token = ch.token.clone();
        tokens.lock().unwrap().insert(token, key_auth.as_str().to_owned());
        ch.set_ready().await?;
    }

    let t_ready = Instant::now();
    let status = order.poll_ready(&RetryPolicy::new().timeout(Duration::from_secs(120))).await?;
    if status != OrderStatus::Ready {
        bail!("order not ready: {status:?}; state={:?}", order.state());
    }
    info!("order ready after {} ms of validation", t_ready.elapsed().as_millis());
    server.abort();

    // ECDSA P-256 key and CSR via rcgen; the CA sets subject and extensions itself.
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new(); // empty subject (IP certs carry only SANs)
    params.subject_alt_names = ips.iter().map(|ip| rcgen::SanType::IpAddress(*ip)).collect();
    let csr = params.serialize_request(&key)?;
    order.finalize_csr(csr.der()).await?;
    let chain_pem = order.poll_certificate(&RetryPolicy::new().timeout(Duration::from_secs(60))).await?;
    let elapsed = t0.elapsed();

    for name in ["fullchain.pem", "key.pem"] {
        let (from, to) = (env_dir.join(name), env_dir.join(name.replace(".pem", ".prev.pem")));
        if from.exists() {
            std::fs::rename(from, to)?;
        }
    }
    write_private(&env_dir.join("key.pem"), key.serialize_pem().as_bytes())?;
    std::fs::write(env_dir.join("fullchain.pem"), &chain_pem)?;

    let chain = parse_chain(chain_pem.as_bytes())?;
    println!("ISSUED env={env} ips={ips:?} profile={PROFILE} chain_len={} total_time_ms={}", chain.len(), elapsed.as_millis());
    describe(&chain)?;
    print_ari(&account, &chain[0]).await;
    Ok(())
}

pub async fn run_info(args: &[String]) -> Result<()> {
    let env = arg(args, "--env").context("--env")?;
    let root = PathBuf::from(arg(args, "--dir").context("--dir DIR")?);
    let cert = PathBuf::from(arg(args, "--cert").context("--cert PEM")?);
    let account = load_or_create_account(&root.join(&env), &directory_url(&env)?).await?;
    let chain = parse_chain(&std::fs::read(cert)?)?;
    describe(&chain)?;
    print_ari(&account, &chain[0]).await;
    Ok(())
}

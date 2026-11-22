//! Interop with a real OpenSSH server: an unprivileged `sshd` of this user on 127.0.0.1 (own host
//! key, own `authorized_keys`, key auth only). It proves that the fingerprint matches
//! `ssh-keygen -l`, that key authentication, `exec`, stdin and exit statuses work against OpenSSH
//! and not only against the in-process russh fixture.
//!
//! Ignored by default (it needs `/usr/sbin/sshd` and `ssh-keygen`). Run with:
//!
//! ```text
//! HX_SSHSETUP_REAL_SSHD=1 cargo nextest run -p hx-sshsetup --run-ignored only --test real_sshd
//! ```
//!
//! It never uses sudo and never touches the host's own sshd or any system file. The install
//! itself is not run here (it needs root, or sudo); the full flow against the nested-Incus L1
//! container is not part of this test.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use hx_sshsetup::{
    Auth, ConnectOptions, Connection, Credentials, KeySource, SshTarget, probe_host_key,
};
use zeroize::Zeroizing;

struct Sshd(Child);

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn keygen(path: &std::path::Path) {
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "hx-test", "-f"])
        .arg(path)
        .status()
        .expect("ssh-keygen");
    assert!(st.success());
}

#[tokio::test]
#[ignore = "needs a real sshd; set HX_SSHSETUP_REAL_SSHD=1"]
async fn real_openssh_interop() {
    if std::env::var_os("HX_SSHSETUP_REAL_SSHD").is_none() {
        eprintln!("HX_SSHSETUP_REAL_SSHD is not set: nothing to do");
        return;
    }
    let dir = std::env::temp_dir().join(format!("hx-sshsetup-sshd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let host = dir.join("host_key");
    let client = dir.join("client_key");
    keygen(&host);
    keygen(&client);
    std::fs::copy(client.with_extension("pub"), dir.join("authorized_keys")).unwrap();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
    let cfg = format!(
        "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\nPidFile {}\n\
         UsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n\
         PubkeyAuthentication yes\nStrictModes no\nLogLevel ERROR\n",
        host.display(),
        dir.join("authorized_keys").display(),
        dir.join("sshd.pid").display(),
    );
    std::fs::write(dir.join("sshd_config"), cfg).unwrap();
    let child = Command::new("/usr/sbin/sshd")
        .args(["-D", "-e", "-f"])
        .arg(dir.join("sshd_config"))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("sshd");
    let _guard = Sshd(child);
    let target = SshTarget::new("127.0.0.1", port);
    let opts = ConnectOptions::default();
    // Wait for the listener.
    let mut hk = None;
    for _ in 0..50 {
        if let Ok(k) = probe_host_key(&target, &opts).await {
            hk = Some(k);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let hk = hk.expect("the unprivileged sshd did not come up");

    // The fingerprint is what OpenSSH itself prints.
    let l = Command::new("ssh-keygen")
        .args(["-l", "-E", "sha256", "-f"])
        .arg(host.with_extension("pub"))
        .output()
        .unwrap();
    let line = String::from_utf8_lossy(&l.stdout).into_owned();
    assert!(
        line.split_whitespace().any(|w| w == hk.fingerprint),
        "ssh-keygen said {line:?}, we said {}",
        hk.fingerprint
    );

    let creds = Credentials {
        user,
        auth: Auth::Key {
            source: KeySource::Path(client),
            passphrase: None,
        },
    };
    let c = Connection::connect(&target, &hk.fingerprint, &creds, &opts)
        .await
        .expect("key login against OpenSSH");
    let o = c
        .exec(
            "cat; echo done >&2; exit 3",
            Some(b"hello over stdin"),
            Duration::from_secs(10),
        )
        .await
        .expect("exec");
    assert_eq!(o.stdout, b"hello over stdin");
    assert_eq!(o.stderr_text().trim(), "done");
    assert_eq!(o.exit, Some(3));

    // A different expected fingerprint is refused by the real server too.
    let e = Connection::connect(&target, "SHA256:AAAA", &creds, &opts)
        .await
        .unwrap_err();
    assert!(
        matches!(e, hx_sshsetup::SshSetupError::HostKeyChanged { .. }),
        "{e:?}"
    );

    // A wrong key is refused.
    let other = dir.join("other_key");
    keygen(&other);
    let bad = Credentials {
        user: creds.user.clone(),
        auth: Auth::Key {
            source: KeySource::Path(other),
            passphrase: None,
        },
    };
    let e = Connection::connect(&target, &hk.fingerprint, &bad, &opts)
        .await
        .unwrap_err();
    assert!(matches!(e, hx_sshsetup::SshSetupError::AuthFailed), "{e:?}");

    // An encrypted key without its passphrase is a typed error.
    let enc = dir.join("enc_key");
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "s3cret-pass", "-f"])
        .arg(&enc)
        .status()
        .unwrap();
    assert!(st.success());
    let mk = |pass: Option<&str>| Credentials {
        user: creds.user.clone(),
        auth: Auth::Key {
            source: KeySource::Path(enc.clone()),
            passphrase: pass.map(|p| Zeroizing::new(p.to_owned())),
        },
    };
    let e = Connection::connect(&target, &hk.fingerprint, &mk(None), &opts)
        .await
        .unwrap_err();
    assert!(
        matches!(e, hx_sshsetup::SshSetupError::KeyPassphraseRequired),
        "{e:?}"
    );
    let e = Connection::connect(&target, &hk.fingerprint, &mk(Some("wrong")), &opts)
        .await
        .unwrap_err();
    assert!(
        matches!(e, hx_sshsetup::SshSetupError::KeyPassphraseRequired),
        "{e:?}"
    );
    // Right passphrase decrypts it (the server then rejects it: not in authorized_keys).
    let e = Connection::connect(&target, &hk.fingerprint, &mk(Some("s3cret-pass")), &opts)
        .await
        .unwrap_err();
    assert!(matches!(e, hx_sshsetup::SshSetupError::AuthFailed), "{e:?}");

    c.disconnect().await;
    let _ = std::fs::remove_dir_all(dir);
}

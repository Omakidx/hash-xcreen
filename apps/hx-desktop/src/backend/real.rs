//! The backends of a real run (not `--demo`).
//!
//! * `InstallEngine`: [`super::ssh::SshInstallEngine`] over `hx-sshsetup`.
//! * `SetupClient`: [`super::setup_real::RealSetupClient`] over `hx_crypto::setup`.
//! * `DeviceAdmin`: [`RealAdmin`]. **Pairing codes go over the app's own session task**
//!   (`Desk::create_pairing_code`, the same `DeviceMgmt` messages as `hx_crypto::device_admin`):
//!   exactly one reader of the control channel exists, so list, revoke and pairing codes share
//!   one request-id map and no two readers compete. The reinstate call uses
//!   `hx_crypto::reinstate_client` on its own connection (there is no session yet).
//! * `ServerControl`: not part of this build yet (its protocol messages are still being built).

use std::sync::Arc;
use std::time::Duration;

use hx_crypto::reinstate_client::{ReinstateOptions, ReinstateOutcome};
use hx_crypto::setup::Password;
use hx_proto::version::ProtocolVersion;

use super::*;

const MSG: &str = "This is not part of this build yet.";

/// Pairing codes and "Pair again".
pub struct RealAdmin {
    /// Name this device gives itself.
    pub device_name: String,
}

/// Lifetime requested for a pairing code, in seconds.
pub const PAIRING_CODE_TTL: u32 = 600;

impl DeviceAdmin for RealAdmin {
    fn create_pairing_code(
        &self,
        ctx: &AdminContext,
    ) -> BoxFuture<'_, Result<IssuedCode, AdminError>> {
        let desk = ctx.session.clone();
        Box::pin(async move {
            match desk {
                Some(d) => d.create_pairing_code(PAIRING_CODE_TTL).await,
                None => Err(AdminError::Failed("Sign in with your PIN first.".into())),
            }
        })
    }

    fn reinstate(
        &self,
        ctx: &AdminContext,
        password: &Secret,
    ) -> BoxFuture<'_, Result<(), AdminError>> {
        let (host, port, key_hex) = (ctx.host.clone(), ctx.port, ctx.server_key_hex.clone());
        let (device, version) = (ctx.device.clone(), ctx.server_version);
        let (pw, name) = (password.expose().to_owned(), self.device_name.clone());
        Box::pin(async move {
            let key = crate::session::net::parse_key(&key_hex)
                .ok_or_else(|| AdminError::Failed("The pinned server key is damaged.".into()))?;
            let target = crate::session::net::target(&host, port)
                .await
                .map_err(|_| AdminError::Unreachable)?;
            let password = Password::new(&pw).map_err(|_| AdminError::Incorrect {
                attempts_left: None,
            })?;
            let opts = ReinstateOptions {
                confirmed_server_version: version
                    .map(|(major, minor)| ProtocolVersion { major, minor }),
                device_name: name.chars().take(64).collect(),
                software: concat!("hx-desktop ", env!("CARGO_PKG_VERSION")).into(),
                ..Default::default()
            };
            match hx_crypto::reinstate_client::reinstate(&target, &device, key, &password, &opts).await {
                Ok(ReinstateOutcome::Reinstated) => Ok(()),
                Ok(ReinstateOutcome::WrongPassword { attempts_left }) => Err(AdminError::Incorrect { attempts_left: Some(attempts_left) }),
                Ok(ReinstateOutcome::Backoff { retry_after: _ }) => Err(AdminError::RateLimited),
                Ok(ReinstateOutcome::NotAvailable { retry_after }) => Err(AdminError::Failed(format!(
                    "The server cannot check the password right now. Try again in {} s; if it keeps happening, run hx-agent devices reinstate on the server.",
                    retry_after.max(Duration::from_secs(30)).as_secs()
                ))),
                Ok(ReinstateOutcome::Refused) => Err(AdminError::Failed(
                    "The server does not offer to re-enable this device: it was not locked out by wrong PINs, or it was removed by someone else. Remove the server and add it again with a pairing code.".into(),
                )),
                Err(hx_crypto::Error::UpdateRequired) => Err(AdminError::UpdateRequired),
                Err(hx_crypto::Error::Transport(_) | hx_crypto::Error::Timeout(_)) => Err(AdminError::Unreachable),
                Err(e) => Err(AdminError::Failed(crate::session::connect::sanitize(&e.to_string()))),
            }
        })
    }
}

/// Server management: not wired.
pub struct UnavailableControl;

impl ServerControl for UnavailableControl {
    fn overview(&self, _c: &AdminContext) -> BoxFuture<'_, Result<Overview, AdminError>> {
        Box::pin(async { Err(AdminError::Failed(MSG.into())) })
    }
    fn change_pin(
        &self,
        _c: &AdminContext,
        _a: &Secret,
        _b: &Secret,
    ) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async {
            Err(AdminError::Failed(
                "Changing the PIN from this app is not part of this build yet.".into(),
            ))
        })
    }
    fn change_password(
        &self,
        _c: &AdminContext,
        _a: &Secret,
        _b: &Secret,
    ) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async {
            Err(AdminError::Failed(
                "Changing the password from this app is not part of this build yet.".into(),
            ))
        })
    }
    fn restart_desktop(&self, _c: &AdminContext) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async { Err(AdminError::Failed(MSG.into())) })
    }
    fn set_docker(&self, _c: &AdminContext, _o: bool) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async { Err(AdminError::Failed(MSG.into())) })
    }
    fn set_limits(&self, _c: &AdminContext, _l: Limits) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async { Err(AdminError::Failed(MSG.into())) })
    }
    fn update_agent(&self, _c: &AdminContext) -> BoxFuture<'_, Result<String, AdminError>> {
        Box::pin(async { Err(AdminError::Failed(MSG.into())) })
    }
}

/// The backends of a real run.
pub fn backends(handle: tokio::runtime::Handle, device_name: String) -> Backends {
    Backends {
        install: Arc::new(super::ssh::SshInstallEngine::default()),
        setup: Arc::new(super::setup_real::RealSetupClient {
            device_name: device_name.clone(),
        }),
        admin: Arc::new(RealAdmin { device_name }),
        control: Arc::new(UnavailableControl),
        connector: Arc::new(crate::session::RealConnector { handle }),
    }
}

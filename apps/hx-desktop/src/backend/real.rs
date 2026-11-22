//! What a build without the parallel workstreams uses outside demo mode: the pieces that exist
//! are real (pairing with a token or a code, the PIN session), the rest answer with a plain
//! "not part of this build yet" instead of pretending.
//!
//! The integrator replaces `install` with an adapter over `hx-sshsetup`, `setup` and `admin`
//! with adapters over `hx_crypto::setup` (protocol 1.3), and `control` once its messages exist.

use std::sync::Arc;

use hx_crypto::IdentityKey;

use super::*;

const MSG: &str = "This is not part of this build yet.";

/// SSH install: not wired.
pub struct UnavailableInstall;

impl InstallEngine for UnavailableInstall {
    fn probe_host_key(&self, _t: &SshTarget) -> BoxFuture<'_, Result<HostKey, EngineError>> {
        Box::pin(async { Err(EngineError::Other("The SSH installer is not part of this build yet. Use the one-liner or a pairing code.".into())) })
    }
    fn preflight(&self, _t: &SshTarget, _a: &SshAuth, _h: &HostKey) -> BoxFuture<'_, Result<Preflight, EngineError>> {
        Box::pin(async { Err(EngineError::Other(MSG.into())) })
    }
    fn install(&self, _r: InstallRequest) -> BoxFuture<'_, Result<Box<dyn InstallRun>, EngineError>> {
        Box::pin(async { Err(EngineError::Other(MSG.into())) })
    }
    fn uninstall(&self, _r: UninstallRequest) -> BoxFuture<'_, Result<(), EngineError>> {
        Box::pin(async { Err(EngineError::Other("Uninstall over SSH is not part of this build yet. Run hx-agent uninstall on the server.".into())) })
    }
}

/// Pairing is real; the setup protocol of 1.3 is not wired.
pub struct RealSetup {
    /// Name this device gives itself at pairing.
    pub device_name: String,
}

impl SetupClient for RealSetup {
    fn pair(&self, addr: &ServerAddr, device: Arc<IdentityKey>, token: &Secret) -> BoxFuture<'_, Result<PairedInfo, SetupError>> {
        let (host, port, cred) = (addr.host.clone(), addr.port, token.expose().to_owned());
        let name = self.device_name.clone();
        Box::pin(async move { crate::session::net::pair(&host, port, &device, &cred, &name).await })
    }

    fn start_setup(&self, _a: &ServerAddr, _d: Arc<IdentityKey>, _p: &PairedInfo, _r: SetupRequest) -> BoxFuture<'_, Result<Box<dyn InstallRun>, SetupError>> {
        Box::pin(async {
            Err(SetupError::Other(
                "Creating the desktop after pairing needs the setup protocol of 1.3, which is not part of this build yet.".into(),
            ))
        })
    }
}

/// Pairing codes and reinstate: not wired.
pub struct UnavailableAdmin;

impl DeviceAdmin for UnavailableAdmin {
    fn create_pairing_code(&self, _c: &AdminContext) -> BoxFuture<'_, Result<IssuedCode, AdminError>> {
        Box::pin(async { Err(AdminError::Failed("Pairing codes from this app are not part of this build yet. Run hx-agent pairing code on the server.".into())) })
    }
    fn reinstate(&self, _c: &AdminContext, _p: &Secret) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async { Err(AdminError::Failed("Pairing again with the account password is not part of this build yet. Remove the server and add it again with a pairing code.".into())) })
    }
}

/// Server management: not wired.
pub struct UnavailableControl;

impl ServerControl for UnavailableControl {
    fn overview(&self, _c: &AdminContext) -> BoxFuture<'_, Result<Overview, AdminError>> {
        Box::pin(async { Err(AdminError::Failed(MSG.into())) })
    }
    fn change_pin(&self, _c: &AdminContext, _a: &Secret, _b: &Secret) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async { Err(AdminError::Failed("Changing the PIN from this app is not part of this build yet.".into())) })
    }
    fn change_password(&self, _c: &AdminContext, _a: &Secret, _b: &Secret) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async { Err(AdminError::Failed("Changing the password from this app is not part of this build yet.".into())) })
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
        install: Arc::new(UnavailableInstall),
        setup: Arc::new(RealSetup { device_name }),
        admin: Arc::new(UnavailableAdmin),
        control: Arc::new(UnavailableControl),
        connector: Arc::new(crate::session::RealConnector { handle }),
    }
}

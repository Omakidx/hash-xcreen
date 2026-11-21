//! What the installer asks of `hx-privd` (as `Admin`) and `hx-gatewayd` (admin socket), as one
//! trait, so every stage can be tested against a fake and the real implementation is a thin shell
//! over the CLI's own clients ([`crate::cli::privd`], [`crate::cli::gatewayd`]).
//!
//! Secrets cross this trait only as byte slices that the caller owns in `Zeroizing` buffers; the
//! real implementation sends them as kind-2 secret frames and nothing else.

use std::path::PathBuf;

use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, LockoutPurpose, request::Command, response::Result as R};
use zeroize::Zeroizing;

use super::error::{InstallError, Result};
use crate::cli::error::CliError;
use crate::cli::gatewayd::{AdminConn, unexpected as admin_unexpected, wipe_code};
use crate::cli::privd::{OutSecret, PrivdConn, ProgressLine, unexpected};

/// A progress callback.
pub type OnProgress<'a> = &'a mut dyn FnMut(&ProgressLine);

/// What `Hello` told.
#[derive(Debug, Clone)]
pub struct PrivdHello {
    /// privd's version.
    pub version: String,
    /// Its phase.
    pub phase: pb::Phase,
}

/// What privd's `Uninstall` reported (design C9).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UninstallSummary {
    /// What it removed.
    pub removed: Vec<String>,
    /// What it left.
    pub kept: Vec<String>,
    /// What it could not do.
    pub warnings: Vec<String>,
}

/// The adapter between `pb::UninstallResult` and [`UninstallSummary`].
///
/// Contract C9 (privd.proto):
/// `message UninstallResult { bool keep_desktop = 1; repeated string removed = 2;
/// repeated string kept = 3; repeated string warnings = 4; }`, entries `kind:name`.
pub fn uninstall_summary(r: &pb::UninstallResult) -> UninstallSummary {
    UninstallSummary {
        removed: r.removed.clone(),
        kept: r.kept.clone(),
        warnings: r.warnings.clone(),
    }
}

/// The adapter for the `ERROR_DETAIL_UNINSTALLING` detail of C9 (privd refuses Gateway commands
/// and Admin mutations while its uninstall marker exists).
/// `ErrorDetail::Uninstalling = 13`, `ProgressStage::Uninstall = 14` (progress needs no
/// code: stages print by name).
pub fn is_uninstalling(d: pb::ErrorDetail) -> bool {
    d == pb::ErrorDetail::Uninstalling
}

/// The daemons.
pub trait Daemons {
    /// `Hello` of privd.
    fn hello(&mut self) -> Result<PrivdHello>;
    /// `GetHostInfo`.
    fn host_info(&mut self) -> Result<pb::GetHostInfoResult>;
    /// `BeginSetup`; returns the expiry.
    fn begin_setup(&mut self, secs: u32) -> Result<u64>;
    /// `FinishSetup`.
    fn finish_setup(&mut self, force: bool) -> Result<()>;
    /// `SetupHost`.
    fn setup_host(
        &mut self,
        req: pb::SetupHostRequest,
        on: OnProgress<'_>,
    ) -> Result<pb::SetupHostResult>;
    /// `CreateDesktop` with the password as secret slot 0.
    fn create_desktop(
        &mut self,
        req: pb::CreateDesktopRequest,
        password: &[u8],
        on: OnProgress<'_>,
    ) -> Result<pb::CreateDesktopResult>;
    /// `GetDesktop`; `None` when it does not exist.
    fn get_desktop(&mut self, id: &str) -> Result<Option<pb::Desktop>>;
    /// `SetLimits`.
    fn set_limits(&mut self, id: &str, limits: pb::Limits) -> Result<()>;
    /// `PepperEnrol`: the MAC of the 32-byte Argon2id output.
    fn pepper_enrol(&mut self, purpose: LockoutPurpose, input: &[u8]) -> Result<Vec<u8>>;
    /// `EnrolOwnerKey`.
    fn enrol_owner_key(&mut self, key: &[u8]) -> Result<()>;
    /// `Uninstall`.
    fn uninstall(&mut self, keep_desktop: bool, on: OnProgress<'_>) -> Result<UninstallSummary>;
    /// gatewayd `SetupWindow`.
    fn gateway_setup_window(&mut self, action: apb::SetupWindowAction, secs: u32) -> Result<()>;
    /// gatewayd `SetPinVerifier` for every device.
    fn set_pin_verifier_all(&mut self, record: Vec<u8>) -> Result<()>;
    /// gatewayd `SetPasswordVerifier`.
    fn set_password_verifier(&mut self, record: Vec<u8>) -> Result<()>;
    /// gatewayd `CreatePairingToken` (the token as a secret frame); returns the expiry.
    fn create_pairing_token(&mut self, token: &[u8], ttl_s: u32) -> Result<u64>;
    /// gatewayd `CreatePairingCode`; returns the code (wiped on drop) and the expiry.
    fn create_pairing_code(&mut self, ttl_s: u32) -> Result<(Zeroizing<String>, u64)>;
}

/// The real daemons, reached over their sockets (a fresh connection per call).
#[derive(Debug, Clone)]
pub struct SocketDaemons {
    /// `/run/hx/privd.sock`.
    pub privd_socket: PathBuf,
    /// `/run/hx/gatewayd-admin.sock`.
    pub admin_socket: PathBuf,
    /// The uid that must own both sockets.
    pub expected_uid: u32,
}

impl SocketDaemons {
    fn privd(&self) -> Result<PrivdConn> {
        Ok(PrivdConn::connect(&self.privd_socket, self.expected_uid)?)
    }

    fn admin(&self) -> Result<AdminConn> {
        Ok(AdminConn::connect(&self.admin_socket, self.expected_uid)?)
    }
}

fn silent(_: &ProgressLine) {}

impl Daemons for SocketDaemons {
    fn hello(&mut self) -> Result<PrivdHello> {
        let c = self.privd()?;
        Ok(PrivdHello {
            version: c.version.clone(),
            phase: c.phase,
        })
    }

    fn host_info(&mut self) -> Result<pb::GetHostInfoResult> {
        match self
            .privd()?
            .simple(Command::GetHostInfo(pb::GetHostInfoRequest {}))?
        {
            R::GetHostInfo(r) => Ok(r),
            _ => Err(unexpected("GetHostInfo").into()),
        }
    }

    fn begin_setup(&mut self, secs: u32) -> Result<u64> {
        match self
            .privd()?
            .simple(Command::BeginSetup(pb::BeginSetupRequest {
                expires_in_s: secs,
            }))? {
            R::BeginSetup(r) => Ok(r.expires_at_unix_s),
            _ => Err(unexpected("BeginSetup").into()),
        }
    }

    fn finish_setup(&mut self, force: bool) -> Result<()> {
        match self
            .privd()?
            .simple(Command::FinishSetup(pb::FinishSetupRequest {
                force: force.then_some(true),
            }))? {
            R::FinishSetup(_) => Ok(()),
            _ => Err(unexpected("FinishSetup").into()),
        }
    }

    fn setup_host(
        &mut self,
        req: pb::SetupHostRequest,
        on: OnProgress<'_>,
    ) -> Result<pb::SetupHostResult> {
        match self.privd()?.call(Command::SetupHost(req), &[], on)? {
            R::SetupHost(r) => Ok(r),
            _ => Err(unexpected("SetupHost").into()),
        }
    }

    fn create_desktop(
        &mut self,
        req: pb::CreateDesktopRequest,
        password: &[u8],
        on: OnProgress<'_>,
    ) -> Result<pb::CreateDesktopResult> {
        match self.privd()?.call(
            Command::CreateDesktop(req),
            &[OutSecret {
                kind: pb::SecretKind::UserPassword,
                bytes: password,
            }],
            on,
        )? {
            R::CreateDesktop(r) => Ok(r),
            _ => Err(unexpected("CreateDesktop").into()),
        }
    }

    fn get_desktop(&mut self, id: &str) -> Result<Option<pb::Desktop>> {
        match self
            .privd()?
            .simple(Command::GetDesktop(pb::GetDesktopRequest {
                desktop_id: id.to_owned(),
            })) {
            Ok(R::GetDesktop(r)) => Ok(r.desktop),
            Ok(_) => Err(unexpected("GetDesktop").into()),
            Err(CliError::Remote(r)) if r.code == pb::ErrorCode::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set_limits(&mut self, id: &str, limits: pb::Limits) -> Result<()> {
        match self
            .privd()?
            .simple(Command::SetLimits(pb::SetLimitsRequest {
                desktop_id: id.to_owned(),
                limits: Some(limits),
            }))? {
            R::SetLimits(_) => Ok(()),
            _ => Err(unexpected("SetLimits").into()),
        }
    }

    fn pepper_enrol(&mut self, purpose: LockoutPurpose, input: &[u8]) -> Result<Vec<u8>> {
        match self.privd()?.call(
            Command::PepperEnrol(pb::PepperEnrolRequest {
                purpose: purpose as i32,
            }),
            &[OutSecret {
                kind: pb::SecretKind::MacInput,
                bytes: input,
            }],
            &mut silent,
        )? {
            R::PepperEnrol(r) => Ok(r.mac.to_vec()),
            _ => Err(unexpected("PepperEnrol").into()),
        }
    }

    fn enrol_owner_key(&mut self, key: &[u8]) -> Result<()> {
        match self
            .privd()?
            .simple(Command::EnrolOwnerKey(pb::EnrolOwnerKeyRequest {
                public_key: key.to_vec().into(),
                replace: false,
            }))? {
            R::EnrolOwnerKey(_) => Ok(()),
            _ => Err(unexpected("EnrolOwnerKey").into()),
        }
    }

    fn uninstall(&mut self, keep_desktop: bool, on: OnProgress<'_>) -> Result<UninstallSummary> {
        match self.privd()?.call(
            Command::Uninstall(pb::UninstallRequest {
                keep_desktop,
                confirm_destroy: !keep_desktop,
            }),
            &[],
            on,
        )? {
            R::Uninstall(r) => Ok(uninstall_summary(&r)),
            _ => Err(unexpected("Uninstall").into()),
        }
    }

    fn gateway_setup_window(&mut self, action: apb::SetupWindowAction, secs: u32) -> Result<()> {
        match self.admin()?.call(
            apb::request::Command::SetupWindow(apb::SetupWindowRequest {
                action: action as i32,
                expires_in_s: secs,
            }),
            None,
        )? {
            apb::response::Result::SetupWindow(_) => Ok(()),
            _ => Err(admin_unexpected("SetupWindow").into()),
        }
    }

    fn set_pin_verifier_all(&mut self, record: Vec<u8>) -> Result<()> {
        match self.admin()?.call(
            apb::request::Command::SetPinVerifier(apb::SetPinVerifierRequest {
                target: Some(apb::set_pin_verifier_request::Target::All(true)),
                verifier: record.into(),
            }),
            None,
        )? {
            apb::response::Result::SetPinVerifier(_) => Ok(()),
            _ => Err(admin_unexpected("SetPinVerifier").into()),
        }
    }

    fn set_password_verifier(&mut self, record: Vec<u8>) -> Result<()> {
        match self.admin()?.call(
            apb::request::Command::SetPasswordVerifier(apb::SetPasswordVerifierRequest {
                verifier: record.into(),
            }),
            None,
        )? {
            apb::response::Result::SetPasswordVerifier(_) => Ok(()),
            _ => Err(admin_unexpected("SetPasswordVerifier").into()),
        }
    }

    fn create_pairing_token(&mut self, token: &[u8], ttl_s: u32) -> Result<u64> {
        match self.admin()?.call(
            apb::request::Command::CreatePairingToken(apb::CreatePairingTokenRequest {
                expires_in_s: ttl_s,
            }),
            Some(token),
        )? {
            apb::response::Result::CreatePairingToken(r) => Ok(r.expires_at_unix_s),
            _ => Err(admin_unexpected("CreatePairingToken").into()),
        }
    }

    fn create_pairing_code(&mut self, ttl_s: u32) -> Result<(Zeroizing<String>, u64)> {
        match self.admin()?.call(
            apb::request::Command::CreatePairingCode(apb::CreatePairingCodeRequest {
                expires_in_s: ttl_s,
            }),
            None,
        )? {
            apb::response::Result::CreatePairingCode(mut r) => {
                let code = Zeroizing::new(crate::cli::text::peer(&r.code, 32));
                let expires = r.expires_at_unix_s;
                wipe_code(&mut r);
                Ok((code, expires))
            }
            _ => Err(admin_unexpected("CreatePairingCode").into()),
        }
    }
}

impl From<InstallError> for CliError {
    fn from(e: InstallError) -> Self {
        CliError::Failed(e.message)
    }
}

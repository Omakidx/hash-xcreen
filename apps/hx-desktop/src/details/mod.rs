//! Server details: pure logic for the device list, the revoke rules, the PIN and password
//! dialogs, the pairing-code countdown and the Danger zone flow.

use hx_proto::pb::{DeviceInfo, DeviceRevokeReason, DeviceStatus, RevokeStatus};

/// One row of the paired-devices table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRow {
    /// 16-byte id.
    pub id: [u8; 16],
    /// Name as plain text, with the first 8 hex digits of the id after it (protocol 5.9).
    pub name: String,
    /// "now", "Today 13:58", "14 Nov", "2 days ago", "never".
    pub last_seen: String,
    /// "Active", "Revoked", "Locked (PIN tries)".
    pub state: String,
    /// Badge tone: 1 success, 3 danger, 2 warning.
    pub tone: i32,
    /// This is the device that asked.
    pub current: bool,
    /// Revoke is offered.
    pub can_revoke: bool,
}

/// Converts the server's list. `now` is Unix seconds; the list order (active first) is kept.
pub fn rows(list: &[DeviceInfo], now: u64) -> Vec<DeviceRow> {
    list.iter()
        .filter_map(|d| {
            let id: [u8; 16] = <[u8; 16]>::try_from(&d.device_id[..]).ok()?;
            let revoked = d.status() == DeviceStatus::Revoked;
            let (state, tone) = if revoked {
                match d.revoke_reason() {
                    DeviceRevokeReason::TooManyPinFailures => ("Revoked (PIN tries)".to_owned(), 3),
                    _ => ("Revoked".to_owned(), 3),
                }
            } else {
                ("Active".to_owned(), 1)
            };
            let short: String = id.iter().take(4).map(|b| format!("{b:02x}")).collect();
            let name = if d.name.is_empty() {
                format!("Device {short}")
            } else {
                format!("{} ({short})", crate::session::connect::sanitize(&d.name))
            };
            Some(DeviceRow {
                id,
                name,
                last_seen: relative_time(d.last_seen_unix, now, d.current),
                state,
                tone,
                current: d.current,
                can_revoke: !revoked,
            })
        })
        .collect()
}

/// "now", "5 min ago", "Today 13:58"-style text without a time zone database: relative for the
/// last day, then days, then a date in UTC.
pub fn relative_time(then: u64, now: u64, current: bool) -> String {
    if current {
        return "now".into();
    }
    if then == 0 {
        return "never".into();
    }
    let d = now.saturating_sub(then);
    match d {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", d / 60),
        3600..=86_399 => format!("{} h ago", d / 3600),
        86_400..=604_799 => {
            let n = d / 86_400;
            if n == 1 {
                "yesterday".into()
            } else {
                format!("{n} days ago")
            }
        }
        _ => date_utc(then),
    }
}

/// "14 Nov" (UTC) from Unix seconds, civil-from-days arithmetic (no date crate).
pub fn date_utc(t: u64) -> String {
    let z = (t / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let _ = era;
    const M: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!("{day} {}", M[(month - 1) as usize])
}

/// What the Revoke dialog says and whether it is the strong "this device" variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokePlan {
    /// Device to revoke.
    pub id: [u8; 16],
    /// Name for the dialog title.
    pub name: String,
    /// Revoking the device in use signs it out.
    pub is_self: bool,
}

/// Plans a revoke of `row`. A device that is already revoked cannot be revoked again.
pub fn plan_revoke(row: &DeviceRow) -> Option<RevokePlan> {
    row.can_revoke.then(|| RevokePlan {
        id: row.id,
        name: row.name.clone(),
        is_self: row.current,
    })
}

/// The user-facing sentence for a revoke result.
pub fn revoke_message(s: RevokeStatus) -> Option<&'static str> {
    match s {
        RevokeStatus::Ok => None,
        RevokeStatus::NotFound => Some("That device is no longer on the server."),
        RevokeStatus::AlreadyRevoked => Some("That device was already revoked."),
        RevokeStatus::LastActiveDevice => Some(
            "This is the only active device. Pair another device first, or reinstall with the server's CLI.",
        ),
        RevokeStatus::RateLimited => {
            Some("Too many revokes in a minute. Wait a moment and try again.")
        }
        RevokeStatus::Failed | RevokeStatus::Unspecified => {
            Some("The server could not revoke the device. Try again.")
        }
    }
}

/// Expiry text of a pairing code: "Expires in 14 min 52 s · works once · 3 tries".
pub fn expiry_text(secs_left: u64, tries: u32) -> String {
    if secs_left == 0 {
        return "This code has expired. Close this window and ask for a new one.".into();
    }
    format!(
        "Expires in {} min {:02} s · works once · {tries} tries",
        secs_left / 60,
        secs_left % 60
    )
}

/// Validation of the Change PIN dialog: (current, new, confirm).
pub fn pin_dialog_problems(current: &str, new: &str, confirm: &str) -> [Option<String>; 3] {
    [
        current
            .is_empty()
            .then(|| "Enter your current PIN.".to_owned()),
        crate::wizard::pin_problem(new).err(),
        crate::wizard::confirm_problem(new, confirm, "PINs").err(),
    ]
}

/// Validation of the Change password dialog.
pub fn password_dialog_problems(current: &str, new: &str, confirm: &str) -> [Option<String>; 3] {
    [
        current
            .is_empty()
            .then(|| "Enter your current password.".to_owned()),
        crate::wizard::password_problem(new).err(),
        crate::wizard::confirm_problem(new, confirm, "passwords").err(),
    ]
}

/// The Danger zone flow (design/mockups/server-details.html, `#danger` to `#uninstall-done`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Danger {
    /// Nothing open.
    Idle,
    /// "Uninstall needs SSH access".
    NeedsSsh,
    /// Confirmation: a simple one for keep, the server name for delete.
    Confirm,
    /// Running.
    Running,
    /// Done: the card stays until removed.
    Done,
}

/// The state machine of the flow. Uninstall is a root action, so the app needs SSH again.
#[derive(Debug)]
pub struct DangerFlow {
    state: Danger,
    /// Keep the desktop on the server.
    pub keep: bool,
}

impl Default for DangerFlow {
    fn default() -> Self {
        Self {
            state: Danger::Idle,
            keep: true,
        }
    }
}

impl DangerFlow {
    /// Current state.
    pub fn state(&self) -> &Danger {
        &self.state
    }
    /// "Uninstall…" pressed.
    pub fn start(&mut self) {
        if self.state == Danger::Idle {
            self.state = Danger::NeedsSsh;
        }
    }
    /// SSH details given: go to the confirmation.
    pub fn ssh_given(&mut self) {
        if self.state == Danger::NeedsSsh {
            self.state = Danger::Confirm;
        }
    }
    /// The SSH username or port was edited after the check: the host key must be checked again.
    pub fn ssh_changed(&mut self) {
        if self.state == Danger::Confirm {
            self.state = Danger::NeedsSsh;
        }
    }
    /// Whether the confirm button is enabled: keep asks nothing, delete needs the server name.
    pub fn can_confirm(&self, typed: &str, server_name: &str) -> bool {
        self.state == Danger::Confirm && (self.keep || typed == server_name)
    }
    /// Confirmed. Returns false if it may not run yet.
    pub fn confirm(&mut self, typed: &str, server_name: &str) -> bool {
        if self.can_confirm(typed, server_name) {
            self.state = Danger::Running;
            true
        } else {
            false
        }
    }
    /// The uninstall ended.
    pub fn finished(&mut self, ok: bool) {
        if self.state == Danger::Running {
            self.state = if ok { Danger::Done } else { Danger::Confirm };
        }
    }
    /// Cancel from any dialog.
    pub fn cancel(&mut self) {
        if matches!(self.state, Danger::NeedsSsh | Danger::Confirm) {
            self.state = Danger::Idle;
        }
    }
}

/// The commands shown after an uninstall to remove Incus (architecture 5.3).
pub const REMOVE_INCUS: &str =
    "apt remove incus && rm /etc/apt/sources.list.d/zabbly-incus-*.sources";

#[cfg(test)]
mod tests {
    use super::*;
    use hx_proto::pb::DeviceInfo;

    fn info(id: u8, name: &str, status: DeviceStatus, last: u64, current: bool) -> DeviceInfo {
        DeviceInfo {
            device_id: bytes::Bytes::from(vec![id; 16]),
            name: name.into(),
            created_unix: 1,
            last_seen_unix: last,
            status: status as i32,
            revoke_reason: if status == DeviceStatus::Revoked {
                DeviceRevokeReason::User as i32
            } else {
                0
            },
            revoked_unix: 0,
            current,
        }
    }

    #[test]
    fn rows_show_plain_names_with_the_id_prefix_and_mark_this_device() {
        let now = 1_700_000_000;
        let list = [
            info(1, "Alex's desktop", DeviceStatus::Active, now, true),
            info(2, "Maya's laptop", DeviceStatus::Active, now - 7200, false),
            info(
                3,
                "Old tablet",
                DeviceStatus::Revoked,
                now - 90 * 86_400,
                false,
            ),
        ];
        let r = rows(&list, now);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].name, "Alex's desktop (01010101)");
        assert!(r[0].current);
        assert_eq!(r[0].last_seen, "now");
        assert_eq!(r[1].last_seen, "2 h ago");
        assert_eq!(r[2].state, "Revoked");
        assert!(!r[2].can_revoke);
        assert!(plan_revoke(&r[2]).is_none());
    }

    #[test]
    fn a_bad_id_is_skipped_and_a_hostile_name_is_cleaned() {
        let mut bad = info(1, "x", DeviceStatus::Active, 0, false);
        bad.device_id = bytes::Bytes::from(vec![1; 3]);
        let evil = info(4, "ev\u{202e}il", DeviceStatus::Active, 0, false);
        let r = rows(&[bad, evil], 10);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "evil (04040404)");
        assert_eq!(r[0].last_seen, "never");
    }

    #[test]
    fn revoking_this_device_is_the_strong_variant() {
        let list = [info(1, "me", DeviceStatus::Active, 0, true)];
        let plan = plan_revoke(&rows(&list, 5)[0]).unwrap();
        assert!(plan.is_self);
    }

    #[test]
    fn revoke_results_have_sentences_and_ok_has_none() {
        assert!(revoke_message(RevokeStatus::Ok).is_none());
        assert!(
            revoke_message(RevokeStatus::LastActiveDevice)
                .unwrap()
                .contains("only active device")
        );
        assert!(revoke_message(RevokeStatus::RateLimited).is_some());
    }

    #[test]
    fn dates_and_times() {
        assert_eq!(date_utc(1_699_920_000), "14 Nov");
        assert_eq!(date_utc(0), "1 Jan");
        assert_eq!(relative_time(0, 5, false), "never");
        assert_eq!(relative_time(100, 100 + 3 * 86_400, false), "3 days ago");
        assert_eq!(
            relative_time(1_699_920_000, 1_699_920_000 + 30 * 86_400, false),
            "14 Nov"
        );
    }

    #[test]
    fn expiry_countdown_text() {
        assert_eq!(
            expiry_text(892, 3),
            "Expires in 14 min 52 s · works once · 3 tries"
        );
        assert!(expiry_text(0, 3).contains("expired"));
    }

    #[test]
    fn dialogs_validate_like_the_wizard() {
        let p = pin_dialog_problems("", "123", "124");
        assert!(p.iter().all(Option::is_some));
        let ok = pin_dialog_problems("111111", "222222", "222222");
        assert!(ok.iter().all(Option::is_none));
        let pw = password_dialog_problems("old", "short", "short");
        assert!(pw[1].is_some() && pw[2].is_none());
    }

    #[test]
    fn danger_flow_needs_ssh_then_confirmation() {
        let mut f = DangerFlow::default();
        assert!(
            !f.confirm("", "Workstation"),
            "cannot confirm before the SSH step"
        );
        f.start();
        assert_eq!(*f.state(), Danger::NeedsSsh);
        f.ssh_given();
        assert_eq!(*f.state(), Danger::Confirm);
        // keep: no typing needed
        assert!(f.can_confirm("", "Workstation"));
        f.keep = false;
        assert!(!f.can_confirm("work", "Workstation"));
        assert!(f.can_confirm("Workstation", "Workstation"));
        assert!(f.confirm("Workstation", "Workstation"));
        assert_eq!(*f.state(), Danger::Running);
        f.finished(true);
        assert_eq!(*f.state(), Danger::Done);
    }

    #[test]
    fn a_failed_uninstall_returns_to_the_confirmation_and_cancel_works() {
        let mut f = DangerFlow::default();
        f.start();
        f.ssh_given();
        assert!(f.confirm("", "x"));
        f.finished(false);
        assert_eq!(*f.state(), Danger::Confirm);
        f.cancel();
        assert_eq!(*f.state(), Danger::Idle);
    }

    #[test]
    fn editing_the_ssh_details_returns_to_the_ssh_step() {
        let mut f = DangerFlow::default();
        f.start();
        f.ssh_given();
        assert_eq!(*f.state(), Danger::Confirm);
        f.ssh_changed();
        assert_eq!(*f.state(), Danger::NeedsSsh);
        assert!(!f.can_confirm("", "x"));
    }
}

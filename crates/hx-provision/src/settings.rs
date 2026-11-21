//! Desktop settings the wizard lets the user choose: hostname, timezone, locale, keyboard
//! (ipc.md 6.5, `CreateDesktop.settings`).
//!
//! They are *user input*, so each is validated once, here, against a strict alphabet before it can
//! be substituted into a recipe as the variable `{{hostname}}`, `{{timezone}}`, `{{locale}}` or
//! `{{keyboard}}`. None of the accepted alphabets contains a shell, path or systemd
//! metacharacter, and the recipe additionally single-quotes every substitution. An unset
//! setting is the empty string and its post step does nothing. The four names are reserved: a
//! recipe cannot define them in `[vars]`.
//!
//! The recipe applies them in the post stage (`recipes/fragments/settings.toml`), so they work the
//! same for a prebuilt image and for a build on the server.

use std::path::Path;

/// Why a setting was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {setting}: {reason}")]
pub struct SettingsError {
    /// Which setting.
    pub setting: &'static str,
    /// Why.
    pub reason: String,
}

fn bad(setting: &'static str, reason: impl Into<String>) -> SettingsError {
    SettingsError {
        setting,
        reason: reason.into(),
    }
}

/// UTF-8 locales a desktop may be set to (the common ones of Debian's and Ubuntu's `SUPPORTED`).
/// Sorted; the accepted input is any of these with or without the `.UTF-8` suffix.
pub const ALLOWED_LOCALES: &[&str] = &[
    "ar_SA", "bg_BG", "ca_ES", "cs_CZ", "da_DK", "de_AT", "de_CH", "de_DE", "el_GR", "en_AU",
    "en_CA", "en_GB", "en_IE", "en_IN", "en_NZ", "en_US", "en_ZA", "es_AR", "es_CL", "es_CO",
    "es_ES", "es_MX", "et_EE", "fi_FI", "fr_BE", "fr_CA", "fr_CH", "fr_FR", "he_IL", "hi_IN",
    "hr_HR", "hu_HU", "id_ID", "is_IS", "it_CH", "it_IT", "ja_JP", "ko_KR", "lt_LT", "lv_LV",
    "nb_NO", "nl_BE", "nl_NL", "pl_PL", "pt_BR", "pt_PT", "ro_RO", "ru_RU", "sk_SK", "sl_SI",
    "sr_RS", "sv_SE", "th_TH", "tr_TR", "uk_UA", "vi_VN", "zh_CN", "zh_HK", "zh_TW",
];

/// The validated settings. Every field is optional; `None` leaves the image's default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    hostname: Option<String>,
    timezone: Option<String>,
    locale: Option<String>,
    keyboard: Option<String>,
}

impl Settings {
    /// No settings.
    pub fn none() -> Self {
        Self::default()
    }

    /// An RFC 1123 label: 1 to 63 characters of `a-z`, `0-9` and `-`, not starting or ending with
    /// `-`. Lower case only (the caller folds case), and not `localhost`.
    pub fn with_hostname(mut self, hostname: &str) -> Result<Self, SettingsError> {
        let ok = !hostname.is_empty()
            && hostname.len() <= 63
            && !hostname.starts_with('-')
            && !hostname.ends_with('-')
            && hostname
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(bad(
                "hostname",
                "must be 1-63 characters of a-z, 0-9 and `-`, not starting or ending with `-`",
            ));
        }
        if hostname == "localhost" {
            return Err(bad("hostname", "`localhost` is not allowed"));
        }
        self.hostname = Some(hostname.to_string());
        Ok(self)
    }

    /// A zoneinfo name such as `Europe/Berlin`, `America/Argentina/Buenos_Aires` or `UTC`: one to
    /// three `/`-separated parts of letters, digits, `_`, `+` and `-`, no `.` at all (so no `..`).
    ///
    /// This checks the *syntax*. `hx-privd` must also check that the name exists on the host with
    /// [`Settings::with_timezone_in`] (ipc.md 6.5); the post step fails the stage if the container
    /// lacks the zone.
    pub fn with_timezone(mut self, timezone: &str) -> Result<Self, SettingsError> {
        let parts: Vec<&str> = timezone.split('/').collect();
        let ok = (1..=3).contains(&parts.len())
            && parts.iter().all(|p| {
                !p.is_empty()
                    && p.len() <= 32
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-'))
            });
        if !ok {
            return Err(bad(
                "timezone",
                "must look like `Europe/Berlin` (letters, digits, `_`, `+`, `-`, up to 3 parts)",
            ));
        }
        self.timezone = Some(timezone.to_string());
        Ok(self)
    }

    /// [`Settings::with_timezone`], and the name must be a regular file under `zoneinfo_dir`
    /// (normally `/usr/share/zoneinfo`).
    pub fn with_timezone_in(
        self,
        timezone: &str,
        zoneinfo_dir: &Path,
    ) -> Result<Self, SettingsError> {
        let s = self.with_timezone(timezone)?;
        // The syntax check above leaves no `.` and no empty part, so this cannot leave the directory.
        let p = zoneinfo_dir.join(timezone);
        if !std::fs::metadata(&p).is_ok_and(|m| m.is_file()) {
            return Err(bad("timezone", format!("`{timezone}` is not a known zone")));
        }
        Ok(s)
    }

    /// A locale from [`ALLOWED_LOCALES`], `de_DE` or `de_DE.UTF-8`; stored with `.UTF-8`.
    pub fn with_locale(mut self, locale: &str) -> Result<Self, SettingsError> {
        let base = locale.strip_suffix(".UTF-8").unwrap_or(locale);
        if !ALLOWED_LOCALES.contains(&base) {
            return Err(bad(
                "locale",
                "must be one of the supported locales, for example `en_US.UTF-8`",
            ));
        }
        self.locale = Some(format!("{base}.UTF-8"));
        Ok(self)
    }

    /// An X keyboard layout and optional variant, `^[a-z]{2}(\+[a-z0-9_-]{1,16})?$`, for example
    /// `de` or `de+nodeadkeys`.
    pub fn with_keyboard(mut self, keyboard: &str) -> Result<Self, SettingsError> {
        let (layout, variant) = match keyboard.split_once('+') {
            Some((l, v)) => (l, Some(v)),
            None => (keyboard, None),
        };
        let ok = layout.len() == 2
            && layout.bytes().all(|b| b.is_ascii_lowercase())
            && variant.is_none_or(|v| {
                (1..=16).contains(&v.len())
                    && v.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                    })
            });
        if !ok {
            return Err(bad(
                "keyboard",
                "must look like `de` or `de+nodeadkeys` (two letters, optional `+variant`)",
            ));
        }
        self.keyboard = Some(keyboard.to_string());
        Ok(self)
    }

    /// Whether nothing is set.
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none()
            && self.timezone.is_none()
            && self.locale.is_none()
            && self.keyboard.is_none()
    }

    /// The recipe variables: all four names, empty when unset.
    pub(crate) fn vars(&self) -> [(&'static str, String); 4] {
        let get = |o: &Option<String>| o.clone().unwrap_or_default();
        [
            ("hostname", get(&self.hostname)),
            ("timezone", get(&self.timezone)),
            ("locale", get(&self.locale)),
            ("keyboard", get(&self.keyboard)),
        ]
    }

    /// The hostname, if set.
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// The timezone, if set.
    pub fn timezone(&self) -> Option<&str> {
        self.timezone.as_deref()
    }

    /// The locale (with `.UTF-8`), if set.
    pub fn locale(&self) -> Option<&str> {
        self.locale.as_deref()
    }

    /// The keyboard layout, if set.
    pub fn keyboard(&self) -> Option<&str> {
        self.keyboard.as_deref()
    }
}

/// Names the recipe variables for settings take; reserved in `[vars]`.
pub(crate) const RESERVED_VARS: [&str; 4] = ["hostname", "timezone", "locale", "keyboard"];

//! App settings (userflow 12), stored as JSON next to the server list. No secret in here.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The settings of this device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// 0 system, 1 dark, 2 light.
    pub theme: u8,
    /// 0 auto, 1 sharp, 2 smooth.
    pub quality: u8,
    /// 0 auto, 1..4 = 5, 10, 25, 50 Mbps.
    pub bandwidth: u8,
    /// Capture all keys.
    pub capture_keys: bool,
    /// Send my clipboard.
    pub clip_send: bool,
    /// Receive the desktop's clipboard.
    pub clip_receive: bool,
    /// Include files.
    pub clip_files: bool,
    /// Start at login (recorded; the autostart entry is packaging's job).
    pub start_at_login: bool,
    /// Name shown in the servers' device lists.
    pub device_name: String,
    /// The toolbar hint was dismissed.
    pub hint_seen: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            theme: 0,
            quality: 0,
            bandwidth: 0,
            capture_keys: true,
            clip_send: true,
            clip_receive: true,
            clip_files: true,
            start_at_login: false,
            device_name: default_device_name(),
            hint_seen: false,
        }
    }
}

/// The machine's host name as a device name, or "hx-desktop".
pub fn default_device_name() -> String {
    let h = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "hx-desktop".into());
    clean_device_name(&h)
}

/// A device name the server accepts: printable, at most 64 bytes, never empty.
pub fn clean_device_name(s: &str) -> String {
    let out: String = s.chars().filter(|c| !c.is_control()).collect();
    let out = out.trim().to_owned();
    let mut cut = out.clone();
    while cut.len() > 64 {
        cut.pop();
    }
    if cut.is_empty() {
        "hx-desktop".into()
    } else {
        cut
    }
}

impl Prefs {
    /// Bandwidth cap in kbit/s (0 = auto).
    pub fn bandwidth_kbps(&self) -> u32 {
        match self.bandwidth {
            1 => 5_000,
            2 => 10_000,
            3 => 25_000,
            4 => 50_000,
            _ => 0,
        }
    }

    /// `prefs.json` in the config directory.
    pub fn path() -> Option<PathBuf> {
        crate::servers::config_dir().map(|d| d.join("prefs.json"))
    }

    /// Loads, or defaults when missing or damaged (settings are never worth a blocking error).
    pub fn load(path: Option<&PathBuf>) -> Self {
        path.and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<Prefs>(&b).ok())
            .map(|mut p| {
                p.device_name = clean_device_name(&p.device_name);
                p
            })
            .unwrap_or_default()
    }

    /// Saves (best effort).
    pub fn save(&self, path: Option<&PathBuf>) {
        let Some(p) = path else { return };
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if let Ok(b) = serde_json::to_vec_pretty(self) {
            let _ = std::fs::write(p, b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names_are_cleaned_and_capped() {
        assert_eq!(
            clean_device_name("  Alex\u{7}'s desktop "),
            "Alex's desktop"
        );
        assert_eq!(clean_device_name(""), "hx-desktop");
        assert_eq!(clean_device_name(&"x".repeat(100)).len(), 64);
    }

    #[test]
    fn round_trip_and_damaged_file_falls_back() {
        let dir = std::env::temp_dir().join(format!("hx-prefs-{}", crate::servers::new_id()));
        let path = dir.join("prefs.json");
        let p = Prefs {
            theme: 2,
            quality: 1,
            ..Prefs::default()
        };
        p.save(Some(&path));
        assert_eq!(Prefs::load(Some(&path)).theme, 2);
        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(Prefs::load(Some(&path)), Prefs::default());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn bandwidth_steps() {
        let mut p = Prefs::default();
        assert_eq!(p.bandwidth_kbps(), 0);
        p.bandwidth = 3;
        assert_eq!(p.bandwidth_kbps(), 25_000);
    }
}

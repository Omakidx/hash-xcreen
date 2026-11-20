//! Incus version numbers.

use std::fmt;
use std::str::FromStr;

/// An Incus server version, `major.minor.patch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IncusVersion {
    /// Major.
    pub major: u32,
    /// Minor.
    pub minor: u32,
    /// Patch (0 when the server reports only two components).
    pub patch: u32,
}

/// Docker in an unprivileged container needs at least this Incus release (architecture 4.3).
/// The version is only a gate; the installed result is verified by the self-test.
pub const DOCKER_MIN_INCUS: IncusVersion = IncusVersion {
    major: 6,
    minor: 0,
    patch: 5,
};

impl IncusVersion {
    /// Build a version.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for IncusVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A version string that has no leading number.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not an Incus version: `{0}`")]
pub struct ParseVersionError(String);

impl FromStr for IncusVersion {
    type Err = ParseVersionError;

    /// Accepts `6.0.5`, `6.0`, `7.6-ubuntu26.04`, `6.0.5 LTS` (anything after the numbers is ignored).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseVersionError(s.to_string());
        let mut parts = [0u32; 3];
        let mut rest = s.trim();
        let mut found = 0;
        for slot in parts.iter_mut() {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() {
                break;
            }
            *slot = digits.parse().map_err(|_| err())?;
            found += 1;
            rest = &rest[digits.len()..];
            match rest.strip_prefix('.') {
                Some(r) => rest = r,
                None => break,
            }
        }
        if found == 0 {
            return Err(err());
        }
        Ok(Self {
            major: parts[0],
            minor: parts[1],
            patch: parts[2],
        })
    }
}

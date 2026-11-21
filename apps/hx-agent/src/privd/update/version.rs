//! Release versions: the strict syntax of ipc.md 6.12 rule 1 and their order.
//!
//! `^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(alpha|beta|rc)\.[0-9]{1,4})?$`. A [`Version`] can only
//! be built from a string that passed `hx_ipc::privd::is_valid_update_version`, so a value of this
//! type is safe to put in a path, a unit instance name or a log line.

use std::cmp::Ordering;
use std::fmt;

/// A pre-release tag, in precedence order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pre {
    /// `alpha`.
    Alpha,
    /// `beta`.
    Beta,
    /// `rc`.
    Rc,
}

/// A validated release version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Version {
    /// Major.
    pub major: u16,
    /// Minor.
    pub minor: u16,
    /// Patch.
    pub patch: u16,
    /// Pre-release tag and number; a release sorts after all its pre-releases.
    pub pre: Option<(Pre, u16)>,
}

impl Version {
    /// Parses a version; `None` unless it matches the strict syntax.
    pub fn parse(s: &str) -> Option<Self> {
        if !hx_ipc::privd::is_valid_update_version(s) {
            return None;
        }
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (s, None),
        };
        let mut n = core.split('.').map(|p| p.parse::<u16>().ok());
        let (major, minor, patch) = (n.next()??, n.next()??, n.next()??);
        let pre = match pre {
            None => None,
            Some(p) => {
                let (tag, num) = p.split_once('.')?;
                let tag = match tag {
                    "alpha" => Pre::Alpha,
                    "beta" => Pre::Beta,
                    "rc" => Pre::Rc,
                    _ => return None,
                };
                Some((tag, num.parse().ok()?))
            }
        };
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre, other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => a.cmp(&b),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some((tag, n)) = self.pre {
            let t = match tag {
                Pre::Alpha => "alpha",
                Pre::Beta => "beta",
                Pre::Rc => "rc",
            };
            write!(f, "-{t}.{n}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn order_follows_semver_with_the_three_tags() {
        let ascending = [
            "0.1.0",
            "0.1.1",
            "0.2.0-alpha.1",
            "0.2.0-alpha.2",
            "0.2.0-beta.1",
            "0.2.0-rc.1",
            "0.2.0",
            "0.10.0",
            "1.0.0-rc.9",
            "1.0.0",
            "9999.9999.9999",
        ];
        for w in ascending.windows(2) {
            assert!(v(w[0]) < v(w[1]), "{} < {}", w[0], w[1]);
        }
        for s in ascending {
            assert_eq!(v(s).to_string(), s);
        }
    }

    #[test]
    fn invalid_strings_do_not_parse() {
        for s in [
            "", "1", "1.2", "1.2.3.4", "1.2.3-", "1.2.3-rc", "1.2.3-gamma.1", "v1.2.3",
        ] {
            assert!(Version::parse(s).is_none(), "{s}");
        }
    }
}

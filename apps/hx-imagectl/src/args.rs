//! A small hand-written argument parser (no CLI crate, like `hx-agent`).
//!
//! Each command declares its options in a [`Spec`]: options with one value (`--out DIR`, also
//! `--out=DIR`), options with one or more values (`--entries A B C`, which takes words until the
//! next `--option`), flags, and a number of positional words. An unknown option, a repeated
//! single-value option, a missing value or a stray word is a usage error.

use std::collections::{BTreeMap, BTreeSet};

/// What a command accepts.
#[derive(Debug, Clone, Copy)]
pub struct Spec {
    /// Options that take exactly one value.
    pub values: &'static [&'static str],
    /// Options that take one or more values (all words up to the next `--option`).
    pub lists: &'static [&'static str],
    /// Options without a value.
    pub flags: &'static [&'static str],
    /// Exactly this many positional words.
    pub positionals: usize,
}

/// The parsed command line of one command.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    values: BTreeMap<String, String>,
    lists: BTreeMap<String, Vec<String>>,
    flags: BTreeSet<String>,
    /// Positional words in order.
    pub positional: Vec<String>,
}

/// A command-line mistake (exit status 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

fn usage<T>(m: impl Into<String>) -> Result<T, UsageError> {
    Err(UsageError(m.into()))
}

impl Parsed {
    /// Parse `args` (the words after the command name) against `spec`.
    pub fn parse(spec: &Spec, args: &[String]) -> Result<Self, UsageError> {
        let mut out = Parsed::default();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            i += 1;
            let Some(body) = a.strip_prefix("--") else {
                out.positional.push(a.clone());
                continue;
            };
            if body.is_empty() {
                // `--`: everything after it is positional.
                out.positional.extend(args[i..].iter().cloned());
                break;
            }
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (body, None),
            };
            if spec.flags.contains(&name) {
                if inline.is_some() {
                    return usage(format!("--{name} takes no value"));
                }
                out.flags.insert(name.to_string());
            } else if spec.values.contains(&name) {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        let Some(v) = args.get(i) else {
                            return usage(format!("--{name} needs a value"));
                        };
                        i += 1;
                        v.clone()
                    }
                };
                if out.values.insert(name.to_string(), v).is_some() {
                    return usage(format!("--{name} was given twice"));
                }
            } else if spec.lists.contains(&name) {
                let mut vs: Vec<String> = inline.into_iter().collect();
                while let Some(v) = args.get(i) {
                    if v.starts_with("--") {
                        break;
                    }
                    vs.push(v.clone());
                    i += 1;
                }
                if vs.is_empty() {
                    return usage(format!("--{name} needs at least one value"));
                }
                if out.lists.insert(name.to_string(), vs).is_some() {
                    return usage(format!("--{name} was given twice"));
                }
            } else {
                return usage(format!("unknown option --{name}"));
            }
        }
        if out.positional.len() != spec.positionals {
            return usage(format!(
                "expected {} positional argument(s), got {}",
                spec.positionals,
                out.positional.len()
            ));
        }
        Ok(out)
    }

    /// The value of a single-value option, if given.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// The value of a required single-value option.
    pub fn require(&self, name: &str) -> Result<&str, UsageError> {
        self.get(name)
            .ok_or_else(|| UsageError(format!("--{name} is required")))
    }

    /// The values of a list option, if given.
    pub fn list(&self, name: &str) -> Option<&[String]> {
        self.lists.get(name).map(Vec::as_slice)
    }

    /// Whether a flag was given.
    pub fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }

    /// A single-value option as an unsigned number.
    pub fn number(&self, name: &str) -> Result<Option<u64>, UsageError> {
        self.get(name)
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| UsageError(format!("--{name} must be a whole number")))
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: Spec = Spec {
        values: &["recipe", "out"],
        lists: &["entries"],
        flags: &["all"],
        positionals: 0,
    };

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn values_flags_lists_and_inline_values() {
        let p = Parsed::parse(&SPEC, &words("--recipe r --out=/x --all --entries a b c")).unwrap();
        assert_eq!(p.get("recipe"), Some("r"));
        assert_eq!(p.get("out"), Some("/x"));
        assert!(p.flag("all"));
        assert_eq!(p.list("entries").unwrap(), ["a", "b", "c"]);
        assert_eq!(p.require("recipe").unwrap(), "r");
    }

    #[test]
    fn a_list_stops_at_the_next_option() {
        let p = Parsed::parse(&SPEC, &words("--entries a b --out o")).unwrap();
        assert_eq!(p.list("entries").unwrap(), ["a", "b"]);
        assert_eq!(p.get("out"), Some("o"));
    }

    #[test]
    fn mistakes_are_usage_errors() {
        for bad in [
            "--nope",
            "--recipe",
            "--recipe a --recipe b",
            "--all=1",
            "--entries",
            "--entries a --entries b",
            "stray",
        ] {
            assert!(Parsed::parse(&SPEC, &words(bad)).is_err(), "{bad}");
        }
        assert!(
            Parsed::parse(&SPEC, &[])
                .unwrap()
                .require("recipe")
                .is_err()
        );
    }

    #[test]
    fn positionals_are_counted_and_double_dash_ends_options() {
        const P: Spec = Spec {
            values: &[],
            lists: &[],
            flags: &[],
            positionals: 2,
        };
        let p = Parsed::parse(&P, &words("a.json b.json")).unwrap();
        assert_eq!(p.positional, ["a.json", "b.json"]);
        assert!(Parsed::parse(&P, &words("a.json")).is_err());
        let p = Parsed::parse(&P, &words("-- --a --b")).unwrap();
        assert_eq!(p.positional, ["--a", "--b"]);
    }

    #[test]
    fn numbers() {
        const N: Spec = Spec {
            values: &["n"],
            lists: &[],
            flags: &[],
            positionals: 0,
        };
        assert_eq!(
            Parsed::parse(&N, &words("--n 7")).unwrap().number("n"),
            Ok(Some(7))
        );
        assert!(
            Parsed::parse(&N, &words("--n x"))
                .unwrap()
                .number("n")
                .is_err()
        );
        assert_eq!(Parsed::parse(&N, &[]).unwrap().number("n"), Ok(None));
    }
}

//! Error types for recipe loading and validation.

/// Everything that can be wrong with a recipe or the request to resolve one.
///
/// Messages name the file and the key so that a recipe author can fix the problem without
/// reading code.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecipeError {
    /// A recipe file could not be read.
    #[error("cannot read recipe file `{path}`: {message}")]
    Read {
        /// Path relative to the recipes root.
        path: String,
        /// Underlying error text.
        message: String,
    },
    /// A file is not valid TOML, or has an unknown key or a value of the wrong type.
    #[error("{path}: {message}")]
    Parse {
        /// Path relative to the recipes root.
        path: String,
        /// Parser or schema message, including line information when available.
        message: String,
    },
    /// `include` chain loops back on itself.
    #[error("include cycle: {}", chain.join(" -> "))]
    IncludeCycle {
        /// The files in include order, ending with the repeated one.
        chain: Vec<String>,
    },
    /// An `include` entry is unusable.
    #[error("{path}: include `{include}` {reason}")]
    BadInclude {
        /// The including file.
        path: String,
        /// The offending entry.
        include: String,
        /// What is wrong with it.
        reason: String,
    },
    /// Includes nest deeper than the limit.
    #[error("{path}: includes nest deeper than {max} levels")]
    IncludeTooDeep {
        /// The file at which the limit was hit.
        path: String,
        /// The limit.
        max: usize,
    },
    /// `{{name}}` refers to a variable that is not in `[vars]`.
    #[error("variable `{name}` is not defined (used in `{key}`)")]
    MissingVar {
        /// The variable name.
        name: String,
        /// The recipe key whose value uses it.
        key: String,
    },
    /// A `{{` without a closing `}}`, or an invalid variable name.
    #[error("malformed variable reference in `{key}`: {reason}")]
    BadTemplate {
        /// The recipe key whose value is malformed.
        key: String,
        /// What is wrong.
        reason: String,
    },
    /// A value is present but not acceptable.
    #[error("invalid `{field}`: {message}")]
    Invalid {
        /// Dotted key path, e.g. `apt_repo[1].key_fingerprint`.
        field: String,
        /// Why it was rejected.
        message: String,
    },
    /// The requested add-on does not exist.
    #[error("unknown add-on `{0}`")]
    UnknownAddon(String),
    /// The requested distro / desktop / preset combination has no recipe.
    #[error("no recipe for `{0}`")]
    UnknownRecipe(String),
}

impl RecipeError {
    pub(crate) fn invalid(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Invalid {
            field: field.into(),
            message: message.into(),
        }
    }
}

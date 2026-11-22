//! `cleanup --prefix P`: remove every object this tool created under the prefix (the instances,
//! the images, the pool, bridge, ACL and profiles). For local runs; a CI runner is thrown away.
//! Only objects under the prefix are touched, and `teardown_host` skips what lacks the
//! hash-xcreen marker.

use hx_provision::incus::Client;
use hx_provision::orchestrate::destroy_instance;
use hx_provision::teardown::teardown_host;

use crate::args::{Parsed, Spec};
use crate::devproxy;
use crate::host::{
    DEFAULT_PREFIX, builder_name, desktop_name, fingerprint_of_alias, import_alias, incus, naming,
    publish_alias, socket,
};
use crate::util::{CliError, failed};

/// Options of `cleanup`.
pub const SPEC: Spec = Spec {
    values: &["prefix"],
    lists: &[],
    flags: &[],
    positionals: 0,
};

pub async fn run(p: &Parsed) -> Result<String, CliError> {
    let prefix = p.get("prefix").unwrap_or(DEFAULT_PREFIX);
    let n = naming(prefix)?;
    let c = Client::unix(socket());
    let mut report = String::new();
    let base0 = devproxy::base_instance(&n);
    for inst in [
        builder_name(prefix),
        desktop_name(prefix, "build"),
        desktop_name(prefix, "prebuilt"),
        base0,
    ] {
        match destroy_instance(&c, &inst).await {
            Ok(()) => report.push_str(&format!("instance {inst}: gone\n")),
            Err(e) => report.push_str(&format!("instance {inst}: {e}\n")),
        }
    }
    for alias in [
        publish_alias(prefix),
        devproxy::base_alias(&n),
        import_alias(prefix),
    ] {
        if fingerprint_of_alias(&c, &alias).await?.is_some() {
            match incus(&["image", "delete", &alias]).await {
                Ok(_) => report.push_str(&format!("image {alias}: deleted\n")),
                Err(e) => report.push_str(&format!("image {alias}: {}\n", e.message())),
            }
        }
    }
    let t = teardown_host(&c, &n)
        .await
        .map_err(|e| failed(format!("teardown_host: {e}")))?;
    report.push_str(&format!("host objects: {t:?}\n"));
    Ok(report)
}

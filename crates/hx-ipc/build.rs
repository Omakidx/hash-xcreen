//! Compiles the enabled schemas with the pure-Rust `protox` front end and feeds the descriptors
//! to `prost-build`, so building needs no `protoc` binary.
//!
//! Only the schemas of the enabled features are compiled, so a crate that enables just `link`
//! never sees the privd messages. The shared `hx.v1` types are mapped to `hx_proto::pb` instead
//! of being generated again.

use std::env;
use std::error::Error;
use std::path::PathBuf;

fn compile(files: &[&str], include_file: &str, extern_hx_v1: bool) -> Result<(), Box<dyn Error>> {
    let fds = protox::compile(files, ["proto", "../hx-proto/proto"])?;
    let mut config = prost_build::Config::new();
    config.bytes(["."]);
    config.include_file(include_file);
    if extern_hx_v1 {
        config.extern_path(".hx.v1", "::hx_proto::pb");
    }
    config.compile_fds(fds)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=../hx-proto/proto/hx.proto");
    let out = PathBuf::from(env::var("OUT_DIR")?);
    // Leave every include file in place so `include!` finds them whatever the features.
    for name in [
        "_privd_includes.rs",
        "_link_includes.rs",
        "_repo_includes.rs",
    ] {
        std::fs::write(out.join(name), "")?;
    }
    if env::var_os("CARGO_FEATURE_PRIVD").is_some() {
        compile(
            &["privd.proto", "gatewayd_admin.proto"],
            "_privd_includes.rs",
            false,
        )?;
    }
    if env::var_os("CARGO_FEATURE_LINK").is_some() {
        compile(&["link.proto"], "_link_includes.rs", true)?;
    }
    if env::var_os("CARGO_FEATURE_REPO").is_some() {
        compile(&["repo.proto"], "_repo_includes.rs", false)?;
    }
    Ok(())
}

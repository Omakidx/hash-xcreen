//! Compiles `proto/hx.proto` with the pure-Rust `protox` front end and feeds the resulting
//! descriptor to `prost-build`, so building needs no `protoc` binary.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=proto/hx.proto");
    let fds = protox::compile(["proto/hx.proto"], ["proto"])?;
    let mut config = prost_build::Config::new();
    config.bytes(["."]);
    // Types that carry secrets get a hand-written, redacting `Debug` (see `src/redact.rs`).
    config.skip_debug([
        ".hx.v1.SetupSetPin",
        ".hx.v1.SetupStart",
        ".hx.v1.Opaque",
        ".hx.v1.PairingCodeIssued",
        ".hx.v1.ServerChangePin",
        ".hx.v1.ServerChangePassword",
    ]);
    config.compile_fds(fds)?;
    Ok(())
}

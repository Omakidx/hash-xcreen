//! Privileged helper: a fixed command set for Incus, snapshots, mounts and restore. Runs as root.

fn main() {
    println!("{} {}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));
}

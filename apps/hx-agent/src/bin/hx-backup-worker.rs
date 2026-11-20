//! Backup worker: uploads a read-only snapshot to Google Drive. Spawned by hx-privd.

fn main() {
    println!("{} {}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));
}

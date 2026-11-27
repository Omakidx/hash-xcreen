//! `hx-backup-worker`: the backup worker and the Drive helper (docs/ipc.md §6.12, Part 3).

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let role = std::env::var_os("HX_BACKUP_ROLE");
    std::process::exit(hx_backup_worker::run(&args, role.as_deref()));
}

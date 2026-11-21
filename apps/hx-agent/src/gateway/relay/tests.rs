use super::*;

#[test]
fn only_a_socket_of_this_user_is_dialled() {
    let d = std::env::temp_dir().join(format!("hx-chk-sock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    // Not there: left to the dial.
    assert!(check_socket(&d.join("none")).is_ok());
    // A regular file, a directory and a symlink are refused.
    let f = d.join("file");
    std::fs::write(&f, b"x").unwrap();
    assert!(check_socket(&f).is_err());
    assert!(check_socket(&d).is_err());
    let l = d.join("link");
    std::os::unix::fs::symlink(&f, &l).unwrap();
    assert!(check_socket(&l).is_err());
    // A socket of ours is fine; a link to it is not the socket.
    let s = d.join("sock");
    let _keep = std::os::unix::net::UnixListener::bind(&s).unwrap();
    assert!(check_socket(&s).is_ok());
    let ls = d.join("sock-link");
    std::os::unix::fs::symlink(&s, &ls).unwrap();
    assert!(check_socket(&ls).is_err());
    let _ = std::fs::remove_dir_all(&d);
}

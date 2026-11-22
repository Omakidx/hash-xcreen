//! "This server must be updated": shown when the client library answers `UpdateRequired`
//! (setup, pairing codes from the app and "Pair again" need protocol 1.3 on the server).

use std::rc::Rc;

use slint::ComponentHandle;

use super::{App, ss};
use crate::{Screen, UpdateVm};

/// The commands the user runs on the server, in order.
pub const COMMANDS: &str = "sudo hx-agent update check\nsudo hx-agent update apply <version>";

/// What the app knows about the server's version, as a sentence.
pub fn found_text(v: Option<(u32, u32)>) -> String {
    match v {
        Some((a, b)) => format!("It speaks protocol {a}.{b}."),
        None => "Its protocol version has not been confirmed.".to_owned(),
    }
}

/// Shows the screen for a saved server.
pub fn show(app: &Rc<App>, server_id: &str) {
    let s = app.server(server_id);
    let ui = app.ui();
    let vm = ui.global::<UpdateVm>();
    vm.set_server_name(ss(s
        .as_ref()
        .map_or("The server".to_owned(), |s| s.name.clone())));
    vm.set_found(ss(found_text(s.as_ref().and_then(|s| s.version()))));
    vm.set_commands(ss(COMMANDS));
    app.go(Screen::Update);
}

pub fn wire(app: &Rc<App>) {
    let ui = app.ui();
    let vm = ui.global::<UpdateVm>();
    let a = app.clone();
    vm.on_back(move || a.show_home());
    let a = app.clone();
    vm.on_copy_commands(move || a.set_clipboard(COMMANDS));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_names_the_commands_and_the_version() {
        assert!(COMMANDS.starts_with("sudo hx-agent update check"));
        assert!(COMMANDS.contains("sudo hx-agent update apply"));
        assert_eq!(found_text(Some((1, 2))), "It speaks protocol 1.2.");
        assert!(found_text(None).contains("not been confirmed"));
    }
}

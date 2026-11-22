//! Home: the server cards and their primary actions.

use std::rc::Rc;

use slint::ComponentHandle;

use super::{App, now_unix, spawn_ui, ss};
use crate::servers::{Lifecycle, Server};
use crate::{HomeVm, ServerCardData};

/// The card of one server, from what is known about it.
pub fn card(s: &Server, reachable: Option<bool>, unavailable: bool) -> ServerCardData {
    let (status, tone, note, action, label, enabled): (&str, i32, String, &str, &str, bool) =
        match s.lifecycle {
            Lifecycle::Revoked => (
                "Pair again",
                3,
                format!(
                    "This device was removed from the server on {}",
                    crate::details::date_utc(s.revoked_unix)
                ),
                "pair",
                "Pair again",
                true,
            ),
            Lifecycle::Installing => (
                "Installing",
                4,
                "The install did not finish. Retry resumes it.".into(),
                "progress",
                "View progress",
                true,
            ),
            Lifecycle::SetupPending => (
                "Setup not finished",
                2,
                "Paired with this app, but the desktop was not created yet".into(),
                "finish",
                "Finish setup",
                true,
            ),
            Lifecycle::Uninstalled => (
                "Uninstalled",
                0,
                "hash-xcreen was uninstalled from this server. Remove the card when you are done."
                    .into(),
                "none",
                "",
                false,
            ),
            Lifecycle::Ready => match reachable {
                None => ("Checking…", 0, String::new(), "connect", "Connect", false),
                Some(false) => (
                    "Offline",
                    0,
                    if s.last_seen_unix == 0 {
                        "No answer yet".into()
                    } else {
                        format!(
                            "Last seen {}",
                            crate::details::relative_time(s.last_seen_unix, now_unix(), false)
                        )
                    },
                    "connect",
                    "Connect",
                    false,
                ),
                Some(true) if unavailable => (
                    "Desktop unavailable",
                    2,
                    "The server is up; retrying every 10 minutes".into(),
                    "connect",
                    "Connect",
                    true,
                ),
                Some(true) => ("Online", 1, String::new(), "connect", "Connect", true),
            },
        };
    ServerCardData {
        id: ss(&s.id),
        name: ss(&s.name),
        address: ss(s.address()),
        status: ss(status),
        tone,
        extra_badge: ss(""),
        note: ss(note),
        action: ss(action),
        action_label: ss(label),
        action_enabled: enabled,
    }
}

/// Fills the Home view model. `loading` shows "Checking…" on every card.
pub fn refresh(app: &Rc<App>, loading: bool) {
    let ui = app.ui();
    let reach = app.reachable.borrow();
    let un = app.unavailable.borrow();
    let cards: Vec<ServerCardData> = app
        .store
        .borrow()
        .list()
        .iter()
        .map(|s| {
            card(
                s,
                if loading {
                    None
                } else {
                    reach.get(&s.id).copied()
                },
                un.contains(&s.id),
            )
        })
        .collect();
    let vm = ui.global::<HomeVm>();
    vm.set_loading(loading && !cards.is_empty());
    vm.set_servers(super::model(cards));
}

/// Checks every server's reachability in the background.
pub fn probe_all(app: &Rc<App>) {
    let list: Vec<(String, String, u16)> = app
        .store
        .borrow()
        .list()
        .iter()
        .filter(|s| s.lifecycle == Lifecycle::Ready)
        .map(|s| (s.id.clone(), s.host.clone(), s.port))
        .collect();
    if list.is_empty() {
        refresh(app, false);
        return;
    }
    let connector = app.be.connector.clone();
    let n = list.len();
    let remaining = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(n));
    for (id, host, port) in list {
        let c = connector.clone();
        let left = remaining.clone();
        spawn_ui(
            app,
            async move { (id, c.probe(&host, port).await) },
            move |a, (id, up)| {
                a.reachable.borrow_mut().insert(id, up);
                let done = left.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1;
                // Cards fall back one by one; the "checking" state ends with the last answer.
                refresh(a, !done);
            },
        );
    }
}

pub fn wire(app: &Rc<App>) {
    let ui = app.ui();
    let vm = ui.global::<HomeVm>();
    let a = app.clone();
    vm.on_add_server(move || super::wizard_ctl::open(&a, false));
    let a = app.clone();
    vm.on_enter_code(move || super::wizard_ctl::open(&a, true));
    let a = app.clone();
    vm.on_details(move |id| super::details_ctl::open(&a, id.as_str()));
    let a = app.clone();
    vm.on_primary(move |id, action| match action.as_str() {
        "connect" => super::connect_ctl::open(&a, id.as_str()),
        "pair" => super::connect_ctl::open_pair_again(&a, id.as_str()),
        "progress" | "finish" => super::progress_ctl::open_for_server(&a, id.as_str()),
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(l: Lifecycle) -> Server {
        Server {
            id: "a".into(),
            name: "Workstation".into(),
            host: "203.0.113.10".into(),
            port: 443,
            server_key: String::new(),
            lifecycle: l,
            last_seen_unix: 0,
            revoked_unix: 1_699_920_000,
            server_version: String::new(),
        }
    }

    #[test]
    fn card_states_follow_the_vocabulary() {
        let c = card(&s(Lifecycle::Ready), Some(true), false);
        assert_eq!(
            (c.status.as_str(), c.tone, c.action_enabled),
            ("Online", 1, true)
        );
        let c = card(&s(Lifecycle::Ready), Some(false), false);
        assert_eq!(c.status.as_str(), "Offline");
        assert!(!c.action_enabled, "offline Connect is disabled");
        let c = card(&s(Lifecycle::Ready), None, false);
        assert_eq!(c.status.as_str(), "Checking…");
        let c = card(&s(Lifecycle::Ready), Some(true), true);
        assert_eq!(c.status.as_str(), "Desktop unavailable");
        assert!(c.action_enabled);
        let c = card(&s(Lifecycle::Revoked), None, false);
        assert_eq!(
            (c.status.as_str(), c.action.as_str()),
            ("Pair again", "pair")
        );
        assert!(c.note.contains("14 Nov"));
        assert_eq!(
            card(&s(Lifecycle::SetupPending), None, false)
                .action
                .as_str(),
            "finish"
        );
        assert_eq!(
            card(&s(Lifecycle::Installing), None, false)
                .action_label
                .as_str(),
            "View progress"
        );
        assert_eq!(
            card(&s(Lifecycle::Uninstalled), None, false)
                .action
                .as_str(),
            "none"
        );
    }
}

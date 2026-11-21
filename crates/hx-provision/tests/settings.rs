//! Recipe variables for the desktop settings (ipc.md 6.5): validation, substitution, reserved names.

use hx_provision::lower::lower;
use hx_provision::recipe::resolve_with_settings;
use hx_provision::{
    Action, Addon, Catalog, Desktop, Distro, MemSource, Preset, RecipeId, Secrets, Settings, Step,
};

fn id() -> RecipeId {
    RecipeId {
        distro: Distro::Debian13,
        desktop: Desktop::Xfce,
        preset: Preset::Basic,
    }
}

fn settings_scripts(settings: &Settings) -> Vec<(String, String)> {
    let plan = Catalog::embedded()
        .resolve_with(id(), &[], None, settings)
        .unwrap();
    plan.post
        .iter()
        .filter_map(|s| match s {
            Step::Command(c) if c.name.starts_with("settings-") => {
                let Action::Exec(r) = &lower(s, &Secrets::none()).unwrap()[0] else {
                    panic!()
                };
                Some((c.name.clone(), r.argv.last().unwrap().clone()))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn hostnames_are_rfc_1123_labels() {
    for ok in ["main", "a", "my-desk-01", "0day", &"a".repeat(63)] {
        assert_eq!(
            Settings::none().with_hostname(ok).unwrap().hostname(),
            Some(ok)
        );
    }
    for bad in [
        "",
        "-a",
        "a-",
        "My",
        "a_b",
        "a.b",
        "a b",
        "a;b",
        "a$(id)",
        "a'b",
        "a\nb",
        "ä",
        "localhost",
        &"a".repeat(64),
    ] {
        assert!(
            Settings::none().with_hostname(bad).is_err(),
            "{bad:?} must be refused"
        );
    }
}

#[test]
fn timezones_are_zoneinfo_names() {
    for ok in [
        "UTC",
        "Europe/Berlin",
        "America/Argentina/Buenos_Aires",
        "Etc/GMT+5",
        "America/Port-au-Prince",
    ] {
        assert!(Settings::none().with_timezone(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "/",
        "/etc/passwd",
        "../etc/passwd",
        "Europe/../x",
        "Europe//Berlin",
        "Europe/Berlin/",
        "a/b/c/d",
        "Europe/Ber lin",
        "UTC;id",
        "UTC'",
        "UTC\n",
        "Europe/Berlin.x",
        &"a".repeat(33),
    ] {
        assert!(
            Settings::none().with_timezone(bad).is_err(),
            "{bad:?} must be refused"
        );
    }
}

#[test]
fn timezone_existence_check_uses_the_directory_given() {
    let dir = std::env::temp_dir().join(format!("hx-zoneinfo-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("Europe")).unwrap();
    std::fs::write(dir.join("Europe/Berlin"), b"x").unwrap();
    assert!(
        Settings::none()
            .with_timezone_in("Europe/Berlin", &dir)
            .is_ok()
    );
    assert!(
        Settings::none()
            .with_timezone_in("Europe/Nowhere", &dir)
            .is_err()
    );
    // A directory is not a zone.
    assert!(Settings::none().with_timezone_in("Europe", &dir).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn locales_come_from_an_allowlist_and_are_normalized() {
    let s = Settings::none().with_locale("de_DE").unwrap();
    assert_eq!(s.locale(), Some("de_DE.UTF-8"));
    let s = Settings::none().with_locale("en_GB.UTF-8").unwrap();
    assert_eq!(s.locale(), Some("en_GB.UTF-8"));
    for bad in [
        "",
        "xx_XX",
        "en_US.ISO-8859-1",
        "en_US.utf8",
        "en_us",
        "C",
        "POSIX",
        "en_US.UTF-8 UTF-8",
        "en_US;id",
        "en_US\n",
        "../en_US",
    ] {
        assert!(
            Settings::none().with_locale(bad).is_err(),
            "{bad:?} must be refused"
        );
    }
    // The allowlist is sorted and every entry matches the documented pattern.
    let l = hx_provision::settings::ALLOWED_LOCALES;
    assert!(l.windows(2).all(|w| w[0] < w[1]));
    assert!(l.iter().all(|x| {
        let (a, b) = x.split_once('_').unwrap();
        (2..=3).contains(&a.len())
            && a.bytes().all(|c| c.is_ascii_lowercase())
            && b.len() == 2
            && b.bytes().all(|c| c.is_ascii_uppercase())
    }));
}

#[test]
fn keyboards_are_layout_and_optional_variant() {
    for ok in [
        "de",
        "us",
        "de+nodeadkeys",
        "us+dvorak-intl",
        "ch+de_nodeadkeys",
    ] {
        assert_eq!(
            Settings::none().with_keyboard(ok).unwrap().keyboard(),
            Some(ok)
        );
    }
    for bad in [
        "",
        "d",
        "deu",
        "DE",
        "de+",
        "de+A",
        "de+x y",
        "de+nodeadkeys+x",
        "de;id",
        "de\n",
        "de+aaaaaaaaaaaaaaaaa",
        "+nodeadkeys",
    ] {
        assert!(
            Settings::none().with_keyboard(bad).is_err(),
            "{bad:?} must be refused"
        );
    }
}

#[test]
fn unset_settings_make_every_step_a_no_op() {
    let steps = settings_scripts(&Settings::none());
    assert_eq!(
        steps.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
        [
            "settings-hostname",
            "settings-timezone",
            "settings-locale",
            "settings-keyboard"
        ]
    );
    // Each starts from an empty, quoted value and acts only when it is non-empty.
    for (name, script) in &steps {
        let first = script.lines().next().unwrap();
        assert!(first.ends_with("=''"), "{name}: {first}");
        assert!(script.contains("if [ -n "), "{name}");
    }
}

#[test]
fn values_are_substituted_single_quoted() {
    let s = Settings::none()
        .with_hostname("my-desk")
        .unwrap()
        .with_timezone("Europe/Berlin")
        .unwrap()
        .with_locale("de_DE")
        .unwrap()
        .with_keyboard("de+nodeadkeys")
        .unwrap();
    let steps = settings_scripts(&s);
    let all: Vec<&str> = steps.iter().map(|(_, s)| s.as_str()).collect();
    assert!(all[0].contains("h='my-desk'"));
    assert!(all[1].contains("tz='Europe/Berlin'"));
    assert!(all[2].contains("l='de_DE.UTF-8'"));
    assert!(all[3].contains("k='de+nodeadkeys'"));
    // The settings never leak into the plan's variables or the equivalence manifest.
    let plan = Catalog::embedded()
        .resolve_with(id(), &[], None, &s)
        .unwrap();
    for k in ["hostname", "timezone", "locale", "keyboard"] {
        assert!(!plan.vars.contains_key(k), "{k}");
    }
    let plain = Catalog::embedded().resolve(id(), &[]).unwrap();
    assert_eq!(plain.build, plan.build);
    assert_eq!(plain.manifest().packages, plan.manifest().packages);
}

#[test]
fn settings_vars_are_reserved_in_recipes() {
    for var in ["hostname", "timezone", "locale", "keyboard"] {
        let src = MemSource::new().with(
            "r.toml",
            &format!(
                "[recipe]\nname = \"r\"\nbase_image = \"images:debian/13\"\n[vars]\n{var} = \"x\"\n"
            ),
        );
        let e = resolve_with_settings(&src, "r.toml", &[], None, &Settings::none()).unwrap_err();
        assert!(e.to_string().contains(&format!("vars.{var}")), "{e}");
    }
}

#[test]
fn an_add_on_resolve_is_unaffected() {
    // The Docker add-on is resolved without settings and has no settings steps.
    let p = Catalog::embedded()
        .resolve_addon(id(), Addon::Docker)
        .unwrap();
    assert!(p.post.is_empty());
}

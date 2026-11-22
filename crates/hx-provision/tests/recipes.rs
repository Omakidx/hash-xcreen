//! Recipe resolution: every shipped combination, golden plans, and precise errors.

use std::path::{Path, PathBuf};

use hx_provision::catalog::embedded_source;
use hx_provision::recipe::{resolve, resolve_addon_only};
use hx_provision::{
    Action, Addon, Catalog, Distro, MemSource, Plan, Preset, RecipeError, RecipeId, Secrets, Stage,
    Step,
};

fn recipes_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../recipes")
}

fn golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("HX_UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (run with HX_UPDATE_GOLDEN=1)", path.display()));
    assert_eq!(
        want, actual,
        "golden mismatch for {name}; review and rerun with HX_UPDATE_GOLDEN=1"
    );
}

fn plan(id: RecipeId, addons: &[Addon]) -> Plan {
    Catalog::embedded()
        .resolve(id, addons)
        .unwrap_or_else(|e| panic!("{} {addons:?}: {e}", id.file_name()))
}

fn id(distro: Distro, preset: Preset) -> RecipeId {
    RecipeId {
        distro,
        desktop: hx_provision::Desktop::Xfce,
        preset,
    }
}

#[test]
fn every_shipped_recipe_resolves() {
    let mut n = 0;
    for rid in RecipeId::all() {
        for addons in [&[][..], &[Addon::Docker][..]] {
            let p = plan(rid, addons);
            n += 1;
            assert_eq!(p.name, format!("{}-xfce-{}", rid.distro, rid.preset));
            assert_eq!(
                p.vars["distro_version"],
                rid.distro.as_str().rsplit('-').next().unwrap()
            );
            assert_eq!(p.vars["preset"], rid.preset.as_str());
            assert_eq!(p.vars["desktop"], "xfce");
            // Stage skeleton.
            assert_eq!(p.build.first(), Some(&Step::WaitNetwork));
            assert!(matches!(p.build[1], Step::AptBootstrap));
            assert_eq!(p.post.first(), Some(&Step::WaitNetwork));
            assert!(
                p.post
                    .iter()
                    .any(|s| matches!(s, Step::SetPassword { user } if user == "desk"))
            );
            assert!(p.post.iter().any(|s| matches!(s, Step::SecurityUpdates)));
            let m = p.manifest();
            assert!(m.packages.contains(&"xfce4-session".to_string()));
            assert!(m.packages.contains(&"pipewire".to_string()));
            assert!(
                m.files
                    .iter()
                    .any(|f| f.path == "/etc/systemd/system/hx-xorg.service")
            );
            assert!(m.system_services.contains(&"hx-xorg.service".to_string()));
            assert_eq!(m.user.as_deref(), Some("desk"));
            // Every repository is pinned by a full fingerprint.
            for r in &m.apt_repos {
                assert_eq!(r.fingerprint.len(), 40, "{}", r.name);
                assert!(
                    r.fingerprint
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
                );
            }
            // Variables were substituted everywhere.
            assert!(!p.render().contains("{{"));
            for s in p.build.iter().chain(p.post.iter()) {
                if let Step::WriteFile(f) = s {
                    assert!(!f.content.contains("{{"), "{}", f.path);
                }
            }
            // Docker add-on.
            let docker = addons.contains(&Addon::Docker);
            assert_eq!(m.packages.contains(&"docker-ce".to_string()), docker);
            assert_eq!(m.apt_repos.iter().any(|r| r.name == "docker"), docker);
            assert_eq!(
                p.incus_config.get("security.nesting").map(String::as_str),
                docker.then_some("true")
            );
            assert_eq!(m.user_groups.contains(&"docker".to_string()), docker);
            // Developer preset.
            let dev = rid.preset == Preset::Developer;
            assert_eq!(m.packages.contains(&"code".to_string()), dev);
            assert_eq!(
                m.post_commands,
                // The settings steps (hostname, timezone, locale, keyboard) come first.
                if dev {
                    vec![
                        "settings-hostname",
                        "settings-timezone",
                        "settings-locale",
                        "settings-keyboard",
                        "claude-code",
                        "codex-cli",
                    ]
                } else {
                    vec![
                        "settings-hostname",
                        "settings-timezone",
                        "settings-locale",
                        "settings-keyboard",
                    ]
                }
            );
        }
    }
    assert_eq!(n, 16);
}

/// The hx-session .deb depends on the distro's libavcodec and libavutil sonames, and privd's
/// InstallSession runs `dpkg -i`, which resolves nothing: every recipe must install exactly them.
/// Sources (checked 2026-11-21): packages.ubuntu.com (resolute: 7:8.0.1-3ubuntu2),
/// packages.debian.org (bookworm 7:5.1.9-0+deb12u1, trixie 7:7.1.5-0+deb13u1), and the spike
/// 1c-e2e for noble (FFmpeg 6.1).
#[test]
fn every_recipe_installs_the_ffmpeg_runtime_the_session_package_needs() {
    for (distro, avcodec, avutil) in [
        (Distro::Ubuntu2404, "libavcodec60", "libavutil58"),
        (Distro::Ubuntu2604, "libavcodec62", "libavutil60"),
        (Distro::Debian12, "libavcodec59", "libavutil57"),
        (Distro::Debian13, "libavcodec61", "libavutil59"),
    ] {
        for preset in [Preset::Basic, Preset::Developer] {
            let m = plan(id(distro, preset), &[]).manifest();
            for want in [avcodec, avutil] {
                assert!(
                    m.packages.contains(&want.to_string()),
                    "{distro:?} {preset:?} does not install {want}"
                );
            }
            assert!(
                !m.packages.iter().any(|p| p.contains("{{")),
                "unexpanded variable in the package list"
            );
        }
    }
}

#[test]
fn distro_specifics() {
    let m = |d| plan(id(d, Preset::Basic), &[]).manifest();
    assert!(
        m(Distro::Ubuntu2404)
            .packages
            .contains(&"firefox".to_string())
    );
    assert!(
        m(Distro::Ubuntu2604)
            .packages
            .contains(&"firefox".to_string())
    );
    assert!(
        m(Distro::Debian12)
            .packages
            .contains(&"firefox-esr".to_string())
    );
    assert!(
        m(Distro::Debian13)
            .packages
            .contains(&"firefox-esr".to_string())
    );
    assert_eq!(
        plan(id(Distro::Ubuntu2604, Preset::Basic), &[])
            .base_image
            .notation(),
        "images:ubuntu/26.04"
    );
    assert_eq!(
        plan(id(Distro::Debian12, Preset::Basic), &[])
            .base_image
            .notation(),
        "images:debian/12"
    );
    let docker = plan(id(Distro::Ubuntu2604, Preset::Basic), &[Addon::Docker]).manifest();
    let repo = docker
        .apt_repos
        .iter()
        .find(|r| r.name == "docker")
        .unwrap();
    assert_eq!(repo.uri, "https://download.docker.com/linux/ubuntu");
    assert_eq!(repo.suite, "resolute");
    let docker = plan(id(Distro::Debian13, Preset::Basic), &[Addon::Docker]).manifest();
    let repo = docker
        .apt_repos
        .iter()
        .find(|r| r.name == "docker")
        .unwrap();
    assert_eq!(repo.uri, "https://download.docker.com/linux/debian");
    assert_eq!(repo.suite, "trixie");
}

#[test]
fn resolution_is_deterministic() {
    for rid in RecipeId::all() {
        assert_eq!(plan(rid, &[Addon::Docker]), plan(rid, &[Addon::Docker]));
        assert_eq!(plan(rid, &[]).render(), plan(rid, &[]).render());
    }
}

#[test]
fn embedded_recipes_equal_the_files_on_disk_and_none_is_missing() {
    let embedded = embedded_source();
    // Every file under recipes/ is embedded...
    let mut on_disk = Vec::new();
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, root, out);
            } else if p.extension().is_some_and(|x| x == "toml") {
                out.push(
                    p.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    walk(&recipes_dir(), &recipes_dir(), &mut on_disk);
    on_disk.sort();
    let mut emb: Vec<&str> = embedded.paths().collect();
    emb.sort();
    assert_eq!(on_disk.iter().map(String::as_str).collect::<Vec<_>>(), emb);
    // ...byte for byte (a stale build cache cannot hide an edit: this reads the files fresh)...
    for rel in &on_disk {
        let disk_text = std::fs::read_to_string(recipes_dir().join(rel)).unwrap();
        assert_eq!(
            hx_provision::RecipeSource::read(&embedded, rel).unwrap(),
            disk_text,
            "embedded `{rel}` differs from recipes/{rel}"
        );
    }
    // ...and resolving from disk gives the same plan.
    let disk = Catalog::from_dir(recipes_dir());
    for rid in RecipeId::all() {
        assert_eq!(
            disk.resolve(rid, &[Addon::Docker]).unwrap(),
            plan(rid, &[Addon::Docker])
        );
    }
}

#[test]
fn golden_plans() {
    golden(
        "ubuntu-24.04-xfce-basic.plan.txt",
        &plan(id(Distro::Ubuntu2404, Preset::Basic), &[]).render(),
    );
    golden(
        "debian-13-xfce-developer-docker.plan.txt",
        &plan(id(Distro::Debian13, Preset::Developer), &[Addon::Docker]).render(),
    );
    golden(
        "debian-13-xfce-developer-docker.manifest.json",
        &(serde_json::to_string_pretty(
            &plan(id(Distro::Debian13, Preset::Developer), &[Addon::Docker]).manifest(),
        )
        .unwrap()
            + "\n"),
    );
}

#[test]
fn developer_post_steps_run_as_the_user_and_are_optional() {
    let p = plan(id(Distro::Ubuntu2404, Preset::Developer), &[]);
    let cmds: Vec<_> = p
        .post
        .iter()
        .filter_map(|s| match s {
            Step::Command(c) => Some(c),
            _ => None,
        })
        .collect();
    assert_eq!(cmds.len(), 6);
    // The four settings steps run as root and are not optional; the vendor installers run as the
    // user and are optional.
    for c in &cmds[..4] {
        assert!(c.name.starts_with("settings-") && c.as_user.is_none() && !c.optional);
    }
    for c in &cmds[4..] {
        assert_eq!(c.as_user.as_deref(), Some("desk"));
        assert!(c.optional);
        assert!(c.timeout_secs <= 7200);
    }
    // Post stage order: network, user, password, updates, vendor installers.
    let order: Vec<String> = p
        .post
        .iter()
        .map(|s| s.describe().split(' ').next().unwrap().to_string())
        .collect();
    assert_eq!(
        order,
        [
            "wait-network",
            "ensure-user",
            "set-password",
            "security-updates",
            "command",
            "command",
            "command",
            "command",
            "command",
            "command"
        ]
    );
}

#[test]
fn addon_only_plan_has_just_the_addon_steps() {
    let c = Catalog::embedded();
    let p = c
        .resolve_addon(id(Distro::Debian13, Preset::Basic), Addon::Docker)
        .unwrap();
    assert!(p.post.is_empty());
    assert_eq!(p.incus_config.len(), 3);
    let kinds: Vec<String> = p
        .build
        .iter()
        .map(|s| s.describe().split(' ').next().unwrap().to_string())
        .collect();
    assert_eq!(
        kinds,
        [
            "wait-network",
            "apt-bootstrap",
            "apt-repo",
            "apt-install",
            "ensure-user",
            "enable-services"
        ]
    );
    let m = p.manifest();
    assert_eq!(
        m.packages,
        [
            "containerd.io",
            "docker-buildx-plugin",
            "docker-ce",
            "docker-ce-cli",
            "docker-compose-plugin"
        ]
    );
    assert_eq!(m.user.as_deref(), Some("desk"));
    assert_eq!(m.user_groups, ["docker"]);
    assert!(m.files.is_empty());
    // The add-on plan agrees with what the full plan adds.
    let full = c
        .resolve(id(Distro::Debian13, Preset::Basic), &[Addon::Docker])
        .unwrap()
        .manifest();
    let base = c
        .resolve(id(Distro::Debian13, Preset::Basic), &[])
        .unwrap()
        .manifest();
    for pkg in &m.packages {
        assert!(full.packages.contains(pkg) && !base.packages.contains(pkg));
    }
}

#[test]
fn manifest_diff_reports_differences() {
    let a = plan(id(Distro::Debian13, Preset::Basic), &[]).manifest();
    let b = plan(id(Distro::Debian13, Preset::Basic), &[Addon::Docker]).manifest();
    assert!(a.diff(&a).is_empty());
    let d = a.diff(&b);
    assert!(d.iter().any(|l| l.contains("docker-ce")), "{d:?}");
    assert!(d.iter().any(|l| l.contains("incus_config")), "{d:?}");
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

const GOOD: &str = r#"
[recipe]
name = "t"
base_image = "images:debian/13"
[vars]
codename = "trixie"
[apt]
packages = ["curl"]
"#;

fn err(src: MemSource, path: &str) -> RecipeError {
    resolve(&src, path, &[]).expect_err("should fail")
}

fn with_main(extra: &str) -> MemSource {
    MemSource::new().with("main.toml", &format!("{GOOD}\n{extra}"))
}

#[test]
fn good_minimal_recipe_resolves() {
    let p = resolve(&MemSource::new().with("main.toml", GOOD), "main.toml", &[]).unwrap();
    assert_eq!(p.name, "t");
    assert!(p.user().is_none());
    assert_eq!(p.post, vec![Step::WaitNetwork, Step::SecurityUpdates]);
    assert_eq!(p.stage(Stage::Build).len(), 3);
}

#[test]
fn unknown_keys_are_rejected_with_the_file_name() {
    let e = err(
        with_main("[services]\nsystm_enable = [\"x\"]\n"),
        "main.toml",
    );
    let msg = e.to_string();
    assert!(matches!(e, RecipeError::Parse { .. }), "{msg}");
    assert!(
        msg.contains("main.toml") && msg.contains("unknown field `systm_enable`"),
        "{msg}"
    );

    let src = MemSource::new()
        .with("main.toml", "include = [\"frag.toml\"]\n[recipe]\nname = \"t\"\nbase_image = \"images:debian/13\"\n")
        .with("frag.toml", "[user]\nnme = \"x\"\n");
    let msg = err(src, "main.toml").to_string();
    assert!(
        msg.contains("frag.toml") && msg.contains("unknown field `nme`"),
        "{msg}"
    );

    let msg = err(
        with_main("[[file]]\npath = \"/etc/x\"\ncontent = \"\"\nmod = \"0600\"\n"),
        "main.toml",
    )
    .to_string();
    assert!(msg.contains("unknown field `mod`"), "{msg}");
    let msg = err(
        with_main("[[step]]\nname = \"a\"\nrun = \"true\"\nsudo = true\n"),
        "main.toml",
    )
    .to_string();
    assert!(msg.contains("unknown field `sudo`"), "{msg}");
    let msg = err(with_main("[bogus]\nx = 1\n"), "main.toml").to_string();
    assert!(msg.contains("unknown field `bogus`"), "{msg}");
}

#[test]
fn toml_syntax_errors_carry_the_file() {
    let msg = err(
        MemSource::new().with("main.toml", "[recipe\nname="),
        "main.toml",
    )
    .to_string();
    assert!(msg.starts_with("main.toml:"), "{msg}");
}

#[test]
fn include_cycles_are_detected() {
    let src = MemSource::new()
        .with("a.toml", "include = [\"b.toml\"]\n")
        .with("b.toml", "include = [\"sub/c.toml\"]\n")
        .with("sub/c.toml", "include = [\"../a.toml\"]\n");
    match err(src, "a.toml") {
        RecipeError::IncludeCycle { chain } => {
            assert_eq!(chain, ["a.toml", "b.toml", "sub/c.toml", "a.toml"])
        }
        other => panic!("{other}"),
    }
    let src = MemSource::new().with("a.toml", "include = [\"a.toml\"]\n");
    assert!(matches!(
        err(src, "a.toml"),
        RecipeError::IncludeCycle { .. }
    ));
}

#[test]
fn includes_cannot_escape_or_be_absolute_and_depth_is_bounded() {
    let msg = err(
        MemSource::new().with("a.toml", "include = [\"../x.toml\"]\n"),
        "a.toml",
    )
    .to_string();
    assert!(msg.contains("leaves the recipes root"), "{msg}");
    let msg = err(
        MemSource::new().with("a.toml", "include = [\"/etc/passwd\"]\n"),
        "a.toml",
    )
    .to_string();
    assert!(msg.contains("relative path"), "{msg}");
    let msg = err(MemSource::new().with("a.toml", "include = [3]\n"), "a.toml").to_string();
    assert!(msg.contains("not a string"), "{msg}");
    let msg = err(
        MemSource::new().with("a.toml", "include = [\"missing.toml\"]\n"),
        "a.toml",
    )
    .to_string();
    assert!(msg.contains("missing.toml"), "{msg}");
    let mut s = MemSource::new();
    for i in 0..12 {
        s = s.with(
            &format!("f{i}.toml"),
            &format!("include = [\"f{}.toml\"]\n", i + 1),
        );
    }
    assert!(matches!(
        err(s, "f0.toml"),
        RecipeError::IncludeTooDeep { .. }
    ));
}

#[test]
fn missing_and_malformed_variables() {
    let e = err(
        with_main(
            "[[apt_repo]]\nname=\"r\"\nkey_url=\"https://x/k\"\nkey_fingerprint=\"0123456789ABCDEF0123456789ABCDEF01234567\"\nuri=\"https://x\"\nsuite=\"{{nosuch}}\"\ncomponents=\"main\"\n",
        ),
        "main.toml",
    );
    assert_eq!(
        e,
        RecipeError::MissingVar {
            name: "nosuch".into(),
            key: "apt_repo[0].suite".into()
        }
    );
    assert!(e.to_string().contains("`nosuch`") && e.to_string().contains("apt_repo[0].suite"));
    let e = err(
        with_main("[[step]]\nname=\"a\"\nrun=\"echo {{ oops\"\n"),
        "main.toml",
    );
    assert!(matches!(e, RecipeError::BadTemplate { .. }), "{e}");
    let e = err(
        with_main("[[step]]\nname=\"a\"\nrun=\"echo {{Bad-Name}}\"\n"),
        "main.toml",
    );
    assert!(matches!(e, RecipeError::BadTemplate { .. }), "{e}");
}

#[test]
fn variables_substitute_and_can_be_escaped() {
    let p = resolve(
        &with_main("[user]\nname=\"bob\"\nuid=1000\n[[step]]\nname=\"s\"\nrun=\"echo {{user}} {{ codename }} \\\\{{literal}}\"\n"),
        "main.toml",
        &[],
    )
    .unwrap();
    let Step::Command(c) = p.build.last().unwrap() else {
        panic!()
    };
    assert_eq!(c.run, "echo bob trixie {{literal}}");
}

#[test]
fn field_validation_messages() {
    let cases: &[(&str, &str, &str)] = &[
        ("[recipe]\nname = \"BAD NAME\"\n", "recipe.name", "required"),
        (
            "[[apt_repo]]\nname=\"r\"\nkey_url=\"https://x/k\"\nkey_fingerprint=\"ABCD\"\nuri=\"https://x\"\nsuite=\"s\"\ncomponents=\"main\"\n",
            "apt_repo[0].key_fingerprint",
            "40 hex",
        ),
        (
            "[[apt_repo]]\nname=\"r\"\nkey_url=\"http://x/k\"\nkey_fingerprint=\"0123456789ABCDEF0123456789ABCDEF01234567\"\nuri=\"https://x\"\nsuite=\"s\"\ncomponents=\"main\"\n",
            "apt_repo[0].key_url",
            "https",
        ),
        (
            "[[apt_repo]]\nname=\"r\"\nkey_url=\"https://x/k\"\nkey_fingerprint=\"0123456789ABCDEF0123456789ABCDEF01234567\"\nuri=\"https://x\"\nsuite=\"s\"\ncomponents=\"main\"\n[[apt_repo]]\nname=\"r\"\nkey_url=\"https://x/k\"\nkey_fingerprint=\"0123456789ABCDEF0123456789ABCDEF01234567\"\nuri=\"https://x\"\nsuite=\"s\"\ncomponents=\"main\"\n",
            "apt_repo[1].name",
            "duplicate",
        ),
        (
            "[incus_config]\n\"security.privileged\" = \"true\"\n",
            "incus_config.security.privileged",
            "unprivileged",
        ),
        (
            "[incus_config]\n\"raw.lxc\" = \"x\"\n",
            "incus_config.raw.lxc",
            "only",
        ),
        (
            "[incus_config]\n\"security.nesting\" = \"yes\"\n",
            "incus_config.security.nesting",
            "true",
        ),
        (
            "[[file]]\npath=\"relative\"\ncontent=\"\"\n",
            "file[0].path",
            "absolute",
        ),
        (
            "[[file]]\npath=\"/etc/../x\"\ncontent=\"\"\n",
            "file[0].path",
            "absolute",
        ),
        (
            "[[file]]\npath=\"/a\"\ncontent=\"\"\n[[file]]\npath=\"/a\"\ncontent=\"\"\n",
            "file[1].path",
            "more than once",
        ),
        (
            "[[file]]\npath=\"/a\"\ncontent=\"\"\nmode=\"9999\"\n",
            "file[0].mode",
            "octal",
        ),
        (
            "[[file]]\npath=\"/a\"\ncontent=\"\"\nowner=\"a b\"\n",
            "file[0].owner",
            "user",
        ),
        ("[user]\nuid = 5\nname = \"u\"\n", "user.uid", "1000"),
        ("[user]\ngroups = [\"x\"]\n", "user.name", "required"),
        (
            "[[step]]\nname=\"a\"\nrun=\"x\"\nas_user=true\n",
            "step[0].as_user",
            "[user]",
        ),
        (
            "[[step]]\nname=\"a\"\nrun=\"x\"\n[[step]]\nname=\"a\"\nrun=\"y\"\n",
            "step[1].name",
            "duplicate",
        ),
        ("[[step]]\nname=\"a\"\nrun=\"  \"\n", "step[0].run", "empty"),
        (
            "[[step]]\nname=\"a\"\nrun=\"x\"\ntimeout_secs=0\n",
            "step[0].timeout_secs",
            "7200",
        ),
        (
            "[services]\nsystem_enable=[\"nodot\"]\n",
            "services.system_enable[0]",
            "unit",
        ),
    ];
    for (extra, field, needle) in cases {
        // `[recipe]` overrides need to keep base_image; build the source accordingly.
        let text = if extra.starts_with("[recipe]") {
            "[recipe]\nname = \"BAD NAME\"\nbase_image = \"images:debian/13\"\n".to_string()
        } else {
            format!("{GOOD}\n{extra}")
        };
        let e =
            resolve(&MemSource::new().with("main.toml", &text), "main.toml", &[]).expect_err(field);
        let RecipeError::Invalid {
            field: got,
            message,
        } = &e
        else {
            panic!("{field}: {e}")
        };
        assert_eq!(got, field, "{e}");
        assert!(message.contains(needle), "{field}: {message}");
        assert!(e.to_string().contains(field));
    }
    let e = resolve(
        &MemSource::new().with("m.toml", "[recipe]\nname=\"x\"\n"),
        "m.toml",
        &[],
    )
    .unwrap_err();
    assert!(
        matches!(e, RecipeError::Invalid { ref field, .. } if field == "recipe.base_image"),
        "{e}"
    );
    let e = resolve(
        &MemSource::new().with(
            "m.toml",
            "[recipe]\nname=\"x\"\nbase_image=\"docker:ubuntu\"\n",
        ),
        "m.toml",
        &[],
    )
    .unwrap_err();
    assert!(e.to_string().contains("images:<alias>"), "{e}");
}

#[test]
fn disabled_steps_are_dropped_and_scalars_override() {
    let src = MemSource::new()
        .with("base.toml", "[recipe]\nname=\"a\"\nbase_image=\"images:debian/12\"\n[user]\nname=\"u1\"\nuid=1000\n[[step]]\nname=\"off\"\nrun=\"true\"\nenabled=false\n")
        .with("main.toml", "include=[\"base.toml\"]\n[recipe]\nname=\"b\"\n[user]\nname=\"u2\"\n");
    let p = resolve(&src, "main.toml", &[]).unwrap();
    assert_eq!(p.name, "b");
    assert_eq!(p.user().unwrap().name, "u2");
    assert!(!p.build.iter().any(|s| matches!(s, Step::Command(_))));
}

#[test]
fn addons_cannot_redefine_the_recipe() {
    let base = MemSource::new()
        .with("main.toml", GOOD)
        .with("addons/a.toml", "[recipe]\nname = \"evil\"\n")
        .with("addons/b.toml", "[user]\nname = \"root2\"\n")
        .with("addons/c.toml", "[vars]\ncodename = \"x\"\n");
    for a in ["addons/a.toml", "addons/b.toml", "addons/c.toml"] {
        let e = resolve(&base, "main.toml", &[a]).unwrap_err();
        assert!(matches!(e, RecipeError::Parse { .. }), "{a}: {e}");
        let e = resolve_addon_only(&base, "main.toml", a).unwrap_err();
        assert!(matches!(e, RecipeError::Parse { .. }), "{a}: {e}");
    }
}

#[test]
fn package_names_are_validated() {
    let text = "[recipe]\nname=\"t\"\nbase_image=\"images:debian/13\"\n[apt]\npackages=[\"ok\", \"bad;touch x\"]\n";
    let e = resolve(&MemSource::new().with("m.toml", text), "m.toml", &[]).unwrap_err();
    assert!(
        matches!(e, RecipeError::Invalid { ref field, .. } if field == "apt.packages[1]"),
        "{e}"
    );
}

#[test]
fn unknown_catalog_names_are_errors() {
    assert!("ubuntu-20.04".parse::<Distro>().is_err());
    assert_eq!("debian-13".parse::<Distro>().unwrap(), Distro::Debian13);
    assert_eq!("developer".parse::<Preset>().unwrap(), Preset::Developer);
    assert_eq!("docker".parse::<Addon>().unwrap(), Addon::Docker);
    assert!("podman".parse::<Addon>().is_err());
}

// ---------------------------------------------------------------------------------------------
// Review fixes: username contract, X cookie, apt keys, curl protocols, PPA pin
// ---------------------------------------------------------------------------------------------

#[test]
fn usernames_are_validated_and_reserved_names_refused() {
    use hx_provision::{Username, UsernameError};
    for ok in [
        "alice",
        "a",
        "_svc",
        "dev-1",
        "user_2",
        &"a".repeat(32),
        "desk",
    ] {
        assert!(Username::new(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "Alice",
        "1abc",
        "-a",
        "a b",
        "a;b",
        "a$(x)",
        "a\nb",
        "a/b",
        "a.b",
        "é",
        &"a".repeat(33),
        "a'b",
        "a\"b",
    ] {
        assert_eq!(
            Username::new(bad).unwrap_err(),
            UsernameError::Invalid,
            "{bad:?}"
        );
    }
    for reserved in [
        "root",
        "ubuntu",
        "debian",
        "docker",
        "sudo",
        "admin",
        "nobody",
        "daemon",
        "www-data",
        "systemd-resolve",
        "sshd",
        "_apt",
        "adm",
        "users",
    ] {
        assert!(
            matches!(Username::new(reserved), Err(UsernameError::Reserved(_))),
            "{reserved}"
        );
    }
    assert_eq!(Username::default_user().as_str(), "desk");
}

#[test]
fn recipes_cannot_define_user_or_uid_vars_or_a_bad_user() {
    for var in ["user", "uid"] {
        let text = format!(
            "[recipe]\nname=\"t\"\nbase_image=\"images:debian/13\"\n[vars]\n{var} = \"x\"\n"
        );
        let e = resolve(&MemSource::new().with("m.toml", &text), "m.toml", &[]).unwrap_err();
        assert!(
            matches!(e, RecipeError::Invalid { ref field, .. } if field == &format!("vars.{var}")),
            "{e}"
        );
    }
    for bad in ["a; touch /x", "root", "a b", "$(id)"] {
        let text = format!(
            "[recipe]\nname=\"t\"\nbase_image=\"images:debian/13\"\n[user]\nname = \"{bad}\"\nuid = 1000\n"
        );
        let e = resolve(&MemSource::new().with("m.toml", &text), "m.toml", &[]).unwrap_err();
        assert!(
            matches!(e, RecipeError::Invalid { ref field, .. } if field == "user.name"),
            "{bad}: {e}"
        );
    }
}

#[test]
fn a_chosen_username_is_used_everywhere_and_prebuilt_images_get_a_rename_step() {
    use hx_provision::Username;
    let c = Catalog::embedded();
    let alice = Username::new("alice").unwrap();
    let rid = id(Distro::Debian13, Preset::Developer);
    let p = c.resolve_for(rid, &[Addon::Docker], Some(&alice)).unwrap();
    assert_eq!(p.user().unwrap().name, "alice");
    assert_eq!(p.vars["user"], "alice");
    assert_eq!(p.vars["uid"], "1000");
    // Post stage: rename the image's `desk` first, then ensure, password, updates, vendor installers.
    let order: Vec<String> = p.post.iter().map(Step::describe).collect();
    assert_eq!(order[0], "wait-network");
    assert_eq!(order[1], "rename-user desk -> alice");
    assert!(order[2].starts_with("ensure-user alice uid=1000"));
    assert_eq!(order[3], "set-password alice");
    assert!(
        p.post
            .iter()
            .any(|s| matches!(s, Step::Command(c) if c.as_user.as_deref() == Some("alice")))
    );
    let m = p.manifest();
    assert_eq!(m.user.as_deref(), Some("alice"));
    // The X server unit refers to the numeric uid, so the rename leaves it valid.
    let unit = p
        .build
        .iter()
        .find_map(|s| match s {
            Step::WriteFile(f) if f.path == "/etc/systemd/system/hx-xorg.service" => {
                Some(f.content.clone())
            }
            _ => None,
        })
        .unwrap();
    assert!(
        unit.contains("-o 1000 ") && !unit.contains("alice") && !unit.contains("desk"),
        "{unit}"
    );
    // Default and explicit `desk` need no rename.
    for p in [
        c.resolve(rid, &[]).unwrap(),
        c.resolve_for(rid, &[], Some(&Username::default_user()))
            .unwrap(),
    ] {
        assert!(!p.post.iter().any(|s| matches!(s, Step::RenameUser { .. })));
    }
    // The add-on plan follows the chosen user.
    let d = c
        .resolve_addon_for(rid, Addon::Docker, Some(&alice))
        .unwrap();
    assert_eq!(d.manifest().user.as_deref(), Some("alice"));
    assert!(d.post.is_empty());
}

#[test]
fn ensure_user_refuses_system_accounts_and_uid_mismatches_and_rename_is_idempotent() {
    use hx_provision::lower::lower;
    let p = Catalog::embedded()
        .resolve(id(Distro::Ubuntu2404, Preset::Basic), &[])
        .unwrap();
    let ensure = p
        .build
        .iter()
        .find(|s| matches!(s, Step::EnsureUser(_)))
        .unwrap();
    let s = script_of(&lower(ensure, &Secrets::none()).unwrap()[0]).to_string();
    assert!(s.contains("[ \"$cur\" -lt 1000 ]") && s.contains("system account"));
    assert!(s.contains("[ \"$cur\" != \"$want\" ]") && s.contains("want='1000'"));
    assert!(s.contains("system group"));
    assert!(
        s.contains("cut -d: -f3 || true"),
        "a missing group must not abort the script under pipefail"
    );
    let rename = Step::RenameUser {
        from: "desk".into(),
        to: "alice".into(),
    };
    let s = script_of(&lower(&rename, &Secrets::none()).unwrap()[0]).to_string();
    assert!(
        s.contains("usermod -l \"$to\" -d \"/home/$to\" -m \"$from\"") && s.contains("groupmod -n")
    );
    assert!(
        s.contains("id -u \"$from\"") && s.contains("! id -u \"$to\""),
        "idempotent guard"
    );
    assert!(s.contains("from='desk'") && s.contains("to='alice'"));
    assert!(
        s.contains("/etc/subuid /etc/subgid") && s.contains("sed -i \"s/^$from:/$to:/\""),
        "the subordinate id ranges follow the rename (found by the equivalence check)"
    );
}

#[test]
fn x_cookie_never_reaches_argv_and_the_file_is_created_private() {
    let p = Catalog::embedded()
        .resolve(id(Distro::Debian12, Preset::Basic), &[])
        .unwrap();
    let unit = p
        .build
        .iter()
        .find_map(|s| match s {
            Step::WriteFile(f) if f.path == "/etc/systemd/system/hx-xorg.service" => {
                Some(f.content.clone())
            }
            _ => None,
        })
        .unwrap();
    assert!(
        unit.contains("install -m 0600 -o 1000 /dev/null /run/hx-xorg/Xauthority"),
        "{unit}"
    );
    assert!(
        unit.contains("echo \"add :0 . $(mcookie)\" | xauth -f /run/hx-xorg/Xauthority source -")
    );
    assert!(
        !unit.contains("xauth -f /run/hx-xorg/Xauthority add"),
        "cookie as an argument"
    );
    assert!(unit.contains("chmod 0600 /run/hx-xorg/Xauthority"));
}

#[test]
fn apt_keys_are_imported_into_a_temp_keyring_and_only_the_pinned_key_is_exported() {
    use hx_provision::lower::lower;
    let p = Catalog::embedded()
        .resolve(id(Distro::Ubuntu2404, Preset::Developer), &[Addon::Docker])
        .unwrap();
    let mut n = 0;
    for step in &p.build {
        if let Step::AptRepo(r) = step {
            let s = script_of(&lower(step, &Secrets::none()).unwrap()[0]).to_string();
            assert!(
                s.contains("export GNUPGHOME=\"$gh\"") && s.contains("gh=$(mktemp -d)"),
                "{s}"
            );
            assert!(s.contains("gpg --batch --quiet --import \"$tmp\""), "{s}");
            assert!(
                s.contains(&format!(
                    "--export-options export-minimal --export '{}'",
                    r.key_fingerprint
                )),
                "{s}"
            );
            assert!(
                !s.contains("--dearmor") && !s.contains("cp \"$tmp\""),
                "{s}"
            );
            assert!(s.contains("fingerprint mismatch"));
            n += 1;
        }
    }
    assert_eq!(n, 3, "mozillateam, vscode, docker");
}

#[test]
fn every_curl_invocation_restricts_protocols_to_https() {
    use hx_provision::lower::lower;
    let mut seen = 0;
    for rid in RecipeId::all() {
        let p = Catalog::embedded().resolve(rid, &[Addon::Docker]).unwrap();
        for step in p.build.iter().chain(p.post.iter()) {
            for a in lower(step, &Secrets::none().with_user_password("x").unwrap()).unwrap() {
                let Action::Exec(r) = a else { continue };
                let script = r.argv.last().unwrap().replace("\\\n", " ");
                for line in script.lines().filter(|l| l.contains("curl -")) {
                    assert!(
                        line.contains("--proto '=https' --proto-redir '=https'"),
                        "{}: {line}",
                        p.name
                    );
                    seen += 1;
                }
            }
        }
    }
    assert!(seen >= 24, "{seen}");
}

#[test]
fn the_mozilla_pin_only_covers_firefox_packages() {
    for d in [Distro::Ubuntu2404, Distro::Ubuntu2604] {
        let p = Catalog::embedded()
            .resolve(id(d, Preset::Basic), &[])
            .unwrap();
        let repo = p
            .build
            .iter()
            .find_map(|s| match s {
                Step::AptRepo(r) if r.name == "mozillateam" => Some(r.clone()),
                _ => None,
            })
            .unwrap();
        let pin = repo.pin.unwrap();
        assert!(
            pin.contains("Package: firefox*") && !pin.contains("Package: *\n"),
            "{pin}"
        );
    }
}

fn script_of(a: &Action) -> &str {
    match a {
        Action::Exec(r) => r.argv.last().unwrap(),
        Action::Push(_) => panic!("not an exec"),
    }
}

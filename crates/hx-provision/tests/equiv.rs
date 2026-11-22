//! `equiv::compare` rules and `collect_facts` parsing (against preloaded fact files).

mod common;

use common::Fake;
use hx_provision::equiv::{
    Area, Drift, FACTS_DIR, FACTS_SCHEMA, Facts, FileFact, INSTANCE_PLACEHOLDER, PackageFact,
    Severity, collect_facts, compare, has_errors, render_table,
};
use hx_provision::manifest::{ManifestFile, ManifestRepo};
use hx_provision::{Manifest, ProvisionError};

fn pkg(name: &str, version: &str) -> PackageFact {
    PackageFact {
        name: name.into(),
        arch: "amd64".into(),
        status: "ii".into(),
        version: version.into(),
    }
}

fn file(path: &str, sha: &str) -> FileFact {
    FileFact {
        path: path.into(),
        kind: "f".into(),
        mode: 0o644,
        owner: "root:root".into(),
        sha256: Some(sha.into()),
        target: None,
    }
}

fn base() -> Facts {
    Facts {
        schema: FACTS_SCHEMA,
        instance: "a".into(),
        user: "alice".into(),
        packages: vec![pkg("bash", "5.2"), pkg("xfce4", "4.18"), pkg("libfoo", "1")],
        apt_auto: vec!["libfoo".into()],
        apt_manual: vec!["bash".into(), "xfce4".into()],
        apt_files: [(
            "/etc/apt/sources.list.d/x.sources".to_string(),
            "h1".to_string(),
        )]
        .into(),
        etc: vec![
            file("/etc/hx/xorg.conf", "aa"),
            file("/etc/default/locale", "bb"),
        ],
        etc_owner: [("/etc/default/locale".to_string(), "bash".to_string())].into(),
        passwd: vec![
            "alice:x:1000:1000::/home/alice:/bin/bash".into(),
            "root:x:0:0::/root:/bin/bash".into(),
        ],
        group: vec!["alice:x:1000:".into(), "audio:x:29:alice".into()],
        subuid: vec!["alice:100000:65536".into()],
        subgid: vec!["alice:100000:65536".into()],
        shadow: vec!["alice:::0:99999:7:::".into()],
        user_groups: vec!["alice".into(), "audio".into()],
        trees: [(
            "/home/alice".to_string(),
            vec![FileFact {
                path: "/home/alice".into(),
                kind: "d".into(),
                mode: 0o750,
                owner: "alice:alice".into(),
                sha256: None,
                target: None,
            }],
        )]
        .into(),
        enabled_system: vec!["hx-xorg.service".into(), "ssh.service".into()],
        enabled_user_global: vec!["hx-xsession.service".into()],
        running_services: vec!["dbus.service".into()],
        system_state: "running".into(),
        failed_units: vec![],
    }
}

fn manifest() -> Manifest {
    Manifest {
        recipe: "t".into(),
        packages: vec!["bash".into(), "xfce4".into()],
        apt_repos: vec![ManifestRepo {
            name: "x".into(),
            fingerprint: "F".into(),
            uri: "u".into(),
            suite: "s".into(),
        }],
        files: vec![ManifestFile {
            path: "/etc/hx/xorg.conf".into(),
            mode: "0644".into(),
            owner: "root:root".into(),
            // sha of "aa" is irrelevant: the facts carry sha strings directly
            sha256: "aa".into(),
        }],
        system_services: vec!["hx-xorg.service".into()],
        user_services: vec!["hx-xsession".into()],
        user: Some("desk".into()),
        user_groups: vec!["audio".into()],
        ..Manifest::default()
    }
}

fn repo_facts() -> Facts {
    let mut f = base();
    f.apt_files
        .insert("/etc/apt/keyrings/x.gpg".into(), "k".into());
    f.apt_files
        .insert("/etc/apt/sources.list.d/x.sources".into(), "h1".into());
    f
}

fn errors(d: &[Drift]) -> Vec<&Drift> {
    d.iter().filter(|d| d.severity == Severity::Error).collect()
}

fn has(d: &[Drift], area: Area, needle: &str) -> bool {
    d.iter()
        .any(|x| x.area == area && format!("{} {}", x.subject, x.detail).contains(needle))
}

#[test]
fn identical_desktops_have_no_drift() {
    let (a, b) = (repo_facts(), repo_facts());
    let d = compare(&a, &b, &manifest());
    assert!(d.is_empty(), "{d:#?}");
    assert!(!has_errors(&d));
    assert!(render_table(&d).contains("No drift"));
}

#[test]
fn packages_manual_set_and_versions() {
    let mut b = repo_facts();
    b.packages[0].version = "5.3".into();
    let d = compare(&repo_facts(), &b, &manifest());
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].severity, Severity::Info);
    assert!(d[0].detail.contains("5.2") && d[0].detail.contains("5.3"));

    // a manual package missing on one side is an error
    let mut b = repo_facts();
    b.packages.retain(|p| p.name != "xfce4");
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(&d, Area::Packages, "xfce4:amd64 installed only on A"));
    assert!(
        errors(&d).len() >= 2,
        "also not marked manual on B and not installed: {d:#?}"
    );

    // the manual sets must be exactly equal
    let mut b = repo_facts();
    b.apt_manual.push("libfoo".into());
    b.apt_auto.clear();
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(&d, Area::Packages, "libfoo"));
    assert!(has_errors(&d));
}

#[test]
fn up_to_five_auto_packages_may_differ_not_six() {
    let extra = |n: usize| {
        let mut b = repo_facts();
        for i in 0..n {
            b.packages.push(pkg(&format!("dep{i}"), "1"));
            b.apt_auto.push(format!("dep{i}"));
        }
        b
    };
    let d = compare(&repo_facts(), &extra(5), &manifest());
    assert_eq!(d.len(), 5);
    assert!(d.iter().all(|x| x.severity == Severity::Info), "{d:#?}");
    let d = compare(&repo_facts(), &extra(6), &manifest());
    assert_eq!(errors(&d).len(), 6, "{d:#?}");
    // a differing package that is manual where it is installed is an error even alone
    let mut b = repo_facts();
    b.packages.push(pkg("tool", "1"));
    b.apt_manual.push("tool".into());
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has_errors(&d));
}

#[test]
fn a_package_that_is_not_ii_is_not_installed() {
    let mut b = repo_facts();
    b.packages[2].status = "rc".into();
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(&d, Area::Packages, "libfoo:amd64 installed only on A"));
}

#[test]
fn apt_sources_and_keyrings_must_be_byte_equal() {
    let mut b = repo_facts();
    b.apt_files
        .insert("/etc/apt/keyrings/x.gpg".into(), "other".into());
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(&d, Area::AptSources, "x.gpg content differs"));
    b.apt_files.remove("/etc/apt/keyrings/x.gpg");
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(&d, Area::AptSources, "only on A"));
    assert!(has(&d, Area::Manifest, "not configured on B"));
}

#[test]
fn recipe_files_must_equal_the_plan_on_both_sides() {
    let mut a = repo_facts();
    a.etc[0].mode = 0o600;
    let d = compare(&a, &repo_facts(), &manifest());
    assert!(has(&d, Area::RecipeFiles, "mode on A is 600"));
    let mut b = repo_facts();
    b.etc[0].sha256 = Some("zz".into());
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(
        &d,
        Area::RecipeFiles,
        "content on B differs from the plan"
    ));
    let mut b = repo_facts();
    b.etc[0].owner = "alice:alice".into();
    assert!(has(
        &compare(&repo_facts(), &b, &manifest()),
        Area::RecipeFiles,
        "owner on B"
    ));
    let mut b = repo_facts();
    b.etc.remove(0);
    assert!(has(
        &compare(&repo_facts(), &b, &manifest()),
        Area::RecipeFiles,
        "missing on B"
    ));
    // The build user maps to the chosen account.
    let mut m = manifest();
    m.files[0].owner = "desk:desk".into();
    let mut a = repo_facts();
    a.etc[0].owner = "alice:alice".into();
    let mut b = repo_facts();
    b.etc[0].owner = "alice:alice".into();
    assert!(!has_errors(&compare(&a, &b, &m)));
}

#[test]
fn etc_tree_is_compared_with_the_package_version_exception() {
    let mut b = repo_facts();
    b.etc[1].sha256 = Some("changed".into());
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(&d, Area::Etc, "/etc/default/locale content differs"));
    assert_eq!(errors(&d).len(), 1);

    // owned by `bash`, whose version differs: tolerated and reported
    b.packages[0].version = "5.3".into();
    let d = compare(&repo_facts(), &b, &manifest());
    let etc: Vec<_> = d.iter().filter(|x| x.area == Area::Etc).collect();
    assert_eq!(etc.len(), 1);
    assert_eq!(etc[0].severity, Severity::Info);

    // mode, owner, type, link target and presence are never tolerated
    let mut b = repo_facts();
    b.etc[1].mode = 0o600;
    b.etc[1].owner = "x:x".into();
    b.etc.push(file("/etc/extra", "q"));
    let d = compare(&repo_facts(), &b, &manifest());
    assert_eq!(errors(&d).iter().filter(|x| x.area == Area::Etc).count(), 3);
    let mut b = repo_facts();
    b.etc[1].kind = "l".into();
    assert!(has(
        &compare(&repo_facts(), &b, &manifest()),
        Area::Etc,
        "type f on A, l on B"
    ));
    let mut a = repo_facts();
    let mut b = repo_facts();
    a.etc[1] = FileFact {
        kind: "l".into(),
        sha256: None,
        target: Some("/x".into()),
        ..a.etc[1].clone()
    };
    b.etc[1] = FileFact {
        target: Some("/y".into()),
        ..a.etc[1].clone()
    };
    assert!(has(&compare(&a, &b, &manifest()), Area::Etc, "link target"));
}

#[test]
fn accounts_rename_check_and_shadow() {
    // the build user is still present on B: the rename did not happen cleanly
    let mut b = repo_facts();
    b.passwd
        .push("desk:x:1001:1001::/home/desk:/bin/bash".into());
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(
        &d,
        Area::Accounts,
        "build user is still in passwd on B"
    ));
    // subuid left behind by usermod -l
    let mut b = repo_facts();
    b.subuid = vec!["desk:100000:65536".into()];
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(&d, Area::Accounts, "subuid: alice") && has(&d, Area::Accounts, "subuid: desk"));
    // shadow differs
    let mut b = repo_facts();
    b.shadow = vec!["alice:::0:99999:7:1:1:".into()];
    assert!(has(
        &compare(&repo_facts(), &b, &manifest()),
        Area::Accounts,
        "shadow"
    ));
    // the user must exist and have the recipe's groups
    let mut b = repo_facts();
    b.user_groups = vec!["alice".into()];
    assert!(has(
        &compare(&repo_facts(), &b, &manifest()),
        Area::Accounts,
        "not in group `audio` on B"
    ));
    // different users compared
    let mut b = repo_facts();
    b.user = "bob".into();
    assert!(has(
        &compare(&repo_facts(), &b, &manifest()),
        Area::Accounts,
        "different users"
    ));
    // build user equal to the chosen user: no rename expected
    let mut m = manifest();
    m.user = Some("alice".into());
    assert!(!has_errors(&compare(&repo_facts(), &repo_facts(), &m)));
}

#[test]
fn trees_compare_structure_not_content() {
    let mut b = repo_facts();
    b.trees.get_mut("/home/alice").unwrap()[0].mode = 0o700;
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(&d, Area::Trees, "/home/alice"));
    let mut b = repo_facts();
    b.trees.get_mut("/home/alice").unwrap().push(FileFact {
        path: "/home/alice/.bashrc".into(),
        kind: "f".into(),
        mode: 0o644,
        owner: "alice:alice".into(),
        sha256: None,
        target: None,
    });
    assert!(has(
        &compare(&repo_facts(), &b, &manifest()),
        Area::Trees,
        "only on B"
    ));
}

#[test]
fn services_and_boot_state() {
    let mut b = repo_facts();
    b.enabled_system.push("extra.service".into());
    b.running_services.clear();
    b.enabled_user_global.clear();
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(&d, Area::Services, "extra.service enabled only on B"));
    assert!(has(&d, Area::Services, "dbus.service running only on A"));
    assert!(has(
        &d,
        Area::Services,
        "hx-xsession.service enabled for all users only on A"
    ));
    assert!(has(
        &d,
        Area::Manifest,
        "hx-xsession enabled for all users by the recipe but not so on B"
    ));

    let mut b = repo_facts();
    b.system_state = "degraded".into();
    b.failed_units = vec!["foo.service".into()];
    let d = compare(&repo_facts(), &b, &manifest());
    assert!(has(&d, Area::Services, "`degraded` on B"));
    assert!(has(&d, Area::Services, "foo.service failed on B"));
}

#[test]
fn on_demand_services_do_not_block() {
    let mut b = repo_facts();
    b.running_services.push("systemd-hostnamed.service".into());
    let d = compare(&repo_facts(), &b, &manifest());
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].severity, Severity::Info);
    b.running_services.push("other.service".into());
    assert!(has_errors(&compare(&repo_facts(), &b, &manifest())));
}

#[test]
fn the_manifest_must_be_satisfied_by_both_sides() {
    let mut a = repo_facts();
    a.packages.retain(|p| p.name != "bash");
    a.apt_manual.retain(|p| p != "bash");
    let mut b = repo_facts();
    b.packages.retain(|p| p.name != "bash");
    b.apt_manual.retain(|p| p != "bash");
    let d = compare(&a, &b, &manifest());
    assert!(has(
        &d,
        Area::Manifest,
        "bash requested by the recipe but not installed on A"
    ));
    assert!(has(
        &d,
        Area::Manifest,
        "bash requested by the recipe but not installed on B"
    ));
}

#[test]
fn the_table_lists_every_drift_and_escapes_pipes() {
    let d = vec![Drift {
        area: Area::Etc,
        severity: Severity::Error,
        subject: "/etc/a|b".into(),
        detail: "x\ny".into(),
    }];
    let t = render_table(&d);
    assert!(t.contains("ERROR") && t.contains("/etc/a\\|b") && t.contains("x y"));
}

#[test]
fn facts_round_trip_as_json() {
    let f = repo_facts();
    let s = serde_json::to_string(&f).unwrap();
    assert_eq!(serde_json::from_str::<Facts>(&s).unwrap(), f);
}

// ---- collect_facts against preloaded files -------------------------------------------------

fn put(fake: &Fake, name: &str, data: &[u8]) {
    fake.with(|s| {
        s.files.insert(format!("{FACTS_DIR}/{name}"), data.to_vec());
    });
}

fn sha_rec(hash: &str, path: &str) -> Vec<u8> {
    format!("{hash}  {path}\0").into_bytes()
}

fn preload(fake: &Fake) {
    let h = "a".repeat(64);
    put(
        fake,
        "packages",
        b"bash\tamd64\tii \t5.2\nold\tamd64\trc \t1\n",
    );
    put(fake, "auto", b"libfoo\n");
    put(fake, "manual", b"bash\n");
    put(
        fake,
        "aptfiles",
        &sha_rec(&h, "/etc/apt/sources.list.d/x.sources"),
    );
    put(
        fake,
        "etc",
        b"f\t644\troot\troot\t/etc/hostname\t\0f\t644\troot\troot\t/etc/hosts\t\0l\t777\troot\troot\t/etc/mtab\t../proc/self/mounts\0",
    );
    let mut etchash = sha_rec(&h, "/etc/hostname");
    etchash.extend(sha_rec(&h, "/etc/hosts"));
    put(fake, "etchash", &etchash);
    put(fake, "etcowner", b"base-files\t/etc/hostname\n");
    for n in [
        "passwd",
        "group",
        "subuid",
        "subgid",
        "shadow",
        "usergroups",
    ] {
        put(fake, n, b"b\na\n");
    }
    for n in ["tree0", "tree1", "tree2"] {
        put(fake, n, b"d\t750\talice\talice\t/home/alice\t\0");
    }
    put(fake, "svc_enabled", b"ssh.service enabled enabled\n");
    put(fake, "svc_user_enabled", b"hx.service enabled enabled\n");
    put(
        fake,
        "svc_running",
        b"dbus.service loaded active running D-Bus\n",
    );
    put(fake, "sysstate", b"running\n");
    put(fake, "failed", b"");
    fake.with(|s| {
        s.files.insert("/etc/hostname".into(), b"inst1\n".to_vec());
        s.files
            .insert("/etc/hosts".into(), b"127.0.1.1 inst1\n".to_vec());
    });
}

#[tokio::test]
async fn collect_facts_parses_the_files_and_cleans_up() {
    let fake = Fake::start().await;
    preload(&fake);
    let f = collect_facts(&fake.client(), "inst1", "alice")
        .await
        .unwrap();
    assert_eq!(f.user, "alice");
    assert_eq!(f.packages.len(), 2);
    assert_eq!(f.packages[0].status, "ii");
    assert_eq!(f.apt_manual, ["bash"]);
    assert_eq!(f.passwd, ["a", "b"], "sorted");
    assert_eq!(f.enabled_system, ["ssh.service"]);
    assert_eq!(f.running_services, ["dbus.service"]);
    assert_eq!(f.system_state, "running");
    assert!(f.failed_units.is_empty());
    assert_eq!(f.etc_owner["/etc/hostname"], "base-files");
    assert_eq!(f.trees.len(), 3);
    let mtab = f.etc.iter().find(|e| e.path == "/etc/mtab").unwrap();
    assert_eq!(
        (mtab.kind.as_str(), mtab.target.as_deref()),
        ("l", Some("../proc/self/mounts"))
    );
    // hostname and hosts hash with the instance name replaced
    let want = |t: &str| {
        use sha2::{Digest, Sha256};
        Sha256::digest(t.replace("inst1", INSTANCE_PLACEHOLDER).as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let host = f.etc.iter().find(|e| e.path == "/etc/hostname").unwrap();
    assert_eq!(host.sha256.as_deref(), Some(want("inst1\n").as_str()));
    let hosts = f.etc.iter().find(|e| e.path == "/etc/hosts").unwrap();
    assert_eq!(
        hosts.sha256.as_deref(),
        Some(want("127.0.1.1 inst1\n").as_str())
    );
    // the script ran with the work directory, the user as an argument, and was cleaned up
    let log = fake.log();
    let script = log
        .iter()
        .find(|r| r.path.ends_with("/exec") && r.json().to_string().contains("dpkg-query"))
        .unwrap()
        .json()
        .to_string();
    assert!(script.contains(FACTS_DIR) && script.contains("alice"));
    assert!(
        log.iter()
            .any(|r| r.path.ends_with("/exec")
                && r.json().to_string().contains("\"rm\",\"-rf\",\"--\"")),
        "facts directory removed"
    );
}

#[tokio::test]
async fn collect_facts_refuses_bad_input_and_reports_failures() {
    let fake = Fake::start().await;
    let c = fake.client();
    assert!(matches!(
        collect_facts(&c, "inst1", "x;rm").await,
        Err(ProvisionError::Invalid(_))
    ));
    assert!(fake.log().is_empty());

    // missing fact file
    let e = collect_facts(&c, "inst1", "alice").await.unwrap_err();
    assert!(
        matches!(&e, ProvisionError::Invalid(m) if m.contains("missing")),
        "{e:?}"
    );

    // malformed content never panics
    preload(&fake);
    put(&fake, "packages", b"only-one-field\n");
    assert!(collect_facts(&c, "inst1", "alice").await.is_err());
    preload(&fake);
    put(&fake, "etc", b"f\t999\troot\troot\t/etc/x\t\0");
    assert!(collect_facts(&c, "inst1", "alice").await.is_err());
    preload(&fake);
    put(&fake, "etchash", b"nothex  /etc/x\0");
    assert!(collect_facts(&c, "inst1", "alice").await.is_err());

    // the script failing is an error carrying sanitized stderr
    preload(&fake);
    fake.rule("apt-mark showmanual", 2, "", "dpkg: broken\u{1b}[0m");
    let e = collect_facts(&c, "inst1", "alice").await.unwrap_err();
    assert!(
        matches!(&e, ProvisionError::Invalid(m) if m.contains("exit 2") && !m.contains('\u{1b}')),
        "{e:?}"
    );
}

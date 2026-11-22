//! `hx-image-fetcher@.service` and `var-lib-hx-imagein.mount` (docs/ipc.md 6.12, "Prebuilt images
//! (1D)"): the same hardening as the update fetcher with their own directory and limits.

use std::collections::BTreeMap;

use hx_agent::fetcher::images::CHUNK_BYTES;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/systemd");

type Unit = BTreeMap<String, BTreeMap<String, Vec<String>>>;

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{DIR}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn parse(text: &str) -> Unit {
    let mut u = Unit::new();
    let mut section = String::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.to_string();
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("bad line: {line}"));
        u.entry(section.clone())
            .or_default()
            .entry(k.trim().to_string())
            .or_default()
            .push(v.trim().to_string());
    }
    u
}

fn service(name: &str) -> BTreeMap<String, Vec<String>> {
    parse(&read(name)).remove("Service").unwrap()
}

fn one<'a>(s: &'a BTreeMap<String, Vec<String>>, k: &str) -> &'a str {
    let v = s.get(k).unwrap_or_else(|| panic!("{k} is missing"));
    assert_eq!(v.len(), 1, "{k}");
    &v[0]
}

/// What the image unit may differ in: its own directory, limits, and the template marker.
const DIFFERENT: &[&str] = &[
    "BindPaths",
    "LimitFSIZE",
    "MemoryMax",
    "RuntimeMaxSec",
    "TimeoutStartSec",
    "Environment",
];

#[test]
fn the_image_fetcher_has_exactly_the_update_fetchers_hardening() {
    let upd = service("hx-update-fetcher@.service");
    let img = service("hx-image-fetcher@.service");
    let keys: std::collections::BTreeSet<_> = upd.keys().chain(img.keys()).collect();
    for k in keys {
        if DIFFERENT.contains(&k.as_str()) {
            continue;
        }
        assert_eq!(
            upd.get(k),
            img.get(k),
            "[Service] {k} must be equal in both templates"
        );
    }
    // Spot checks of what matters, so a change to both at once is still noticed.
    assert_eq!(one(&img, "DynamicUser"), "yes");
    assert_eq!(one(&img, "CapabilityBoundingSet"), "");
    assert_eq!(one(&img, "AmbientCapabilities"), "");
    assert_eq!(one(&img, "NoNewPrivileges"), "yes");
    assert_eq!(one(&img, "RestrictAddressFamilies"), "AF_INET AF_INET6");
    assert_eq!(one(&img, "ProtectSystem"), "strict");
    assert_eq!(one(&img, "MemoryDenyWriteExecute"), "yes");
    assert!(img["SystemCallFilter"].iter().any(|f| f.contains("mkdir")));
    assert!(
        img["SystemCallFilter"]
            .iter()
            .any(|f| f.contains("@privileged"))
    );
    assert!(!img.contains_key("ReadWritePaths"));
    assert!(!img.contains_key("Restart"));
}

#[test]
fn the_image_fetcher_runs_the_same_binary_with_the_instance_as_its_whole_argv() {
    let img = service("hx-image-fetcher@.service");
    assert_eq!(
        one(&img, "ExecStart"),
        "/usr/lib/hx/current/hx-update-fetcher %i"
    );
    // The one thing it adds: the template marker the binary reads. The update unit has none.
    assert_eq!(img["Environment"], ["HX_FETCH_TEMPLATE=image"]);
    assert!(!service("hx-update-fetcher@.service").contains_key("Environment"));
    assert!(!img.contains_key("EnvironmentFile"));
    assert_eq!(hx_agent::fetcher::images::TEMPLATE_ENV, "HX_FETCH_TEMPLATE");
    assert_eq!(hx_agent::fetcher::images::TEMPLATE_IMAGE, "image");
}

#[test]
fn the_image_fetcher_writes_only_its_own_directory_with_chunk_sized_files() {
    let img = service("hx-image-fetcher@.service");
    assert_eq!(
        one(&img, "BindPaths"),
        "/var/lib/hx/imagein:/var/lib/hx-image"
    );
    assert_eq!(
        hx_agent::fetcher::images::IMAGE_OUT_DIR,
        "/var/lib/hx-image"
    );
    // One file is at most one chunk: LimitFSIZE is exactly 32 MiB.
    assert_eq!(one(&img, "LimitFSIZE").parse::<u64>().unwrap(), CHUNK_BYTES);
    assert_eq!(CHUNK_BYTES, 32 * 1024 * 1024);
    assert_eq!(one(&img, "MemoryMax"), "128M");
    // The hard stop is a little after the 20 minute timeout the binary keeps itself.
    let own = hx_agent::fetcher::images::IMAGE_TIMEOUT.as_secs();
    assert_eq!(own, 1200);
    let stop: u64 = one(&img, "RuntimeMaxSec").parse().unwrap();
    assert_eq!(stop, 1260);
    assert_eq!(one(&img, "TimeoutStartSec").parse::<u64>().unwrap(), stop);
    let unit = parse(&read("hx-image-fetcher@.service"));
    assert!(
        unit["Unit"]["RequiresMountsFor"]
            .iter()
            .any(|v| v == "/var/lib/hx/imagein")
    );
    // It sees none of the agent's other state, like the update fetcher.
    assert_eq!(
        img["InaccessiblePaths"],
        service("hx-update-fetcher@.service")["InaccessiblePaths"]
    );
}

#[test]
fn the_imagein_directory_is_an_80_mib_tmpfs_with_16_inodes() {
    let m = parse(&read("var-lib-hx-imagein.mount"));
    let get = |k: &str| m["Mount"][k][0].clone();
    assert_eq!(get("Type"), "tmpfs");
    assert_eq!(get("Where"), "/var/lib/hx/imagein");
    let opts: Vec<String> = get("Options").split(',').map(str::to_string).collect();
    assert!(opts.iter().any(|o| o == "size=80M"));
    assert!(opts.iter().any(|o| o == "nr_inodes=16"));
    for o in ["mode=1733", "uid=0", "gid=0", "nosuid", "nodev", "noexec"] {
        assert!(opts.iter().any(|x| x == o), "{o}");
    }
    // Two chunks (back-pressure) plus markers fit with room to spare.
    const { assert!(80 * 1024 * 1024 >= 2 * CHUNK_BYTES + 8 * 1024 * 1024) };
    // Same dependency shape as the update mount (no cycle with tmpfiles at boot).
    assert_eq!(m["Unit"]["DefaultDependencies"], ["no"]);
    assert!(
        m["Unit"]["After"]
            .iter()
            .any(|v| v == "systemd-tmpfiles-setup.service")
    );
    assert!(
        !m["Install"]["WantedBy"]
            .iter()
            .any(|v| v == "local-fs.target")
    );
    assert!(
        m["Install"]["WantedBy"]
            .iter()
            .any(|v| v == "multi-user.target")
    );
    for key in ["Before", "Conflicts"] {
        assert!(m["Unit"][key].iter().any(|v| v == "umount.target"), "{key}");
    }
    assert_eq!(
        m["Unit"]["ConditionPathIsDirectory"],
        ["/var/lib/hx/imagein"]
    );
}

#[test]
fn tmpfiles_make_the_mount_points_and_the_import_directory() {
    let t = read("tmpfiles.d/hx.conf");
    let has = |path: &str, mode: &str| {
        t.lines().any(|l| {
            let f: Vec<_> = l.split_whitespace().collect();
            f.len() >= 5 && f[0] == "d" && f[1] == path && f[2] == mode && f[3] == "root"
        })
    };
    assert!(has("/var/lib/hx/imagein", "1733"), "{t}");
    assert!(has("/var/lib/hx/import", "0700"), "{t}");
    assert!(has("/var/lib/hx-image", "0755"), "{t}");
    // The update directory is still there.
    assert!(has("/var/lib/hx/updates", "1733"));
}

#[test]
fn privd_needs_both_mounts_and_may_still_run_no_ip() {
    let u = parse(&read("hx-privd.service"));
    let mounts: Vec<&str> = u["Unit"]["RequiresMountsFor"]
        .iter()
        .flat_map(|v| v.split_whitespace())
        .collect();
    assert!(mounts.contains(&"/var/lib/hx/updates") && mounts.contains(&"/var/lib/hx/imagein"));
    assert_eq!(u["Service"]["IPAddressDeny"], ["any"]);
}

#[test]
fn the_installer_embeds_the_new_units() {
    let names: Vec<&str> = hx_agent::install::units::FILES
        .iter()
        .map(|f| f.name)
        .collect();
    assert!(names.contains(&"hx-image-fetcher@.service"));
    assert!(names.contains(&"var-lib-hx-imagein.mount"));
}

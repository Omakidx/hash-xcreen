//! The repository lease (ipc.md §29): who may write, when it is read, what a takeover does, and
//! what a lost lease costs. Another server is played by editing the lease object in the fake Drive.

mod drive_common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use drive_common::*;

fn lease_reads(rig: &Rig) -> usize {
    let id = rig
        .fake
        .with(|m| m.id_of("repo/hx-lease.json"))
        .expect("a lease");
    rig.fake.with(|m| {
        m.log
            .iter()
            .filter(|r| r.category == "get.media" && r.path.ends_with(&id))
            .count()
    })
}

fn uploads(rig: &Rig) -> usize {
    rig.fake.with(|m| m.count("upload"))
}

#[test]
fn no_lease_means_generation_one_written_with_a_sanitized_hint() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    let l = rig.lease().expect("the lease was written");
    assert_eq!(l["format"], 1);
    assert_eq!(l["server_id"], hex(&SERVER_A));
    assert_eq!(l["generation"], 1);
    assert_eq!(
        l["hostname_hint"], "test-host-1",
        "the host name 'test host/1', sanitized"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(l["taken_at"].as_u64().unwrap().abs_diff(now) < 60);
    // the lease is not a repository object
    for ty in [T::Config, T::Key, T::Snapshot, T::Index, T::Pack] {
        assert_eq!(s.env.list(ty), Reply::List(vec![]), "{ty:?}");
    }
}

#[test]
fn the_same_server_is_accepted_without_a_rewrite() {
    let rig = Rig::new();
    rig.open_session().finish();
    let before = uploads(&rig);
    let first = rig.lease().unwrap();
    let mut s = rig.session();
    s.env.hello();
    s.env.open("repo", true, SERVER_A, false).ok();
    assert_eq!(rig.lease().unwrap(), first, "unchanged");
    assert_eq!(uploads(&rig), before, "nothing was written");
    // even a takeover request by the holder is a no-op
    let mut s2 = rig.session();
    s2.env.hello();
    s2.env.open("repo", true, SERVER_A, true).ok();
    assert_eq!(rig.lease().unwrap(), first);
}

#[test]
fn another_server_without_takeover_gets_lease_held_and_changes_nothing() {
    let rig = Rig::new();
    rig.open_session().finish();
    let before = rig.lease().unwrap();
    let mut s = rig.session();
    s.env.hello();
    let r = s.env.open("repo", true, SERVER_B, false);
    assert_eq!(r.class(), Some(EC::LeaseHeld), "{r:?}");
    assert_eq!(rig.lease().unwrap(), before);
    // and nothing can be done in that session
    assert_ne!(s.env.write(T::Pack, &id(0x40), b"x").class(), None);
    assert!(
        rig.fake
            .with(|m| m.get(&path_of(T::Pack, &id(0x40))).is_none())
    );
}

#[test]
fn a_takeover_writes_generation_plus_one_and_locks_the_old_owner_out() {
    let rig = Rig::new();
    rig.open_session().finish();
    let mut s = rig.session();
    s.env.hello();
    s.env.open("repo", true, SERVER_B, true).ok();
    let l = rig.lease().unwrap();
    assert_eq!(l["server_id"], hex(&SERVER_B));
    assert_eq!(l["generation"], 2);
    s.env.write(T::Pack, &id(0x40), &data(100, 1)).ok();
    // the old owner no longer opens it
    let mut old = rig.session();
    old.env.hello();
    assert_eq!(
        old.env.open("repo", true, SERVER_A, false).class(),
        Some(EC::LeaseHeld)
    );
    // a second takeover counts on
    let mut third = rig.session();
    third.env.hello();
    third.env.open("repo", true, SERVER_A, true).ok();
    assert_eq!(rig.lease().unwrap()["generation"], 3);
}

#[test]
fn a_lease_taken_over_before_the_first_write_refuses_it() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    rig.put_lease(&SERVER_B, 2); // another server takes over after OpenRepo
    let before = uploads(&rig);
    let r = s.env.write(T::Pack, &id(0x40), &data(100, 1));
    assert_eq!(r.class(), Some(EC::LeaseHeld), "{r:?}");
    assert_eq!(uploads(&rig), before, "no byte of the object was uploaded");
    assert!(
        rig.fake
            .with(|m| m.get(&path_of(T::Pack, &id(0x40))).is_none())
    );
}

#[test]
fn the_lease_is_read_before_every_remove_even_inside_the_cache_window() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(100, 1)).ok();
    s.env.remove(T::Pack, &id(0x40)).ok(); // inside the 400 ms cache window of the last read
    s.env.write(T::Pack, &id(0x41), &data(100, 1)).ok();
    rig.put_lease(&SERVER_B, 2);
    let r = s.env.remove(T::Pack, &id(0x41));
    assert_eq!(r.class(), Some(EC::LeaseHeld), "{r:?}");
    assert!(
        rig.fake
            .with(|m| m.get(&path_of(T::Pack, &id(0x41))).is_some()),
        "the object a lost owner tried to remove is still there"
    );
}

#[test]
fn writes_use_the_cached_lease_for_the_window_and_read_it_again_after() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    let reads = |rig: &Rig| lease_reads(rig);
    // OpenRepo found no lease (its stat said so) and wrote one: nothing was downloaded yet
    assert_eq!(reads(&rig), 0);
    s.env.create().ok();
    assert_eq!(reads(&rig), 1, "the first mutation reads the lease");
    s.env.write(T::Pack, &id(0x40), &data(100, 1)).ok();
    s.env.write(T::Pack, &id(0x41), &data(100, 1)).ok();
    assert_eq!(reads(&rig), 1, "inside the window the writes use the cache");
    s.env.remove(T::Pack, &id(0x40)).ok();
    assert_eq!(reads(&rig), 2, "a remove always reads");
    std::thread::sleep(Duration::from_millis(500)); // the test window is 400 ms
    s.env.write(T::Pack, &id(0x42), &data(100, 1)).ok();
    assert_eq!(
        reads(&rig),
        3,
        "after the window the next write reads again"
    );
}

#[test]
fn a_lease_lost_in_the_middle_of_a_job_stops_every_write_and_leaves_the_reads() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(100, 1)).ok();
    rig.put_lease(&SERVER_B, 2);
    std::thread::sleep(Duration::from_millis(500)); // past the cache window
    assert_eq!(
        s.env.write(T::Pack, &id(0x41), &data(100, 1)).class(),
        Some(EC::LeaseHeld)
    );
    // sticky: even if the lease came back, the job is over
    rig.put_lease(&SERVER_A, 1);
    assert_eq!(
        s.env.write(T::Pack, &id(0x42), &data(100, 1)).class(),
        Some(EC::LeaseHeld)
    );
    assert_eq!(
        s.env.remove(T::Pack, &id(0x40)).class(),
        Some(EC::LeaseHeld)
    );
    assert_eq!(s.env.create().class(), Some(EC::LeaseHeld));
    // reads still work
    assert_eq!(
        s.env.read_full(T::Pack, &id(0x40)),
        Reply::Read(data(100, 1))
    );
    assert!(matches!(s.env.list(T::Pack), Reply::List(v) if v.len() == 1));
}

#[test]
fn an_unreadable_lease_is_internal_and_only_a_takeover_replaces_it() {
    for bad in [
        b"not json".to_vec(),
        br#"{"format":2,"server_id":"00","generation":1,"taken_at":1,"hostname_hint":""}"#.to_vec(),
        vec![b' '; 5000], // over 4 KiB: not even downloaded
    ] {
        let rig = Rig::new();
        rig.fake.with(|m| m.put("repo/hx-lease.json", &bad));
        let mut s = rig.session();
        s.env.hello();
        let r = s.env.open("repo", false, SERVER_A, false);
        assert_eq!(r.class(), Some(EC::Internal), "{r:?}");
        assert_eq!(
            rig.fake.with(|m| m.get("repo/hx-lease.json").unwrap()),
            bad,
            "left alone"
        );
        let mut s2 = rig.session();
        s2.env.hello();
        s2.env.open("repo", false, SERVER_A, true).ok();
        let l = rig.lease().unwrap();
        assert_eq!(
            (
                l["server_id"].as_str().unwrap(),
                l["generation"].as_u64().unwrap()
            ),
            (hex(&SERVER_A).as_str(), 1)
        );
    }
}

#[test]
fn config_is_written_once_and_never_overwritten() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Config, &[0; 32], &data(100, 1)).ok();
    let before = uploads(&rig);
    let r = s.env.write(T::Config, &[0; 32], &data(100, 2));
    assert_eq!(r.class(), Some(EC::Permission), "{r:?}");
    assert_eq!(uploads(&rig), before);
    assert_eq!(
        rig.fake.with(|m| m.get("repo/config").unwrap()),
        data(100, 1)
    );
    // other types may be rewritten (a retry does)
    s.env.write(T::Key, &id(1), &data(10, 1)).ok();
    s.env.write(T::Key, &id(1), &data(10, 2)).ok();
}

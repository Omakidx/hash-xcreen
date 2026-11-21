//! Exposing the Incus background operation so that a caller can cancel it and wait (ipc.md 4).

mod common;

use std::time::Duration;

use common::Fake;
use hx_provision::incus::{
    ImageSource, IncusError, InstanceCreate, OperationEnd, OperationId, StateAction,
};

fn spec() -> InstanceCreate {
    InstanceCreate {
        name: "hx-main".into(),
        image: ImageSource::LocalAlias("x".into()),
        profiles: vec!["p".into()],
        config: Default::default(),
        devices: Default::default(),
    }
}

async fn wait_until_listed(c: &hx_provision::incus::Client<hx_provision::incus::UnixTransport>) {
    for _ in 0..200 {
        if !c.in_flight_operations().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the operation never appeared in the in-flight list");
}

#[tokio::test]
async fn a_finished_operation_is_not_in_flight() {
    let fake = Fake::start().await;
    let c = fake.client();
    c.create_instance(&spec(), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(c.in_flight_operations().is_empty());
}

#[tokio::test]
async fn a_dropped_future_leaves_its_operation_listed_and_cancel_ends_it() {
    let fake = Fake::start().await;
    fake.with(|s| s.stuck_ops = true);
    let c = fake.client().scoped();
    let c2 = c.clone();
    let task =
        tokio::spawn(async move { c2.create_instance(&spec(), Duration::from_secs(120)).await });
    wait_until_listed(&c).await;
    // The caller cancels: the future is dropped (aborted). The operation lives on at the daemon...
    task.abort();
    let _ = task.await;
    let ids = c.in_flight_operations();
    assert_eq!(ids.len(), 1);
    // ...and the client still knows it, so it can be cancelled and waited for.
    assert_eq!(c.cancel_in_flight(Duration::from_secs(5)).await, Ok(1));
    assert!(c.in_flight_operations().is_empty());
    assert!(
        fake.keys()
            .contains(&format!("DELETE /1.0/operations/{}", ids[0]))
    );
}

#[tokio::test]
async fn cancelling_a_running_wait_makes_the_waiter_fail_with_cancelled() {
    let fake = Fake::start().await;
    fake.with(|s| s.stuck_ops = true);
    let c = fake.client().scoped();
    let c2 = c.clone();
    let task = tokio::spawn(async move {
        c2.set_state(
            "hx-main",
            StateAction::Start,
            false,
            Duration::from_secs(120),
        )
        .await
    });
    wait_until_listed(&c).await;
    let id = c.in_flight_operations().remove(0);
    assert!(c.cancel_operation(&id).await.unwrap());
    assert_eq!(
        c.wait_operation_end(&id, Duration::from_secs(5))
            .await
            .unwrap(),
        OperationEnd::Cancelled
    );
    let err = task.await.unwrap().unwrap_err();
    assert!(
        matches!(&err, IncusError::Operation(m) if m.contains("cancelled")),
        "{err}"
    );
}

#[tokio::test]
async fn an_operation_that_will_not_end_is_reported_stuck() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.stuck_ops = true;
        s.refuse_cancel = true;
    });
    let c = fake.client().scoped();
    let c2 = c.clone();
    let task =
        tokio::spawn(async move { c2.create_instance(&spec(), Duration::from_secs(120)).await });
    wait_until_listed(&c).await;
    task.abort();
    let _ = task.await;
    let stuck = c
        .cancel_in_flight(Duration::from_millis(1500))
        .await
        .unwrap_err();
    assert_eq!(stuck.len(), 1);
    // Still listed: the caller sets STUCK_OPERATION and may try again later.
    assert_eq!(c.in_flight_operations(), stuck);
}

#[tokio::test]
async fn an_operation_the_daemon_forgot_counts_as_ended() {
    let fake = Fake::start().await;
    let c = fake.client();
    let id = OperationId::new("00000000-0000-4000-8000-000000000042").unwrap();
    fake.with(|s| {
        s.forgotten_ops.insert(id.to_string());
    });
    assert!(!c.cancel_operation(&id).await.unwrap());
    assert_eq!(
        c.wait_operation_end(&id, Duration::from_secs(2))
            .await
            .unwrap(),
        OperationEnd::Gone
    );
}

#[tokio::test]
async fn scoped_clients_do_not_see_each_others_operations() {
    let fake = Fake::start().await;
    fake.with(|s| s.stuck_ops = true);
    let base = fake.client();
    let a = base.scoped();
    let b = base.scoped();
    let a2 = a.clone();
    let task =
        tokio::spawn(async move { a2.create_instance(&spec(), Duration::from_secs(120)).await });
    wait_until_listed(&a).await;
    assert!(b.in_flight_operations().is_empty());
    assert!(base.in_flight_operations().is_empty());
    // Cancelling b touches nothing of a's.
    assert_eq!(b.cancel_in_flight(Duration::from_secs(1)).await, Ok(0));
    assert_eq!(a.in_flight_operations().len(), 1);
    assert_eq!(a.cancel_in_flight(Duration::from_secs(5)).await, Ok(1));
    let _ = task.await;
}

#[tokio::test]
async fn a_wait_that_times_out_with_a_500_is_not_a_failure() {
    // Incus 6.0.0 answers a `/wait` that ran out with `500 context deadline exceeded`.
    let fake = Fake::start().await;
    fake.with(|s| s.wait_timeouts = 3);
    let c = fake.client();
    c.create_instance(&spec(), Duration::from_secs(30))
        .await
        .unwrap();
    // The same for waiting on an operation by id.
    fake.with(|s| s.wait_timeouts = 2);
    let id = OperationId::new("6b2d0c1e-0a5e-4f0e-9a52-0f0b7d3e3b11").unwrap();
    assert_eq!(
        c.wait_operation_end(&id, Duration::from_secs(30))
            .await
            .unwrap(),
        OperationEnd::Success
    );
    // Other 500s still fail.
    fake.with(|s| {
        s.overrides.insert(
            "POST /1.0/instances".into(),
            (
                500,
                r#"{"type":"error","error_code":500,"error":"boom"}"#.into(),
            ),
        );
    });
    assert!(
        c.create_instance(&spec(), Duration::from_secs(5))
            .await
            .is_err()
    );
}

#[test]
fn operation_ids_are_validated() {
    for bad in ["", "../x", "a b", "a/b", "x\n", &"a".repeat(65)] {
        assert!(OperationId::new(bad).is_err(), "{bad:?}");
    }
    assert!(OperationId::new("6b2d0c1e-0a5e-4f0e-9a52-0f0b7d3e3b11").is_ok());
}

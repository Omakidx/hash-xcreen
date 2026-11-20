//! Property tests for the pairing and auth envelopes.

use bytes::Bytes;
use hx_crypto::wire::{
    AuthMessage, AuthResult, PairConfirm, PairFailure, PairServerHello, PairStart, PairingMessage,
    PinAttempt, auth_message, pairing_message,
};
use hx_proto::pb::{ControlMessage, Opaque, control_message::Message as Ctl};
use proptest::prelude::*;

fn pairing_body() -> impl Strategy<Value = pairing_message::Body> {
    prop_oneof![
        (
            0..3i32,
            prop::collection::vec(any::<u8>(), 0..16),
            prop::collection::vec(any::<u8>(), 0..64),
            ".{0,64}"
        )
            .prop_map(
                |(mode, token_id, spake, device_name)| pairing_message::Body::Start(PairStart {
                    mode,
                    token_id,
                    spake,
                    device_name
                })
            ),
        (prop::collection::vec(any::<u8>(), 0..64), ".{0,64}").prop_map(|(spake, server_name)| {
            pairing_message::Body::ServerHello(PairServerHello { spake, server_name })
        }),
        prop::collection::vec(any::<u8>(), 0..64)
            .prop_map(|mac| pairing_message::Body::ClientConfirm(PairConfirm { mac })),
        prop::collection::vec(any::<u8>(), 0..64)
            .prop_map(|mac| pairing_message::Body::ServerConfirm(PairConfirm { mac })),
        (0..4i32).prop_map(|reason| pairing_message::Body::Failure(PairFailure { reason })),
    ]
}

fn auth_body() -> impl Strategy<Value = auth_message::Body> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..32)
            .prop_map(|pin| auth_message::Body::Pin(PinAttempt { pin })),
        (0..6i32, any::<u32>(), any::<u32>()).prop_map(
            |(status, attempts_left, retry_after_ms)| {
                auth_message::Body::Result(AuthResult {
                    status,
                    attempts_left,
                    retry_after_ms,
                })
            }
        ),
    ]
}

proptest! {
    #[test]
    fn pairing_messages_round_trip(body in pairing_body()) {
        let m = PairingMessage::new(body);
        let c = m.clone().into_control().unwrap();
        prop_assert_eq!(PairingMessage::from_control(&c).unwrap(), m);
        // Wrong envelope field is rejected.
        prop_assert!(AuthMessage::from_control(&c).is_err());
    }

    #[test]
    fn auth_messages_round_trip(body in auth_body()) {
        let m = AuthMessage::new(body);
        let c = m.clone().into_control().unwrap();
        prop_assert_eq!(AuthMessage::from_control(&c).unwrap(), m);
        prop_assert!(PairingMessage::from_control(&c).is_err());
    }

    #[test]
    fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let pairing = ControlMessage::new(Ctl::Pairing(Opaque { data: Bytes::from(data.clone()) }));
        let auth = ControlMessage::new(Ctl::Auth(Opaque { data: Bytes::from(data) }));
        let _ = PairingMessage::from_control(&pairing);
        let _ = AuthMessage::from_control(&auth);
    }
}

#[test]
fn envelopes_over_the_size_limit_are_refused_both_ways() {
    let big = PairingMessage::new(pairing_message::Body::Start(PairStart {
        mode: 1,
        token_id: vec![],
        spake: vec![0; 5000],
        device_name: String::new(),
    }));
    assert!(big.into_control().is_err());
    let oversized = ControlMessage::new(Ctl::Pairing(Opaque {
        data: Bytes::from(vec![0u8; 5000]),
    }));
    assert!(PairingMessage::from_control(&oversized).is_err());
}

#[test]
fn pin_attempt_debug_is_redacted() {
    let a = PinAttempt {
        pin: b"123456".to_vec(),
    };
    assert!(!format!("{a:?}").contains("123456"));
    assert!(!format!("{a:?}").contains("49, 50"));
}

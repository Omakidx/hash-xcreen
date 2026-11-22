//! Version and capability negotiation as pure functions (protocol §4).

use prost::Message;

use crate::{
    channel::MAX_FILE_SIZE,
    pb::{self, VideoCodec},
};

/// Major version of this implementation; also part of the ALPN and WebSocket path.
pub const PROTOCOL_MAJOR: u32 = 1;
/// Minor version of this implementation.
pub const PROTOCOL_MINOR: u32 = 3;
/// QUIC and TLS ALPN for native clients.
pub const ALPN: &[u8] = b"hx/1";
/// ALPN of the WebTransport (HTTP/3) entry, dispatched but not implemented in Phase 1.
pub const ALPN_H3: &[u8] = b"h3";
/// TLS ALPN used for the WebSocket fallback.
pub const ALPN_WEBSOCKET: &[u8] = b"http/1.1";
/// WebSocket request path of the fallback.
pub const WEBSOCKET_PATH: &str = "/hx/1";

/// A protocol `major.minor` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    /// Incompatible changes bump this.
    pub major: u32,
    /// Compatible additions bump this.
    pub minor: u32,
}

impl ProtocolVersion {
    /// The version this build speaks.
    pub const CURRENT: Self = Self {
        major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR,
    };
}

impl From<ProtocolVersion> for pb::Version {
    fn from(v: ProtocolVersion) -> Self {
        Self {
            major: v.major,
            minor: v.minor,
        }
    }
}

impl From<&pb::Version> for ProtocolVersion {
    fn from(v: &pb::Version) -> Self {
        Self {
            major: v.major,
            minor: v.minor,
        }
    }
}

/// Feature bitmask carried in `Capabilities.features`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Features(pub u64);

impl Features {
    /// No features.
    pub const NONE: Self = Self(0);
    /// Audio channel (1.0).
    pub const AUDIO: Self = Self(1 << 0);
    /// Clipboard channel (1.0).
    pub const CLIPBOARD: Self = Self(1 << 1);
    /// File transfer channel (1.0).
    pub const FILE_TRANSFER: Self = Self(1 << 2);
    /// `ServerStats` control messages (1.1).
    pub const SERVER_STATS: Self = Self(1 << 3);
    /// `DeviceMgmt` control messages: list and revoke paired devices (1.2).
    pub const DEVICE_MANAGEMENT: Self = Self(1 << 4);
    /// `SetupMessage` control messages on `INTENT_SETUP` connections (1.3). Never offered on a
    /// normal session.
    pub const SETUP: Self = Self(1 << 5);

    /// Every feature defined up to and including `minor` of the current major.
    pub const fn defined_up_to(minor: u32) -> Self {
        // Version 1.0 defines bits 0..=2, 1.1 adds bit 3, 1.2 adds bit 4, 1.3 adds bit 5. A
        // later minor adds its bits here.
        let mut bits = Self::AUDIO.0 | Self::CLIPBOARD.0 | Self::FILE_TRANSFER.0;
        if minor >= 1 {
            bits |= Self::SERVER_STATS.0;
        }
        if minor >= 2 {
            bits |= Self::DEVICE_MANAGEMENT.0;
        }
        if minor >= 3 {
            bits |= Self::SETUP.0;
        }
        Self(bits)
    }

    /// True if all bits of `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Bits present in both.
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// The bits of `self` that are not in `other`.
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Union of both sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Build a `Capabilities` message.
pub fn capabilities(codecs: &[VideoCodec], features: Features) -> pb::Capabilities {
    pb::Capabilities {
        video_codecs: codecs.iter().map(|c| *c as i32).collect(),
        features: features.0,
        max_file_bytes: 0,
    }
}

/// Like [`capabilities`], also stating the largest file this side accepts (1.1).
pub fn capabilities_with_file_limit(
    codecs: &[VideoCodec],
    features: Features,
    max_file_bytes: u64,
) -> pb::Capabilities {
    pb::Capabilities {
        max_file_bytes,
        ..capabilities(codecs, features)
    }
}

/// Outcome of a successful negotiation; both peers compute the same value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// Agreed version: the common major and the lower minor.
    pub version: ProtocolVersion,
    /// Features both support and that exist at the agreed minor.
    pub features: Features,
    /// Codecs both support, in the server's order of preference.
    pub codecs: Vec<VideoCodec>,
    /// Effective file transfer limit (protocol §5.6): the lowest of the 4 GiB ceiling and the
    /// limits both sides stated (stated limits count from negotiated minor 1).
    pub max_file_bytes: u64,
}

/// Negotiation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NegotiateError {
    /// Majors differ: the older side must update.
    #[error("protocol major mismatch: server {server_major}, client {client_major}")]
    MajorMismatch {
        /// Server's major.
        server_major: u32,
        /// Client's major.
        client_major: u32,
    },
}

/// Negotiate a session. Symmetric in effect: the server and the client call it with the same
/// arguments in the same slots and obtain the same [`Negotiated`].
///
/// Different major: error. Same major: the lower minor wins, features are intersected and
/// masked to those defined at that minor, unknown bits and unknown/unspecified codec numbers
/// are ignored, codecs follow the server's preference order without duplicates.
pub fn negotiate(
    server_version: ProtocolVersion,
    server: &pb::Capabilities,
    client_version: ProtocolVersion,
    client: &pb::Capabilities,
) -> Result<Negotiated, NegotiateError> {
    if server_version.major != client_version.major {
        return Err(NegotiateError::MajorMismatch {
            server_major: server_version.major,
            client_major: client_version.major,
        });
    }
    let minor = server_version.minor.min(client_version.minor);
    let features = Features(server.features)
        .intersect(Features(client.features))
        .intersect(Features::defined_up_to(minor));
    let client_codecs: Vec<VideoCodec> =
        client.video_codecs.iter().filter_map(known_codec).collect();
    let mut codecs = Vec::new();
    for c in server.video_codecs.iter().filter_map(known_codec) {
        if client_codecs.contains(&c) && !codecs.contains(&c) {
            codecs.push(c);
        }
    }
    let max_file_bytes = if minor >= 1 {
        [server.max_file_bytes, client.max_file_bytes]
            .into_iter()
            .filter(|v| *v != 0)
            .fold(MAX_FILE_SIZE, u64::min)
    } else {
        MAX_FILE_SIZE
    };
    Ok(Negotiated {
        version: ProtocolVersion {
            major: server_version.major,
            minor,
        },
        features,
        codecs,
        max_file_bytes,
    })
}

fn known_codec(v: &i32) -> Option<VideoCodec> {
    match VideoCodec::try_from(*v) {
        Ok(VideoCodec::Unspecified) | Err(_) => None,
        Ok(c) => Some(c),
    }
}

/// Probe types: decode only `ControlMessage.hello.version`, ignoring everything else, so a
/// `Hello` of a future major (whose other fields may differ) can still be refused cleanly.
#[derive(Clone, PartialEq, Message)]
struct EnvelopeProbe {
    #[prost(message, optional, tag = "1")]
    hello: Option<HelloProbe>,
}

#[derive(Clone, PartialEq, Message)]
struct HelloProbe {
    #[prost(message, optional, tag = "1")]
    version: Option<pb::Version>,
}

/// Extract the version of a `Hello` control message without validating the rest.
/// Returns `None` if the bytes are not a control message carrying a `hello` with a version.
pub fn peek_hello_version(control_message: &[u8]) -> Option<ProtocolVersion> {
    let probe = EnvelopeProbe::decode(control_message).ok()?;
    probe.hello?.version.as_ref().map(ProtocolVersion::from)
}

//! Wisp v2.1 wire-level constants: packet types, stream types, close
//! reasons, and extension IDs.
//!
//! Values come directly from the Wisp v2.1 spec
//! (`/home/amplify/Projects/NightShade/wisp-protocol/protocol.md`).
//! Cross-verified against `MoonBeam`'s TypeScript implementation
//! (`src/wisp-types.ts`) for wire compatibility.

/// Packet type identifiers (spec §"Packet Types").
///
/// Represented as `u8` on the wire. Every wisp packet begins with a
/// `PacketType` byte followed by a `u32` little-endian stream ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Connect = 0x01,
    Data = 0x02,
    Continue = 0x03,
    Close = 0x04,
    Info = 0x05,
}

impl PacketType {
    /// Try to decode a `u8` from the wire into a known packet type.
    /// Returns `None` for unrecognized values.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Connect),
            0x02 => Some(Self::Data),
            0x03 => Some(Self::Continue),
            0x04 => Some(Self::Close),
            0x05 => Some(Self::Info),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Stream type carried in the CONNECT payload (spec §"CONNECT").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamType {
    Tcp = 0x01,
    Udp = 0x02,
}

impl StreamType {
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Tcp),
            0x02 => Some(Self::Udp),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Close reason (spec §"Close Reasons"). Sent in the CLOSE payload as a
/// single `u8`. Values in three ranges:
///
///  - `0x01..=0x04`: common (either side).
///  - `0x41..=0x49`: server-only.
///  - `0x81`: client-only.
///  - `0xC0..=0xC2`: extension-defined (auth failures).
///
/// Unknown values are wrapped in `Unknown(u8)` to preserve fidelity —
/// wisp never rejects a CLOSE packet just because the reason is
/// unrecognized; consumers get the byte through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    // Common
    Unspecified,           // 0x01
    Voluntary,             // 0x02
    NetworkError,          // 0x03
    IncompatibleExtensions, // 0x04

    // Server only
    StreamInvalidInfo,     // 0x41
    StreamUnreachable,     // 0x42
    StreamTimedOut,        // 0x43
    StreamRefused,         // 0x44
    TcpDataTimedOut,       // 0x47
    StreamBlocked,         // 0x48
    Throttled,             // 0x49

    // Client only
    ClientError,           // 0x81

    // Auth extensions
    AuthInvalidCredentials, // 0xC0
    AuthInvalidSignature,   // 0xC1
    AuthRequired,           // 0xC2

    Unknown(u8),
}

impl CloseReason {
    #[must_use]
    pub fn from_u8(b: u8) -> Self {
        match b {
            0x01 => Self::Unspecified,
            0x02 => Self::Voluntary,
            0x03 => Self::NetworkError,
            0x04 => Self::IncompatibleExtensions,
            0x41 => Self::StreamInvalidInfo,
            0x42 => Self::StreamUnreachable,
            0x43 => Self::StreamTimedOut,
            0x44 => Self::StreamRefused,
            0x47 => Self::TcpDataTimedOut,
            0x48 => Self::StreamBlocked,
            0x49 => Self::Throttled,
            0x81 => Self::ClientError,
            0xC0 => Self::AuthInvalidCredentials,
            0xC1 => Self::AuthInvalidSignature,
            0xC2 => Self::AuthRequired,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Unspecified => 0x01,
            Self::Voluntary => 0x02,
            Self::NetworkError => 0x03,
            Self::IncompatibleExtensions => 0x04,
            Self::StreamInvalidInfo => 0x41,
            Self::StreamUnreachable => 0x42,
            Self::StreamTimedOut => 0x43,
            Self::StreamRefused => 0x44,
            Self::TcpDataTimedOut => 0x47,
            Self::StreamBlocked => 0x48,
            Self::Throttled => 0x49,
            Self::ClientError => 0x81,
            Self::AuthInvalidCredentials => 0xC0,
            Self::AuthInvalidSignature => 0xC1,
            Self::AuthRequired => 0xC2,
            Self::Unknown(b) => b,
        }
    }
}

/// Extension IDs (spec §"Protocol Extensions").
///
/// Values that appear in the `Extension ID` field of an INFO packet's
/// extension array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtensionId {
    Udp = 0x01,
    PasswordAuth = 0x02,
    PubkeyAuth = 0x03,
    Motd = 0x04,
    StreamOpenConfirmation = 0x05,
}

impl ExtensionId {
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Udp),
            0x02 => Some(Self::PasswordAuth),
            0x03 => Some(Self::PubkeyAuth),
            0x04 => Some(Self::Motd),
            0x05 => Some(Self::StreamOpenConfirmation),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Stream ID 0 is reserved for the initial handshake (spec §"Packet Format").
pub const HANDSHAKE_STREAM_ID: u32 = 0;

/// Current supported Wisp major version.
pub const WISP_MAJOR: u8 = 2;
/// Current supported Wisp minor version.
pub const WISP_MINOR: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_type_round_trips() {
        for b in [0x01u8, 0x02, 0x03, 0x04, 0x05] {
            let p = PacketType::from_u8(b).unwrap();
            assert_eq!(p.as_u8(), b);
        }
    }

    #[test]
    fn packet_type_rejects_unknown() {
        assert!(PacketType::from_u8(0x00).is_none());
        assert!(PacketType::from_u8(0x06).is_none());
        assert!(PacketType::from_u8(0xFF).is_none());
    }

    #[test]
    fn stream_type_round_trips() {
        assert_eq!(StreamType::from_u8(0x01), Some(StreamType::Tcp));
        assert_eq!(StreamType::from_u8(0x02), Some(StreamType::Udp));
        assert!(StreamType::from_u8(0x00).is_none());
    }

    #[test]
    fn close_reason_common_round_trip() {
        for r in [
            CloseReason::Unspecified,
            CloseReason::Voluntary,
            CloseReason::NetworkError,
            CloseReason::IncompatibleExtensions,
        ] {
            let b = r.as_u8();
            assert_eq!(CloseReason::from_u8(b), r);
        }
    }

    #[test]
    fn close_reason_server_only_round_trip() {
        for r in [
            CloseReason::StreamInvalidInfo,
            CloseReason::StreamUnreachable,
            CloseReason::StreamTimedOut,
            CloseReason::StreamRefused,
            CloseReason::TcpDataTimedOut,
            CloseReason::StreamBlocked,
            CloseReason::Throttled,
        ] {
            let b = r.as_u8();
            assert_eq!(CloseReason::from_u8(b), r);
        }
    }

    #[test]
    fn close_reason_preserves_unknown_bytes() {
        // Reserved-but-unassigned values pass through as Unknown(b).
        assert_eq!(CloseReason::from_u8(0x00), CloseReason::Unknown(0x00));
        assert_eq!(CloseReason::from_u8(0x77), CloseReason::Unknown(0x77));
        assert_eq!(CloseReason::from_u8(0xFF), CloseReason::Unknown(0xFF));

        // And the u8 round-trips.
        assert_eq!(CloseReason::Unknown(0x77).as_u8(), 0x77);
    }

    #[test]
    fn extension_id_round_trip() {
        for b in [0x01u8, 0x02, 0x03, 0x04, 0x05] {
            assert_eq!(ExtensionId::from_u8(b).unwrap().as_u8(), b);
        }
        assert!(ExtensionId::from_u8(0x00).is_none());
        assert!(ExtensionId::from_u8(0x06).is_none());
    }

    #[test]
    fn version_constants_match_v2_1() {
        assert_eq!(WISP_MAJOR, 2);
        assert_eq!(WISP_MINOR, 1);
    }
}

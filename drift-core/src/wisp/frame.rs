//! Wisp v2.1 frame encoders and decoders (encoders in Task 6; decoders in Task 7).
//!
//! Wire format (spec §"Packet Format"):
//!   [0]      : packet type (u8)
//!   [1..=4]  : stream ID (u32, little-endian)
//!   [5..]    : payload (variable, type-specific)
//!
//! All multi-byte integers are little-endian. Strings are UTF-8, NOT
//! null-terminated, and fill their assigned regions.

use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

use super::types::{
    CloseReason, ExtensionId, PacketType, StreamType, WISP_MAJOR, WISP_MINOR,
};

/// Header size: type (1 byte) + stream ID (4 bytes) = 5 bytes.
pub const HEADER_LEN: usize = 5;

// ---------------------------------------------------------------------------
// Generic wrapper: given a payload, produce a full packet
// ---------------------------------------------------------------------------

/// Wrap a payload in a wisp packet header.
///
/// Returns `HEADER_LEN + payload.len()` bytes ready to send on the wire.
#[must_use]
pub fn encode_packet(packet_type: PacketType, stream_id: u32, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER_LEN + payload.len());
    buf.put_u8(packet_type.as_u8());
    buf.put_u32_le(stream_id);
    buf.extend_from_slice(payload);
    buf.freeze()
}

/// Encode a packet directly into a `Vec<u8>`. Avoids the `Bytes` intermediate
/// so the transport can send it without an extra copy.
#[must_use]
pub fn encode_packet_to_vec(packet_type: PacketType, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    buf.push(packet_type.as_u8());
    buf.extend_from_slice(&stream_id.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

// ---------------------------------------------------------------------------
// CONNECT (0x01)
// ---------------------------------------------------------------------------

/// Encode a CONNECT payload (spec §"CONNECT").
///
/// Payload:
///   [0]     : stream type (u8; 0x01=TCP, 0x02=UDP)
///   [1..=2] : destination port (u16 LE)
///   [3..]   : destination hostname (UTF-8, not null-terminated)
#[must_use]
pub fn encode_connect(stream_type: StreamType, port: u16, hostname: &str) -> Bytes {
    let host_bytes = hostname.as_bytes();
    let mut buf = BytesMut::with_capacity(1 + 2 + host_bytes.len());
    buf.put_u8(stream_type.as_u8());
    buf.put_u16_le(port);
    buf.extend_from_slice(host_bytes);
    buf.freeze()
}

// ---------------------------------------------------------------------------
// DATA (0x02) — payload is raw stream bytes; no wrapping needed
// ---------------------------------------------------------------------------

/// Encode a DATA payload — just returns the input bytes as a `Bytes`.
/// Present for API symmetry.
#[must_use]
pub fn encode_data(data: &[u8]) -> Bytes {
    Bytes::copy_from_slice(data)
}

// ---------------------------------------------------------------------------
// CONTINUE (0x03)
// ---------------------------------------------------------------------------

/// Encode a CONTINUE payload (spec §"CONTINUE").
///
/// Payload: buffer_remaining (u32 LE) — number of DATA packets the server
/// can still buffer for this stream.
#[must_use]
pub fn encode_continue(buffer_remaining: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(4);
    buf.put_u32_le(buffer_remaining);
    buf.freeze()
}

// ---------------------------------------------------------------------------
// CLOSE (0x04)
// ---------------------------------------------------------------------------

/// Encode a CLOSE payload (spec §"CLOSE").
///
/// Payload: close_reason (u8).
#[must_use]
pub fn encode_close(reason: CloseReason) -> Bytes {
    let mut buf = BytesMut::with_capacity(1);
    buf.put_u8(reason.as_u8());
    buf.freeze()
}

// ---------------------------------------------------------------------------
// INFO (0x05)
// ---------------------------------------------------------------------------

/// A single extension entry inside an INFO payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionEntry {
    /// Well-known ID (Wisp's typed enum) or a raw byte for unknown extensions.
    pub id: u8,
    /// Extension-specific metadata bytes. May be empty.
    pub metadata: Bytes,
}

impl ExtensionEntry {
    #[must_use]
    pub fn new_known(id: ExtensionId, metadata: Bytes) -> Self {
        Self {
            id: id.as_u8(),
            metadata,
        }
    }

    #[must_use]
    pub fn empty(id: ExtensionId) -> Self {
        Self {
            id: id.as_u8(),
            metadata: Bytes::new(),
        }
    }
}

/// Encode an INFO payload (spec §"INFO").
///
/// Payload:
///   [0]   : major version (u8)
///   [1]   : minor version (u8)
///   [2..] : extension entries, each:
///           [0]     : extension ID (u8)
///           [1..=4] : payload length (u32 LE)
///           [5..]   : metadata (`payload_length` bytes)
///
/// Uses `WISP_MAJOR`/`WISP_MINOR` for the version fields.
#[must_use]
pub fn encode_info(extensions: &[ExtensionEntry]) -> Bytes {
    // Precompute size to avoid reallocations.
    let mut total = 2;
    for ext in extensions {
        total += 1 + 4 + ext.metadata.len();
    }

    let mut buf = BytesMut::with_capacity(total);
    buf.put_u8(WISP_MAJOR);
    buf.put_u8(WISP_MINOR);
    for ext in extensions {
        buf.put_u8(ext.id);
        // Clamp to u32 in case of a pathological metadata length; realistic
        // extensions are small (<64 KiB).
        let len = u32::try_from(ext.metadata.len()).unwrap_or(u32::MAX);
        buf.put_u32_le(len);
        buf.extend_from_slice(&ext.metadata);
    }
    buf.freeze()
}

// ---------------------------------------------------------------------------
// Decoder errors
// ---------------------------------------------------------------------------

/// Errors returned by the wisp decoders. All indicate a malformed or
/// truncated packet on the wire.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("packet too short: got {got} bytes, need at least {need}")]
    TooShort { got: usize, need: usize },

    #[error("unknown packet type: 0x{0:02x}")]
    UnknownPacketType(u8),

    #[error("unknown stream type: 0x{0:02x}")]
    UnknownStreamType(u8),

    #[error("hostname is not valid UTF-8")]
    InvalidHostname,

    #[error("info extension entry declares length {declared} but only {available} bytes remain")]
    ExtensionOverrun { declared: u32, available: usize },
}

// ---------------------------------------------------------------------------
// Generic packet header decoder
// ---------------------------------------------------------------------------

/// A decoded packet header + reference to its payload.
///
/// The `payload` field borrows from the input buffer — cheap, no copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPacket<'a> {
    pub packet_type: PacketType,
    pub stream_id: u32,
    pub payload: &'a [u8],
}

/// A decoded packet header with an owned payload.
///
/// The `payload` is a `Bytes` slice sharing the input allocation (refcounted)
/// so no copy is needed.
#[derive(Debug, Clone)]
pub struct DecodedPacketOwned {
    pub packet_type: PacketType,
    pub stream_id: u32,
    pub payload: Bytes,
}

/// Decode a wisp packet header from a raw wire buffer.
///
/// Returns the packet type, stream ID, and a slice into the payload region.
/// The payload is borrowed — no allocation.
///
/// # Errors
///
/// - `TooShort` if the buffer is smaller than the 5-byte header.
/// - `UnknownPacketType` if the type byte is not one of 0x01..=0x05.
pub fn decode_packet(buf: &[u8]) -> std::result::Result<DecodedPacket<'_>, DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::TooShort {
            got: buf.len(),
            need: HEADER_LEN,
        });
    }
    let packet_type = PacketType::from_u8(buf[0])
        .ok_or(DecodeError::UnknownPacketType(buf[0]))?;
    let stream_id = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
    Ok(DecodedPacket {
        packet_type,
        stream_id,
        payload: &buf[HEADER_LEN..],
    })
}

/// Decode a wisp packet from an owned `Bytes` buffer, returning an owned
/// `DecodedPacketOwned`. The payload is a refcounted slice of the input —
/// no copy.
///
/// # Errors
///
/// Same as `decode_packet`.
#[allow(clippy::needless_pass_by_value)]
pub fn decode_packet_owned(buf: Bytes) -> std::result::Result<DecodedPacketOwned, DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::TooShort {
            got: buf.len(),
            need: HEADER_LEN,
        });
    }
    let packet_type = PacketType::from_u8(buf[0])
        .ok_or(DecodeError::UnknownPacketType(buf[0]))?;
    let stream_id = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let payload = buf.slice(HEADER_LEN..);
    Ok(DecodedPacketOwned {
        packet_type,
        stream_id,
        payload,
    })
}

// ---------------------------------------------------------------------------
// CONNECT payload
// ---------------------------------------------------------------------------

/// A decoded CONNECT payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedConnect {
    pub stream_type: StreamType,
    pub port: u16,
    pub hostname: String,
}

/// Decode a CONNECT payload.
///
/// Layout (spec §"CONNECT"):
///   [0]     stream type (u8)
///   [1..=2] port (u16 LE)
///   [3..]   hostname (UTF-8)
///
/// # Errors
///
/// - `TooShort` if the payload is <3 bytes.
/// - `UnknownStreamType` if byte 0 is not 0x01 or 0x02.
/// - `InvalidHostname` if the hostname bytes are not UTF-8.
pub fn decode_connect(payload: &[u8]) -> std::result::Result<DecodedConnect, DecodeError> {
    if payload.len() < 3 {
        return Err(DecodeError::TooShort {
            got: payload.len(),
            need: 3,
        });
    }
    let stream_type = StreamType::from_u8(payload[0])
        .ok_or(DecodeError::UnknownStreamType(payload[0]))?;
    let port = u16::from_le_bytes([payload[1], payload[2]]);
    let hostname = std::str::from_utf8(&payload[3..])
        .map_err(|_| DecodeError::InvalidHostname)?
        .to_string();
    Ok(DecodedConnect {
        stream_type,
        port,
        hostname,
    })
}

// ---------------------------------------------------------------------------
// CONTINUE payload
// ---------------------------------------------------------------------------

/// Decode a CONTINUE payload — a single u32 LE (buffer remaining).
///
/// # Errors
///
/// - `TooShort` if the payload is <4 bytes.
pub fn decode_continue(payload: &[u8]) -> std::result::Result<u32, DecodeError> {
    if payload.len() < 4 {
        return Err(DecodeError::TooShort {
            got: payload.len(),
            need: 4,
        });
    }
    Ok(u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]))
}

// ---------------------------------------------------------------------------
// CLOSE payload
// ---------------------------------------------------------------------------

/// Decode a CLOSE payload — a single close-reason byte.
///
/// # Errors
///
/// - `TooShort` if the payload is empty.
pub fn decode_close(payload: &[u8]) -> std::result::Result<CloseReason, DecodeError> {
    if payload.is_empty() {
        return Err(DecodeError::TooShort { got: 0, need: 1 });
    }
    Ok(CloseReason::from_u8(payload[0]))
}

// ---------------------------------------------------------------------------
// INFO payload
// ---------------------------------------------------------------------------

/// A decoded INFO payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInfo {
    pub major: u8,
    pub minor: u8,
    pub extensions: Vec<DecodedExtension>,
}

/// A single extension entry from a decoded INFO packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedExtension {
    pub id: u8,
    pub metadata: Bytes,
}

/// Decode an INFO payload.
///
/// Layout (spec §"INFO"):
///   [0]     major version (u8)
///   [1]     minor version (u8)
///   [2..]   zero or more extension entries, each:
///           [0]     extension ID (u8)
///           [1..=4] payload length (u32 LE)
///           [5..]   metadata (`payload length` bytes)
///
/// # Errors
///
/// - `TooShort` if the payload is <2 bytes, or if an extension header is
///   incomplete.
/// - `ExtensionOverrun` if a declared extension length exceeds the bytes
///   remaining in the buffer.
pub fn decode_info(payload: &[u8]) -> std::result::Result<DecodedInfo, DecodeError> {
    if payload.len() < 2 {
        return Err(DecodeError::TooShort {
            got: payload.len(),
            need: 2,
        });
    }
    let major = payload[0];
    let minor = payload[1];
    let mut extensions = Vec::new();
    let mut i = 2usize;
    while i < payload.len() {
        // Need 1 byte ID + 4 bytes length header.
        if payload.len() - i < 5 {
            return Err(DecodeError::TooShort {
                got: payload.len() - i,
                need: 5,
            });
        }
        let id = payload[i];
        let len = u32::from_le_bytes([
            payload[i + 1],
            payload[i + 2],
            payload[i + 3],
            payload[i + 4],
        ]);
        let start = i + 5;
        let len_usize = len as usize;
        if payload.len() - start < len_usize {
            return Err(DecodeError::ExtensionOverrun {
                declared: len,
                available: payload.len() - start,
            });
        }
        let metadata = Bytes::copy_from_slice(&payload[start..start + len_usize]);
        extensions.push(DecodedExtension { id, metadata });
        i = start + len_usize;
    }
    Ok(DecodedInfo {
        major,
        minor,
        extensions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- encode_packet ----

    #[test]
    fn encode_packet_header_layout() {
        let payload = &[0xAA, 0xBB, 0xCC];
        let out = encode_packet(PacketType::Data, 0x0403_0201, payload);

        // Header: [type=0x02] [stream_id LE=0x01 0x02 0x03 0x04]
        assert_eq!(out[0], 0x02);
        assert_eq!(&out[1..=4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&out[5..], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(out.len(), HEADER_LEN + 3);
    }

    #[test]
    fn encode_packet_handshake_stream_id_zero() {
        let out = encode_packet(PacketType::Info, 0, &[]);
        assert_eq!(out.as_ref(), &[0x05, 0x00, 0x00, 0x00, 0x00]);
    }

    // ---- CONNECT ----

    #[test]
    fn encode_connect_tcp_example_com_80() {
        let out = encode_connect(StreamType::Tcp, 80, "example.com");

        // [stream_type=0x01] [port LE=80 = 0x50 0x00] [hostname bytes]
        assert_eq!(out[0], 0x01);
        assert_eq!(&out[1..=2], &[0x50, 0x00]);
        assert_eq!(&out[3..], b"example.com");
        assert_eq!(out.len(), 3 + "example.com".len());
    }

    #[test]
    fn encode_connect_udp_high_port() {
        let out = encode_connect(StreamType::Udp, 53535, "a.b");
        assert_eq!(out[0], 0x02);
        assert_eq!(&out[1..=2], &[0x1F, 0xD1]);  // 53535 = 0xD11F
        assert_eq!(&out[3..], b"a.b");
    }

    #[test]
    fn encode_connect_empty_hostname_is_valid_bytes() {
        // Wire encoder is dumb about content validation — that's a server-side
        // concern per the spec (CONNECT with invalid payload -> server sends CLOSE).
        let out = encode_connect(StreamType::Tcp, 0, "");
        assert_eq!(out.as_ref(), &[0x01, 0x00, 0x00]);
    }

    // ---- DATA ----

    #[test]
    fn encode_data_returns_bytes_copy() {
        let out = encode_data(&[1, 2, 3]);
        assert_eq!(out.as_ref(), &[1, 2, 3]);
    }

    // ---- CONTINUE ----

    #[test]
    fn encode_continue_u32_le() {
        let out = encode_continue(0x0403_0201);
        assert_eq!(out.as_ref(), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn encode_continue_zero() {
        assert_eq!(encode_continue(0).as_ref(), &[0, 0, 0, 0]);
    }

    // ---- CLOSE ----

    #[test]
    fn encode_close_voluntary() {
        assert_eq!(encode_close(CloseReason::Voluntary).as_ref(), &[0x02]);
    }

    #[test]
    fn encode_close_preserves_unknown_reason() {
        assert_eq!(
            encode_close(CloseReason::Unknown(0x99)).as_ref(),
            &[0x99]
        );
    }

    // ---- INFO ----

    #[test]
    fn encode_info_empty_extensions() {
        let out = encode_info(&[]);
        assert_eq!(out.as_ref(), &[WISP_MAJOR, WISP_MINOR]);
    }

    #[test]
    fn encode_info_udp_only() {
        let entries = [ExtensionEntry::empty(ExtensionId::Udp)];
        let out = encode_info(&entries);
        // [major=2] [minor=1] [ext_id=0x01] [payload_len=0x00 0x00 0x00 0x00]
        assert_eq!(
            out.as_ref(),
            &[WISP_MAJOR, WISP_MINOR, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn encode_info_two_extensions_with_metadata() {
        let entries = [
            ExtensionEntry::empty(ExtensionId::Udp),
            ExtensionEntry::new_known(ExtensionId::Motd, Bytes::from_static(b"hi")),
        ];
        let out = encode_info(&entries);
        assert_eq!(
            out.as_ref(),
            &[
                WISP_MAJOR, WISP_MINOR,
                0x01, 0x00, 0x00, 0x00, 0x00,          // UDP, len=0
                0x04, 0x02, 0x00, 0x00, 0x00, b'h', b'i', // MOTD, len=2, "hi"
            ]
        );
    }

    // ---- full packet composition ----

    #[test]
    fn full_connect_packet_wire_layout() {
        let payload = encode_connect(StreamType::Tcp, 443, "example.com");
        let out = encode_packet(PacketType::Connect, 1, &payload);

        // [type=0x01] [stream_id LE=1] [stream_type=0x01] [port LE=443] [hostname]
        assert_eq!(out[0], 0x01);
        assert_eq!(&out[1..=4], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(out[5], 0x01);
        assert_eq!(&out[6..=7], &[0xBB, 0x01]); // 443 = 0x01BB
        assert_eq!(&out[8..], b"example.com");
    }

    // -----------------------------------------------------------------------
    // decode_packet
    // -----------------------------------------------------------------------

    #[test]
    fn decode_packet_short_buffer_fails() {
        let err = decode_packet(&[0x01, 0x00, 0x00]).unwrap_err();
        assert_eq!(err, DecodeError::TooShort { got: 3, need: 5 });
    }

    #[test]
    fn decode_packet_unknown_type_fails() {
        let err = decode_packet(&[0x00, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, DecodeError::UnknownPacketType(0x00));
    }

    #[test]
    fn decode_packet_round_trip_data() {
        let wire = encode_packet(PacketType::Data, 42, &[1, 2, 3]);
        let d = decode_packet(&wire).unwrap();
        assert_eq!(d.packet_type, PacketType::Data);
        assert_eq!(d.stream_id, 42);
        assert_eq!(d.payload, &[1, 2, 3]);
    }

    #[test]
    fn decode_packet_round_trip_zero_payload() {
        let wire = encode_packet(PacketType::Close, 7, &[]);
        let d = decode_packet(&wire).unwrap();
        assert_eq!(d.packet_type, PacketType::Close);
        assert_eq!(d.stream_id, 7);
        assert!(d.payload.is_empty());
    }

    // -----------------------------------------------------------------------
    // decode_connect
    // -----------------------------------------------------------------------

    #[test]
    fn decode_connect_round_trip() {
        let wire = encode_connect(StreamType::Tcp, 443, "example.com");
        let d = decode_connect(&wire).unwrap();
        assert_eq!(d.stream_type, StreamType::Tcp);
        assert_eq!(d.port, 443);
        assert_eq!(d.hostname, "example.com");
    }

    #[test]
    fn decode_connect_short_payload_fails() {
        let err = decode_connect(&[0x01, 0x00]).unwrap_err();
        assert_eq!(err, DecodeError::TooShort { got: 2, need: 3 });
    }

    #[test]
    fn decode_connect_unknown_stream_type_fails() {
        let err = decode_connect(&[0x99, 0x00, 0x00]).unwrap_err();
        assert_eq!(err, DecodeError::UnknownStreamType(0x99));
    }

    #[test]
    fn decode_connect_invalid_utf8_hostname_fails() {
        // Valid header + invalid UTF-8 hostname bytes.
        let wire = vec![0x01, 0x50, 0x00, 0xFF, 0xFE, 0xFD];
        let err = decode_connect(&wire).unwrap_err();
        assert_eq!(err, DecodeError::InvalidHostname);
    }

    #[test]
    fn decode_connect_empty_hostname_allowed_by_wire() {
        // Semantic validity (empty hostname) is a server-side concern per spec;
        // the decoder just yields the empty string.
        let d = decode_connect(&[0x01, 0x00, 0x00]).unwrap();
        assert_eq!(d.hostname, "");
    }

    // -----------------------------------------------------------------------
    // decode_continue
    // -----------------------------------------------------------------------

    #[test]
    fn decode_continue_round_trip() {
        let wire = encode_continue(0xDEAD_BEEF);
        assert_eq!(decode_continue(&wire).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn decode_continue_short_fails() {
        assert!(matches!(
            decode_continue(&[0x00, 0x00]).unwrap_err(),
            DecodeError::TooShort { got: 2, need: 4 }
        ));
    }

    // -----------------------------------------------------------------------
    // decode_close
    // -----------------------------------------------------------------------

    #[test]
    fn decode_close_common_reason() {
        assert_eq!(decode_close(&[0x02]).unwrap(), CloseReason::Voluntary);
    }

    #[test]
    fn decode_close_unknown_reason_preserved() {
        assert_eq!(decode_close(&[0x77]).unwrap(), CloseReason::Unknown(0x77));
    }

    #[test]
    fn decode_close_empty_fails() {
        assert!(matches!(
            decode_close(&[]).unwrap_err(),
            DecodeError::TooShort { got: 0, need: 1 }
        ));
    }

    // -----------------------------------------------------------------------
    // decode_info
    // -----------------------------------------------------------------------

    #[test]
    fn decode_info_no_extensions() {
        let wire = encode_info(&[]);
        let d = decode_info(&wire).unwrap();
        assert_eq!(d.major, WISP_MAJOR);
        assert_eq!(d.minor, WISP_MINOR);
        assert!(d.extensions.is_empty());
    }

    #[test]
    fn decode_info_two_extensions_round_trip() {
        let entries = vec![
            ExtensionEntry::empty(ExtensionId::Udp),
            ExtensionEntry::new_known(ExtensionId::Motd, Bytes::from_static(b"welcome")),
        ];
        let wire = encode_info(&entries);
        let d = decode_info(&wire).unwrap();

        assert_eq!(d.extensions.len(), 2);
        assert_eq!(d.extensions[0].id, ExtensionId::Udp.as_u8());
        assert!(d.extensions[0].metadata.is_empty());
        assert_eq!(d.extensions[1].id, ExtensionId::Motd.as_u8());
        assert_eq!(d.extensions[1].metadata.as_ref(), b"welcome");
    }

    #[test]
    fn decode_info_truncated_extension_header_fails() {
        // major/minor + partial extension header (only 3 bytes of the 5-byte
        // header for an extension entry).
        let wire = [WISP_MAJOR, WISP_MINOR, 0x01, 0x00, 0x00];
        assert!(matches!(
            decode_info(&wire).unwrap_err(),
            DecodeError::TooShort { .. }
        ));
    }

    #[test]
    fn decode_info_extension_overrun_fails() {
        // Declares a 100-byte metadata but only supplies 1 byte.
        let wire = [
            WISP_MAJOR, WISP_MINOR,
            0x01, 0x64, 0x00, 0x00, 0x00, // ext id + len=100
            0xAA,                          // only 1 metadata byte
        ];
        assert!(matches!(
            decode_info(&wire).unwrap_err(),
            DecodeError::ExtensionOverrun { declared: 100, available: 1 }
        ));
    }
}

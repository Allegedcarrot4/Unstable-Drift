//! Wisp v2.1 protocol implementation.

pub mod frame;
pub mod mux;
pub mod stream;
pub mod stream_io;
pub mod types;

pub use frame::{
    decode_close, decode_connect, decode_continue, decode_info, decode_packet,
    decode_packet_owned, encode_close, encode_connect, encode_continue, encode_data,
    encode_info, encode_packet, encode_packet_to_vec, DecodeError, DecodedConnect,
    DecodedExtension, DecodedInfo, DecodedPacket, DecodedPacketOwned, ExtensionEntry,
    HEADER_LEN,
};
pub use mux::{Mux, MuxError, StreamHandle};
pub use stream::WispStream;
pub use stream_io::WispStreamIo;
pub use types::{
    CloseReason, ExtensionId, HANDSHAKE_STREAM_ID, PacketType, StreamType,
    WISP_MAJOR, WISP_MINOR,
};

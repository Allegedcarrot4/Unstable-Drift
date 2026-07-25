use std::time::Duration;

use bytes::Bytes;
use flume::{Receiver, Sender};
use drift_core::wisp::{
    decode_packet, encode_close, encode_continue, encode_info, encode_packet_to_vec,
    CloseReason, DecodeError, DecodedConnect, DecodedInfo, ExtensionEntry, PacketType,
    HANDSHAKE_STREAM_ID,
};

use crate::paired_transport::PairedTransport;

/// A single client packet observed by the server, in decoded form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerReceived {
    Connect {
        stream_id: u32,
        payload: DecodedConnect,
    },
    Data {
        stream_id: u32,
        payload: Bytes,
    },
    Continue {
        stream_id: u32,
        credit: u32,
    },
    Close {
        stream_id: u32,
        reason: CloseReason,
    },
    Info {
        stream_id: u32,
        payload: DecodedInfo,
    },
    /// A packet we couldn't decode. Preserved for test visibility.
    Raw {
        bytes: Bytes,
        err: String,
    },
}

/// The scripted mock server. Owns the server-side channel from a
/// `PairedTransport`. Callers use it to script server behavior in tests.
pub struct MockWispServer {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl MockWispServer {
    /// Build a mock server from a `PairedTransport`. Consumes the pair's
    /// server-side channels; the pair's `.client` transport is what's
    /// handed to a `Mux`.
    #[must_use]
    pub fn from_pair(pair: &PairedTransport) -> Self {
        Self {
            tx: pair.server_tx.clone(),
            rx: pair.server_rx.clone(),
        }
    }

    // ---- Scripting: server -> client ----

    /// Push an INFO packet on stream 0 with the given extensions.
    ///
    /// # Panics
    /// Panics if the internal channel is closed.
    pub fn send_info(&self, extensions: &[ExtensionEntry]) {
        let payload = encode_info(extensions);
        let pkt = encode_packet_to_vec(PacketType::Info, HANDSHAKE_STREAM_ID, &payload);
        self.tx.send(pkt).expect("mock server: send_info failed");
    }

    /// Push a CONTINUE on stream 0 (post-handshake initial credit grant).
    ///
    /// # Panics
    /// Panics if the internal channel is closed.
    pub fn send_handshake_continue(&self, buffer_size: u32) {
        let pkt = encode_packet_to_vec(
            PacketType::Continue,
            HANDSHAKE_STREAM_ID,
            &encode_continue(buffer_size),
        );
        self.tx.send(pkt).expect("mock server: send_handshake_continue failed");
    }

    /// Push a per-stream CONTINUE (credit refill).
    ///
    /// # Panics
    /// Panics if the internal channel is closed.
    pub fn send_stream_continue(&self, stream_id: u32, buffer_remaining: u32) {
        let pkt = encode_packet_to_vec(
            PacketType::Continue,
            stream_id,
            &encode_continue(buffer_remaining),
        );
        self.tx.send(pkt).expect("mock server: send_stream_continue failed");
    }

    /// Push a DATA packet on `stream_id`.
    ///
    /// # Panics
    /// Panics if the internal channel is closed.
    pub fn send_data(&self, stream_id: u32, data: &[u8]) {
        let pkt = encode_packet_to_vec(PacketType::Data, stream_id, data);
        self.tx.send(pkt).expect("mock server: send_data failed");
    }

    /// Push a CLOSE for `stream_id`.
    ///
    /// # Panics
    /// Panics if the internal channel is closed.
    pub fn send_close(&self, stream_id: u32, reason: CloseReason) {
        let pkt = encode_packet_to_vec(PacketType::Close, stream_id, &encode_close(reason));
        self.tx.send(pkt).expect("mock server: send_close failed");
    }

    // ---- Observation: client -> server ----

    /// Drain all frames observed from the client so far into decoded form.
    /// Non-blocking.
    #[must_use]
    pub fn received(&self) -> Vec<ServerReceived> {
        let mut out = Vec::new();
        while let Ok(vec) = self.rx.try_recv() {
            out.push(decode_one(&Bytes::from(vec)));
        }
        out
    }

    /// Await the next frame from the client (with a timeout).
    ///
    /// # Errors
    ///
    /// - Returns `Err(())` on timeout.
    pub async fn recv_one(&self, timeout: Duration) -> Result<ServerReceived, ()> {
        match tokio::time::timeout(timeout, self.rx.recv_async()).await {
            Ok(Ok(vec)) => Ok(decode_one(&Bytes::from(vec))),
            _ => Err(()),
        }
    }
}

fn decode_one(bytes: &Bytes) -> ServerReceived {
    match decode_packet(bytes) {
        Ok(pkt) => match pkt.packet_type {
            PacketType::Connect => match drift_core::wisp::decode_connect(pkt.payload) {
                Ok(payload) => ServerReceived::Connect {
                    stream_id: pkt.stream_id,
                    payload,
                },
                Err(e) => raw_from(bytes, &e),
            },
            PacketType::Data => ServerReceived::Data {
                stream_id: pkt.stream_id,
                payload: Bytes::copy_from_slice(pkt.payload),
            },
            PacketType::Continue => match drift_core::wisp::decode_continue(pkt.payload) {
                Ok(credit) => ServerReceived::Continue {
                    stream_id: pkt.stream_id,
                    credit,
                },
                Err(e) => raw_from(bytes, &e),
            },
            PacketType::Close => match drift_core::wisp::decode_close(pkt.payload) {
                Ok(reason) => ServerReceived::Close {
                    stream_id: pkt.stream_id,
                    reason,
                },
                Err(e) => raw_from(bytes, &e),
            },
            PacketType::Info => match drift_core::wisp::decode_info(pkt.payload) {
                Ok(payload) => ServerReceived::Info {
                    stream_id: pkt.stream_id,
                    payload,
                },
                Err(e) => raw_from(bytes, &e),
            },
        },
        Err(e) => raw_from(bytes, &e),
    }
}

fn raw_from(bytes: &Bytes, err: &DecodeError) -> ServerReceived {
    ServerReceived::Raw {
        bytes: bytes.clone(),
        err: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paired_transport::make_paired_transport;
    use drift_core::transport::WispTransport;
    use std::sync::Arc;

    #[tokio::test]
    async fn mock_server_scripts_handshake_and_observes_client_info() {
        let pair = make_paired_transport();
        let srv = MockWispServer::from_pair(&pair);

        // Script the handshake.
        srv.send_info(&[]);
        srv.send_handshake_continue(64);

        // The client would call recv() twice (INFO, then CONTINUE) and
        // send its INFO in between. Simulate that dumbly by draining the
        // client transport's inbound queue and firing its send() by hand.
        let client: Arc<dyn WispTransport> = pair.client.clone();
        let first = client.recv().await.unwrap();
        let d = decode_packet(&first).unwrap();
        assert_eq!(d.packet_type, PacketType::Info);

        let payload = encode_info(&[]);
        let pkt = encode_packet_to_vec(PacketType::Info, HANDSHAKE_STREAM_ID, &payload);
        client.send(pkt).await.unwrap();

        let second = client.recv().await.unwrap();
        assert_eq!(decode_packet(&second).unwrap().packet_type, PacketType::Continue);

        // Server observed our INFO.
        let observed = srv.received();
        assert_eq!(observed.len(), 1);
        assert!(matches!(observed[0], ServerReceived::Info { stream_id: 0, .. }));
    }

    #[tokio::test]
    async fn mock_server_recv_one_times_out() {
        let pair = make_paired_transport();
        let srv = MockWispServer::from_pair(&pair);
        let err = srv.recv_one(Duration::from_millis(50)).await;
        assert!(err.is_err());
    }
}

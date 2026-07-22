//! Wisp multiplexer — connection-level state machine.
//!
//! Owns:
//!   - the transport
//!   - handshake state (INFO/CONTINUE exchange)
//!   - per-stream state (credit, close-state)
//!   - the client's next-stream-ID allocator
//!
//! Task 9 layers `WispStream` on top of the mux's stream-tracking API.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use flume::{Receiver, Sender};
use tokio::sync::Notify;

use super::frame::{
    decode_continue, decode_info, decode_packet, decode_packet_owned, encode_close,
    encode_connect, encode_info, encode_packet_to_vec, DecodeError, ExtensionEntry,
};
use super::types::{
    CloseReason, PacketType, StreamType, HANDSHAKE_STREAM_ID,
};
use crate::transport::{TransportError, WispTransport};

/// Errors surfaced by the mux to callers.
#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("decode: {0}")]
    Decode(#[from] DecodeError),
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("stream {0} closed by peer: {1:?}")]
    StreamClosed(u32, CloseReason),
    #[error("stream {0} not found")]
    UnknownStream(u32),
    #[error("stream id space exhausted")]
    StreamIdExhausted,
}

/// Per-stream state tracked by the mux.
#[derive(Debug)]
struct StreamState {
    stream_type: StreamType,
    /// Remaining CONTINUE credit (DATA packets we may still send).
    /// UDP streams never receive CONTINUE; their credit is `u32::MAX` and
    /// never decremented (spec §"CONTINUE": UDP is credit-less).
    credit: u32,
    /// Sender for inbound DATA payloads on this stream.
    inbound_tx: Sender<Bytes>,
    /// Notify used to wake senders blocked on zero credit. Woken on
    /// CONTINUE (credit refill) or CLOSE (so waiters fail cleanly).
    credit_notify: Arc<Notify>,
}

/// A newly-opened stream. Callers keep the `id` and the `inbound_rx`.
#[derive(Debug)]
pub struct StreamHandle {
    pub id: u32,
    pub stream_type: StreamType,
    /// DATA packets arriving on this stream.
    pub inbound_rx: Receiver<Bytes>,
    /// Shared notifier used by the mux to signal credit changes.
    pub credit_notify: Arc<Notify>,
}

/// The multiplexer.
///
/// Held inside an `Arc<Mux>` so multiple `WispStream`s can share it. All
/// mutable state is inside internal channels or `parking_lot::Mutex`
/// (Phase 1: `std::sync::Mutex` is fine — no async-in-lock hazards yet).
pub struct Mux {
    transport: Arc<dyn WispTransport>,
    inner: parking_lot::Mutex<MuxInner>,
}

struct MuxInner {
    handshake: HandshakeState,
    next_stream_id: u32,
    streams: HashMap<u32, StreamState>,
    /// Initial CONTINUE credit granted by the server (from the handshake
    /// CONTINUE on stream 0).
    initial_credit: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeState {
    Pending,
    Established,
    #[allow(dead_code)] // reserved for teardown paths in Task 11
    Closed,
}

impl Mux {
    /// Create a new mux over the given transport. The handshake is not yet
    /// driven — call `run_handshake` to complete it.
    #[must_use]
    pub fn new(transport: Arc<dyn WispTransport>) -> Self {
        Self {
            transport,
            inner: parking_lot::Mutex::new(MuxInner {
                handshake: HandshakeState::Pending,
                next_stream_id: 1,
                streams: HashMap::new(),
                initial_credit: 0,
            }),
        }
    }

    /// Drive the wisp v2 handshake to completion.
    ///
    /// Sequence (spec §"Handshake Steps"):
    ///   1. Receive server INFO (stream 0)
    ///   2. Send client INFO (stream 0)
    ///   3. Receive server CONTINUE (stream 0) with initial buffer size
    ///
    /// This method returns `Ok(())` after step 3 or on any handshake error.
    ///
    /// # Errors
    ///
    /// - `Handshake` if the peer sends an unexpected packet.
    /// - `Transport` on I/O error.
    pub async fn run_handshake(
        &self,
        client_extensions: &[ExtensionEntry],
    ) -> Result<(), MuxError> {
        // Step 1: server INFO (v2) or CONTINUE (v1 fallback).
        //
        // Per spec §Handshake Steps: "If the client instead receives a
        // CONTINUE packet first, version 1 of the protocol must be used,
        // and the rest of these steps no longer apply." MoonBeam's client
        // handles this the same way (src/wisp-client.ts, `allowV1` path).
        let server_frame = self.transport.recv().await?;
        let server_pkt = decode_packet(&server_frame)?;
        if server_pkt.stream_id != HANDSHAKE_STREAM_ID {
            return Err(MuxError::Handshake(format!(
                "expected handshake packet on stream 0, got stream {}",
                server_pkt.stream_id
            )));
        }
        if server_pkt.packet_type == PacketType::Continue {
            // v1 server. Skip the v2 INFO exchange; use this CONTINUE's
            // buffer size as our initial credit.
            let initial_credit = decode_continue(server_pkt.payload)?;
            let mut inner = self.inner.lock();
            inner.handshake = HandshakeState::Established;
            inner.initial_credit = initial_credit;
            return Ok(());
        }
        if server_pkt.packet_type != PacketType::Info {
            return Err(MuxError::Handshake(format!(
                "expected server INFO or CONTINUE on stream 0, got {:?}",
                server_pkt.packet_type
            )));
        }
        let _server_info = decode_info(server_pkt.payload)?;

        // Step 2: send our INFO
        let client_info_payload = encode_info(client_extensions);
        let client_info_packet =
            encode_packet_to_vec(PacketType::Info, HANDSHAKE_STREAM_ID, &client_info_payload);
        self.transport.send(client_info_packet).await?;

        // Step 3: server CONTINUE
        let continue_frame = self.transport.recv().await?;
        let continue_pkt = decode_packet(&continue_frame)?;
        if continue_pkt.packet_type != PacketType::Continue
            || continue_pkt.stream_id != HANDSHAKE_STREAM_ID
        {
            return Err(MuxError::Handshake(format!(
                "expected server CONTINUE on stream 0, got {:?} on stream {}",
                continue_pkt.packet_type, continue_pkt.stream_id
            )));
        }
        let initial_credit = decode_continue(continue_pkt.payload)?;

        let mut inner = self.inner.lock();
        inner.handshake = HandshakeState::Established;
        inner.initial_credit = initial_credit;
        Ok(())
    }

    /// Open a new stream. Sends CONNECT to the peer and returns a handle.
    ///
    /// # Errors
    ///
    /// - `Handshake` if the mux hasn't completed its handshake.
    /// - `StreamIdExhausted` after ~4 billion streams (extremely unlikely
    ///   in practice; guard is here to avoid ID reuse).
    /// - `Transport` on I/O error.
    pub async fn open(
        &self,
        host: &str,
        port: u16,
        stream_type: StreamType,
    ) -> Result<StreamHandle, MuxError> {
        let (id, initial_credit) = {
            let mut inner = self.inner.lock();
            if inner.handshake != HandshakeState::Established {
                return Err(MuxError::Handshake(
                    "cannot open stream before handshake completes".into(),
                ));
            }
            if inner.next_stream_id == 0 {
                inner.next_stream_id = 1;
            }
            let id = inner.next_stream_id;
            // Advance, wrapping and skipping the reserved 0.
            inner.next_stream_id = inner.next_stream_id.checked_add(1)
                .ok_or(MuxError::StreamIdExhausted)?;
            if inner.next_stream_id == HANDSHAKE_STREAM_ID {
                inner.next_stream_id = 1;
            }
            (id, inner.initial_credit)
        };

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let credit_notify = Arc::new(Notify::new());
        {
            let mut inner = self.inner.lock();
            let credit = match stream_type {
                StreamType::Tcp => initial_credit,
                StreamType::Udp => u32::MAX,
            };
            inner.streams.insert(
                id,
                StreamState {
                    stream_type,
                    credit,
                    inbound_tx,
                    credit_notify: credit_notify.clone(),
                },
            );
        }

        // Send CONNECT.
        let payload = encode_connect(stream_type, port, host);
        let packet = encode_packet_to_vec(PacketType::Connect, id, &payload);
        self.transport.send(packet).await?;

        Ok(StreamHandle {
            id,
            stream_type,
            inbound_rx,
            credit_notify,
        })
    }

    /// Send DATA on a stream. Awaits CONTINUE credit if exhausted (TCP only;
    /// UDP streams are credit-less per spec §"CONTINUE").
    ///
    /// # Errors
    ///
    /// - `UnknownStream` if the stream doesn't exist (or is closed while
    ///   waiting for credit).
    /// - `Transport` on I/O error.
    pub async fn send_data(&self, stream_id: u32, data: &[u8]) -> Result<(), MuxError> {
        loop {
            let notify = {
                let mut inner = self.inner.lock();
                let st = inner
                    .streams
                    .get_mut(&stream_id)
                    .ok_or(MuxError::UnknownStream(stream_id))?;
                match st.stream_type {
                    StreamType::Udp => {
                        // No credit tracking.
                        break;
                    }
                    StreamType::Tcp => {
                        if st.credit > 0 {
                            st.credit -= 1;
                            break;
                        }
                        // Credit is 0 — grab the notify to await outside the lock.
                        st.credit_notify.clone()
                    }
                }
            };
            // Wait for a CONTINUE (or CLOSE) to wake us, then retry the loop.
            notify.notified().await;
            // Loop retries: if credit is now > 0, we consume and break; if the
            // stream was closed, `get_mut` returns None and we surface UnknownStream.
        }
        let packet = encode_packet_to_vec(PacketType::Data, stream_id, data);
        self.transport.send(packet).await?;
        Ok(())
    }

    /// Send a CLOSE for a stream. Removes local stream state.
    ///
    /// # Errors
    ///
    /// - `Transport` on I/O error.
    pub async fn close_stream(&self, stream_id: u32, reason: CloseReason) -> Result<(), MuxError> {
        {
            let mut inner = self.inner.lock();
            inner.streams.remove(&stream_id);
        }
        let payload = encode_close(reason);
        let packet = encode_packet_to_vec(PacketType::Close, stream_id, &payload);
        self.transport.send(packet).await?;
        Ok(())
    }

    /// Handle a single inbound frame. Dispatches to per-stream inbound
    /// channels; may update credit; may remove closed streams.
    ///
    /// Callers typically loop this in a background task.
    ///
    /// # Errors
    ///
    /// - `Decode` on malformed frames.
    #[allow(clippy::unused_async)]
    pub async fn dispatch_inbound(&self, frame: Bytes) -> Result<(), MuxError> {
        let pkt = decode_packet_owned(frame)?;
        match pkt.packet_type {
            PacketType::Data => {
                let inbound_tx = {
                    let inner = self.inner.lock();
                    inner.streams.get(&pkt.stream_id).map(|s| s.inbound_tx.clone())
                };
                if let Some(tx) = inbound_tx {
                    let _ = tx.send(pkt.payload);
                }
            }
            PacketType::Continue => {
                if pkt.stream_id == HANDSHAKE_STREAM_ID {
                    return Ok(());
                }
                let credit = decode_continue(&pkt.payload)?;
                let notify = {
                    let mut inner = self.inner.lock();
                    if let Some(st) = inner.streams.get_mut(&pkt.stream_id) {
                        st.credit = credit;
                        Some(st.credit_notify.clone())
                    } else {
                        None
                    }
                };
                if let Some(n) = notify {
                    n.notify_waiters();
                }
            }
            PacketType::Close => {
                let notify = {
                    let mut inner = self.inner.lock();
                    let n = inner
                        .streams
                        .get(&pkt.stream_id)
                        .map(|s| s.credit_notify.clone());
                    inner.streams.remove(&pkt.stream_id);
                    n
                };
                if let Some(n) = notify {
                    n.notify_waiters();
                }
            }
            PacketType::Info | PacketType::Connect => {}
        }
        Ok(())
    }

    /// Test helper: is the handshake established?
    #[cfg(test)]
    #[must_use]
    pub fn is_established(&self) -> bool {
        matches!(
            self.inner.lock().handshake,
            HandshakeState::Established
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::frame::{encode_continue, encode_packet};
    use super::super::types::ExtensionId;
    use crate::transport::BoxFuture;
    use std::sync::Mutex;

    /// In-memory transport for tests. `sent[]` records outbound frames;
    /// `inbound` is a channel the test can push frames into.
    struct FakeTransport {
        sent: Mutex<Vec<Vec<u8>>>,
        inbound: flume::Receiver<Vec<u8>>,
    }

    struct FakeTransportPair {
        transport: Arc<FakeTransport>,
        server_tx: flume::Sender<Vec<u8>>,
    }

    fn make_transport() -> FakeTransportPair {
        let (server_tx, client_rx) = flume::unbounded();
        FakeTransportPair {
            transport: Arc::new(FakeTransport {
                sent: Mutex::new(Vec::new()),
                inbound: client_rx,
            }),
            server_tx,
        }
    }

    impl WispTransport for FakeTransport {
        fn send<'a>(&'a self, packet: Vec<u8>) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async move {
                self.sent.lock().expect("sent mutex poisoned").push(packet);
                Ok(())
            })
        }

        fn recv<'a>(&'a self) -> BoxFuture<'a, Result<Bytes, TransportError>> {
            Box::pin(async move {
                let vec = self
                    .inbound
                    .recv_async()
                    .await
                    .map_err(|_| TransportError::Closed)?;
                Ok(Bytes::from(vec))
            })
        }

        fn close<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async move { Ok(()) })
        }
    }

    #[tokio::test]
    async fn handshake_completes_with_valid_server_sequence() {
        let pair = make_transport();
        let mux = Mux::new(pair.transport.clone());

        // Server INFO.
        pair.server_tx
            .send(encode_packet_to_vec(
                PacketType::Info,
                HANDSHAKE_STREAM_ID,
                &encode_info(&[]),
            ))
            .unwrap();
        // Server CONTINUE with buffer size 128.
        pair.server_tx
            .send(encode_packet_to_vec(
                PacketType::Continue,
                HANDSHAKE_STREAM_ID,
                &encode_continue(128),
            ))
            .unwrap();

        mux.run_handshake(&[]).await.unwrap();
        assert!(mux.is_established());
    }

    #[tokio::test]
    async fn open_fails_before_handshake() {
        let pair = make_transport();
        let mux = Mux::new(pair.transport.clone());
        let err = mux.open("example.com", 80, StreamType::Tcp).await.unwrap_err();
        assert!(matches!(err, MuxError::Handshake(_)));
    }

    #[tokio::test]
    async fn open_after_handshake_sends_connect_and_returns_handle() {
        let pair = make_transport();
        let mux = Mux::new(pair.transport.clone());

        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Info, HANDSHAKE_STREAM_ID, &encode_info(&[])))
            .unwrap();
        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Continue, HANDSHAKE_STREAM_ID, &encode_continue(16)))
            .unwrap();
        mux.run_handshake(&[]).await.unwrap();

        let handle = mux.open("example.com", 443, StreamType::Tcp).await.unwrap();
        assert_eq!(handle.id, 1);
        assert_eq!(handle.stream_type, StreamType::Tcp);

        // Verify a CONNECT packet was sent by the mux.
        let sent = pair.transport.sent.lock().unwrap();
        assert_eq!(sent.len(), 2, "expected client INFO + CONNECT");
        let last = &sent[sent.len() - 1];
        let d = decode_packet(last).unwrap();
        assert_eq!(d.packet_type, PacketType::Connect);
        assert_eq!(d.stream_id, 1);
    }

    #[tokio::test]
    async fn send_data_decrements_credit_and_forwards() {
        let pair = make_transport();
        let mux = Arc::new(Mux::new(pair.transport.clone()));

        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Info, HANDSHAKE_STREAM_ID, &encode_info(&[])))
            .unwrap();
        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Continue, HANDSHAKE_STREAM_ID, &encode_continue(2)))
            .unwrap();
        mux.run_handshake(&[]).await.unwrap();

        let handle = mux.open("h", 1, StreamType::Tcp).await.unwrap();
        mux.send_data(handle.id, b"hi").await.unwrap();
        mux.send_data(handle.id, b"there").await.unwrap();

        // Third send should suspend until a CONTINUE arrives.
        let mux_clone = mux.clone();
        let stream_id = handle.id;
        let send_task = tokio::spawn(async move {
            mux_clone.send_data(stream_id, b"x").await
        });

        // Yield so the send task blocks on the notify.
        tokio::task::yield_now().await;
        assert!(!send_task.is_finished(), "expected send to be blocked awaiting credit");

        // Refill credit via a CONTINUE dispatch.
        mux.dispatch_inbound(encode_packet(
            PacketType::Continue,
            stream_id,
            &encode_continue(3),
        ))
        .await
        .unwrap();

        send_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn continue_from_server_refills_credit() {
        let pair = make_transport();
        let mux = Mux::new(pair.transport.clone());

        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Info, HANDSHAKE_STREAM_ID, &encode_info(&[])))
            .unwrap();
        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Continue, HANDSHAKE_STREAM_ID, &encode_continue(1)))
            .unwrap();
        mux.run_handshake(&[]).await.unwrap();

        let handle = mux.open("h", 1, StreamType::Tcp).await.unwrap();
        mux.send_data(handle.id, b"1").await.unwrap();

        // Server sends CONTINUE with credit=5 for the stream.
        let refill = encode_packet(PacketType::Continue, handle.id, &encode_continue(5));
        mux.dispatch_inbound(refill).await.unwrap();

        // Now five more sends should succeed.
        mux.send_data(handle.id, b"2").await.unwrap();
        mux.send_data(handle.id, b"3").await.unwrap();
        mux.send_data(handle.id, b"4").await.unwrap();
        mux.send_data(handle.id, b"5").await.unwrap();
        mux.send_data(handle.id, b"6").await.unwrap();
    }

    #[tokio::test]
    async fn inbound_data_reaches_stream_channel() {
        let pair = make_transport();
        let mux = Mux::new(pair.transport.clone());

        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Info, HANDSHAKE_STREAM_ID, &encode_info(&[])))
            .unwrap();
        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Continue, HANDSHAKE_STREAM_ID, &encode_continue(4)))
            .unwrap();
        mux.run_handshake(&[]).await.unwrap();

        let handle = mux.open("h", 1, StreamType::Tcp).await.unwrap();
        let inbound = encode_packet(PacketType::Data, handle.id, b"hello");
        mux.dispatch_inbound(inbound).await.unwrap();

        let received = handle.inbound_rx.recv_async().await.unwrap();
        assert_eq!(received.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn close_removes_stream_and_signals_eof() {
        let pair = make_transport();
        let mux = Mux::new(pair.transport.clone());

        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Info, HANDSHAKE_STREAM_ID, &encode_info(&[])))
            .unwrap();
        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Continue, HANDSHAKE_STREAM_ID, &encode_continue(4)))
            .unwrap();
        mux.run_handshake(&[]).await.unwrap();

        let handle = mux.open("h", 1, StreamType::Tcp).await.unwrap();
        let inbound = handle.inbound_rx.clone();

        // Server closes the stream.
        let close_pkt = encode_packet(
            PacketType::Close,
            handle.id,
            &encode_close(CloseReason::Voluntary),
        );
        mux.dispatch_inbound(close_pkt).await.unwrap();

        // The receiver should now report the channel closed.
        assert!(inbound.recv_async().await.is_err());
    }

    #[tokio::test]
    async fn udp_streams_do_not_track_credit() {
        let pair = make_transport();
        let mux = Mux::new(pair.transport.clone());

        pair.server_tx
            .send(encode_packet_to_vec(
                PacketType::Info,
                HANDSHAKE_STREAM_ID,
                &encode_info(&[ExtensionEntry::empty(ExtensionId::Udp)]),
            ))
            .unwrap();
        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Continue, HANDSHAKE_STREAM_ID, &encode_continue(0)))
            .unwrap();
        mux.run_handshake(&[]).await.unwrap();

        let handle = mux.open("h", 1, StreamType::Udp).await.unwrap();
        // With credit=0 but a UDP stream, we should still be allowed to send.
        for _ in 0..10 {
            mux.send_data(handle.id, b"udp").await.unwrap();
        }
    }
}

//! `WispStream` — a higher-level per-stream handle over the mux.
//!
//! Wraps a `StreamHandle` from `Mux::open` and provides ergonomic
//! `send` / `recv` / `close` methods. Backpressure is honored on send
//! (awaits a CONTINUE if credit is exhausted).

use std::sync::Arc;

use bytes::Bytes;

use super::mux::{Mux, MuxError, StreamHandle};
use super::types::{CloseReason, StreamType};

/// A per-stream handle. `send` awaits credit; `recv` awaits the next
/// inbound DATA packet or returns `None` on close.
pub struct WispStream {
    id: u32,
    stream_type: StreamType,
    mux: Arc<Mux>,
    inbound_rx: flume::Receiver<Bytes>,
    closed: bool,
}

impl WispStream {
    /// Wrap a `StreamHandle` (from `Mux::open`) into a `WispStream`.
    #[must_use]
    pub fn from_handle(mux: Arc<Mux>, handle: StreamHandle) -> Self {
        Self {
            id: handle.id,
            stream_type: handle.stream_type,
            mux,
            inbound_rx: handle.inbound_rx,
            closed: false,
        }
    }

    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[must_use]
    pub fn stream_type(&self) -> StreamType {
        self.stream_type
    }

    /// Send bytes on this stream. Awaits credit (TCP only) before writing.
    ///
    /// # Errors
    ///
    /// - Any `MuxError` from the underlying send path.
    /// - Fails immediately if the stream has already been closed locally.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), MuxError> {
        if self.closed {
            return Err(MuxError::UnknownStream(self.id));
        }
        self.mux.send_data(self.id, data).await
    }

    /// Await the next inbound frame. Returns `None` when the peer has
    /// closed the stream (channel is closed).
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.inbound_rx.recv_async().await.ok()
    }

    /// Try to receive without awaiting. Returns `None` if no frame is
    /// currently buffered.
    pub fn try_recv(&mut self) -> Option<Bytes> {
        self.inbound_rx.try_recv().ok()
    }

    /// Close the stream locally, sending a CLOSE packet to the peer.
    ///
    /// # Errors
    ///
    /// - `Transport` on I/O error.
    pub async fn close(mut self, reason: CloseReason) -> Result<(), MuxError> {
        if !self.closed {
            self.closed = true;
            self.mux.close_stream(self.id, reason).await?;
        }
        Ok(())
    }

    /// Access the mux `Arc` — for adapters that need to drive send futures
    /// (e.g. `WispStreamIo`, which owns pinned futures using `Arc<Mux>`).
    #[must_use]
    pub fn mux(&self) -> Arc<Mux> {
        self.mux.clone()
    }

    /// Access a clone of the inbound DATA receiver. Both ends of the
    /// underlying `flume` channel remain wired; cloning shares the
    /// receiving side. Used by `WispStreamIo` so it can drive its own
    /// `'static` recv future without borrowing `&self`.
    #[must_use]
    pub fn inbound_receiver(&self) -> flume::Receiver<Bytes> {
        self.inbound_rx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{BoxFuture, TransportError, WispTransport};
    use crate::wisp::frame::{
        decode_packet, encode_continue, encode_info, encode_packet, encode_packet_to_vec,
    };
    use crate::wisp::types::{PacketType, HANDSHAKE_STREAM_ID};
    use std::sync::Mutex;

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
                self.sent.lock().unwrap().push(packet);
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

    async fn make_established_mux() -> (FakeTransportPair, Arc<Mux>) {
        let pair = make_transport();
        let mux = Arc::new(Mux::new(pair.transport.clone()));
        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Info, HANDSHAKE_STREAM_ID, &encode_info(&[])))
            .unwrap();
        pair.server_tx
            .send(encode_packet_to_vec(PacketType::Continue, HANDSHAKE_STREAM_ID, &encode_continue(4)))
            .unwrap();
        mux.run_handshake(&[]).await.unwrap();
        (pair, mux)
    }

    #[tokio::test]
    async fn stream_send_and_recv_round_trip() {
        let (pair, mux) = make_established_mux().await;
        let handle = mux.open("h", 1, StreamType::Tcp).await.unwrap();
        let mut stream = WispStream::from_handle(mux.clone(), handle);

        stream.send(b"hello").await.unwrap();

        // Verify DATA packet reached the transport.
        let sent = pair.transport.sent.lock().unwrap();
        let last = sent.last().unwrap();
        let d = decode_packet(last).unwrap();
        assert_eq!(d.packet_type, PacketType::Data);
        assert_eq!(d.payload, b"hello");
        drop(sent);

        // Simulate server pushing a DATA packet at the stream.
        mux.dispatch_inbound(encode_packet(PacketType::Data, stream.id(), b"world"))
            .await
            .unwrap();

        let got = stream.recv().await.unwrap();
        assert_eq!(got.as_ref(), b"world");
    }

    #[tokio::test]
    async fn stream_recv_returns_none_on_close() {
        let (_pair, mux) = make_established_mux().await;
        let handle = mux.open("h", 1, StreamType::Tcp).await.unwrap();
        let mut stream = WispStream::from_handle(mux.clone(), handle);

        // Server closes the stream.
        mux.dispatch_inbound(encode_packet(
            PacketType::Close,
            stream.id(),
            &crate::wisp::frame::encode_close(CloseReason::Voluntary),
        ))
        .await
        .unwrap();

        assert!(stream.recv().await.is_none());
    }

    #[tokio::test]
    async fn stream_close_sends_close_packet() {
        let (pair, mux) = make_established_mux().await;
        let handle = mux.open("h", 1, StreamType::Tcp).await.unwrap();
        let stream = WispStream::from_handle(mux.clone(), handle);
        let id = stream.id();

        stream.close(CloseReason::Voluntary).await.unwrap();

        // Confirm a CLOSE packet was sent.
        let sent = pair.transport.sent.lock().unwrap();
        let last = sent.last().unwrap();
        let d = decode_packet(last).unwrap();
        assert_eq!(d.packet_type, PacketType::Close);
        assert_eq!(d.stream_id, id);
    }
}

//! In-memory paired transport for tests.
//!
//! `make_paired_transport()` returns a `PairedTransport`: the client-side
//! `WispTransport` impl (to be handed to a `Mux`), plus channels that the
//! server-side scripter (`MockWispServer`) uses to inject frames back to
//! the client and observe what the client sent.

use std::sync::Arc;

use bytes::Bytes;
use flume::{Receiver, Sender};
use drift_core::transport::{BoxFuture, TransportError, WispTransport};
use parking_lot::Mutex;

/// The client-side transport. Hand this (as `Arc<dyn WispTransport>`) to
/// a `Mux`.
pub struct ClientTransport {
    /// Frames the client has sent.
    sent: Mutex<Vec<Vec<u8>>>,
    /// Broadcast sender: every send fans out to `sent_tx_broadcast` and
    /// `sent` — so servers can await/react in tests.
    sent_tx: Sender<Vec<u8>>,
    /// Frames coming FROM the server TO the client (server → client push).
    inbound: Receiver<Vec<u8>>,
}

/// A paired transport handed back from `make_paired_transport`.
pub struct PairedTransport {
    /// Give this to `Mux::new` (or wherever expects `Arc<dyn WispTransport>`).
    pub client: Arc<ClientTransport>,
    /// Push frames here — they will be delivered to the client as inbound
    /// wisp packets.
    pub server_tx: Sender<Vec<u8>>,
    /// Observe frames the client has sent. Await for arrivals or
    /// `client_sent()`-style inspection via the server's accessor.
    pub server_rx: Receiver<Vec<u8>>,
}

/// Build a fresh pair.
#[must_use]
pub fn make_paired_transport() -> PairedTransport {
    // client -> server channel
    let (sent_tx, server_rx) = flume::unbounded();
    // server -> client channel
    let (server_tx, inbound) = flume::unbounded();
    PairedTransport {
        client: Arc::new(ClientTransport {
            sent: Mutex::new(Vec::new()),
            sent_tx,
            inbound,
        }),
        server_tx,
        server_rx,
    }
}

impl PairedTransport {
    /// Push a frame from the server to the client's recv stream.
    pub fn push_server_frame(&self, frame: Vec<u8>) {
        let _ = self.server_tx.send(frame);
    }
}

impl ClientTransport {
    /// Read all frames the client has sent so far. Cheap snapshot.
    #[must_use]
    pub fn snapshot_sent(&self) -> Vec<Vec<u8>> {
        self.sent.lock().clone()
    }
}

impl WispTransport for ClientTransport {
    fn send<'a>(&'a self, packet: Vec<u8>) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            self.sent.lock().push(packet.clone());
            let _ = self.sent_tx.send_async(packet).await;
            Ok(())
        })
    }

    fn recv<'a>(&'a self) -> BoxFuture<'a, Result<Bytes, TransportError>> {
        Box::pin(async move {
            let vec: Vec<u8> = self
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

    fn is_closed(&self) -> bool {
        // The paired transport is "closed" once the server has dropped
        // the sender for our inbound channel (`inbound`) and we can no
        // longer receive frames.
        self.inbound.is_disconnected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use drift_core::transport::WispTransport;

    #[tokio::test]
    async fn is_closed_reflects_server_drop() {
        let pair = make_paired_transport();
        assert!(!pair.client.is_closed());
        drop(pair.server_tx);
        // Once the server-tx (our inbound sender) is dropped, is_closed flips.
        assert!(pair.client.is_closed());
    }

    #[tokio::test]
    async fn snapshot_sent_captures_all_sends() {
        let pair = make_paired_transport();
        pair.client.send(b"one".to_vec()).await.unwrap();
        pair.client.send(b"two".to_vec()).await.unwrap();
        let sent = pair.client.snapshot_sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].as_slice(), b"one");
        assert_eq!(sent[1].as_slice(), b"two");
    }
}

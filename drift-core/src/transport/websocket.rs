//! Native WebSocket transport via `tokio-tungstenite`.
//!
//! WASM builds skip this file; see `message_port.rs` and a future
//! `websocket_wasm.rs` for WASM WebSocket support.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use tokio::sync::Mutex as AsyncMutex;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::MaybeTlsStream;

use super::{BoxFuture, TransportError, WispTransport};

type WsStream = tokio_tungstenite::WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Native WebSocket transport.
///
/// Splits the WebSocket into read/write halves internally so `send()` and
/// `recv()` can operate concurrently. Uses tokio `Mutex` for the halves
/// since real I/O sits behind them; a synchronous mutex would block the
/// runtime.
pub struct WebSocketTransport {
    write: AsyncMutex<futures_util::stream::SplitSink<WsStream, Message>>,
    read: AsyncMutex<futures_util::stream::SplitStream<WsStream>>,
    closed: Mutex<bool>,
}

impl WebSocketTransport {
    /// Connect to a wisp WebSocket URL.
    ///
    /// Sends the `wisp-v2` subprotocol per spec §"Establishing a Websocket
    /// Connection". The `Sec-WebSocket-Protocol` header must be present
    /// for v2; a v1 server will treat it as a v1 connection but this is
    /// negotiated during the wisp handshake, not here.
    ///
    /// # Errors
    ///
    /// - `TransportError::Handshake` on WebSocket upgrade failure.
    /// - `TransportError::Io` on TCP/TLS failure.
    pub async fn connect(url: &str) -> Result<Arc<Self>, TransportError> {
        // Do NOT advertise a Sec-WebSocket-Protocol subprotocol here. Real-
        // world wisp servers (Mercury Workshop, ampscat, wisp-server-node)
        // don't echo it back, which triggers tungstenite's RFC 6455 strict
        // check and fails the handshake. The wisp protocol autodetects v2
        // vs v1 via the initial INFO exchange (see MoonBeam's client at
        // src/wisp-client.ts:381-388 for the same reasoning).
        let request = url
            .into_client_request()
            .map_err(|e| TransportError::Handshake(format!("bad url: {e}")))?;

        let (ws, _resp) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(|e| TransportError::Handshake(format!("connect_async: {e}")))?;

        let (write, read) = ws.split();
        Ok(Arc::new(Self {
            write: AsyncMutex::new(write),
            read: AsyncMutex::new(read),
            closed: Mutex::new(false),
        }))
    }
}

impl WispTransport for WebSocketTransport {
    fn send(&self, packet: Vec<u8>) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            if *self.closed.lock() {
                return Err(TransportError::Closed);
            }
            let mut write = self.write.lock().await;
            write
                .send(Message::Binary(packet))
                .await
                .map_err(|e| TransportError::Io(format!("ws send: {e}")))
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Bytes, TransportError>> {
        Box::pin(async move {
            loop {
                if *self.closed.lock() {
                    return Err(TransportError::Closed);
                }
                let mut read = self.read.lock().await;
                let msg = match read.next().await {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => return Err(TransportError::Io(format!("ws recv: {e}"))),
                    None => {
                        *self.closed.lock() = true;
                        return Err(TransportError::Closed);
                    }
                };
                match msg {
                    Message::Binary(b) => return Ok(Bytes::from(b)),
                    Message::Close(_) => {
                        *self.closed.lock() = true;
                        return Err(TransportError::Closed);
                    }
                    // Text/ping/pong/frame are noise for wisp; keep polling.
                    Message::Text(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                }
            }
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            {
                let mut c = self.closed.lock();
                if *c {
                    return Ok(());
                }
                *c = true;
            }
            let mut write = self.write.lock().await;
            let _ = write
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "".into(),
                })))
                .await;
            let _ = write.close().await;
            Ok(())
        })
    }

    fn is_closed(&self) -> bool {
        *self.closed.lock()
    }
}

//! Transport abstraction for wisp packets.
//!
//! A `WispTransport` is a bidirectional, boundary-preserving byte channel.
//! Every `send(bytes)` results in exactly one framed message on the wire;
//! every `recv()` returns exactly one complete message. WebSockets fit
//! this shape naturally; MessagePort with `postMessage` does too.
//!
//! **Concurrency model:** implementations must be safe for one concurrent
//! `send` and one concurrent `recv`. Multiple concurrent `send`s or
//! multiple concurrent `recv`s are not required to work — the `Mux` calls
//! each direction from a single task.
//!
//! **Lifecycle:** `close()` is idempotent; calling it twice is a no-op.
//! After `close()` (or a peer-initiated close), `send` and `recv` return
//! `TransportError::Closed`.

use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use thiserror::Error;

/// Boxed future type used by the transport trait.
///
/// Explicit for now — Rust doesn't have async in traits without external
/// crates until 1.75+, and even then boxed futures give us the object
/// safety we need (`dyn WispTransport`).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Errors produced by a transport implementation.
///
/// These are surfaced to the `Mux`, which wraps them into `MuxError::Transport`.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The transport has been closed (locally or by the peer).
    #[error("transport closed")]
    Closed,

    /// The transport failed at the underlying I/O layer. String message
    /// preserves detail without coupling wisp-core to specific I/O libs.
    #[error("transport io error: {0}")]
    Io(String),

    /// A message we received was malformed at the framing layer (not at
    /// the wisp payload layer — that's the mux's problem).
    #[error("transport framing error: {0}")]
    Framing(String),

    /// The transport handshake failed (e.g. WebSocket upgrade rejected).
    #[error("transport handshake failed: {0}")]
    Handshake(String),
}

/// A wisp transport carries opaque byte frames in both directions.
///
/// Each `send`/`recv` corresponds to exactly one wisp packet — the mux
/// handles wisp-level framing internally; the transport just delivers
/// bytes in message-boundary-preserving fashion (matching WebSocket
/// semantics).
pub trait WispTransport: Send + Sync {
    /// Send a wisp packet as one boundary-preserving frame.
    ///
    /// Takes `Vec<u8>` to avoid an extra copy — the encoder already owns the
    /// buffer. Implementations should pass the vec directly to the I/O layer
    /// without copying.
    ///
    /// # Errors
    ///
    /// - `Closed` if the transport has been closed.
    /// - `Io` on underlying transport failure.
    fn send<'a>(&'a self, packet: Vec<u8>) -> BoxFuture<'a, Result<(), TransportError>>;

    /// Receive the next inbound wisp packet.
    ///
    /// # Errors
    ///
    /// - `Closed` if the transport is closed (peer or local).
    /// - `Io` / `Framing` on transport-layer trouble.
    fn recv<'a>(&'a self) -> BoxFuture<'a, Result<Bytes, TransportError>>;

    /// Signal end-of-transport. Idempotent.
    ///
    /// # Errors
    ///
    /// - `Io` on trouble sending the close frame. If the transport was
    ///   already closed, returns `Ok(())`.
    fn close<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>>;

    /// Cheap synchronous check: is the transport currently closed?
    ///
    /// Default returns `false`. Real implementations backed by a WebSocket
    /// or MessagePort should override to expose their `readyState`.
    fn is_closed(&self) -> bool {
        false
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub mod websocket;

#[cfg(not(target_arch = "wasm32"))]
pub use websocket::WebSocketTransport;

#[cfg(target_arch = "wasm32")]
pub mod websocket_wasm;

#[cfg(target_arch = "wasm32")]
pub use websocket_wasm::WebSocketWasmTransport;

#[cfg(target_arch = "wasm32")]
pub mod message_port;

#[cfg(target_arch = "wasm32")]
pub use message_port::MessagePortTransport;

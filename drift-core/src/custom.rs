//! Custom protocol registration.
//!
//! Users register a `CustomProtocol` implementation with `WispHandle` (or
//! the high-level `WispClient` in Phase 6). When Wisp opens a wisp stream
//! for that protocol, it drives the codec through `on_bytes_from_transport`
//! and `encode_message` calls, wrapping the result in a socket that
//! behaves like a WebSocket to consumers.

use bytes::Bytes;
use std::sync::Arc;

/// A message flowing between a consumer and a custom protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Bytes),
}

/// An event surfaced by a `CustomProtocol` codec as bytes arrive from
/// the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolEvent {
    Message(Message),
    Close { code: u16, reason: String },
    Error(String),
}

/// The custom-protocol codec trait.
///
/// Implementations are single-instance per registered scheme; Wisp
/// clones the `Arc<dyn CustomProtocol>` when it opens a stream for that
/// scheme. Implementations must be `Send + Sync` and internally
/// thread-safe if they hold mutable state — for most cases, wrap mutable
/// state in a `Mutex`.
pub trait CustomProtocol: Send + Sync {
    /// Handshake bytes to send after the transport connects.
    ///
    /// Called once, before any `on_bytes_from_transport`. May return
    /// empty bytes if the protocol has no client-first handshake.
    fn handshake(&self, url: &str) -> Bytes;

    /// Consume bytes received from the transport. May emit zero or more
    /// events.
    ///
    /// Called with each chunk that arrives. Implementations that need
    /// buffering across calls must keep internal state.
    fn on_bytes_from_transport(&self, buf: &[u8]) -> Vec<ProtocolEvent>;

    /// Encode a user message for the wire.
    fn encode_message(&self, msg: &Message) -> Bytes;

    /// Optional: on graceful close, emit final bytes to send to peer.
    /// Default returns empty (no close-time bytes).
    fn on_close(&self, _code: u16, _reason: &str) -> Bytes {
        Bytes::new()
    }
}

/// Registry mapping scheme names → protocol implementations.
///
/// Held inside `WispHandle` and (later) `WispClient`. Entries are added
/// via the builder; lookups happen when a URL with a registered scheme is
/// used.
#[derive(Default, Clone)]
pub struct CustomProtocolRegistry {
    entries: std::collections::HashMap<String, Arc<dyn CustomProtocol>>,
}

impl std::fmt::Debug for CustomProtocolRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomProtocolRegistry")
            .field("registered_schemes", &self.entries.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl CustomProtocolRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a protocol for a URL scheme (e.g. `"mqtt"`, `"nats"`).
    ///
    /// Overwrites any prior registration for the same scheme; returns the
    /// registry for builder-style chaining.
    pub fn register(&mut self, scheme: impl Into<String>, proto: Arc<dyn CustomProtocol>) -> &mut Self {
        self.entries.insert(scheme.into(), proto);
        self
    }

    /// Look up a registered protocol by scheme name.
    #[must_use]
    pub fn get(&self, scheme: &str) -> Option<Arc<dyn CustomProtocol>> {
        self.entries.get(scheme).cloned()
    }

    /// Iterate registered scheme names.
    pub fn schemes(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    /// A trivial protocol that echoes text messages verbatim, framed with
    /// a 4-byte little-endian length prefix.
    struct EchoLengthPrefixed {
        recv_buf: Mutex<Vec<u8>>,
    }

    impl EchoLengthPrefixed {
        fn new() -> Self {
            Self { recv_buf: Mutex::new(Vec::new()) }
        }
    }

    impl CustomProtocol for EchoLengthPrefixed {
        fn handshake(&self, _url: &str) -> Bytes {
            Bytes::new()
        }

        fn on_bytes_from_transport(&self, buf: &[u8]) -> Vec<ProtocolEvent> {
            let mut b = self.recv_buf.lock();
            b.extend_from_slice(buf);
            let mut out = Vec::new();
            loop {
                if b.len() < 4 {
                    break;
                }
                let len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                if b.len() < 4 + len {
                    break;
                }
                let payload = b.drain(..4 + len).collect::<Vec<u8>>();
                let msg_bytes = &payload[4..];
                match std::str::from_utf8(msg_bytes) {
                    Ok(s) => out.push(ProtocolEvent::Message(Message::Text(s.to_string()))),
                    Err(_) => out.push(ProtocolEvent::Message(Message::Binary(
                        Bytes::copy_from_slice(msg_bytes),
                    ))),
                }
            }
            out
        }

        fn encode_message(&self, msg: &Message) -> Bytes {
            let body: Bytes = match msg {
                Message::Text(s) => Bytes::from(s.clone().into_bytes()),
                Message::Binary(b) => b.clone(),
            };
            let mut out = Vec::with_capacity(4 + body.len());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
            Bytes::from(out)
        }
    }

    #[test]
    fn registry_empty_by_default() {
        let r = CustomProtocolRegistry::new();
        assert!(r.get("mqtt").is_none());
        assert_eq!(r.schemes().count(), 0);
    }

    #[test]
    fn register_and_lookup() {
        let mut r = CustomProtocolRegistry::new();
        r.register("echo", Arc::new(EchoLengthPrefixed::new()));
        assert!(r.get("echo").is_some());
        assert!(r.get("unknown").is_none());
    }

    #[test]
    fn overwrite_registration_by_scheme() {
        let mut r = CustomProtocolRegistry::new();
        let a = Arc::new(EchoLengthPrefixed::new());
        let b = Arc::new(EchoLengthPrefixed::new());
        r.register("echo", a);
        r.register("echo", b);
        assert_eq!(r.schemes().count(), 1);
    }

    #[test]
    fn echo_protocol_round_trip() {
        let p = EchoLengthPrefixed::new();
        let wire = p.encode_message(&Message::Text("hi".into()));
        let events = p.on_bytes_from_transport(&wire);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], ProtocolEvent::Message(Message::Text(s)) if s == "hi"));
    }

    #[test]
    fn echo_protocol_partial_frames() {
        let p = EchoLengthPrefixed::new();
        // Feed 2 bytes of a 4-byte length prefix; expect nothing.
        let evs = p.on_bytes_from_transport(&[3, 0]);
        assert!(evs.is_empty());
        // Feed the rest of the length + 2 bytes of the payload; still incomplete.
        let evs = p.on_bytes_from_transport(&[0, 0, b'h', b'i']);
        assert!(evs.is_empty());
        // Feed final byte -> one message emitted.
        let evs = p.on_bytes_from_transport(&[b'!']);
        assert_eq!(evs.len(), 1);
    }

    #[test]
    fn default_on_close_returns_empty() {
        let p = EchoLengthPrefixed::new();
        assert!(p.on_close(1000, "bye").is_empty());
    }
}

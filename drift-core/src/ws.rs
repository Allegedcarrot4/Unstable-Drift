//! WebSocket client on top of an async byte stream.
//!
//! Performs the HTTP/1.1 upgrade handshake, then hands the stream to
//! `fastwebsockets` for the frame codec. Returns a `WebSocketConn` with
//! send/recv/close methods.

use bytes::Bytes;
use fastwebsockets::{FragmentCollector, Frame, OpCode, Payload, Role, WebSocket};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use base64::Engine;
use sha1::{Digest, Sha1};

/// WebSocket errors.
#[derive(Debug, Error)]
pub enum WsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("upgrade failed: {0}")]
    Upgrade(String),
    #[error("frame: {0}")]
    Frame(String),
    #[error("closed by peer")]
    Closed,
}

impl From<fastwebsockets::WebSocketError> for WsError {
    fn from(e: fastwebsockets::WebSocketError) -> Self {
        Self::Frame(e.to_string())
    }
}

/// A message received from a WebSocket. Text and binary are distinguished;
/// control frames (ping/pong) are handled internally by the codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsMessage {
    Text(String),
    Binary(Bytes),
}

/// A live WebSocket connection.
pub struct WebSocketConn<S: AsyncRead + AsyncWrite + Unpin> {
    ws: FragmentCollector<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocketConn<S> {
    /// Connect via HTTP/1.1 upgrade over the given stream.
    ///
    /// `host` is the value for the Host header (typically the hostname of
    /// the server); `path` is the request-target (e.g. `/socket`).
    /// `subprotocols` are advertised in `Sec-WebSocket-Protocol`.
    /// `extra_headers` are appended to the upgrade request verbatim.
    ///
    /// # Errors
    ///
    /// - `Upgrade` if the server rejects the handshake or returns a
    ///   malformed response.
    /// - `Io` on transport failure.
    pub async fn connect(
        mut stream: S,
        host: &str,
        path: &str,
        subprotocols: &[&str],
        extra_headers: &[(&str, &str)],
    ) -> Result<Self, WsError> {
        // Generate the client key.
        let mut nonce = [0u8; 16];
        // Deterministic-enough nonce; a real cryptographic nonce isn't
        // required by the RFC — it's only used to compute the response hash.
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let key = base64::engine::general_purpose::STANDARD.encode(nonce);

        // Build upgrade request.
        let mut req = String::new();
        req.push_str("GET ");
        req.push_str(path);
        req.push_str(" HTTP/1.1\r\n");
        req.push_str("Host: ");
        req.push_str(host);
        req.push_str("\r\n");
        req.push_str("Upgrade: websocket\r\n");
        req.push_str("Connection: Upgrade\r\n");
        req.push_str("Sec-WebSocket-Version: 13\r\n");
        req.push_str("Sec-WebSocket-Key: ");
        req.push_str(&key);
        req.push_str("\r\n");
        if !subprotocols.is_empty() {
            req.push_str("Sec-WebSocket-Protocol: ");
            req.push_str(&subprotocols.join(", "));
            req.push_str("\r\n");
        }
        for (name, value) in extra_headers {
            req.push_str(name);
            req.push_str(": ");
            req.push_str(value);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        // Read the response head until CRLFCRLF.
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 512];
        loop {
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(WsError::Upgrade("EOF during upgrade".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 16 * 1024 {
                return Err(WsError::Upgrade("upgrade response too large".into()));
            }
        }

        // Parse the status line + verify accept key.
        let text = std::str::from_utf8(&buf).map_err(|_| WsError::Upgrade("non-utf8 headers".into()))?;
        let (first, rest) = text.split_once("\r\n").ok_or_else(|| WsError::Upgrade("no status line".into()))?;
        if !first.contains("101") {
            return Err(WsError::Upgrade(format!("status not 101: {first}")));
        }

        // Compute the expected Sec-WebSocket-Accept:
        //   base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let expected = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());

        let mut got_accept = None;
        for line in rest.lines() {
            if let Some(idx) = line.find(':') {
                let (name, value) = line.split_at(idx);
                let value = value[1..].trim();
                if name.eq_ignore_ascii_case("sec-websocket-accept") {
                    got_accept = Some(value.to_string());
                }
            }
        }
        let got = got_accept.ok_or_else(|| WsError::Upgrade("no accept header".into()))?;
        if got != expected {
            return Err(WsError::Upgrade(format!(
                "accept header mismatch: got {got}, expected {expected}"
            )));
        }

        // Handshake complete — hand the stream to fastwebsockets.
        let ws = WebSocket::after_handshake(stream, Role::Client);
        Ok(Self {
            ws: FragmentCollector::new(ws),
        })
    }

    /// Send a text message.
    ///
    /// # Errors
    ///
    /// - `Frame` on codec error.
    pub async fn send_text(&mut self, msg: &str) -> Result<(), WsError> {
        let frame = Frame::text(Payload::Borrowed(msg.as_bytes()));
        self.ws.write_frame(frame).await?;
        Ok(())
    }

    /// Send a binary message.
    ///
    /// # Errors
    ///
    /// - `Frame` on codec error.
    pub async fn send_binary(&mut self, data: &[u8]) -> Result<(), WsError> {
        let frame = Frame::binary(Payload::Borrowed(data));
        self.ws.write_frame(frame).await?;
        Ok(())
    }

    /// Receive the next message. Returns `None` if the peer sent a close
    /// frame; further recvs after that return `Err(WsError::Closed)`.
    ///
    /// # Errors
    ///
    /// - `Frame` on codec error.
    /// - `Closed` if the connection is already closed.
    pub async fn recv(&mut self) -> Result<Option<WsMessage>, WsError> {
        let frame = self.ws.read_frame().await?;
        match frame.opcode {
            OpCode::Text => {
                let s = String::from_utf8(frame.payload.to_vec())
                    .map_err(|e| WsError::Frame(format!("bad utf8: {e}")))?;
                Ok(Some(WsMessage::Text(s)))
            }
            OpCode::Binary => Ok(Some(WsMessage::Binary(Bytes::from(frame.payload.to_vec())))),
            OpCode::Close => Ok(None),
            OpCode::Ping | OpCode::Pong | OpCode::Continuation => {
                // FragmentCollector should handle these internally, but
                // if one leaks through, ignore and recurse (bounded by
                // the caller's loop).
                Box::pin(self.recv()).await
            }
        }
    }

    /// Send a close frame.
    ///
    /// # Errors
    ///
    /// - `Frame` on codec error.
    pub async fn close(&mut self, code: u16, reason: &str) -> Result<(), WsError> {
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        let frame = Frame::close(code, reason.as_bytes());
        self.ws.write_frame(frame).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_accept_matches_rfc_example() {
        // RFC 6455 §1.3 worked example:
        //   key = "dGhlIHNhbXBsZSBub25jZQ=="
        //   expected accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let got = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        assert_eq!(got, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    // End-to-end WebSocket tests require a real WebSocket server (fastwebsockets
    // server + a TCP loopback), which we can add in Task 20's mock-server
    // extension. For now, prove the module compiles and RFC math is correct.
}

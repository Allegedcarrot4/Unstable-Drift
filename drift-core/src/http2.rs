//! HTTP/2 client on top of an async byte stream.
//!
//! Uses the `h2` crate (patched via workspace `[patch.crates-io]` to
//! Mercury Workshop's `h2-wasm` fork for WASM compatibility) to speak
//! HTTP/2 over a TLS-wrapped `WispStream`.
//!
//! Feature-gated: `wisp-core` is built with `default-features = ["http2"]`.
//! Consumers who want HTTP/1-only can build with `--no-default-features`.

#![cfg(feature = "http2")]

use bytes::Bytes;
use http::{Request, Response, Version};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

/// HTTP/2 client errors.
#[derive(Debug, Error)]
pub enum Http2Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("h2 protocol error: {0}")]
    Protocol(String),
    #[error("h2 handshake failed: {0}")]
    Handshake(String),
    #[error("response body: {0}")]
    Body(String),
    #[error("response exceeded max size")]
    ResponseTooLarge,
    #[error("http type conversion: {0}")]
    Http(String),
}

impl From<h2::Error> for Http2Error {
    fn from(e: h2::Error) -> Self {
        Self::Protocol(e.to_string())
    }
}

/// Send a single HTTP/2 request over an already-established byte stream
/// (typically TLS-wrapped) and read the full response.
///
/// The stream must already be TLS-negotiated with ALPN `h2` — that's the
/// caller's responsibility. This function performs only the h2 handshake
/// and one request/response.
///
/// # Errors
///
/// See `Http2Error` variants.
pub async fn send_request<S>(
    stream: S,
    req: Request<Bytes>,
    max_response_bytes: Option<u64>,
) -> Result<Response<Bytes>, Http2Error>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (h2, conn) = h2::client::handshake(stream)
        .await
        .map_err(|e| Http2Error::Handshake(e.to_string()))?;

    // Drive the connection concurrently with our request work by racing it
    // against the request future via `futures::future::select`. We avoid
    // `tokio::spawn` because wisp-core's tokio isn't built with the `rt`
    // feature (it must build on wasm32 where multi-thread rt is unavailable).
    // The connection future returns when the connection ends; while we're
    // doing work we `select` it against each await point.
    futures::pin_mut!(conn);

    let mut client = {
        let ready = h2.ready();
        futures::pin_mut!(ready);
        match futures::future::select(ready, conn.as_mut()).await {
            futures::future::Either::Left((res, _)) => {
                res.map_err(|e| Http2Error::Handshake(e.to_string()))?
            }
            futures::future::Either::Right((res, _)) => {
                res.map_err(|e| Http2Error::Handshake(e.to_string()))?;
                return Err(Http2Error::Handshake(
                    "connection closed before ready".into(),
                ));
            }
        }
    };

    // Split the body out of the request; h2 takes headers + body separately.
    let (parts, body_bytes) = req.into_parts();
    let mut hreq = Request::builder()
        .method(parts.method)
        .uri(parts.uri)
        .version(Version::HTTP_2);
    // Move the header map onto the builder.
    if let Some(hs) = hreq.headers_mut() {
        *hs = parts.headers;
    }
    let hreq = hreq
        .body(())
        .map_err(|e| Http2Error::Http(e.to_string()))?;

    let (response_fut, mut send_body) = client
        .send_request(hreq, body_bytes.is_empty())
        .map_err(Http2Error::from)?;

    if !body_bytes.is_empty() {
        send_body
            .send_data(body_bytes, true)
            .map_err(Http2Error::from)?;
    }

    let resp = {
        futures::pin_mut!(response_fut);
        match futures::future::select(response_fut, conn.as_mut()).await {
            futures::future::Either::Left((res, _)) => res.map_err(Http2Error::from)?,
            futures::future::Either::Right((res, _)) => {
                res.map_err(|e| Http2Error::Protocol(e.to_string()))?;
                return Err(Http2Error::Protocol(
                    "connection closed before response".into(),
                ));
            }
        }
    };
    let (parts, mut body) = resp.into_parts();

    // Drain the body, racing each read against the connection driver.
    let mut out = Vec::new();
    loop {
        let chunk_opt = {
            let next = body.data();
            futures::pin_mut!(next);
            match futures::future::select(next, conn.as_mut()).await {
                futures::future::Either::Left((c, _)) => c,
                futures::future::Either::Right((res, _)) => {
                    res.map_err(|e| Http2Error::Protocol(e.to_string()))?;
                    // Connection ended cleanly; treat as end of body.
                    None
                }
            }
        };
        let Some(chunk) = chunk_opt else { break };
        let chunk = chunk.map_err(Http2Error::from)?;
        if let Some(max) = max_response_bytes {
            if (out.len() as u64) + (chunk.len() as u64) > max {
                return Err(Http2Error::ResponseTooLarge);
            }
        }
        out.extend_from_slice(&chunk);
        // h2 flow-control: release the received bytes back to the peer.
        let _ = body.flow_control().release_capacity(chunk.len());
    }

    // Consume trailers if present (not exposed on the returned Response).
    let _ = body.trailers().await;

    // Drop the client so the connection can shut down.
    drop(client);

    // Decompress body if Content-Encoding is present.
    let enc = parts
        .headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok());
    let decoded = crate::compression::decode_body(&out, enc)
        .await
        .map_err(|e| Http2Error::Body(e.to_string()))?;

    let mut response = Response::builder()
        .status(parts.status)
        .version(Version::HTTP_2);
    if let Some(hs) = response.headers_mut() {
        *hs = parts.headers;
    }
    let response = response
        .body(decoded)
        .map_err(|e| Http2Error::Http(e.to_string()))?;

    Ok(response)
}

#[cfg(test)]
mod tests {
    // Meaningful HTTP/2 tests require a real HTTP/2 server (either a hyper
    // server bound to a local port or an h2::server::handshake pair). Both
    // are substantial to set up and add flakiness to CI. For Phase 4 we
    // ship the client and cover it via the Task 20 end-to-end tests once
    // a mock server exists in wisp-test-support (Task 20 addition).
    //
    // For now: prove the module compiles by exercising a type-level check.

    #[test]
    fn error_variants_compile() {
        let _ = super::Http2Error::Body("x".into());
        let _ = super::Http2Error::Protocol("x".into());
    }
}

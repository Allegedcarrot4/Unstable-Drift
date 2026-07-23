//! Response body decompression (gzip, brotli).
//!
//! `decode_body(body_bytes, encoding)` returns the decoded bytes for one
//! of the supported encodings, or an error for anything else. Used by
//! http1 and http2 modules to decode `Content-Encoding` responses.
//!
//! Streaming decode is not exposed here in Phase 4 — bodies are already
//! buffered before this runs. A follow-up phase may add stream-decoding
//! if response sizes push memory pressure.

use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder};
use bytes::Bytes;
use thiserror::Error;
use tokio::io::{AsyncReadExt, BufReader};

use crate::options::Compression;

/// Compression errors.
#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported encoding: {0}")]
    Unsupported(String),
}

/// Decode a buffered response body according to its `Content-Encoding`.
///
/// The `header_value` is the value of the `Content-Encoding` HTTP header
/// (e.g. `"gzip"`, `"br"`, `"identity"`, or missing → passthrough).
///
/// # Errors
///
/// - `Io` on stream error.
/// - `Unsupported` for encodings we don't handle (deflate, compress, etc.).
pub async fn decode_body(
    body: &[u8],
    header_value: Option<&str>,
) -> Result<Bytes, CompressionError> {
    let Some(v) = header_value else {
        return Ok(Bytes::copy_from_slice(body));
    };
    let v = v.trim().to_lowercase();
    if v.is_empty() || v == "identity" {
        return Ok(Bytes::copy_from_slice(body));
    }

    match v.as_str() {
        "gzip" | "x-gzip" => {
            let mut decoder = GzipDecoder::new(BufReader::new(body));
            let mut out = Vec::with_capacity(body.len() * 2);
            decoder.read_to_end(&mut out).await?;
            Ok(Bytes::from(out))
        }
        "br" => {
            let mut decoder = BrotliDecoder::new(BufReader::new(body));
            let mut out = Vec::with_capacity(body.len() * 2);
            decoder.read_to_end(&mut out).await?;
            Ok(Bytes::from(out))
        }
        other => Err(CompressionError::Unsupported(other.to_string())),
    }
}

/// Which encodings to advertise in an outgoing `Accept-Encoding` header,
/// per user's `Compression` option.
///
/// Returns None if compression is disabled (`Compression::None`); otherwise
/// a comma-separated header value.
#[must_use]
pub fn accept_encoding_header(mode: Compression) -> Option<&'static str> {
    match mode {
        Compression::None => None,
        Compression::Gzip => Some("gzip"),
        Compression::Brotli => Some("br"),
        Compression::Auto => Some("br, gzip"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_compression::tokio::write::{BrotliEncoder, GzipEncoder};
    use tokio::io::AsyncWriteExt;

    async fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut enc = GzipEncoder::new(&mut out);
        enc.write_all(payload).await.unwrap();
        enc.shutdown().await.unwrap();
        out
    }

    async fn brotli(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut enc = BrotliEncoder::new(&mut out);
        enc.write_all(payload).await.unwrap();
        enc.shutdown().await.unwrap();
        out
    }

    #[tokio::test]
    async fn identity_passthrough() {
        let out = decode_body(b"hello", Some("identity")).await.unwrap();
        assert_eq!(out.as_ref(), b"hello");

        let out = decode_body(b"hello", None).await.unwrap();
        assert_eq!(out.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn gzip_round_trip() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        let encoded = gzip(payload).await;
        let decoded = decode_body(&encoded, Some("gzip")).await.unwrap();
        assert_eq!(decoded.as_ref(), payload);
    }

    #[tokio::test]
    async fn brotli_round_trip() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        let encoded = brotli(payload).await;
        let decoded = decode_body(&encoded, Some("br")).await.unwrap();
        assert_eq!(decoded.as_ref(), payload);
    }

    #[tokio::test]
    async fn unsupported_encoding_errors() {
        let err = decode_body(b"data", Some("deflate")).await.unwrap_err();
        assert!(matches!(err, CompressionError::Unsupported(_)));
    }

    #[test]
    fn accept_encoding_matches_mode() {
        assert_eq!(accept_encoding_header(Compression::None), None);
        assert_eq!(accept_encoding_header(Compression::Gzip), Some("gzip"));
        assert_eq!(accept_encoding_header(Compression::Brotli), Some("br"));
        assert_eq!(accept_encoding_header(Compression::Auto), Some("br, gzip"));
    }

    #[tokio::test]
    async fn case_insensitive_encoding_names() {
        let payload = b"hello";
        let encoded = gzip(payload).await;
        let decoded = decode_body(&encoded, Some("GZIP")).await.unwrap();
        assert_eq!(decoded.as_ref(), payload);
    }
}

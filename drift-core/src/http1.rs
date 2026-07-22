//! HTTP/1.1 client on top of an async byte stream.
//!
//! Encodes requests, parses responses via `httparse`, handles chunked and
//! content-length response bodies. Not a full HTTP client — no cookie jar,
//! no redirect following, no connection pooling here. Those live in the
//! high-level `wisp` crate (Phase 6).

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// HTTP/1.1 errors returned from `send_request`.
#[derive(Debug, Error)]
pub enum Http1Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed status line or headers")]
    ParseHeaders,
    #[error("parse: {0}")]
    Parse(String),
    #[error("bad header name or value: {0}")]
    BadHeader(String),
    #[error("chunked transfer decoding failed: {0}")]
    Chunked(String),
    #[error("unsupported transfer encoding: {0}")]
    UnsupportedTransferEncoding(String),
    #[error("response exceeded max size")]
    ResponseTooLarge,
}

/// A minimal HTTP/1.1 request. Body is buffered — chunked-request-encoding
/// isn't necessary for wisp-tunneled clients since we always know sizes.
#[derive(Debug, Clone)]
pub struct Http1Request {
    pub method: Method,
    /// Path + query, e.g. `/foo?bar=1`. NOT the full URL.
    pub path: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// A parsed HTTP/1.1 response with a buffered body.
#[derive(Debug, Clone)]
pub struct Http1Response {
    pub version: Version,
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// Send an HTTP/1.1 request on the given stream and read the full response.
///
/// `max_response_bytes` bounds the accepted response body size; a stream
/// that exceeds it errors out (fail-safe on malicious/broken origins).
///
/// # Errors
///
/// See `Http1Error` variants.
pub async fn send_request<S>(
    stream: &mut S,
    req: &Http1Request,
    max_response_bytes: Option<u64>,
) -> Result<Http1Response, Http1Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ---- Write the request ----
    let wire = encode_request(req)?;
    stream.write_all(&wire).await?;
    stream.flush().await?;

    // ---- Read status + headers ----
    let mut buf: Vec<u8> = Vec::with_capacity(32768);
    let header_end = read_until_headers_end(stream, &mut buf).await?;

    let (version, status, headers) = parse_response_head(&buf[..header_end])?;

    // ---- Read the body ----
    let body = read_body(stream, &headers, &buf[header_end..], max_response_bytes).await?;

    Ok(Http1Response {
        version,
        status,
        headers,
        body,
    })
}

/// Encode a request into wire bytes.
fn encode_request(req: &Http1Request) -> Result<Vec<u8>, Http1Error> {
    let mut out = Vec::with_capacity(256 + req.body.len());
    out.extend_from_slice(req.method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(req.path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");

    // Ensure Host header is present — caller's responsibility to include it.
    for (name, value) in req.headers.iter() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    // If we have a body and no Content-Length header, add one.
    let has_cl = req.headers.contains_key("content-length");
    let has_te = req.headers.contains_key("transfer-encoding");
    if !req.body.is_empty() && !has_cl && !has_te {
        let cl = req.body.len().to_string();
        out.extend_from_slice(b"Content-Length: ");
        out.extend_from_slice(cl.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(b"\r\n");
    if !req.body.is_empty() {
        out.extend_from_slice(&req.body);
    }
    Ok(out)
}

/// Read from `stream` into `buf` until we see `\r\n\r\n`. Returns the index
/// (exclusive) where headers end — the byte AFTER the trailing `\n`.
async fn read_until_headers_end<S>(stream: &mut S, buf: &mut Vec<u8>) -> Result<usize, Http1Error>
where
    S: AsyncRead + Unpin,
{
    let mut tmp = [0u8; 32768];
    loop {
        if let Some(idx) = find_headers_end(buf) {
            return Ok(idx);
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(Http1Error::ParseHeaders);
        }
        buf.extend_from_slice(&tmp[..n]);
        // Guard against garbage streams sending unbounded headers.
        if buf.len() > 1024 * 1024 {
            return Err(Http1Error::ParseHeaders);
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    // Look for the CRLFCRLF sequence.
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse an HTTP/1.1 response head (status line + headers) using httparse.
fn parse_response_head(head: &[u8]) -> Result<(Version, StatusCode, HeaderMap), Http1Error> {
    let mut header_storage = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut header_storage);
    match resp.parse(head).map_err(|e| Http1Error::Parse(e.to_string()))? {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return Err(Http1Error::ParseHeaders),
    }

    let version = match resp.version {
        Some(1) => Version::HTTP_11,
        Some(0) => Version::HTTP_10,
        _ => Version::HTTP_11,
    };
    let code = resp.code.ok_or(Http1Error::ParseHeaders)?;
    let status = StatusCode::from_u16(code).map_err(|e| Http1Error::Parse(e.to_string()))?;

    let mut headers = HeaderMap::with_capacity(resp.headers.len());
    for h in resp.headers.iter() {
        let name = HeaderName::from_bytes(h.name.as_bytes())
            .map_err(|e| Http1Error::BadHeader(format!("name {:?}: {e}", h.name)))?;
        let value = HeaderValue::from_bytes(h.value)
            .map_err(|e| Http1Error::BadHeader(format!("value: {e}")))?;
        headers.append(name, value);
    }
    Ok((version, status, headers))
}

/// Read the response body according to the headers.
async fn read_body<S>(
    stream: &mut S,
    headers: &HeaderMap,
    prefix: &[u8],
    max_bytes: Option<u64>,
) -> Result<Bytes, Http1Error>
where
    S: AsyncRead + Unpin,
{
    // 1. transfer-encoding: chunked?
    if let Some(te) = headers.get("transfer-encoding") {
        let val = te.to_str().unwrap_or("").to_lowercase();
        if val.contains("chunked") {
            return read_chunked_body(stream, prefix, max_bytes).await;
        } else {
            return Err(Http1Error::UnsupportedTransferEncoding(val));
        }
    }

    // 2. content-length?
    if let Some(cl) = headers.get("content-length") {
        let n: u64 = cl
            .to_str()
            .unwrap_or("")
            .parse()
            .map_err(|_| Http1Error::Parse("bad content-length".into()))?;
        if let Some(max) = max_bytes {
            if n > max {
                return Err(Http1Error::ResponseTooLarge);
            }
        }
        return read_exact_body(stream, prefix, n as usize).await;
    }

    // 3. close-delimited (read to EOF).
    let mut out = Vec::with_capacity(prefix.len() + 65536);
    out.extend_from_slice(prefix);
    let mut tmp = [0u8; 65536];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        if let Some(max) = max_bytes {
            if (out.len() as u64) + (n as u64) > max {
                return Err(Http1Error::ResponseTooLarge);
            }
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(Bytes::from(out))
}

/// Read exactly `n` bytes for the body, starting with any bytes already
/// buffered in `prefix`.
async fn read_exact_body<S>(
    stream: &mut S,
    prefix: &[u8],
    n: usize,
) -> Result<Bytes, Http1Error>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::with_capacity(n);
    let take = prefix.len().min(n);
    out.extend_from_slice(&prefix[..take]);
    while out.len() < n {
        let mut tmp = vec![0u8; (n - out.len()).min(65536)];
        let rd = stream.read(&mut tmp).await?;
        if rd == 0 {
            return Err(Http1Error::ParseHeaders); // truncated
        }
        out.extend_from_slice(&tmp[..rd]);
    }
    Ok(Bytes::from(out))
}

/// Decode a chunked body.
async fn read_chunked_body<S>(
    stream: &mut S,
    prefix: &[u8],
    max_bytes: Option<u64>,
) -> Result<Bytes, Http1Error>
where
    S: AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::from(prefix);
    let mut out: Vec<u8> = Vec::new();

    loop {
        // Ensure we have a complete size line: read until CRLF.
        let size_end = loop {
            if let Some(p) = find_crlf(&buf) {
                break p;
            }
            let mut tmp = [0u8; 32768];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(Http1Error::Chunked("EOF before size line".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
        };
        let size_line = &buf[..size_end];
        // Strip any chunk extensions after ';'.
        let size_str = std::str::from_utf8(size_line)
            .map_err(|_| Http1Error::Chunked("non-utf8 size line".into()))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| Http1Error::Chunked(format!("bad size hex: {size_str}")))?;
        // Consume the size line + CRLF.
        buf.drain(..size_end + 2);

        if size == 0 {
            // Consume the trailing CRLF (or trailers + CRLF).
            // Simplified: read until CRLF that closes the trailers/empty.
            loop {
                if let Some(p) = find_crlf(&buf) {
                    if p == 0 {
                        buf.drain(..2);
                        return Ok(Bytes::from(out));
                    }
                    // Skip trailer line.
                    buf.drain(..p + 2);
                } else {
                    let mut tmp = [0u8; 4096];
                    let n = stream.read(&mut tmp).await?;
                    if n == 0 {
                        return Ok(Bytes::from(out));
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
            }
        }

        // Ensure we have `size` body bytes + 2 for the trailing CRLF.
        while buf.len() < size + 2 {
            let mut tmp = vec![0u8; (size + 2 - buf.len()).min(65536)];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(Http1Error::Chunked("EOF in chunk body".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        if let Some(max) = max_bytes {
            if (out.len() as u64) + (size as u64) > max {
                return Err(Http1Error::ResponseTooLarge);
            }
        }
        out.extend_from_slice(&buf[..size]);
        // Drop the chunk body + CRLF.
        buf.drain(..size + 2);
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;



    #[test]
    fn encode_request_simple_get() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        let req = Http1Request {
            method: Method::GET,
            path: "/hello".into(),
            headers,
            body: Bytes::new(),
        };
        let wire = encode_request(&req).unwrap();
        let text = std::str::from_utf8(&wire).unwrap();
        assert!(text.starts_with("GET /hello HTTP/1.1\r\n"));
        assert!(text.contains("host: example.com\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn encode_request_adds_content_length_when_body_present() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("x"));
        let req = Http1Request {
            method: Method::POST,
            path: "/".into(),
            headers,
            body: Bytes::from_static(b"hello"),
        };
        let wire = encode_request(&req).unwrap();
        let text = std::str::from_utf8(&wire).unwrap();
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.ends_with("\r\nhello"));
    }

    #[test]
    fn parse_response_head_ok() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n";
        let (v, s, h) = parse_response_head(head).unwrap();
        assert_eq!(v, Version::HTTP_11);
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h.get("content-length").unwrap(), "3");
    }

    #[test]
    fn parse_response_head_bad_partial() {
        let head = b"HTTP/1.1 200 O";
        let err = parse_response_head(head).unwrap_err();
        assert!(matches!(err, Http1Error::ParseHeaders));
    }

    #[tokio::test]
    async fn send_request_reads_content_length_body() {
        let (client_side, mut server_side) = duplex(4096);
        let mut client = client_side;

        // Server task: read the request, then write a canned response.
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            // read anything (we don't validate the request bytes exhaustively here)
            let _ = server_side.read(&mut buf).await.unwrap();
            server_side
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
        });

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        let req = Http1Request {
            method: Method::GET,
            path: "/".into(),
            headers,
            body: Bytes::new(),
        };
        let resp = send_request(&mut client, &req, None).await.unwrap();
        server.await.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn send_request_reads_chunked_body() {
        let (client_side, mut server_side) = duplex(4096);
        let mut client = client_side;
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let _ = server_side.read(&mut buf).await.unwrap();
            server_side
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                      5\r\nhello\r\n\
                      6\r\n world\r\n\
                      0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        let req = Http1Request {
            method: Method::GET,
            path: "/".into(),
            headers,
            body: Bytes::new(),
        };
        let resp = send_request(&mut client, &req, None).await.unwrap();
        server.await.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"hello world");
    }

    #[tokio::test]
    async fn send_request_respects_max_response_bytes() {
        let (client_side, mut server_side) = duplex(4096);
        let mut client = client_side;
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let _ = server_side.read(&mut buf).await.unwrap();
            server_side
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                .await
                .unwrap();
        });
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        let req = Http1Request {
            method: Method::GET,
            path: "/".into(),
            headers,
            body: Bytes::new(),
        };
        let err = send_request(&mut client, &req, Some(10)).await.unwrap_err();
        server.await.unwrap();
        assert!(matches!(err, Http1Error::ResponseTooLarge));
    }


}

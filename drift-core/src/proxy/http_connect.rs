//! HTTP CONNECT proxy client.
//!
//! `CONNECT host:port HTTP/1.1` → expect `HTTP/1.1 200 OK` → tunnel is
//! established. Auth (Basic) is supported via `Proxy-Authorization`
//! headers computed here.

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{ProxyAuth, ProxyError};

/// Perform an HTTP CONNECT negotiation.
///
/// # Errors
///
/// - `Protocol` on malformed status line.
/// - `Refused` if the server returns a non-2xx status.
pub async fn negotiate_http_connect<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    auth: Option<&ProxyAuth>,
) -> Result<(), ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = String::new();
    req.push_str(&format!("CONNECT {host}:{port} HTTP/1.1\r\n"));
    req.push_str(&format!("Host: {host}:{port}\r\n"));
    req.push_str("Proxy-Connection: keep-alive\r\n");
    if let Some(ProxyAuth::UserPassword { user, pass }) = auth {
        let credentials = format!("{user}:{pass}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // Read status line + headers until \r\n\r\n.
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 256];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(ProxyError::Protocol("EOF during CONNECT reply".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 16 * 1024 {
            return Err(ProxyError::Protocol("CONNECT reply too large".into()));
        }
    }
    let text = std::str::from_utf8(&buf).map_err(|_| ProxyError::Protocol("non-utf8".into()))?;
    let first_line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| ProxyError::Protocol("no status line".into()))?;
    // "HTTP/x.y CODE REASON"
    let mut parts = first_line.split_whitespace();
    let _version = parts.next().ok_or_else(|| ProxyError::Protocol("no version".into()))?;
    let code_str = parts.next().ok_or_else(|| ProxyError::Protocol("no status code".into()))?;
    let code: u16 = code_str.parse().map_err(|_| ProxyError::Protocol("bad status code".into()))?;
    if !(200..300).contains(&code) {
        return Err(ProxyError::Refused(format!("HTTP {code}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn http_connect_happy_path() {
        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let n = server.read(&mut buf).await.unwrap();
            let s = std::str::from_utf8(&buf[..n]).unwrap();
            assert!(s.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(s.contains("Host: example.com:443"));
            server
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });
        negotiate_http_connect(&mut client, "example.com", 443, None)
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_basic_auth() {
        let (mut client, mut server) = duplex(4096);
        let auth = ProxyAuth::UserPassword {
            user: "alice".into(),
            pass: "s3cret".into(),
        };
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let n = server.read(&mut buf).await.unwrap();
            let s = std::str::from_utf8(&buf[..n]).unwrap();
            // alice:s3cret -> YWxpY2U6czNjcmV0
            assert!(s.contains("Proxy-Authorization: Basic YWxpY2U6czNjcmV0"));
            server.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });
        negotiate_http_connect(&mut client, "example.com", 443, Some(&auth))
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_407_returned_as_refused() {
        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let err = negotiate_http_connect(&mut client, "example.com", 443, None)
            .await
            .unwrap_err();
        server_task.await.unwrap();
        assert!(matches!(err, ProxyError::Refused(_)));
    }
}

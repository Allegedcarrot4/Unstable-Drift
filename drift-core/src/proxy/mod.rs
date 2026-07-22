//! Proxy client implementations for SOCKS4/4a/5 and HTTP CONNECT, plus
//! chain composition.

pub mod http_connect;
pub mod socks4;
pub mod socks5;

use tokio::io::{AsyncRead, AsyncWrite};

pub use http_connect::negotiate_http_connect;
pub use socks4::{negotiate_socks4, Socks4Variant};
pub use socks5::negotiate_socks5;

/// Auth material for a proxy hop.
#[derive(Debug, Clone)]
pub enum ProxyAuth {
    UserPassword { user: String, pass: String },
}

/// Errors from proxy negotiation.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("proxy refused: {0}")]
    Refused(String),
    #[error("auth failed")]
    AuthFailed,
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// A single proxy hop in a chain.
///
/// Mirrors the spec's `Proxy` struct (§9.1). `kind` selects the wire
/// protocol; `host`/`port` are where to reach the proxy; `auth` is
/// optional credentials for this hop.
#[derive(Debug, Clone)]
pub struct Proxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
}

/// Wire protocol used by a proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Socks4,
    Socks4a,
    Socks5,
    HttpConnect,
}

/// Apply a chain of proxies to `stream`, ending with the tunnel established
/// to `final_host:final_port`.
///
/// For a chain `[p0, p1, ..., pN]` and destination `H:P`:
///   1. Caller has already opened a byte stream to `p0.host:p0.port`.
///   2. This function negotiates `p0` to reach `p1.host:p1.port`.
///   3. Then negotiates `p1` (using the same stream) to reach `p2.host:p2.port`.
///   ...
///   N+1. Negotiates `pN` to reach `H:P`.
///
/// After success, the stream is a raw tunnel to `H:P`.
///
/// An empty chain is a no-op (returns Ok).
///
/// # Errors
///
/// - Any `ProxyError` from any hop.
pub async fn apply_chain<S>(
    stream: &mut S,
    chain: &[Proxy],
    final_host: &str,
    final_port: u16,
) -> Result<(), ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for i in 0..chain.len() {
        // The current hop must negotiate through the current stream toward
        // the NEXT hop's address (or the final destination if this is the
        // last proxy).
        let (next_host, next_port) = if i + 1 < chain.len() {
            (chain[i + 1].host.as_str(), chain[i + 1].port)
        } else {
            (final_host, final_port)
        };

        let cur = &chain[i];
        match cur.kind {
            ProxyKind::Socks5 => {
                negotiate_socks5(stream, next_host, next_port, cur.auth.as_ref()).await?;
            }
            ProxyKind::Socks4 => {
                let user = extract_user(&cur.auth);
                negotiate_socks4(stream, Socks4Variant::V4, next_host, next_port, &user).await?;
            }
            ProxyKind::Socks4a => {
                let user = extract_user(&cur.auth);
                negotiate_socks4(stream, Socks4Variant::V4a, next_host, next_port, &user).await?;
            }
            ProxyKind::HttpConnect => {
                negotiate_http_connect(stream, next_host, next_port, cur.auth.as_ref()).await?;
            }
        }
    }
    Ok(())
}

fn extract_user(auth: &Option<ProxyAuth>) -> String {
    match auth {
        Some(ProxyAuth::UserPassword { user, .. }) => user.clone(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn empty_chain_is_noop() {
        let (mut client, _server) = duplex(1024);
        apply_chain(&mut client, &[], "example.com", 443).await.unwrap();
    }

    #[tokio::test]
    async fn single_socks5_hop_targets_final_destination() {
        // Chain of one socks5, so it negotiates toward "example.com:443".
        let (mut client, mut server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            // greet
            let mut buf = [0u8; 3];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();
            // CONNECT with domain "example.com" port 443
            let mut head = [0u8; 5];
            server.read_exact(&mut head).await.unwrap();
            let name_len = head[4] as usize;
            let mut name = vec![0u8; name_len + 2];
            server.read_exact(&mut name).await.unwrap();
            assert_eq!(&name[..name_len], b"example.com");
            let port = u16::from_be_bytes([name[name_len], name[name_len + 1]]);
            assert_eq!(port, 443);
            server.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        let chain = vec![Proxy {
            kind: ProxyKind::Socks5,
            host: "socksproxy".into(), // unused in this test — the client stream is already "at" the proxy
            port: 1080,
            auth: None,
        }];
        apply_chain(&mut client, &chain, "example.com", 443).await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn two_hop_chain_first_targets_second_second_targets_destination() {
        // Chain: [socks5(A), http_connect(B)], destination: example.com:443
        //
        // First hop (socks5) should negotiate toward the SECOND hop's
        // address (B). Second hop (http_connect) should negotiate toward
        // the final destination (example.com:443).
        let (mut client, mut server) = duplex(16 * 1024);

        let server_task = tokio::spawn(async move {
            // ---- Step 1: SOCKS5 negotiation toward "B:2222" ----
            let mut greet = [0u8; 3];
            server.read_exact(&mut greet).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();
            let mut head = [0u8; 5];
            server.read_exact(&mut head).await.unwrap();
            let name_len = head[4] as usize;
            let mut name_and_port = vec![0u8; name_len + 2];
            server.read_exact(&mut name_and_port).await.unwrap();
            assert_eq!(&name_and_port[..name_len], b"B");
            assert_eq!(
                u16::from_be_bytes([name_and_port[name_len], name_and_port[name_len + 1]]),
                2222
            );
            server.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();

            // ---- Step 2: HTTP CONNECT toward example.com:443 ----
            let mut buf = [0u8; 512];
            let n = server.read(&mut buf).await.unwrap();
            let s = std::str::from_utf8(&buf[..n]).unwrap();
            assert!(s.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"), "got: {s}");
            server.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });

        let chain = vec![
            Proxy {
                kind: ProxyKind::Socks5,
                host: "A".into(),
                port: 1080,
                auth: None,
            },
            Proxy {
                kind: ProxyKind::HttpConnect,
                host: "B".into(),
                port: 2222,
                auth: None,
            },
        ];
        apply_chain(&mut client, &chain, "example.com", 443).await.unwrap();
        server_task.await.unwrap();
    }
}

//! SOCKS4 and `SOCKS4a` client.
//!
//! SOCKS4:  target address is IPv4, IP resolved client-side.
//! `SOCKS4a`: sets IP to 0.0.0.x (x nonzero), appends hostname, proxy
//!          resolves DNS.
//!
//! Wire format (client → server):
//!   [VER=4] [CMD=1(connect)] [DSTPORT: u16 BE] [DSTIP: 4 bytes] [USERID] [0x00]
//!   For 4a, DSTIP is 0.0.0.x (x != 0) and hostname + 0x00 is appended
//!   after the userid null.
//!
//! Response (server → client):
//!   [VN=0] [CD] [DSTPORT: u16] [DSTIP: 4 bytes]
//!   CD=0x5A: request granted
//!   CD=0x5B: request rejected or failed
//!   CD=0x5C: request rejected — cannot connect to identd
//!   CD=0x5D: request rejected — identd userid mismatch

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::ProxyError;

/// SOCKS4 variant selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks4Variant {
    /// Classic SOCKS4: caller resolves hostname to IPv4 before calling.
    V4,
    /// `SOCKS4a`: proxy resolves hostname. `host` argument may be a name.
    V4a,
}

/// Perform a SOCKS4 or `SOCKS4a` negotiation.
///
/// For `V4`, `host` MUST be a dotted-quad IPv4 literal.
/// For `V4a`, `host` may be any hostname.
///
/// # Errors
///
/// - `Protocol` on malformed reply or (V4) invalid IPv4 literal.
/// - `Refused` on non-granted reply codes.
pub async fn negotiate_socks4<S>(
    stream: &mut S,
    variant: Socks4Variant,
    host: &str,
    port: u16,
    user: &str,
) -> Result<(), ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = Vec::with_capacity(9 + user.len() + host.len());
    req.push(0x04); // VER
    req.push(0x01); // CMD = connect
    req.extend_from_slice(&port.to_be_bytes());
    match variant {
        Socks4Variant::V4 => {
            let ip: std::net::Ipv4Addr = host
                .parse()
                .map_err(|e| ProxyError::Protocol(format!("SOCKS4 requires IPv4 literal, got {host:?}: {e}")))?;
            req.extend_from_slice(&ip.octets());
        }
        Socks4Variant::V4a => {
            // Bogus IP 0.0.0.1 signals hostname-mode.
            req.extend_from_slice(&[0, 0, 0, 1]);
        }
    }
    req.extend_from_slice(user.as_bytes());
    req.push(0x00);
    if variant == Socks4Variant::V4a {
        req.extend_from_slice(host.as_bytes());
        req.push(0x00);
    }
    stream.write_all(&req).await?;
    stream.flush().await?;

    let mut resp = [0u8; 8];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0 {
        return Err(ProxyError::Protocol(format!("bad reply VN: {}", resp[0])));
    }
    match resp[1] {
        0x5A => Ok(()),
        0x5B => Err(ProxyError::Refused("SOCKS4 rejected".into())),
        0x5C => Err(ProxyError::Refused("SOCKS4 rejected: identd unreachable".into())),
        0x5D => Err(ProxyError::Refused("SOCKS4 rejected: identd userid mismatch".into())),
        other => Err(ProxyError::Protocol(format!("SOCKS4 unknown CD: 0x{other:02x}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn socks4_happy_path_with_ipv4_literal() {
        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            // 9 = 8 fixed + 1 null after userid (no user name = 0 bytes)
            let mut req = [0u8; 9];
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 0x04);
            assert_eq!(req[1], 0x01);
            assert_eq!(u16::from_be_bytes([req[2], req[3]]), 8080);
            assert_eq!(&req[4..8], &[192, 168, 1, 1]);
            assert_eq!(req[8], 0);
            server.write_all(&[0, 0x5A, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        negotiate_socks4(&mut client, Socks4Variant::V4, "192.168.1.1", 8080, "")
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks4a_happy_path_with_hostname() {
        let (mut client, mut server) = duplex(4096);
        let host = "example.com".to_string();
        let host_clone = host.clone();
        let server_task = tokio::spawn(async move {
            // fixed prefix (8) + null (1) + host + null
            let expected_len = 8 + 1 + host_clone.len() + 1;
            let mut req = vec![0u8; expected_len];
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(&req[..2], &[0x04, 0x01]);
            assert_eq!(&req[4..8], &[0, 0, 0, 1]);
            assert_eq!(req[8], 0);
            assert_eq!(&req[9..9 + host_clone.len()], host_clone.as_bytes());
            assert_eq!(req[9 + host_clone.len()], 0);
            server.write_all(&[0, 0x5A, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        negotiate_socks4(&mut client, Socks4Variant::V4a, &host, 80, "")
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks4_rejects_non_ipv4_host_in_v4() {
        let (mut client, _server) = duplex(4096);
        let err = negotiate_socks4(&mut client, Socks4Variant::V4, "example.com", 80, "")
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Protocol(_)));
    }

    #[tokio::test]
    async fn socks4_refused() {
        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut req = [0u8; 9];
            server.read_exact(&mut req).await.unwrap();
            server.write_all(&[0, 0x5B, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        let err = negotiate_socks4(&mut client, Socks4Variant::V4, "1.2.3.4", 80, "")
            .await
            .unwrap_err();
        server_task.await.unwrap();
        assert!(matches!(err, ProxyError::Refused(_)));
    }
}

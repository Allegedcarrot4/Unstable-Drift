//! SOCKS5 client (RFC 1928 + RFC 1929).
//!
//! Flow:
//!   1. Client → server: version=5, nmethods, methods (0x00=no-auth, 0x02=user/pass)
//!   2. Server → client: version=5, chosen method
//!   3. If method=0x02, RFC 1929 auth exchange
//!   4. Client → server: CONNECT request (VER=5, CMD=1, RSV=0, ATYP, DST.ADDR, DST.PORT)
//!   5. Server → client: reply (VER=5, REP, RSV, ATYP, BND.ADDR, BND.PORT)
//!
//! We use domain-name ATYP (0x03) so the proxy resolves DNS server-side.
//! This is `--socks5-hostname` behavior; the classic `--socks5` mode
//! (client-side DNS) is a v2 concern.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{ProxyAuth, ProxyError};

const VER: u8 = 5;
const CMD_CONNECT: u8 = 1;
const RSV: u8 = 0;

const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Perform a SOCKS5 negotiation on an already-connected stream.
///
/// # Errors
///
/// - `Protocol` on malformed server responses.
/// - `Refused` if the server returns a non-zero reply code.
/// - `AuthFailed` if user/pass auth is rejected.
/// - `Unsupported` if the server selects a method we don't implement.
pub async fn negotiate_socks5<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    auth: Option<&ProxyAuth>,
) -> Result<(), ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Method selection.
    let mut methods = vec![METHOD_NO_AUTH];
    if auth.is_some() {
        methods.push(METHOD_USER_PASS);
    }
    let mut greet = Vec::with_capacity(2 + methods.len());
    greet.push(VER);
    let n_methods: u8 = methods
        .len()
        .try_into()
        .map_err(|_| ProxyError::Protocol("too many methods".into()))?;
    greet.push(n_methods);
    greet.extend_from_slice(&methods);
    stream.write_all(&greet).await?;
    stream.flush().await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != VER {
        return Err(ProxyError::Protocol(format!("bad VER in method reply: {}", resp[0])));
    }
    match resp[1] {
        METHOD_NO_AUTH => {}
        METHOD_USER_PASS => {
            let auth = auth.ok_or_else(|| {
                ProxyError::Protocol("server chose user/pass but no creds supplied".into())
            })?;
            do_user_pass(stream, auth).await?;
        }
        METHOD_NONE_ACCEPTABLE => {
            return Err(ProxyError::AuthFailed);
        }
        other => {
            return Err(ProxyError::Unsupported(format!("server chose method 0x{other:02x}")));
        }
    }

    // CONNECT request. Prefer domain-name ATYP so the proxy handles DNS.
    let mut req = Vec::with_capacity(7 + host.len());
    req.push(VER);
    req.push(CMD_CONNECT);
    req.push(RSV);
    req.push(ATYP_DOMAIN);
    let host_bytes = host.as_bytes();
    let host_len: u8 = host_bytes
        .len()
        .try_into()
        .map_err(|_| ProxyError::Protocol("host name > 255 bytes".into()))?;
    req.push(host_len);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;
    stream.flush().await?;

    // CONNECT reply.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(ProxyError::Protocol(format!("bad VER in connect reply: {}", head[0])));
    }
    if head[1] != 0 {
        return Err(ProxyError::Refused(format!("REP=0x{:02x}", head[1])));
    }
    // Consume the BND address + port; length depends on ATYP.
    match head[3] {
        ATYP_IPV4 => {
            let mut skip = [0u8; 4 + 2];
            stream.read_exact(&mut skip).await?;
        }
        ATYP_IPV6 => {
            let mut skip = [0u8; 16 + 2];
            stream.read_exact(&mut skip).await?;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        other => {
            return Err(ProxyError::Protocol(format!("bad ATYP in reply: 0x{other:02x}")));
        }
    }

    Ok(())
}

async fn do_user_pass<S>(stream: &mut S, auth: &ProxyAuth) -> Result<(), ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ProxyAuth::UserPassword { user, pass } = auth;
    let user_bytes = user.as_bytes();
    let pass_bytes = pass.as_bytes();
    let ulen: u8 = user_bytes
        .len()
        .try_into()
        .map_err(|_| ProxyError::Protocol("username > 255 bytes".into()))?;
    let plen: u8 = pass_bytes
        .len()
        .try_into()
        .map_err(|_| ProxyError::Protocol("password > 255 bytes".into()))?;

    let mut msg = Vec::with_capacity(3 + user_bytes.len() + pass_bytes.len());
    msg.push(0x01); // subnegotiation version
    msg.push(ulen);
    msg.extend_from_slice(user_bytes);
    msg.push(plen);
    msg.extend_from_slice(pass_bytes);
    stream.write_all(&msg).await?;
    stream.flush().await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x01 {
        return Err(ProxyError::Protocol(format!(
            "bad user/pass subnegotiation version: 0x{:02x}",
            resp[0]
        )));
    }
    if resp[1] != 0 {
        return Err(ProxyError::AuthFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn no_auth_happy_path_to_example_com_443() {
        let (mut client, mut server) = duplex(8192);

        // Server side: play the server.
        let target_host = "example.com".to_string();
        let server_task = tokio::spawn(async move {
            // 1. Read greet.
            let mut buf = [0u8; 3]; // VER + NMETHODS=1 + METHOD
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 5);
            assert_eq!(buf[1], 1);
            assert_eq!(buf[2], METHOD_NO_AUTH);
            // 2. Method reply.
            server.write_all(&[5, METHOD_NO_AUTH]).await.unwrap();
            // 3. Read CONNECT request.
            let mut head = [0u8; 5];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 5);
            assert_eq!(head[1], CMD_CONNECT);
            assert_eq!(head[3], ATYP_DOMAIN);
            let name_len = head[4] as usize;
            let mut name = vec![0u8; name_len + 2];
            server.read_exact(&mut name).await.unwrap();
            assert_eq!(&name[..name_len], target_host.as_bytes());
            let port = u16::from_be_bytes([name[name_len], name[name_len + 1]]);
            assert_eq!(port, 443);
            // 4. Reply: succeeded, ATYP=IPv4, bind=0.0.0.0:0
            server
                .write_all(&[5, 0, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        negotiate_socks5(&mut client, "example.com", 443, None)
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn user_pass_happy_path() {
        let (mut client, mut server) = duplex(8192);
        let auth = ProxyAuth::UserPassword {
            user: "alice".into(),
            pass: "secret".into(),
        };
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 5);
            assert_eq!(buf[1], 2);
            // methods should include no-auth and user/pass
            assert!(buf[2..].contains(&METHOD_USER_PASS));
            // choose user/pass
            server.write_all(&[5, METHOD_USER_PASS]).await.unwrap();
            // read user/pass
            let mut hdr = [0u8; 2];
            server.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], 1);
            let ulen = hdr[1] as usize;
            let mut u = vec![0u8; ulen];
            server.read_exact(&mut u).await.unwrap();
            assert_eq!(u.as_slice(), b"alice");
            let mut plen = [0u8; 1];
            server.read_exact(&mut plen).await.unwrap();
            let mut p = vec![0u8; plen[0] as usize];
            server.read_exact(&mut p).await.unwrap();
            assert_eq!(p.as_slice(), b"secret");
            // auth ok
            server.write_all(&[1, 0]).await.unwrap();
            // read CONNECT + reply as before (shorter path since it's tested elsewhere)
            let mut head = [0u8; 5];
            server.read_exact(&mut head).await.unwrap();
            let mut rest = vec![0u8; head[4] as usize + 2];
            server.read_exact(&mut rest).await.unwrap();
            server
                .write_all(&[5, 0, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        negotiate_socks5(&mut client, "example.com", 80, Some(&auth))
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn server_rejects_connect() {
        let (mut client, mut server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 3];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(&[5, METHOD_NO_AUTH]).await.unwrap();
            let mut head = [0u8; 5];
            server.read_exact(&mut head).await.unwrap();
            let mut rest = vec![0u8; head[4] as usize + 2];
            server.read_exact(&mut rest).await.unwrap();
            // REP=0x05 = connection refused
            server.write_all(&[5, 5, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        let err = negotiate_socks5(&mut client, "example.com", 80, None)
            .await
            .unwrap_err();
        server_task.await.unwrap();
        assert!(matches!(err, ProxyError::Refused(_)));
    }

    #[tokio::test]
    async fn server_rejects_auth() {
        let (mut client, mut server) = duplex(8192);
        let auth = ProxyAuth::UserPassword {
            user: "u".into(),
            pass: "wrong".into(),
        };
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(&[5, METHOD_USER_PASS]).await.unwrap();
            let mut hdr = [0u8; 2];
            server.read_exact(&mut hdr).await.unwrap();
            let mut u = vec![0u8; hdr[1] as usize];
            server.read_exact(&mut u).await.unwrap();
            let mut plen = [0u8; 1];
            server.read_exact(&mut plen).await.unwrap();
            let mut p = vec![0u8; plen[0] as usize];
            server.read_exact(&mut p).await.unwrap();
            server.write_all(&[1, 1]).await.unwrap(); // rejected
        });
        let err = negotiate_socks5(&mut client, "example.com", 80, Some(&auth))
            .await
            .unwrap_err();
        server_task.await.unwrap();
        assert!(matches!(err, ProxyError::AuthFailed));
    }

    #[tokio::test]
    async fn server_offers_no_acceptable_method() {
        let (mut client, mut server) = duplex(8192);
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 3];
            server.read_exact(&mut buf).await.unwrap();
            server.write_all(&[5, METHOD_NONE_ACCEPTABLE]).await.unwrap();
        });
        let err = negotiate_socks5(&mut client, "example.com", 80, None)
            .await
            .unwrap_err();
        server_task.await.unwrap();
        assert!(matches!(err, ProxyError::AuthFailed));
    }
}

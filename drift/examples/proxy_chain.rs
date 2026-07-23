use drift_core::proxy::{Proxy, ProxyKind};
use drift_core::WispHandle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut handle = WispHandle::new();
    handle.set_url("https://example.com")?;
    handle.set_proxy_chain(vec![Proxy {
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".into(),
        port: 9050,
        auth: None,
    }]);
    let resp = handle.perform().await?;
    println!("status: {}", resp.status);
    Ok(())
}

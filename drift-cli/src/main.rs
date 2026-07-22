//! wisp CLI entry point. Curl-shaped.

mod flags;
mod output;

use std::sync::Arc;
use std::process::ExitCode;

use clap::Parser;
use drift::{Method, WispClient};
use drift_core::options::{Compression, HttpVersion, TimeoutOptions};
use drift_core::proxy::{Proxy, ProxyKind};
#[cfg(not(target_arch = "wasm32"))]
use drift_core::transport::{WebSocketTransport, WispTransport};
#[cfg(not(target_arch = "wasm32"))]
use drift_core::wisp::Mux;

#[tokio::main]
async fn main() -> ExitCode {
    let args = flags::Args::parse();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wisp: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: flags::Args) -> Result<(), Box<dyn std::error::Error>> {
    // ---- Wisp transport (if --wisp is set) ----
    #[cfg(not(target_arch = "wasm32"))]
    let mux: Option<Arc<Mux>> = if let Some(wisp_url) = &args.wisp {
        let transport: Arc<dyn WispTransport> = WebSocketTransport::connect(wisp_url).await?;
        let mux = Arc::new(Mux::new(transport.clone()));
        mux.run_handshake(&[]).await?;

        // Spawn inbound pump — reads frames from the transport and
        // dispatches them into the mux. Runs until the connection closes.
        let pump_mux = mux.clone();
        let pump_transport = transport;
        tokio::spawn(async move {
            loop {
                match pump_transport.recv().await {
                    Ok(frame) => {
                        if pump_mux.dispatch_inbound(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Some(mux)
    } else {
        None
    };

    // ---- Proxy chain (used only when no --wisp is set) ----
    let proxy_chain: Vec<Proxy> = if args.wisp.is_none() {
        build_proxy_chain(&args)
    } else {
        Vec::new()
    };

    // ---- Client build ----
    let mut builder = WispClient::builder();
    if !proxy_chain.is_empty() {
        builder = builder.proxy_chain(proxy_chain);
    }
    #[cfg(not(target_arch = "wasm32"))]
    if let Some(m) = mux {
        builder = builder.mux(m);
    }

    if let Some(ua) = args.user_agent.as_deref() {
        builder = builder.user_agent(ua);
    }

    // Timeouts.
    let mut timeouts = TimeoutOptions::default();
    let mut touched_timeouts = false;
    if let Some(secs) = args.max_time {
        timeouts.total = Some(std::time::Duration::from_secs_f64(secs));
        touched_timeouts = true;
    }
    if let Some(secs) = args.connect_timeout {
        timeouts.connect = std::time::Duration::from_secs_f64(secs);
        touched_timeouts = true;
    }
    if touched_timeouts {
        builder = builder.timeout_options(timeouts);
    }

    // HTTP options.
    let mut http = drift_core::options::HttpOptions::default();
    if args.http1 {
        http.version_preference = HttpVersion::Http1_1;
    } else if args.http2 {
        http.version_preference = HttpVersion::Http2;
    }
    http.follow_redirects = args.follow_redirects;
    http.max_redirects = args.max_redirects;
    builder = builder.http_options(http);

    // Compression.
    if args.compressed {
        let mut general = drift_core::options::GeneralOptions::default();
        if let Some(ua) = args.user_agent.as_deref() {
            general.user_agent = ua.to_string();
        }
        general.compression = Compression::Auto;
        builder = builder.general_options(general);
    }

    // Verbose flag flows into general options.
    if args.verbose {
        // If we already set general options (via --compressed), we'd need to
        // re-apply. For simplicity, just re-set with verbose=true.
        let mut general = drift_core::options::GeneralOptions::default();
        if let Some(ua) = args.user_agent.as_deref() {
            general.user_agent = ua.to_string();
        }
        if args.compressed {
            general.compression = Compression::Auto;
        }
        general.verbose = true;
        builder = builder.general_options(general);
    }

    // TLS options.
    let mut tls = drift_core::options::TlsOptions::default();
    tls.verify_peer = !args.insecure;
    tls.verify_host = !args.insecure;
    if let Some(path) = args.cacert.as_deref() {
        tls.ca_bundle_path = Some(path.to_string());
    }
    if let Some(path) = args.cert.as_deref() {
        tls.client_cert_path = Some(path.to_string());
    }
    if let Some(path) = args.key.as_deref() {
        tls.client_key_path = Some(path.to_string());
    }
    if args.tls_v12 {
        tls.min_version = drift_core::options::TlsVersion::V1_2;
        tls.max_version = drift_core::options::TlsVersion::V1_2;
    } else if args.tls_v13 {
        tls.min_version = drift_core::options::TlsVersion::V1_3;
        tls.max_version = drift_core::options::TlsVersion::V1_3;
    }
    builder = builder.tls_options(tls);

    let client = builder.build()?;

    // ---- Build the request ----
    let method = match args.method.as_deref() {
        Some(m) => Method::Custom(m.to_string()),
        None if args.head => Method::Head,
        None if args.data.is_some() || args.data_binary.is_some() || args.json.is_some() => {
            Method::Post
        }
        None => Method::Get,
    };

    let mut req = client.request(method, &args.url);
    for h in &args.headers {
        if let Some((name, value)) = h.split_once(':') {
            req = req.header(name.trim(), value.trim());
        } else {
            return Err(format!("bad header format: {h:?} — expected 'Name: Value'").into());
        }
    }

    // Body.
    if let Some(data) = &args.data {
        let body = if let Some(path) = data.strip_prefix('@') {
            std::fs::read_to_string(path)?
        } else {
            data.clone()
        };
        req = req.body_text(body);
    } else if let Some(data) = &args.data_binary {
        let body = if let Some(path) = data.strip_prefix('@') {
            std::fs::read(path)?
        } else {
            data.as_bytes().to_vec()
        };
        req = req.body_bytes(bytes::Bytes::from(body));
    } else if let Some(json) = &args.json {
        req = req.header("Content-Type", "application/json");
        req = req.body_text(json.clone());
    }

    // ---- Send ----
    let resp = req.send().await?;

    // ---- Output ----
    if args.head {
        output::write_head_only(&resp)?;
    } else {
        output::write_response(
            &resp,
            args.include_headers,
            args.output.as_deref(),
            args.dump_header.as_deref(),
        )?;
    }

    Ok(())
}

/// Build a proxy chain from CLI flags. Order: --socks5/--socks5-hostname
/// come first, then --proxy entries (maintaining CLI order).
fn build_proxy_chain(args: &flags::Args) -> Vec<Proxy> {
    let mut chain = Vec::new();

    // --socks5 / --socks5-hostname (convenience shortcuts).
    if let Some(ref hostport) = args.socks5 {
        if let Some((host, port_str)) = hostport.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                chain.push(Proxy {
                    kind: ProxyKind::Socks5,
                    host: host.to_string(),
                    port,
                    auth: None,
                });
            }
        }
    }
    if let Some(ref hostport) = args.socks5_hostname {
        if let Some((host, port_str)) = hostport.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                chain.push(Proxy {
                    kind: ProxyKind::Socks4a, // SOCKS4a resolves hostnames client-side
                    host: host.to_string(),
                    port,
                    auth: None,
                });
            }
        }
    }

    // --proxy URL (repeatable). Supported schemes: socks5://, socks4://,
    // socks4a://, http://.
    for raw in &args.proxy {
        if let Some(proxy) = parse_proxy_url(raw) {
            chain.push(proxy);
        }
    }

    chain
}

/// Parse a --proxy URL into a Proxy hop.
fn parse_proxy_url(raw: &str) -> Option<Proxy> {
    let (scheme, rest) = raw.split_once("://")?;
    let (host, port_str) = rest.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    let kind = match scheme {
        "socks5" => ProxyKind::Socks5,
        "socks4" => ProxyKind::Socks4,
        "socks4a" | "socks5h" => ProxyKind::Socks4a,
        "http" => ProxyKind::HttpConnect,
        _ => return None,
    };
    Some(Proxy {
        kind,
        host: host.to_string(),
        port,
        auth: None,
    })
}

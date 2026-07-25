//! Command-line flag definitions for the `wisp` binary.
//!
//! Curl-shaped subset — ~40 flags covering the common HTTP/HTTPS/WebSocket
//! use cases plus Wisp-native `--wisp` / `--proxy` extensions. Not a full
//! curl-compat CLI; unsupported flags are documented separately.

use clap::Parser;

/// A Rust wisp client, curl-shaped. See `--help` for the flag list.
///
/// wisp-native extensions:
///   `--wisp <URL>`       point at a wisp server (repeatable? no — one wisp)
///   `--proxy <URL>`      add a proxy hop (repeatable — creates a chain)
///   `--allow-wisp-v1`    accept v1 wisp servers (default: on)
#[derive(Parser, Debug)]
#[command(
    name = "wisp",
    about = "Rust wisp client, curl-shaped",
    version,
    long_about = None,
)]
#[allow(clippy::struct_excessive_bools)]
pub struct Args {
    /// The URL to request.
    pub url: String,

    /// HTTP method (default: GET, or POST if -d is given).
    #[arg(short = 'X', long = "request", value_name = "METHOD")]
    pub method: Option<String>,

    /// Additional headers. Repeatable.
    #[arg(short = 'H', long = "header", value_name = "HEADER", num_args = 1)]
    pub headers: Vec<String>,

    /// User-Agent shortcut.
    #[arg(short = 'A', long = "user-agent", value_name = "STRING")]
    pub user_agent: Option<String>,

    /// Send a body (URL-encoded implied). Use `@file` to read from file.
    #[arg(short = 'd', long = "data", value_name = "DATA")]
    pub data: Option<String>,

    /// Send raw body bytes verbatim (no URL-encoding).
    #[arg(long = "data-binary", value_name = "DATA")]
    pub data_binary: Option<String>,

    /// Send a JSON body — sets Content-Type: application/json.
    #[arg(long = "json", value_name = "JSON")]
    pub json: Option<String>,

    /// Write response body to file.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<String>,

    /// Save response body to a file named after the URL's last path segment.
    #[arg(short = 'O', long = "remote-name")]
    pub remote_name: bool,

    /// Include response headers in the output.
    #[arg(short = 'i', long = "include")]
    pub include_headers: bool,

    /// Send a HEAD request and show only the response headers.
    #[arg(short = 'I', long = "head")]
    pub head: bool,

    /// Silent mode (suppress progress and error messages).
    #[arg(short = 's', long = "silent")]
    pub silent: bool,

    /// Verbose mode.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Dump response headers to a file.
    #[arg(long = "dump-header", value_name = "FILE")]
    pub dump_header: Option<String>,

    /// Skip TLS peer verification (dangerous).
    #[arg(short = 'k', long = "insecure")]
    pub insecure: bool,

    /// Path to CA bundle for TLS verification.
    #[arg(long = "cacert", value_name = "FILE")]
    pub cacert: Option<String>,

    /// Client certificate for mTLS.
    #[arg(long = "cert", value_name = "FILE")]
    pub cert: Option<String>,

    /// Client private key for mTLS.
    #[arg(long = "key", value_name = "FILE")]
    pub key: Option<String>,

    /// Force TLS 1.2.
    #[arg(long = "tlsv1.2")]
    pub tls_v12: bool,

    /// Force TLS 1.3.
    #[arg(long = "tlsv1.3")]
    pub tls_v13: bool,

    /// Add a proxy hop to the chain. Repeatable; each `--proxy URL` appends
    /// one hop, applied in order from outer to inner.
    #[arg(long = "proxy", value_name = "URL", num_args = 1)]
    pub proxy: Vec<String>,

    /// Convenience: SOCKS5 shortcut equivalent to `--proxy socks5://<HOST>`.
    #[arg(long = "socks5", value_name = "HOST:PORT")]
    pub socks5: Option<String>,

    /// SOCKS5 with server-side name resolution.
    #[arg(long = "socks5-hostname", value_name = "HOST:PORT")]
    pub socks5_hostname: Option<String>,

    /// Wisp server URL.
    #[arg(long = "wisp", value_name = "WSS_URL")]
    pub wisp: Option<String>,

    /// Accept v1 wisp servers (default true; pass --no-allow-wisp-v1 to disable).
    #[arg(long = "allow-wisp-v1", default_value_t = true)]
    pub allow_wisp_v1: bool,

    /// Total request timeout (seconds).
    #[arg(long = "max-time", value_name = "SECONDS")]
    pub max_time: Option<f64>,

    /// Connect timeout (seconds).
    #[arg(long = "connect-timeout", value_name = "SECONDS")]
    pub connect_timeout: Option<f64>,

    /// Follow redirects.
    #[arg(short = 'L', long = "location")]
    pub follow_redirects: bool,

    /// Max number of redirects to follow.
    #[arg(long = "max-redirs", value_name = "N", default_value_t = 20)]
    pub max_redirects: u32,

    /// Advertise Accept-Encoding: br, gzip.
    #[arg(long = "compressed")]
    pub compressed: bool,

    /// Force HTTP/1.1.
    #[arg(long = "http1.1")]
    pub http1: bool,

    /// Force HTTP/2.
    #[arg(long = "http2")]
    pub http2: bool,
}

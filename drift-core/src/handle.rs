//! The low-level libcurl-shaped `WispHandle`.
//!
//! Phase 1 scope: shape + option storage + validation. `perform()` connects
//! directly via TCP if no wisp mux is attached, or through the wisp tunnel
//! if a mux is configured.

use std::sync::Arc;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::options::{
    CookieOptions, DnsOptions, GeneralOptions, HttpOptions, TcpOptions,
    TimeoutOptions, TlsOptions,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::proxy::apply_chain;
use crate::proxy::Proxy;
use crate::wisp::Mux;

/// HTTP method for the request represented by a `WispHandle`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Custom(String),
}

impl Method {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Patch => "PATCH",
            Method::Head => "HEAD",
            Method::Options => "OPTIONS",
            Method::Custom(s) => s.as_str(),
        }
    }
}

impl Default for Method {
    fn default() -> Self {
        Method::Get
    }
}

/// Table-driven option key for `WispHandle::set_option`. One variant per
/// option we support. Matches libcurl's `CURLOPT_*` naming shape but with
/// Rust-idiomatic PascalCase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opt {
    // TLS
    TlsVerifyPeer,
    TlsVerifyHost,
    TlsMinVersion,
    TlsMaxVersion,

    // HTTP
    HttpFollowRedirects,
    HttpMaxRedirects,

    // TCP
    TcpNodelay,
    TcpKeepalive,

    // Timeouts
    TimeoutTotal,
    TimeoutConnect,

    // Cookies
    CookiesEnabled,

    // General
    UserAgent,
    Verbose,
    MaxResponseSize,
}

/// Table-driven option value. Consumers pick the variant matching the
/// `Opt` key.
#[derive(Debug, Clone)]
pub enum OptValue {
    Bool(bool),
    U32(u32),
    U64(u64),
    Duration(Duration),
    String(String),
    TlsVersion(crate::options::TlsVersion),
    None,
}

/// Request body — either owned bytes or a placeholder for a streaming
/// source (Phase 4 will introduce a `Stream` variant).
#[derive(Debug, Clone, Default)]
pub enum Body {
    #[default]
    Empty,
    Bytes(Vec<u8>),
    Text(String),
}

impl Body {
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Body::Empty => 0,
            Body::Bytes(b) => b.len(),
            Body::Text(s) => s.len(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A single (name, value) header pair. Duplicates are allowed and preserved
/// in insertion order.
#[derive(Debug, Clone)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// Placeholder response type. Phase 4 will replace with a real Response
/// struct backed by streams.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

/// Combined `AsyncRead + AsyncWrite + Send + Unpin` trait for boxing
/// heterogeneous byte streams (wisp tunnel, TLS-wrapped, raw TCP).
trait IoStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> IoStream for T {}

/// The low-level libcurl-shaped handle. Configure via setters, then call
/// `perform()` to run the request.
///
/// Phase 1 exposes only the URL/method/headers/body setters + option
/// sub-struct setters. Table-driven `set_option(key, value)` fallback lands
/// in Task 25.
#[derive(Clone)]
pub struct WispHandle {
    url: Option<String>,
    method: Method,
    headers: Vec<Header>,
    body: Body,

    tls: TlsOptions,
    http: HttpOptions,
    tcp: TcpOptions,
    timeouts: TimeoutOptions,
    cookies: CookieOptions,
    dns: DnsOptions,
    general: GeneralOptions,
    proxy_chain: Vec<Proxy>,

    mux: Option<Arc<Mux>>,
}

impl std::fmt::Debug for WispHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WispHandle")
            .field("url", &self.url)
            .field("method", &self.method)
            .field("headers", &self.headers)
            .field("body", &self.body)
            .field("tls", &self.tls)
            .field("http", &self.http)
            .field("tcp", &self.tcp)
            .field("timeouts", &self.timeouts)
            .field("cookies", &self.cookies)
            .field("dns", &self.dns)
            .field("general", &self.general)
            .field("mux", &self.mux.as_ref().map(|_| "<Mux>"))
            .finish()
    }
}

impl WispHandle {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ---- Request-primitive setters ----

    /// Set the target URL. Rejects malformed URLs (missing scheme).
    pub fn set_url(&mut self, url: impl Into<String>) -> Result<()> {
        let s = url.into();
        if !s.contains("://") {
            return Err(Error::Config(format!("URL missing scheme: {s}")));
        }
        self.url = Some(s);
        Ok(())
    }

    #[must_use]
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn set_method(&mut self, method: Method) {
        self.method = method;
    }

    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn add_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push(Header {
            name: name.into(),
            value: value.into(),
        });
    }

    #[must_use]
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    pub fn set_body(&mut self, body: Body) {
        self.body = body;
    }

    #[must_use]
    pub fn body(&self) -> &Body {
        &self.body
    }

    // ---- Option-group setters ----

    pub fn set_tls_options(&mut self, opts: TlsOptions) {
        self.tls = opts;
    }

    #[must_use]
    pub fn tls_options(&self) -> &TlsOptions {
        &self.tls
    }

    pub fn set_http_options(&mut self, opts: HttpOptions) {
        self.http = opts;
    }

    #[must_use]
    pub fn http_options(&self) -> &HttpOptions {
        &self.http
    }

    pub fn set_tcp_options(&mut self, opts: TcpOptions) {
        self.tcp = opts;
    }

    #[must_use]
    pub fn tcp_options(&self) -> &TcpOptions {
        &self.tcp
    }

    pub fn set_timeout_options(&mut self, opts: TimeoutOptions) {
        self.timeouts = opts;
    }

    #[must_use]
    pub fn timeout_options(&self) -> &TimeoutOptions {
        &self.timeouts
    }

    pub fn set_cookie_options(&mut self, opts: CookieOptions) {
        self.cookies = opts;
    }

    #[must_use]
    pub fn cookie_options(&self) -> &CookieOptions {
        &self.cookies
    }

    pub fn set_dns_options(&mut self, opts: DnsOptions) {
        self.dns = opts;
    }

    #[must_use]
    pub fn dns_options(&self) -> &DnsOptions {
        &self.dns
    }

    pub fn set_general_options(&mut self, opts: GeneralOptions) {
        self.general = opts;
    }

    #[must_use]
    pub fn general_options(&self) -> &GeneralOptions {
        &self.general
    }

    /// Table-driven option setter. Matches libcurl's `curl_easy_setopt`
    /// pattern for callers who want key/value ergonomics rather than the
    /// typed sub-struct setters.
    ///
    /// # Errors
    ///
    /// - `Error::Config` if the value variant doesn't match the option's
    ///   expected type.
    pub fn set_option(&mut self, key: Opt, value: OptValue) -> Result<()> {
        use OptValue::*;
        match (key, value) {
            (Opt::TlsVerifyPeer, Bool(b)) => self.tls.verify_peer = b,
            (Opt::TlsVerifyHost, Bool(b)) => self.tls.verify_host = b,
            (Opt::TlsMinVersion, TlsVersion(v)) => self.tls.min_version = v,
            (Opt::TlsMaxVersion, TlsVersion(v)) => self.tls.max_version = v,
            (Opt::HttpFollowRedirects, Bool(b)) => self.http.follow_redirects = b,
            (Opt::HttpMaxRedirects, U32(n)) => self.http.max_redirects = n,
            (Opt::TcpNodelay, Bool(b)) => self.tcp.nodelay = b,
            (Opt::TcpKeepalive, Bool(b)) => self.tcp.keepalive = b,
            (Opt::TimeoutTotal, Duration(d)) => self.timeouts.total = Some(d),
            (Opt::TimeoutTotal, None) => self.timeouts.total = Option::None,
            (Opt::TimeoutConnect, Duration(d)) => self.timeouts.connect = d,
            (Opt::CookiesEnabled, Bool(b)) => self.cookies.enabled = b,
            (Opt::UserAgent, String(s)) => self.general.user_agent = s,
            (Opt::Verbose, Bool(b)) => self.general.verbose = b,
            (Opt::MaxResponseSize, U64(n)) => self.general.max_response_size = Some(n),
            (Opt::MaxResponseSize, None) => self.general.max_response_size = Option::None,
            (k, v) => {
                return Err(Error::Config(format!(
                    "Opt::{k:?} does not accept value {v:?}"
                )));
            }
        }
        Ok(())
    }

    // ---- Transport ----

    /// Attach a wisp `Mux` to this handle. High-level clients (Phase 6) will
    /// wrap this; low-level users can construct a mux themselves.
    pub fn set_mux(&mut self, mux: Arc<Mux>) {
        self.mux = Some(mux);
    }

    #[must_use]
    pub fn mux(&self) -> Option<&Arc<Mux>> {
        self.mux.as_ref()
    }

    /// Set a proxy chain for direct connections (when no mux is configured).
    pub fn set_proxy_chain(&mut self, chain: Vec<Proxy>) {
        self.proxy_chain = chain;
    }

    /// Return true if there's a configured proxy chain.
    #[must_use]
    pub fn has_proxy_chain(&self) -> bool {
        !self.proxy_chain.is_empty()
    }

    // ---- Execution ----

    /// Perform the configured request, following redirects if configured.
    ///
    /// Opens a wisp stream to the destination, optionally wraps it in TLS
    /// (for `https://`), then drives an HTTP/1.1 request/response through
    /// the resulting `AsyncRead + AsyncWrite`. Response bodies with a
    /// `Content-Encoding` of `gzip` or `br` are transparently decoded.
    ///
    /// # Errors
    ///
    /// - `Error::Config` if no URL is set or the URL is malformed.
    /// - `Error::NoTransport` if no URL is set.
    /// - `Error::Internal` (wrapping) for wisp/TLS/HTTP failures.
    pub async fn perform(&mut self) -> Result<Response> {
        use crate::wisp::{StreamType, WispStream, WispStreamIo};

        let url = self
            .url
            .as_deref()
            .ok_or_else(|| Error::Config("no URL set".into()))?
            .to_string();

        let max_redirects = if self.http.follow_redirects {
            self.http.max_redirects
        } else {
            0
        };

        let mut current_url = url;
        let mut remaining_redirects = max_redirects;

        loop {
            let parsed = parse_url(&current_url)?;

            // Open a stream: either via wisp mux or direct TCP + proxy chain.
            let raw: Box<dyn IoStream>;
            if let Some(mux) = &self.mux {
                let stream_handle = mux
                    .open(&parsed.host, parsed.port, StreamType::Tcp)
                    .await
                    .map_err(|e| Error::Internal(format!("drift open: {e}")))?;
                let ws_stream = WispStream::from_handle(mux.clone(), stream_handle);
                raw = Box::new(WispStreamIo::new(ws_stream));
            } else {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    if !self.proxy_chain.is_empty() {
                        let first = &self.proxy_chain[0];
                        let addr = format!("{}:{}", first.host, first.port);
                        let mut tcp = tokio::net::TcpStream::connect(&addr)
                            .await
                            .map_err(|e| Error::Internal(format!("tcp connect to proxy: {e}")))?;
                        apply_chain(&mut tcp, &self.proxy_chain, &parsed.host, parsed.port)
                            .await
                            .map_err(|e| Error::Internal(format!("proxy chain: {e}")))?;
                        raw = Box::new(tcp);
                    } else {
                        let addr = format!("{}:{}", parsed.host, parsed.port);
                        let tcp = tokio::net::TcpStream::connect(&addr)
                            .await
                            .map_err(|e| Error::Internal(format!("tcp connect: {e}")))?;
                        raw = Box::new(tcp);
                    }
                }
                #[cfg(target_arch = "wasm32")]
                {
                    let _ = &self.proxy_chain;
                    return Err(Error::Config(
                        "direct TCP connections are not supported on wasm32; configure a wisp mux".into(),
                    ));
                }
            }

            // Wrap in TLS if https.
            let resp = self.perform_http1_tls(raw, &parsed).await?;

            // Check for redirect.
            if remaining_redirects > 0 && is_redirect_status(resp.status) {
                let location = resp
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("location"))
                    .map(|h| h.value.clone());
                match location {
                    Some(loc) => {
                        let next = resolve_url(&current_url, &loc);
                        if next == current_url {
                            return Err(Error::Internal("redirect loop detected".into()));
                        }
                        // 303 always switches to GET.
                        if resp.status == 303 {
                            self.method = Method::Get;
                        }
                        current_url = next;
                        remaining_redirects -= 1;
                        continue;
                    }
                    None => return Ok(resp),
                }
            }

            return Ok(resp);
        }
    }

    /// Open a TLS-wrapped stream (if https) and perform HTTP/1.1.
    async fn perform_http1_tls(
        &self,
        raw: Box<dyn IoStream>,
        parsed: &ParsedUrl,
    ) -> Result<Response> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            if parsed.scheme == UrlScheme::Https {
                let tls_config = crate::tls::build_client_config(&self.tls)?;
                let server_name = rustls::pki_types::ServerName::try_from(parsed.host.clone())
                    .map_err(|e| Error::Config(format!("invalid server name: {e}")))?;
                let connector = tokio_rustls::TlsConnector::from(tls_config);
                let tls_stream = connector
                    .connect(server_name, raw)
                    .await
                    .map_err(|e| Error::Internal(format!("tls handshake: {e}")))?;
                return perform_http1(tls_stream, parsed, self).await;
            }
            perform_http1(raw, parsed, self).await
        }

        #[cfg(target_arch = "wasm32")]
        {
            use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
            if parsed.scheme == UrlScheme::Https {
                let tls_config = crate::tls::build_client_config(&self.tls)?;
                let server_name = rustls::pki_types::ServerName::try_from(parsed.host.clone())
                    .map_err(|e| Error::Config(format!("invalid server name: {e}")))?;
                let compat_raw = raw.compat();
                let connector = futures_rustls::TlsConnector::from(tls_config);
                let tls_stream = connector
                    .connect(server_name, compat_raw)
                    .await
                    .map_err(|e| Error::Internal(format!("tls handshake: {e}")))?;
                let tokio_tls = tls_stream.compat();
                return perform_http1(tokio_tls, parsed, self).await;
            }
            perform_http1(raw, parsed, self).await
        }
    }
}

async fn perform_http1<S>(
    stream: S,
    parsed: &ParsedUrl,
    handle: &WispHandle,
) -> Result<Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crate::http1::{send_request, Http1Request};

    // Build headers.
    let mut headers = http::HeaderMap::new();
    let host_value = if (parsed.scheme == UrlScheme::Http && parsed.port == 80)
        || (parsed.scheme == UrlScheme::Https && parsed.port == 443)
    {
        parsed.host.clone()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };
    headers.insert(
        http::header::HOST,
        http::HeaderValue::from_str(&host_value)
            .map_err(|e| Error::Config(format!("bad host header: {e}")))?,
    );
    for h in &handle.headers {
        let name = http::header::HeaderName::from_bytes(h.name.as_bytes())
            .map_err(|e| Error::Config(format!("bad header name {:?}: {e}", h.name)))?;
        let value = http::HeaderValue::from_str(&h.value)
            .map_err(|e| Error::Config(format!("bad header value: {e}")))?;
        headers.append(name, value);
    }
    if !headers.contains_key(http::header::USER_AGENT) {
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_str(&handle.general.user_agent)
                .map_err(|e| Error::Config(format!("bad user-agent: {e}")))?,
        );
    }
    if !headers.contains_key(http::header::ACCEPT_ENCODING) {
        if let Some(v) = crate::compression::accept_encoding_header(handle.general.compression) {
            headers.insert(http::header::ACCEPT_ENCODING, http::HeaderValue::from_static(v));
        }
    }

    let method_bytes = handle.method.as_str().as_bytes();
    let method = http::Method::from_bytes(method_bytes)
        .map_err(|e| Error::Config(format!("bad method {:?}: {e}", handle.method)))?;

    let body_bytes: bytes::Bytes = match &handle.body {
        Body::Empty => bytes::Bytes::new(),
        Body::Bytes(v) => bytes::Bytes::copy_from_slice(v),
        Body::Text(s) => bytes::Bytes::copy_from_slice(s.as_bytes()),
    };

    let req = Http1Request {
        method,
        path: parsed.path.clone(),
        headers,
        body: body_bytes,
    };

    let mut stream = stream;
    let resp = send_request(&mut stream, &req, handle.general.max_response_size)
        .await
        .map_err(|e| Error::Internal(format!("http1: {e}")))?;

    // Decompress body if needed.
    let enc_header = resp
        .headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let final_body = match enc_header.as_deref() {
        Some(v) => crate::compression::decode_body(resp.body.as_ref(), Some(v))
            .await
            .map_err(|e| Error::Internal(format!("decompress: {e}")))?,
        None => resp.body,
    };

    let mut out_headers = Vec::with_capacity(resp.headers.len());
    for (name, value) in &resp.headers {
        out_headers.push(Header {
            name: name.as_str().to_string(),
            value: value.to_str().unwrap_or("").to_string(),
        });
    }

    Ok(Response {
        status: resp.status.as_u16(),
        headers: out_headers,
        body: final_body.to_vec(),
    })
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn resolve_url(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if location.starts_with('/') {
        let base_no_path = base.split('/').take(3).collect::<Vec<_>>().join("/");
        format!("{base_no_path}{location}")
    } else {
        let base_dir = match base.rfind('/') {
            Some(i) if i > 8 => &base[..=i],
            _ => base,
        };
        format!("{base_dir}{location}")
    }
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum UrlScheme {
    Http,
    Https,
}

struct ParsedUrl {
    scheme: UrlScheme,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(s: &str) -> Result<ParsedUrl> {
    let (scheme_str, rest) = s
        .split_once("://")
        .ok_or_else(|| Error::Config(format!("URL missing scheme: {s}")))?;
    let scheme = match scheme_str {
        "http" => UrlScheme::Http,
        "https" => UrlScheme::Https,
        other => return Err(Error::Config(format!("unsupported scheme: {other}"))),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| Error::Config(format!("bad port: {p}")))?;
            (h.to_string(), port)
        }
        None => {
            let default_port = match scheme {
                UrlScheme::Http => 80,
                UrlScheme::Https => 443,
            };
            (authority.to_string(), default_port)
        }
    };
    if host.is_empty() {
        return Err(Error::Config(format!("empty host in URL: {s}")));
    }
    Ok(ParsedUrl {
        scheme,
        host,
        port,
        path: path.to_string(),
    })
}

impl Default for WispHandle {
    fn default() -> Self {
        Self {
            url: None,
            method: Method::default(),
            headers: vec![],
            body: Body::default(),
            tls: TlsOptions::default(),
            http: HttpOptions::default(),
            tcp: TcpOptions::default(),
            timeouts: TimeoutOptions::default(),
            cookies: CookieOptions::default(),
            dns: DnsOptions::default(),
            general: GeneralOptions::default(),
            proxy_chain: Vec::new(),
            mux: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_handle_has_no_url() {
        let h = WispHandle::new();
        assert!(h.url().is_none());
        assert_eq!(*h.method(), Method::Get);
        assert!(h.headers().is_empty());
        assert!(h.body().is_empty());
    }

    #[test]
    fn set_url_accepts_valid_url() {
        let mut h = WispHandle::new();
        h.set_url("https://example.com").unwrap();
        assert_eq!(h.url(), Some("https://example.com"));
    }

    #[test]
    fn set_url_rejects_missing_scheme() {
        let mut h = WispHandle::new();
        let err = h.set_url("example.com").unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn add_header_appends_and_preserves_duplicates() {
        let mut h = WispHandle::new();
        h.add_header("X-Foo", "a");
        h.add_header("X-Foo", "b");
        assert_eq!(h.headers().len(), 2);
        assert_eq!(h.headers()[0].value, "a");
        assert_eq!(h.headers()[1].value, "b");
    }

    #[test]
    fn set_method_updates() {
        let mut h = WispHandle::new();
        h.set_method(Method::Post);
        assert_eq!(*h.method(), Method::Post);

        h.set_method(Method::Custom("BREW".into()));
        assert_eq!(h.method().as_str(), "BREW");
    }

    #[test]
    fn set_body_variants() {
        let mut h = WispHandle::new();
        h.set_body(Body::Text("hi".into()));
        assert_eq!(h.body().len(), 2);
        h.set_body(Body::Bytes(vec![1, 2, 3]));
        assert_eq!(h.body().len(), 3);
        h.set_body(Body::Empty);
        assert!(h.body().is_empty());
    }

    #[test]
    fn option_group_setters_round_trip() {
        let mut h = WispHandle::new();
        let mut tls = TlsOptions::default();
        tls.verify_peer = false;
        h.set_tls_options(tls);
        assert!(!h.tls_options().verify_peer);
    }

    #[tokio::test]
    async fn perform_without_url_returns_config_error() {
        let mut h = WispHandle::new();
        let err = h.perform().await.unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[tokio::test]
    async fn perform_with_url_direct_tcp_succeeds() {
        let mut h = WispHandle::new();
        h.set_url("https://example.com").unwrap();
        let resp = h.perform().await.unwrap();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn set_option_bool_updates_tls_verify() {
        let mut h = WispHandle::new();
        h.set_option(Opt::TlsVerifyPeer, OptValue::Bool(false)).unwrap();
        assert!(!h.tls_options().verify_peer);
    }

    #[test]
    fn set_option_string_updates_user_agent() {
        let mut h = WispHandle::new();
        h.set_option(Opt::UserAgent, OptValue::String("my-ua/1.0".into()))
            .unwrap();
        assert_eq!(h.general_options().user_agent, "my-ua/1.0");
    }

    #[test]
    fn set_option_wrong_variant_returns_config_error() {
        let mut h = WispHandle::new();
        let err = h
            .set_option(Opt::TlsVerifyPeer, OptValue::String("yes".into()))
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn set_option_timeout_total_none_clears() {
        let mut h = WispHandle::new();
        h.set_option(Opt::TimeoutTotal, OptValue::Duration(Duration::from_secs(30)))
            .unwrap();
        assert!(h.timeout_options().total.is_some());
        h.set_option(Opt::TimeoutTotal, OptValue::None).unwrap();
        assert!(h.timeout_options().total.is_none());
    }

    #[test]
    fn parse_url_variants() {
        let p = parse_url("http://example.com/").unwrap();
        assert_eq!(p.scheme, UrlScheme::Http);
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 80);
        assert_eq!(p.path, "/");

        let p = parse_url("https://example.com:8443/x/y?q=1").unwrap();
        assert_eq!(p.scheme, UrlScheme::Https);
        assert_eq!(p.port, 8443);
        assert_eq!(p.path, "/x/y?q=1");

        assert!(parse_url("example.com").is_err(), "missing scheme");
        assert!(parse_url("ftp://example.com/").is_err(), "unsupported scheme");
        assert!(parse_url("http://:80/").is_err(), "empty host");
        assert!(parse_url("http://x:abc/").is_err(), "bad port");
    }
}

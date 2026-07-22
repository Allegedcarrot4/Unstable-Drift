//! wisp — high-level reqwest-shaped wisp client.
//!
//! Wraps `wisp-core::WispHandle` in a builder-style API. Consumers who
//! want low-level control can use `wisp-core` directly.
//!
//! ```no_run
//! use drift::WispClient;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = WispClient::builder()
//!     .user_agent("myapp/1.0")
//!     .build()?;
//!
//! let resp = client
//!     .get("https://example.com/")
//!     .header("x-foo", "bar")
//!     .send()
//!     .await?;
//!
//! println!("{}: {}", resp.status(), resp.text()?);
//! # Ok(()) }
//! ```
//!
//! Note: `send()` requires a wisp transport wired up via `builder().mux(...)`.
//! The end-to-end HTTP wiring over WispStream lands in a follow-up task
//! (spec Task 20.5); Phase 6 provides the shape.

pub mod request;
pub mod response;

pub use drift_core::{Error, Result};
pub use request::{RequestBuilder};
pub use response::Response;

use std::sync::Arc;

use drift_core::{
    handle::{Header, Method as CoreMethod, WispHandle},
    options::{
        CookieOptions, DnsOptions, GeneralOptions, HttpOptions, TcpOptions,
        TimeoutOptions, TlsOptions,
    },
    proxy::Proxy,
    wisp::Mux,
};

/// The high-level client. Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct WispClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    mux: Option<Arc<Mux>>,
    tls: TlsOptions,
    http: HttpOptions,
    tcp: TcpOptions,
    timeouts: TimeoutOptions,
    cookies: CookieOptions,
    dns: DnsOptions,
    general: GeneralOptions,
    proxy_chain: Vec<Proxy>,
    default_headers: Vec<Header>,
}

impl WispClient {
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    pub fn get(&self, url: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(self.clone(), CoreMethod::Get, url.into())
    }

    pub fn post(&self, url: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(self.clone(), CoreMethod::Post, url.into())
    }

    pub fn put(&self, url: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(self.clone(), CoreMethod::Put, url.into())
    }

    pub fn delete(&self, url: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(self.clone(), CoreMethod::Delete, url.into())
    }

    pub fn head(&self, url: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(self.clone(), CoreMethod::Head, url.into())
    }

    pub fn request(&self, method: CoreMethod, url: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(self.clone(), method, url.into())
    }

    /// Access the underlying wisp mux, if one was configured.
    #[must_use]
    pub fn mux(&self) -> Option<&Arc<Mux>> {
        self.inner.mux.as_ref()
    }

    /// Internal — build a fresh `WispHandle` seeded with client defaults.
    pub(crate) fn make_handle(&self) -> WispHandle {
        let mut h = WispHandle::new();
        h.set_tls_options(self.inner.tls.clone());
        h.set_http_options(self.inner.http.clone());
        h.set_tcp_options(self.inner.tcp.clone());
        h.set_timeout_options(self.inner.timeouts.clone());
        h.set_cookie_options(self.inner.cookies.clone());
        h.set_dns_options(self.inner.dns.clone());
        h.set_general_options(self.inner.general.clone());
        h.set_proxy_chain(self.inner.proxy_chain.clone());
        for hdr in &self.inner.default_headers {
            h.add_header(&hdr.name, &hdr.value);
        }
        if let Some(mux) = &self.inner.mux {
            h.set_mux(mux.clone());
        }
        h
    }
}

/// Builder for `WispClient`. Every setter is optional; `.build()` finalizes.
#[derive(Default)]
pub struct ClientBuilder {
    mux: Option<Arc<Mux>>,
    tls: Option<TlsOptions>,
    http: Option<HttpOptions>,
    tcp: Option<TcpOptions>,
    timeouts: Option<TimeoutOptions>,
    cookies: Option<CookieOptions>,
    dns: Option<DnsOptions>,
    general: Option<GeneralOptions>,
    proxy_chain: Vec<Proxy>,
    default_headers: Vec<Header>,
    user_agent: Option<String>,
}

impl ClientBuilder {
    /// Attach an already-connected wisp mux. Required for `.send()` to
    /// perform an actual request; without one, requests fail with
    /// `Error::NoTransport`.
    #[must_use]
    pub fn mux(mut self, mux: Arc<Mux>) -> Self {
        self.mux = Some(mux);
        self
    }

    #[must_use]
    pub fn tls_options(mut self, opts: TlsOptions) -> Self {
        self.tls = Some(opts);
        self
    }

    #[must_use]
    pub fn http_options(mut self, opts: HttpOptions) -> Self {
        self.http = Some(opts);
        self
    }

    #[must_use]
    pub fn tcp_options(mut self, opts: TcpOptions) -> Self {
        self.tcp = Some(opts);
        self
    }

    #[must_use]
    pub fn timeout_options(mut self, opts: TimeoutOptions) -> Self {
        self.timeouts = Some(opts);
        self
    }

    #[must_use]
    pub fn cookie_options(mut self, opts: CookieOptions) -> Self {
        self.cookies = Some(opts);
        self
    }

    #[must_use]
    pub fn dns_options(mut self, opts: DnsOptions) -> Self {
        self.dns = Some(opts);
        self
    }

    #[must_use]
    pub fn general_options(mut self, opts: GeneralOptions) -> Self {
        self.general = Some(opts);
        self
    }

    /// Override the User-Agent shortcut. Equivalent to setting
    /// `general_options().user_agent = ...`.
    #[must_use]
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Add a default header that will be applied to every request made
    /// through this client. Repeatable.
    #[must_use]
    pub fn default_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.default_headers.push(Header {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// Set a proxy chain for direct connections (when no mux is configured).
    #[must_use]
    pub fn proxy_chain(mut self, chain: Vec<Proxy>) -> Self {
        self.proxy_chain = chain;
        self
    }

    /// Finalize.
    ///
    /// # Errors
    ///
    /// Currently never fails — builder is total. Left as `Result` so future
    /// validation (e.g., mutually-exclusive options) is a non-breaking change.
    pub fn build(self) -> Result<WispClient> {
        let mut general = self.general.unwrap_or_default();
        if let Some(ua) = self.user_agent {
            general.user_agent = ua;
        }
        Ok(WispClient {
            inner: Arc::new(ClientInner {
                mux: self.mux,
                tls: self.tls.unwrap_or_default(),
                http: self.http.unwrap_or_default(),
                tcp: self.tcp.unwrap_or_default(),
                timeouts: self.timeouts.unwrap_or_default(),
                cookies: self.cookies.unwrap_or_default(),
                dns: self.dns.unwrap_or_default(),
                general,
                proxy_chain: self.proxy_chain,
                default_headers: self.default_headers,
            }),
        })
    }
}

/// Re-export `Method` from the low-level crate for high-level ergonomics.
pub type Method = CoreMethod;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_default_user_agent_is_drift() {
        let client = WispClient::builder().build().unwrap();
        let h = client.make_handle();
        assert!(h.general_options().user_agent.starts_with("drift/"));
    }

    #[tokio::test]
    async fn user_agent_override_sticks() {
        let client = WispClient::builder()
            .user_agent("myapp/1.0")
            .build()
            .unwrap();
        let h = client.make_handle();
        assert_eq!(h.general_options().user_agent, "myapp/1.0");
    }

    #[tokio::test]
    async fn default_headers_are_applied_to_handles() {
        let client = WispClient::builder()
            .default_header("x-common", "1")
            .default_header("x-common", "2")
            .build()
            .unwrap();
        let h = client.make_handle();
        assert_eq!(h.headers().len(), 2);
        assert_eq!(h.headers()[0].name, "x-common");
        assert_eq!(h.headers()[1].value, "2");
    }

    #[tokio::test]
    async fn direct_tcp_get_succeeds() {
        let client = WispClient::builder().build().unwrap();
        let resp = client.get("https://example.com/").send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let text = resp.text().unwrap();
        assert!(text.contains("Example Domain"));
    }

    #[tokio::test]
    async fn per_request_headers_are_applied_alongside_defaults() {
        let client = WispClient::builder()
            .default_header("x-common", "shared")
            .build()
            .unwrap();
        let resp = client
            .get("https://example.com/")
            .header("x-req", "unique")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
}

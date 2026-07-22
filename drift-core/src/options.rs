//! Grouped option sub-structs for wisp-core.
//!
//! These map to Wisp's libcurl-parity option surface (spec §6.2). Each
//! group is a plain `struct` with `Default` derived; consumers construct one
//! via `TlsOptions::default()` and mutate fields, then hand to a
//! `WispHandle`. A table-driven `Opt` enum for `set_option(key, value)`
//! callers arrives in Task 25.

use std::time::Duration;

/// TLS-related options. See spec §6.2.
#[derive(Debug, Clone)]
pub struct TlsOptions {
    pub verify_peer: bool,
    pub verify_host: bool,
    /// Path to a CA-bundle PEM file, if overriding the built-in roots.
    pub ca_bundle_path: Option<String>,
    /// In-memory CA-bundle PEM contents, if overriding the built-in roots.
    pub ca_bundle_data: Option<Vec<u8>>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub min_version: TlsVersion,
    pub max_version: TlsVersion,
    /// ALPN advertisements; e.g. `vec!["h2".into(), "http/1.1".into()]`.
    pub alpn: Vec<String>,
    /// Override the SNI hostname; None = use URL hostname.
    pub sni_override: Option<String>,
    pub session_resumption: bool,
    pub keylog_file: Option<String>,
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            verify_peer: true,
            verify_host: true,
            ca_bundle_path: None,
            ca_bundle_data: None,
            client_cert_path: None,
            client_key_path: None,
            min_version: TlsVersion::V1_2,
            max_version: TlsVersion::V1_3,
            alpn: vec![],
            sni_override: None,
            session_resumption: true,
            keylog_file: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    V1_2,
    V1_3,
}

/// HTTP-related options.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    pub version_preference: HttpVersion,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub referer_policy: RefererPolicy,
    pub expect_100_timeout: Duration,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            version_preference: HttpVersion::Auto,
            follow_redirects: false,
            max_redirects: 20,
            referer_policy: RefererPolicy::StrictOriginWhenCrossOrigin,
            expect_100_timeout: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http1_1,
    Http2,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefererPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

/// TCP-level options.
#[derive(Debug, Clone)]
pub struct TcpOptions {
    pub nodelay: bool,
    pub keepalive: bool,
    pub keepidle: Duration,
    pub keepintvl: Duration,
    pub keepcnt: u32,
    pub interface: Option<String>,
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    /// Per-second bytes; 0 = unlimited.
    pub low_speed_limit: u64,
    pub low_speed_time: Duration,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            nodelay: true,
            keepalive: true,
            keepidle: Duration::from_secs(60),
            keepintvl: Duration::from_secs(30),
            keepcnt: 3,
            interface: None,
            ipv4_only: false,
            ipv6_only: false,
            low_speed_limit: 0,
            low_speed_time: Duration::from_secs(0),
        }
    }
}

/// Timeout options; every stage has an independent limit.
#[derive(Debug, Clone)]
pub struct TimeoutOptions {
    pub total: Option<Duration>,
    pub dns: Duration,
    pub connect: Duration,
    pub tls: Duration,
    pub first_byte: Duration,
}

impl Default for TimeoutOptions {
    fn default() -> Self {
        Self {
            total: None,
            dns: Duration::from_secs(30),
            connect: Duration::from_secs(30),
            tls: Duration::from_secs(30),
            first_byte: Duration::from_secs(60),
        }
    }
}

/// Cookie options.
#[derive(Debug, Clone, Default)]
pub struct CookieOptions {
    pub enabled: bool,
    pub jar_path: Option<String>,
    pub session_only: bool,
    pub secure_only: bool,
}

/// DNS options.
#[derive(Debug, Clone)]
pub struct DnsOptions {
    /// Manual resolver entries: `("host:port", "ip:port")`. Matches libcurl `--resolve`.
    pub resolve_overrides: Vec<(String, String)>,
    pub cache_ttl: Duration,
    pub servers: Vec<String>,
    pub prefer_ipv6: bool,
}

impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            resolve_overrides: vec![],
            cache_ttl: Duration::from_secs(60),
            servers: vec![],
            prefer_ipv6: false,
        }
    }
}

/// General/miscellaneous options that don't fit a specific group.
#[derive(Debug, Clone)]
pub struct GeneralOptions {
    pub user_agent: String,
    pub verbose: bool,
    pub max_response_size: Option<u64>,
    pub buffer_size: usize,
    pub compression: Compression,
}

impl Default for GeneralOptions {
    fn default() -> Self {
        Self {
            user_agent: format!("drift/{}", env!("CARGO_PKG_VERSION")),
            verbose: false,
            max_response_size: None,
            buffer_size: 64 * 1024,
            compression: Compression::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Brotli,
    Auto,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_defaults_are_safe() {
        let t = TlsOptions::default();
        assert!(t.verify_peer);
        assert!(t.verify_host);
        assert_eq!(t.min_version, TlsVersion::V1_2);
        assert_eq!(t.max_version, TlsVersion::V1_3);
    }

    #[test]
    fn http_defaults_are_conservative() {
        let h = HttpOptions::default();
        assert_eq!(h.version_preference, HttpVersion::Auto);
        assert!(!h.follow_redirects, "default must not follow redirects");
        assert_eq!(h.max_redirects, 20);
    }

    #[test]
    fn tcp_defaults_enable_nodelay_and_keepalive() {
        let t = TcpOptions::default();
        assert!(t.nodelay);
        assert!(t.keepalive);
    }

    #[test]
    fn timeout_defaults_bounded() {
        let t = TimeoutOptions::default();
        assert!(t.total.is_none(), "no total-timeout by default");
        assert_eq!(t.connect, Duration::from_secs(30));
    }

    #[test]
    fn cookie_default_is_off() {
        let c = CookieOptions::default();
        assert!(!c.enabled);
    }

    #[test]
    fn dns_default_has_no_overrides() {
        let d = DnsOptions::default();
        assert!(d.resolve_overrides.is_empty());
    }

    #[test]
    fn general_user_agent_mentions_drift() {
        let g = GeneralOptions::default();
        assert!(g.user_agent.starts_with("drift/"));
    }
}

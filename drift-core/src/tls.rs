//! TLS layer for wisp-core: builds `rustls::ClientConfig` from `TlsOptions`.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore, SupportedProtocolVersion};

use crate::error::{Error, Result};
use crate::options::{TlsOptions, TlsVersion};

/// Build a `rustls::ClientConfig` from `TlsOptions`.
///
/// Uses the ring crypto provider (WASM-friendly, avoids aws-lc-rs).
///
/// # Errors
///
/// - `Error::Config` on malformed CA bundle or empty version range.
/// - `Error::Config` if `verify_peer` is false (no dangerous-mode support yet).
pub fn build_client_config(opts: &TlsOptions) -> Result<Arc<ClientConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    if !opts.verify_peer {
        return Err(Error::Config(
            "TlsOptions.verify_peer = false is not supported in this release".into(),
        ));
    }

    let root_store = build_root_store(opts)?;

    let versions = allowed_versions(opts.min_version, opts.max_version);
    if versions.is_empty() {
        return Err(Error::Config(format!(
            "TLS version range empty: min={:?}, max={:?}",
            opts.min_version, opts.max_version
        )));
    }

    let mut config = ClientConfig::builder_with_protocol_versions(&versions)
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if !opts.alpn.is_empty() {
        config.alpn_protocols = opts.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    }

    Ok(Arc::new(config))
}

fn build_root_store(opts: &TlsOptions) -> Result<RootCertStore> {
    let user_bytes: Option<Vec<u8>> = if let Some(bytes) = &opts.ca_bundle_data {
        Some(bytes.clone())
    } else if let Some(path) = &opts.ca_bundle_path {
        Some(std::fs::read(path).map_err(|e| Error::Config(format!("ca_bundle_path {path:?}: {e}")))?)
    } else {
        None
    };

    let mut store = RootCertStore::empty();

    if let Some(bytes) = user_bytes {
        let mut count = 0usize;
        for cert in split_pem_certs(&bytes) {
            let der = CertificateDer::from(cert);
            store
                .add(der)
                .map_err(|e| Error::Config(format!("ca_bundle: rustls rejected cert: {e:?}")))?;
            count += 1;
        }
        if count == 0 {
            return Err(Error::Config("ca_bundle contained no CERTIFICATE PEM blocks".into()));
        }
    } else {
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    Ok(store)
}

fn allowed_versions(min: TlsVersion, max: TlsVersion) -> Vec<&'static SupportedProtocolVersion> {
    let mut out = Vec::new();
    if min <= TlsVersion::V1_2 && max >= TlsVersion::V1_2 {
        out.push(&rustls::version::TLS12);
    }
    if min <= TlsVersion::V1_3 && max >= TlsVersion::V1_3 {
        out.push(&rustls::version::TLS13);
    }
    out
}

impl PartialOrd for TlsVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TlsVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn rank(v: TlsVersion) -> u8 {
            match v {
                TlsVersion::V1_2 => 12,
                TlsVersion::V1_3 => 13,
            }
        }
        rank(*self).cmp(&rank(*other))
    }
}

fn split_pem_certs(bytes: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(bytes) else { return Vec::new() };
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            current = Some(String::new());
        } else if line == "-----END CERTIFICATE-----" {
            if let Some(b64) = current.take() {
                if let Ok(der) = base64_decode(&b64) {
                    out.push(der);
                }
            }
        } else if let Some(buf) = current.as_mut() {
            buf.push_str(line);
        }
    }
    out
}

fn base64_decode(s: &str) -> std::result::Result<Vec<u8>, &'static str> {
    fn v(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(26 + c - b'a'),
            b'0'..=b'9' => Some(52 + c - b'0'),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let d = v(c).ok_or("invalid base64 byte")?;
        buf = (buf << 6) | u32::from(d);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_with_default_options_succeeds() {
        let opts = TlsOptions::default();
        let cfg = build_client_config(&opts).unwrap();
        assert!(cfg.crypto_provider().kx_groups.iter().count() > 0);
    }

    #[test]
    fn build_config_with_alpn_populates_it() {
        let mut opts = TlsOptions::default();
        opts.alpn = vec!["h2".into(), "http/1.1".into()];
        let cfg = build_client_config(&opts).unwrap();
        assert_eq!(cfg.alpn_protocols.len(), 2);
        assert_eq!(cfg.alpn_protocols[0], b"h2");
        assert_eq!(cfg.alpn_protocols[1], b"http/1.1");
    }

    #[test]
    fn build_config_rejects_no_verify_peer() {
        let mut opts = TlsOptions::default();
        opts.verify_peer = false;
        let err = build_client_config(&opts).unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn build_config_rejects_impossible_version_range() {
        let mut opts = TlsOptions::default();
        opts.min_version = TlsVersion::V1_3;
        opts.max_version = TlsVersion::V1_2;
        let err = build_client_config(&opts).unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn split_pem_extracts_multiple_certs() {
        let cert1 = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let cert2 = rcgen::generate_simple_self_signed(vec!["another.example".into()]).unwrap();
        let combined = format!("{}\n{}", cert1.cert.pem(), cert2.cert.pem());
        let der_bytes = split_pem_certs(combined.as_bytes());
        assert_eq!(der_bytes.len(), 2);
    }

    #[test]
    fn ca_bundle_data_replaces_default_roots() {
        let cert = rcgen::generate_simple_self_signed(vec!["test.example".into()]).unwrap();
        let pem = cert.cert.pem();
        let mut opts = TlsOptions::default();
        opts.ca_bundle_data = Some(pem.into_bytes());
        let _ = build_client_config(&opts).unwrap();
    }

    #[test]
    fn ca_bundle_data_with_no_certs_fails() {
        let mut opts = TlsOptions::default();
        opts.ca_bundle_data = Some(b"garbage without any pem markers".to_vec());
        let err = build_client_config(&opts).unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn base64_decode_basic() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
    }
}

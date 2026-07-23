//! wisp-core — low-level libcurl-shaped wisp client.

pub mod compression;
pub mod custom;
pub mod error;
pub mod handle;
pub mod http1;
pub mod pool;
#[cfg(feature = "http2")]
pub mod http2;
pub mod options;
pub mod proxy;
pub mod tls;
pub mod transport;
pub mod wisp;
pub mod ws;

pub use error::{Error, Result};
pub use handle::{Body, Header, IoStream, Method, WispHandle, Opt, OptValue, Response};

/// Sanity function.
#[must_use]
pub fn hello_drift() -> &'static str {
    "hello from drift-core"
}

#[cfg(test)]
mod tests {
    use super::hello_drift;

    #[test]
    fn hello_returns_expected_string() {
        assert_eq!(hello_drift(), "hello from drift-core");
    }
}

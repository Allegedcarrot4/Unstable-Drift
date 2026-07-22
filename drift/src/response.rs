//! High-level Response wrapper.

use drift_core::handle::{Header as CoreHeader, Response as CoreResponse};
use drift_core::{Error, Result};

/// High-level response. Body is already fully buffered.
#[derive(Debug, Clone)]
pub struct Response {
    status: u16,
    headers: Vec<CoreHeader>,
    body: Vec<u8>,
}

impl Response {
    pub(crate) fn from_core(r: CoreResponse) -> Self {
        Self {
            status: r.status,
            headers: r.headers,
            body: r.body,
        }
    }

    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn headers(&self) -> &[CoreHeader] {
        &self.headers
    }

    /// Get a single header value by name, case-insensitive. Returns the
    /// first match if multiple.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Get the response body as bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Get the response body as text, expecting UTF-8.
    ///
    /// # Errors
    ///
    /// - `Error::Config` if the body is not valid UTF-8.
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| Error::Config(format!("response body is not UTF-8: {e}")))
    }
}

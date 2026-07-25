//! Request builder — configures a single request and calls `.send()`.

use bytes::Bytes;
use drift_core::handle::{Body, Method};

use crate::{WispClient, Response};
use drift_core::Result;

/// Builder for a single HTTP request.
pub struct RequestBuilder {
    client: WispClient,
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Body,
}

impl RequestBuilder {
    pub(crate) fn new(client: WispClient, method: Method, url: String) -> Self {
        Self {
            client,
            method,
            url,
            headers: Vec::new(),
            body: Body::Empty,
        }
    }

    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    #[must_use]
    pub fn body_bytes(mut self, body: impl Into<Bytes>) -> Self {
        let b = body.into();
        self.body = Body::Bytes(b.to_vec());
        self
    }

    #[must_use]
    pub fn body_text(mut self, body: impl Into<String>) -> Self {
        self.body = Body::Text(body.into());
        self
    }

    /// Send the request. Consumes the builder.
    ///
    /// # Errors
    ///
    /// - `Error::NoTransport` if the client has no attached mux.
    /// - `Error::Config` for malformed inputs.
    /// - `Error::Internal` for pre-execution setup failures.
    #[allow(clippy::large_futures)]
    pub async fn send(self) -> Result<Response> {
        let mut handle = self.client.make_handle();
        handle.set_method(self.method);
        handle.set_url(&self.url)?;
        for (name, value) in self.headers {
            handle.add_header(name, value);
        }
        handle.set_body(self.body);

        let core_resp = handle.perform().await?;
        Ok(Response::from_core(core_resp))
    }
}

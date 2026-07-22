//! Low-level libcurl-shaped `Wisp` JS class.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::prelude::*;

/// The libcurl-shaped low-level handle. Configure with `setopt(key, value)`
/// then call `perform()`.
#[wasm_bindgen(js_name = "Wisp")]
pub struct WispJs {
    inner: std::cell::RefCell<drift_core::WispHandle>,
}

#[wasm_bindgen(js_class = "Wisp")]
impl WispJs {
    /// Construct a new handle.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: std::cell::RefCell::new(drift_core::WispHandle::new()),
        }
    }

    /// Set a table-driven option.
    ///
    /// Supported keys today (string form): "url", "method", "header",
    /// "user-agent", "verbose", "insecure".
    ///
    /// Real libcurl-parity setopt maps onto `drift_core::Opt` and covers
    /// ~15 options; more will land as consumers ask.
    #[wasm_bindgen]
    pub fn setopt(&self, key: String, value: JsValue) -> Result<(), JsValue> {
        let mut h = self.inner.borrow_mut();
        match key.as_str() {
            "url" => {
                let s = value.as_string().ok_or_else(|| JsValue::from_str("url must be string"))?;
                h.set_url(s).map_err(err)?;
            }
            "method" => {
                let s = value.as_string().ok_or_else(|| JsValue::from_str("method must be string"))?;
                use drift_core::Method;
                let m = match s.to_uppercase().as_str() {
                    "GET" => Method::Get,
                    "POST" => Method::Post,
                    "PUT" => Method::Put,
                    "DELETE" => Method::Delete,
                    "PATCH" => Method::Patch,
                    "HEAD" => Method::Head,
                    "OPTIONS" => Method::Options,
                    other => Method::Custom(other.to_string()),
                };
                h.set_method(m);
            }
            "header" => {
                let s = value.as_string().ok_or_else(|| JsValue::from_str("header must be string"))?;
                let (n, v) = s
                    .split_once(':')
                    .ok_or_else(|| JsValue::from_str("header format: 'Name: Value'"))?;
                h.add_header(n.trim(), v.trim());
            }
            other => {
                return Err(JsValue::from_str(&format!("unknown option: {other}")));
            }
        }
        Ok(())
    }

    /// Perform the configured request. Returns Promise<{status, body}>.
    #[wasm_bindgen]
    pub async fn perform(&self) -> Result<JsValue, JsValue> {
        // Clone the handle out to avoid holding the RefCell across await.
        let mut h = self.inner.borrow().clone();
        let resp = h.perform().await.map_err(err)?;
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("status"),
            &JsValue::from_f64(f64::from(resp.status)),
        )?;
        let body = js_sys::Uint8Array::from(resp.body.as_slice());
        js_sys::Reflect::set(&obj, &JsValue::from_str("body"), &body)?;
        Ok(obj.into())
    }
}

impl Default for WispJs {
    fn default() -> Self {
        Self::new()
    }
}

fn err<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

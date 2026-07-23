use std::sync::Arc;

use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{Response as WebResponse, ResponseInit};

use drift_core::transport::{MessagePortTransport, WebSocketWasmTransport, WispTransport};
use drift_core::wisp::Mux;

/// Options for constructing a `WispClient`. Passed as a JS object.
#[wasm_bindgen(getter_with_clone)]
pub struct WispClientOptions {
    /// Either a wisp WebSocket URL (string) or a MoonbeamRelay object.
    /// If a string: Wisp will open a WebSocket to that URL.
    /// If an object with an `.attach()` method returning a MessagePort:
    /// Wisp will attach and use the MessagePort as its transport.
    #[wasm_bindgen(js_name = "transport")]
    pub transport: JsValue,
}

#[wasm_bindgen]
impl WispClientOptions {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(transport: JsValue) -> Self {
        Self { transport }
    }
}

/// The high-level Wisp client.
#[wasm_bindgen(js_name = "WispClient")]
pub struct WispClientJs {
    inner: std::cell::RefCell<Option<drift::WispClient>>,
    transport_opts: WispClientOptions,
}

#[wasm_bindgen(js_class = "WispClient")]
impl WispClientJs {
    /// Construct a new WispClient. The transport is not connected until the
    /// first `fetch()` call, so construction is synchronous.
    #[wasm_bindgen(constructor)]
    pub fn new(opts: WispClientOptions) -> Result<WispClientJs, JsValue> {
        Ok(Self {
            inner: std::cell::RefCell::new(None),
            transport_opts: opts,
        })
    }

    /// Ensure the mux is connected. Called lazily on first fetch.
    async fn ensure_connected(&self) -> Result<(), JsValue> {
        if self.inner.borrow().is_some() {
            return Ok(());
        }

        // Determine transport type from options.
        let transport: Arc<dyn WispTransport> = if let Some(url) = self.transport_opts.transport.as_string() {
            // WebSocket transport.
            WebSocketWasmTransport::connect(&url)
                .await
                .map_err(|e| JsValue::from_str(&format!("WebSocket connect: {e}")))?
        } else if self.transport_opts.transport.is_object() {
            let port = crate::moonbeam::attach_moonbeam(self.transport_opts.transport.clone())?;
            MessagePortTransport::new(port)
                .map_err(|e| JsValue::from_str(&format!("MessagePort transport: {e}")))?
        } else {
            return Err(JsValue::from_str(
                "transport: expected a string URL or a MoonBeam relay object",
            ));
        };

        let mux = Arc::new(Mux::new(transport.clone()));
        mux.run_handshake(&[])
            .await
            .map_err(|e| JsValue::from_str(&format!("drift handshake: {e}")))?;

        // Spawn inbound pump.
        let pump_mux = mux.clone();
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                match transport.recv().await {
                    Ok(frame) => {
                        if pump_mux.dispatch_inbound(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let client = drift::WispClient::builder()
            .mux(mux)
            .build()
            .map_err(|e| JsValue::from_str(&format!("WispClient::build: {e}")))?;

        *self.inner.borrow_mut() = Some(client);
        Ok(())
    }

    /// Perform a fetch. Returns a Promise<Response>.
    /// `init` can contain `method`, `headers` (object), and `body` (string or Uint8Array).
    #[wasm_bindgen]
    pub async fn fetch(&self, url: String, init: JsValue) -> Result<WebResponse, JsValue> {
        self.ensure_connected().await?;

        let client = self
            .inner
            .borrow()
            .clone()
            .ok_or_else(|| JsValue::from_str("WispClient: not initialized"))?;

        // Parse method, headers, body from init.
        let method_str = if !init.is_null() && !init.is_undefined() {
            Reflect::get(&init, &JsValue::from_str("method"))
                .ok()
                .and_then(|v| v.as_string())
        } else {
            None
        };

        let mut req = match method_str.as_deref() {
            Some("POST") => client.post(url),
            Some("PUT") => client.put(url),
            Some("DELETE") => client.delete(url),
            _ => client.get(url),
        };

        if !init.is_null() && !init.is_undefined() {
            if let Ok(headers) = Reflect::get(&init, &JsValue::from_str("headers")) {
                if !headers.is_null() && !headers.is_undefined() {
                    if let Some(obj) = headers.dyn_ref::<Object>() {
                        let entries = Object::entries(obj);
                        for i in 0..entries.length() {
                            let pair = entries.get(i);
                            if let Ok(arr) = pair.dyn_into::<js_sys::Array>() {
                                let name = arr.get(0).as_string().unwrap_or_default();
                                let value = arr.get(1).as_string().unwrap_or_default();
                                if !name.is_empty() {
                                    req = req.header(name, value);
                                }
                            }
                        }
                    }
                }
            }
            if let Ok(body) = Reflect::get(&init, &JsValue::from_str("body")) {
                if !body.is_null() && !body.is_undefined() {
                    if let Some(s) = body.as_string() {
                        req = req.body_text(s);
                    } else if let Ok(arr) = body.dyn_into::<Uint8Array>() {
                        req = req.body_bytes(arr.to_vec());
                    }
                }
            }
        }

        let resp = req.send().await.map_err(|e| {
            JsValue::from_str(&format!("fetch: {e}"))
        })?;

        let body_bytes = Uint8Array::from(resp.bytes());
        let init = ResponseInit::new();
        init.set_status(resp.status());
        let hdrs = web_sys::Headers::new().map_err(|e| {
            JsValue::from_str(&format!("Headers::new: {e:?}"))
        })?;
        for h in resp.headers() {
            let _ = hdrs.set(&h.name, &h.value);
        }
        init.set_headers(&hdrs);
        WebResponse::new_with_opt_buffer_source_and_init(Some(body_bytes.as_ref()), &init)
            .map_err(|e| JsValue::from_str(&format!("Response::new: {e:?}")))
    }

    /// Connect a WebSocket over the wisp tunnel.
    ///
    /// `url` — a `ws://` or `wss://` URL for the destination WebSocket server.
    /// `protocols` — optional JS array of sub-protocol strings, or null/undefined.
    /// `_headers` — not yet supported (reserved for future use).
    ///
    /// Returns a `WispWebSocket` object with `send(data)`, `close(code, reason)`,
    /// `readyState` getter, and settable `onmessage`, `onclose`, `onerror` callbacks.
    #[wasm_bindgen(js_name = "connectWebSocket")]
    pub async fn connect_websocket(
        &self,
        url: String,
        protocols: JsValue,
        _headers: JsValue,
    ) -> Result<crate::websocket::WispWebSocketJs, JsValue> {
        self.ensure_connected().await?;

        let (host, port, path) = crate::websocket::parse_ws_url(&url)?;

        let mut proto_vec: Vec<String> = Vec::new();
        if let Some(arr) = protocols.dyn_ref::<js_sys::Array>() {
            for i in 0..arr.length() {
                if let Some(s) = arr.get(i).as_string() {
                    proto_vec.push(s);
                }
            }
        }

        let client = self
            .inner
            .borrow()
            .clone()
            .ok_or_else(|| JsValue::from_str("WispClient: not initialized"))?;
        let mux = client
            .mux()
            .cloned()
            .ok_or_else(|| JsValue::from_str("connectWebSocket: no wisp mux (use --wisp)"))?;

        crate::websocket::spawn_websocket(mux, host, port, path, proto_vec)
    }
}

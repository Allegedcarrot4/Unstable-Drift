use std::sync::Arc;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

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

    /// Perform a fetch. Returns a Promise<Response-shaped-object>.
    #[wasm_bindgen]
    pub async fn fetch(&self, url: String, _init: JsValue) -> Result<JsValue, JsValue> {
        self.ensure_connected().await?;

        let client = self
            .inner
            .borrow()
            .clone()
            .ok_or_else(|| JsValue::from_str("WispClient: not initialized"))?;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| JsValue::from_str(&format!("fetch: {e}")))?;
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("status"),
            &JsValue::from_f64(f64::from(resp.status())),
        )?;
        let body_bytes = js_sys::Uint8Array::from(resp.bytes());
        js_sys::Reflect::set(&obj, &JsValue::from_str("body"), &body_bytes)?;
        Ok(obj.into())
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

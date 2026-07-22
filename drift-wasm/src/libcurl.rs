//! libcurl.js-shaped adapter.
//!
//! Exposes a `LibCurl` JS class matching the interface DuskJS's
//! `src/host/net.ts` expects. Consumers call `new LibCurl()`, then
//! `await lc.load_wasm()`, `lc.set_websocket(wispUrl)`, and then
//! `.fetch(...)`, `new lc.WebSocket(...)`, `new lc.HTTPSession(...)`,
//! `new lc.TLSSocket(...)`.
//!
//! Only `fetch` and `HTTPSession` are fully wired. `WebSocket` and
//! `TLSSocket` are stubbed to return errors — DuskJS feature-detects
//! and falls back gracefully.

#![cfg(target_arch = "wasm32")]

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use js_sys::{Object, Reflect, Uint8Array};
use drift_core::transport::{MessagePortTransport, WebSocketWasmTransport, WispTransport};
use drift_core::wisp::Mux;
use drift_core::WispHandle;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::{Response as WebResponse, ResponseInit};

/// Shared connection state — held inside `LibCurl` and reused across
/// requests so a single wisp WebSocket + mux serves many concurrent
/// fetches/streams.
struct ConnectionState {
    wisp_url: RefCell<Option<String>>,
    moonbeam_port: RefCell<Option<web_sys::MessagePort>>,
    mux: RefCell<Option<Arc<Mux>>>,
}

impl ConnectionState {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            wisp_url: RefCell::new(None),
            moonbeam_port: RefCell::new(None),
            mux: RefCell::new(None),
        })
    }

    async fn ensure_mux(&self) -> Result<Arc<Mux>, JsValue> {
        if let Some(m) = self.mux.borrow().as_ref() {
            return Ok(m.clone());
        }

        // Prefer MoonBeam relay if one was set; otherwise fall back to a
        // direct WebSocket connection.
        let port_opt = self.moonbeam_port.borrow().clone();
        let transport: Arc<dyn WispTransport> = if let Some(port) = port_opt {
            let mp = MessagePortTransport::new(port).map_err(|e| {
                JsValue::from_str(&format!("LibCurl: message-port transport: {e}"))
            })?;
            mp as Arc<dyn WispTransport>
        } else {
            let url = self.wisp_url.borrow().clone().ok_or_else(|| {
                JsValue::from_str(
                    "LibCurl: neither set_websocket(url) nor set_moonbeam_relay(relay) was called",
                )
            })?;
            let ws = WebSocketWasmTransport::connect(&url).await.map_err(|e| {
                JsValue::from_str(&format!("LibCurl: wisp connect: {e}"))
            })?;
            ws as Arc<dyn WispTransport>
        };

        let mux = Arc::new(Mux::new(transport.clone()));
        mux.run_handshake(&[])
            .await
            .map_err(|e| JsValue::from_str(&format!("LibCurl: wisp handshake: {e}")))?;

        // Spawn the inbound-packet pump. Mux::run_handshake consumes the
        // initial INFO/CONTINUE via transport.recv(), but nothing polls
        // recv() after that. Without this pump, post-handshake packets
        // (CONNECT ack, DATA carrying TLS handshake bytes, CONTINUE credit
        // refills) sit in the transport forever, and any WispStream read
        // (including the TLS handshake) blocks indefinitely. On native
        // targets callers typically tokio::spawn this loop themselves;
        // wasm32 uses wasm_bindgen_futures::spawn_local.
        let pump_mux = mux.clone();
        let pump_transport = transport;
        spawn_local(async move {
            loop {
                match pump_transport.recv().await {
                    Ok(frame) => {
                        if pump_mux.dispatch_inbound(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        *self.mux.borrow_mut() = Some(mux.clone());
        Ok(mux)
    }
}

/// The libcurl.js-shaped JS class DuskJS expects.
#[wasm_bindgen(js_name = "LibCurl")]
pub struct LibCurlJs {
    state: Rc<ConnectionState>,
}

#[wasm_bindgen(js_class = "LibCurl")]
impl LibCurlJs {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: ConnectionState::new(),
        }
    }

    /// No-op for Wisp. Kept for API compatibility with libcurl.js which
    /// downloads its WASM here. Wisp's WASM is already loaded via
    /// `wasm-bindgen`'s `init()` entry point.
    #[wasm_bindgen]
    pub async fn load_wasm(&self, _url: Option<String>) -> Result<(), JsValue> {
        Ok(())
    }

    /// Set the wisp server URL. Called once by DuskJS with the proxy URL.
    #[wasm_bindgen]
    pub fn set_websocket(&self, url: String) {
        *self.state.wisp_url.borrow_mut() = Some(url);
        // Invalidate any existing mux so the next call reconnects.
        *self.state.mux.borrow_mut() = None;
    }

    /// Route wisp through a MoonBeam relay instead of a fresh WebSocket.
    ///
    /// `relay` must be a JS object with an `.attach()` method returning a
    /// `MessagePort` (matches `@nightnetwork/moonbeam` v0.2+'s
    /// `MoonbeamRelay` shape). This is duck-typed to avoid a direct
    /// dependency on MoonBeam's package.
    ///
    /// After calling this, all subsequent `fetch`/`HTTPSession`/etc. calls
    /// on this LibCurl instance route through the relay.
    ///
    /// # Errors
    ///
    /// Returns a JS error if `relay.attach()` isn't callable or doesn't
    /// return a `MessagePort`.
    #[wasm_bindgen]
    pub fn set_moonbeam_relay(&self, relay: JsValue) -> Result<(), JsValue> {
        let port = crate::moonbeam::attach_moonbeam(relay)?;
        *self.state.moonbeam_port.borrow_mut() = Some(port);
        // Invalidate the mux so the next request builds one via the port.
        *self.state.mux.borrow_mut() = None;
        // Clear the WebSocket URL so `ensure_mux` picks the relay path.
        *self.state.wisp_url.borrow_mut() = None;
        Ok(())
    }

    /// Perform an HTTP fetch. Returns a real `Response`.
    #[wasm_bindgen]
    pub async fn fetch(&self, url: String, opts: JsValue) -> Result<WebResponse, JsValue> {
        let mux = self.state.ensure_mux().await?;
        let mut handle = WispHandle::new();
        handle.set_mux(mux);
        handle
            .set_url(&url)
            .map_err(|e| JsValue::from_str(&format!("set_url: {e}")))?;

        // Extract method, headers, body from opts if present.
        if !opts.is_null() && !opts.is_undefined() {
            if let Some(method) = Reflect::get(&opts, &JsValue::from_str("method"))
                .ok()
                .and_then(|v| v.as_string())
            {
                use drift_core::Method;
                let m = match method.to_uppercase().as_str() {
                    "GET" => Method::Get,
                    "POST" => Method::Post,
                    "PUT" => Method::Put,
                    "DELETE" => Method::Delete,
                    "PATCH" => Method::Patch,
                    "HEAD" => Method::Head,
                    "OPTIONS" => Method::Options,
                    other => Method::Custom(other.to_string()),
                };
                handle.set_method(m);
            }
            if let Ok(headers) = Reflect::get(&opts, &JsValue::from_str("headers")) {
                if !headers.is_null() && !headers.is_undefined() {
                    apply_headers(&mut handle, &headers)?;
                }
            }
            if let Ok(body) = Reflect::get(&opts, &JsValue::from_str("body")) {
                if !body.is_null() && !body.is_undefined() {
                    if let Some(s) = body.as_string() {
                        handle.set_body(drift_core::Body::Bytes(s.into_bytes()));
                    } else if let Ok(arr) = body.dyn_into::<Uint8Array>() {
                        handle.set_body(drift_core::Body::Bytes(arr.to_vec()));
                    }
                }
            }
        }

        let core_resp = handle
            .perform()
            .await
            .map_err(|e| JsValue::from_str(&format!("fetch: {e}")))?;

        // Construct a real Response.
        let body_bytes = Uint8Array::from(core_resp.body.as_slice());
        let init = ResponseInit::new();
        init.set_status(core_resp.status);
        // Build headers.
        let hdrs = web_sys::Headers::new()?;
        for h in &core_resp.headers {
            let _ = hdrs.set(&h.name, &h.value);
        }
        init.set_headers(&hdrs);
        WebResponse::new_with_opt_buffer_source_and_init(Some(body_bytes.as_ref()), &init)
    }

    /// The `WebSocket` class getter.
    ///
    /// Currently returns `undefined` — full WebSocket-over-wisp support
    /// is a follow-up. DuskJS `net.ts` will error at construction time,
    /// which is safe for feature-gated use.
    #[wasm_bindgen(getter, js_name = "WebSocket")]
    pub fn websocket_ctor(&self) -> JsValue {
        JsValue::UNDEFINED
    }

    /// `HTTPSession` getter. Returns a JS constructor function bound to
    /// this LibCurl instance via the thread-local latch below.
    #[wasm_bindgen(getter, js_name = "HTTPSession")]
    pub fn http_session_ctor(&self) -> JsValue {
        LIBCURL_LATEST_STATE.with(|slot| {
            *slot.borrow_mut() = Some(self.state.clone());
        });
        // The generated bindings module exports WispHTTPSession as a
        // top-level named export. Consumers wiring the shim into
        // globalThis (e.g. via a bootstrap JS file) can look it up here.
        // If not published on globalThis, this returns undefined —
        // DuskJS then falls back to LibCurl.fetch which is equivalent.
        let global = js_sys::global();
        Reflect::get(&global, &JsValue::from_str("__drift_HTTPSession"))
            .unwrap_or(JsValue::UNDEFINED)
    }

    /// `TLSSocket` getter.
    ///
    /// Currently returns `undefined` — DuskJS's `net.ts:181` checks
    /// `if (!c.TLSSocket)` and errors gracefully.
    #[wasm_bindgen(getter, js_name = "TLSSocket")]
    pub fn tls_socket_ctor(&self) -> JsValue {
        JsValue::UNDEFINED
    }

    /// Currently configured transport name. Wisp only supports wisp;
    /// returns the string "wisp".
    #[wasm_bindgen(getter)]
    pub fn transport(&self) -> JsValue {
        JsValue::from_str("wisp")
    }

    /// Version string.
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> JsValue {
        JsValue::from_str(concat!("drift-libcurl-shim/", env!("CARGO_PKG_VERSION")))
    }
}

impl Default for LibCurlJs {
    fn default() -> Self {
        Self::new()
    }
}

fn apply_headers(handle: &mut WispHandle, headers: &JsValue) -> Result<(), JsValue> {
    // Accept plain object shape: {name: value, ...}. Object.entries
    // yields [name, value] pairs regardless of input being a Headers,
    // Map, or plain object.
    if let Some(obj) = headers.dyn_ref::<Object>() {
        let entries = Object::entries(obj);
        for i in 0..entries.length() {
            let pair = entries.get(i);
            let pair_arr = pair
                .dyn_into::<js_sys::Array>()
                .map_err(|_| JsValue::from_str("header entry not an array"))?;
            let name = pair_arr.get(0).as_string().unwrap_or_default();
            let value = pair_arr.get(1).as_string().unwrap_or_default();
            if !name.is_empty() {
                handle.add_header(name, value);
            }
        }
    }
    Ok(())
}

// Thread-local latch: the most recently-constructed LibCurl instance's
// state is stashed here so `WispHTTPSession` (which is a
// constructor-function returned to JS) can find a mux. WASM is
// single-threaded so this is safe.
thread_local! {
    static LIBCURL_LATEST_STATE: RefCell<Option<Rc<ConnectionState>>> = const { RefCell::new(None) };
}

fn latest_state() -> Result<Rc<ConnectionState>, JsValue> {
    LIBCURL_LATEST_STATE.with(|slot| {
        slot.borrow()
            .clone()
            .ok_or_else(|| JsValue::from_str("no LibCurl instance available"))
    })
}

// ---- WispHTTPSession ----

/// HTTP session — reuses the connection state across fetches. Same as
/// calling `LibCurl.fetch` repeatedly; sessions are just a facade for
/// libcurl.js API compatibility.
#[wasm_bindgen(js_name = "WispHTTPSession")]
pub struct WispHTTPSessionJs {
    state: Rc<ConnectionState>,
}

#[wasm_bindgen(js_class = "WispHTTPSession")]
impl WispHTTPSessionJs {
    #[wasm_bindgen(constructor)]
    pub fn new(_opts: JsValue) -> Result<WispHTTPSessionJs, JsValue> {
        let state = latest_state()?;
        Ok(Self { state })
    }

    #[wasm_bindgen]
    pub async fn fetch(&self, url: String, opts: JsValue) -> Result<WebResponse, JsValue> {
        let stub = LibCurlJs {
            state: self.state.clone(),
        };
        stub.fetch(url, opts).await
    }

    #[wasm_bindgen]
    pub fn close(&self) {
        // No per-session state to release; the underlying mux is shared.
    }
}

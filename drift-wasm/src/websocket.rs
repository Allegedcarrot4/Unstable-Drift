use std::sync::Arc;

use wasm_bindgen::prelude::*;

use drift_core::wisp::{stream::WispStream, stream_io::WispStreamIo, Mux};
use drift_core::ws::{WebSocketConn, WsMessage};

#[wasm_bindgen(js_name = "WispWebSocket")]
pub struct WispWebSocketJs {
    inner: Arc<std::cell::RefCell<WispWebSocketInner>>,
}

struct WispWebSocketInner {
    conn: Option<WebSocketConn<WispStreamIo>>,
    onmessage: Option<js_sys::Function>,
    onclose: Option<js_sys::Function>,
    onerror: Option<js_sys::Function>,
    ready_state: i32,
}

#[wasm_bindgen(js_class = "WispWebSocket")]
impl WispWebSocketJs {
    #[wasm_bindgen(getter)]
    pub fn ready_state(&self) -> i32 {
        self.inner.borrow().ready_state
    }

    #[wasm_bindgen(setter)]
    pub fn set_onmessage(&self, cb: JsValue) {
        self.inner.borrow_mut().onmessage = if cb.is_function() {
            cb.dyn_into::<js_sys::Function>().ok()
        } else {
            None
        };
    }

    #[wasm_bindgen(setter)]
    pub fn set_onclose(&self, cb: JsValue) {
        self.inner.borrow_mut().onclose = if cb.is_function() {
            cb.dyn_into::<js_sys::Function>().ok()
        } else {
            None
        };
    }

    #[wasm_bindgen(setter)]
    pub fn set_onerror(&self, cb: JsValue) {
        self.inner.borrow_mut().onerror = if cb.is_function() {
            cb.dyn_into::<js_sys::Function>().ok()
        } else {
            None
        };
    }

    #[wasm_bindgen]
    pub fn send(&self, data: JsValue) {
        let inner = self.inner.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let mut inner = inner.borrow_mut();
            if inner.ready_state != 1 {
                return;
            }
            let conn = match inner.conn.as_mut() {
                Some(c) => c,
                None => return,
            };
            if let Some(s) = data.as_string() {
                if let Err(e) = conn.send_text(&s).await {
                    web_sys::console::error_1(&JsValue::from_str(&e.to_string()));
                }
            } else if let Some(buf) = data.dyn_ref::<js_sys::ArrayBuffer>() {
                let bytes = js_sys::Uint8Array::new(buf).to_vec();
                if let Err(e) = conn.send_binary(&bytes).await {
                    web_sys::console::error_1(&JsValue::from_str(&e.to_string()));
                }
            }
        });
    }

    #[wasm_bindgen]
    pub fn close(&self, code: u16, reason: String) {
        let inner = self.inner.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let mut inner = inner.borrow_mut();
            if inner.ready_state >= 2 {
                return;
            }
            inner.ready_state = 2;
            if let Some(ref mut conn) = inner.conn {
                let _ = conn.close(code, &reason).await;
            }
            inner.ready_state = 3;
        });
    }
}

fn set_prop(obj: &js_sys::Object, key: &str, val: &JsValue) {
    let _ = js_sys::Reflect::set(obj, &JsValue::from_str(key), val);
}

pub fn spawn_websocket(
    mux: Arc<Mux>,
    host: String,
    port: u16,
    path: String,
    protocols: Vec<String>,
) -> Result<WispWebSocketJs, JsValue> {
    let inner = Arc::new(std::cell::RefCell::new(WispWebSocketInner {
        conn: None,
        onmessage: None,
        onclose: None,
        onerror: None,
        ready_state: 0,
    }));

    let inner_clone = inner.clone();
    wasm_bindgen_futures::spawn_local(async move {
        let stream_handle = match mux
            .open(&host, port, drift_core::wisp::types::StreamType::Tcp)
            .await
        {
            Ok(h) => h,
            Err(e) => {
                let inner = inner_clone.borrow();
                if let Some(ref cb) = inner.onerror {
                    let evt = js_sys::Object::new();
                    set_prop(&evt, "message", &JsValue::from_str(&format!("drift open: {e}")));
                    let _ = cb.call1(&JsValue::null(), &evt);
                }
                return;
            }
        };
        let ws_stream = WispStream::from_handle(mux, stream_handle);
        let io = WispStreamIo::new(ws_stream);

        let subprotocols: Vec<&str> = protocols.iter().map(|s| s.as_str()).collect();
        match WebSocketConn::connect(io, &host, &path, &subprotocols, &[]).await {
            Ok(conn) => {
                {
                    let mut inner = inner_clone.borrow_mut();
                    inner.conn = Some(conn);
                    inner.ready_state = 1;
                }

                let pump_inner = inner_clone.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    loop {
                        let mut inner = pump_inner.borrow_mut();
                        if inner.ready_state >= 2 {
                            break;
                        }
                        let conn = inner.conn.as_mut().expect("conn missing after handshake");
                        match conn.recv().await {
                            Ok(Some(WsMessage::Text(text))) => {
                                if let Some(ref cb) = inner.onmessage {
                                    let evt = js_sys::Object::new();
                                    set_prop(&evt, "data", &JsValue::from_str(&text));
                                    let _ = cb.call1(&JsValue::null(), &evt);
                                }
                            }
                            Ok(Some(WsMessage::Binary(data))) => {
                                if let Some(ref cb) = inner.onmessage {
                                    let evt = js_sys::Object::new();
                                    let arr = js_sys::Uint8Array::from(data.as_ref());
                                    set_prop(&evt, "data", &arr.buffer());
                                    let _ = cb.call1(&JsValue::null(), &evt);
                                }
                            }
                            Ok(None) => {
                                inner.ready_state = 3;
                                if let Some(ref cb) = inner.onclose {
                                    let evt = js_sys::Object::new();
                                    let _ = cb.call1(&JsValue::null(), &evt);
                                }
                                break;
                            }
                            Err(e) => {
                                inner.ready_state = 3;
                                if let Some(ref cb) = inner.onerror {
                                    let evt = js_sys::Object::new();
                                    set_prop(&evt, "message", &JsValue::from_str(&e.to_string()));
                                    let _ = cb.call1(&JsValue::null(), &evt);
                                }
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => {
                let inner = inner_clone.borrow();
                if let Some(ref cb) = inner.onerror {
                    let evt = js_sys::Object::new();
                    set_prop(&evt, "message", &JsValue::from_str(&format!("WebSocket handshake: {e}")));
                    let _ = cb.call1(&JsValue::null(), &evt);
                }
            }
        }
    });

    Ok(WispWebSocketJs { inner })
}

pub fn parse_ws_url(url: &str) -> Result<(String, u16, String), JsValue> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("wss://") {
        ("wss", r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        ("ws", r)
    } else {
        return Err(JsValue::from_str(
            "connectWebSocket: URL must start with ws:// or wss://",
        ));
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| JsValue::from_str(&format!("connectWebSocket: invalid port: {p}")))?;
        (h.to_string(), port)
    } else {
        let default_port = if scheme == "wss" { 443 } else { 80 };
        (host_port.to_string(), default_port)
    };
    Ok((host, port, path))
}

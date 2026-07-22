//! WebSocket transport for `wasm32-unknown-unknown` targets.
//!
//! Uses the browser's native `WebSocket` via `web-sys`. Because the
//! browser API is event-driven (onopen/onmessage/onerror/onclose), we
//! bridge to async by pushing every inbound message and every
//! terminating event into a `flume` channel that `recv()` polls.
//!
//! The transport is version-neutral at the WebSocket layer: it does NOT
//! advertise a `wisp-v2` subprotocol, because deployed public Wisp
//! servers commonly reject subprotocols they do not echo. Wisp v1/v2
//! negotiation happens in the first protocol packet, matching the
//! native transport and MoonBeam behavior.

#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use bytes::Bytes;
use flume::Receiver;
use js_sys::{ArrayBuffer, Uint8Array};
use parking_lot::Mutex;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{BinaryType, CloseEvent, Event, MessageEvent, WebSocket};

use super::{BoxFuture, TransportError, WispTransport};

/// Signal type internal to the WASM transport — combines inbound data
/// and terminating events on a single channel so `recv()` can await one
/// thing.
enum InboundSignal {
    Data(Bytes),
    Closed,
    Error(String),
}

/// WASM WebSocket transport.
pub struct WebSocketWasmTransport {
    ws: WebSocket,
    inbound_rx: Receiver<InboundSignal>,
    closed: Arc<Mutex<bool>>,

    // Keep the closures alive for the lifetime of the transport; dropping
    // them would deregister the browser event listeners.
    _on_open: Closure<dyn FnMut(JsValue)>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_error: Closure<dyn FnMut(Event)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
}

impl WebSocketWasmTransport {
    /// Open a WebSocket to a wisp server URL.
    ///
    /// No subprotocol is advertised; Wisp version negotiation happens in
    /// the initial Wisp packet exchange.
    ///
    /// # Errors
    ///
    /// - `Handshake` if the browser refuses to create the WebSocket.
    /// - `Closed` if the connection fails during the async handshake wait.
    pub async fn connect(url: &str) -> Result<Arc<Self>, TransportError> {
        let ws = WebSocket::new(url)
            .map_err(|e| TransportError::Handshake(format!("WebSocket ctor: {e:?}")))?;
        ws.set_binary_type(BinaryType::Arraybuffer);

        let (open_tx, open_rx) = flume::bounded::<Result<(), String>>(1);
        let (inbound_tx, inbound_rx) = flume::unbounded::<InboundSignal>();

        // Shared closed-state flag. Cloned into every browser callback so
        // close/error can be recorded synchronously and observed by both
        // send() (short-circuit) and later termination handlers.
        let closed = Arc::new(Mutex::new(false));

        // onopen — unblocks the handshake wait.
        let open_tx_c = open_tx.clone();
        let on_open = Closure::wrap(Box::new(move |_ev: JsValue| {
            // Nonblocking: the browser event loop must never be blocked by
            // a flume send. try_send is safe because the channel is bounded
            // to 1 and only one of open/error/close should ever fire first.
            let _ = open_tx_c.try_send(Ok(()));
        }) as Box<dyn FnMut(JsValue)>);
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        // onmessage — pushes DATA to inbound.
        let inbound_tx_msg = inbound_tx.clone();
        let on_message = Closure::wrap(Box::new(move |ev: MessageEvent| {
            let data = ev.data();
            if let Some(buf) = data.dyn_ref::<ArrayBuffer>() {
                let u8 = Uint8Array::new(buf);
                let mut v = vec![0u8; u8.length() as usize];
                u8.copy_to(&mut v);
                let _ = inbound_tx_msg.try_send(InboundSignal::Data(Bytes::from(v)));
            }
            // String messages are noise for wisp; ignore.
        }) as Box<dyn FnMut(MessageEvent)>);
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        // onerror — surface the error to both the handshake-wait and
        // inbound channels. Treat the event as a generic browser Event:
        // some browsers deliver a plain Event here (not an ErrorEvent)
        // and reading `.message` would crash wasm-bindgen glue with
        // "Cannot read properties of undefined (reading 'length')".
        let open_tx_err = open_tx.clone();
        let inbound_tx_err = inbound_tx.clone();
        let closed_error = closed.clone();
        let on_error = Closure::wrap(Box::new(move |_ev: Event| {
            *closed_error.lock() = true;
            let msg = "WebSocket error".to_string();
            let _ = open_tx_err.try_send(Err(msg.clone()));
            let _ = inbound_tx_err.try_send(InboundSignal::Error(msg));
        }) as Box<dyn FnMut(Event)>);
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        // onclose — mark closed, wake any pre-open waiter (so an early
        // close doesn't leave connect() hanging forever), and signal the
        // inbound channel.
        let open_tx_close = open_tx;
        let inbound_tx_close = inbound_tx;
        let closed_close = closed.clone();
        let on_close = Closure::wrap(Box::new(move |_ev: CloseEvent| {
            *closed_close.lock() = true;
            let _ = open_tx_close.try_send(Err("WebSocket closed before open".to_string()));
            let _ = inbound_tx_close.try_send(InboundSignal::Closed);
        }) as Box<dyn FnMut(CloseEvent)>);
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        // Wait for open (or error/close).
        match open_rx.recv_async().await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(TransportError::Handshake(e)),
            Err(_) => return Err(TransportError::Closed),
        }

        Ok(Arc::new(Self {
            ws,
            inbound_rx,
            closed,
            _on_open: on_open,
            _on_message: on_message,
            _on_error: on_error,
            _on_close: on_close,
        }))
    }
}

impl WispTransport for WebSocketWasmTransport {
    fn send<'a>(&'a self, packet: Vec<u8>) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            if *self.closed.lock() {
                return Err(TransportError::Closed);
            }
            // `send_with_u8_array` copies internally; the browser owns the
            // buffer after this call returns.
            self.ws
                .send_with_u8_array(&packet)
                .map_err(|e| TransportError::Io(format!("ws.send: {e:?}")))
        })
    }

    fn recv<'a>(&'a self) -> BoxFuture<'a, Result<Bytes, TransportError>> {
        Box::pin(async move {
            match self.inbound_rx.recv_async().await {
                Ok(InboundSignal::Data(b)) => Ok(b),
                Ok(InboundSignal::Closed) => {
                    *self.closed.lock() = true;
                    Err(TransportError::Closed)
                }
                Ok(InboundSignal::Error(e)) => Err(TransportError::Io(e)),
                Err(_) => Err(TransportError::Closed),
            }
        })
    }

    fn close<'a>(&'a self) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            {
                let mut c = self.closed.lock();
                if *c {
                    return Ok(());
                }
                *c = true;
            }
            let _ = self.ws.close();
            Ok(())
        })
    }

    fn is_closed(&self) -> bool {
        *self.closed.lock()
    }
}

// Safety: web-sys types are !Send/!Sync by default (WebSocket includes a
// JsValue), but wasm32 is single-threaded. WispTransport requires
// Send + Sync. This is the standard pattern for WASM wrappers.
unsafe impl Send for WebSocketWasmTransport {}
unsafe impl Sync for WebSocketWasmTransport {}

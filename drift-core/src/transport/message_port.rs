//! MessagePort transport (WASM only).
//!
//! Used by Wisp to talk to MoonBeam's in-page relay endpoint. MoonBeam
//! hands out a `MessagePort` from `MoonbeamRelay.attach()`; Wisp wraps it
//! in this transport and speaks wisp v2 over the port.
//!
//! Wire format on the port: each `postMessage` carries exactly one wisp
//! packet as an `ArrayBuffer`. MoonBeam's relay uses this shape too.

#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use bytes::Bytes;
use flume::Receiver;
use js_sys::{ArrayBuffer, Uint8Array};
use parking_lot::Mutex;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, MessagePort};

use super::{BoxFuture, TransportError, WispTransport};

/// A wisp transport backed by a `MessagePort`.
///
/// Take ownership of a port returned by (e.g.) `MoonbeamRelay.attach()`.
/// The transport registers an `onmessage` handler that pushes every
/// inbound packet into an async-observable channel. Sending calls
/// `port.postMessage(ArrayBuffer)` — the browser guarantees message
/// boundary preservation, which is exactly what wisp needs.
pub struct MessagePortTransport {
    port: MessagePort,
    inbound_rx: Receiver<Bytes>,
    closed: Mutex<bool>,

    // Keep the closure alive for the lifetime of the transport.
    _on_message: Closure<dyn FnMut(MessageEvent)>,
}

impl MessagePortTransport {
    /// Wrap a `MessagePort` in a wisp transport.
    ///
    /// Registers an `onmessage` handler and starts the port. **The port
    /// is consumed** — the caller must not attach additional listeners
    /// after handing it over.
    ///
    /// # Errors
    ///
    /// - `Handshake` if the browser rejects `start()` (should never happen
    ///   with a valid port).
    pub fn new(port: MessagePort) -> Result<Arc<Self>, TransportError> {
        let (inbound_tx, inbound_rx) = flume::unbounded::<Bytes>();

        let inbound_tx_msg = inbound_tx.clone();
        let on_message = Closure::wrap(Box::new(move |ev: MessageEvent| {
            let data = ev.data();
            if let Some(buf) = data.dyn_ref::<ArrayBuffer>() {
                let u8 = Uint8Array::new(buf);
                let mut v = vec![0u8; u8.length() as usize];
                u8.copy_to(&mut v);
                let _ = inbound_tx_msg.send(Bytes::from(v));
            }
            // Non-ArrayBuffer messages are unexpected; drop silently.
        }) as Box<dyn FnMut(MessageEvent)>);
        port.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        // Explicitly start the port. Necessary if the port was received
        // via addEventListener rather than via onmessage assignment on
        // the other end. Idempotent.
        port.start();

        Ok(Arc::new(Self {
            port,
            inbound_rx,
            closed: Mutex::new(false),
            _on_message: on_message,
        }))
    }
}

impl WispTransport for MessagePortTransport {
    fn send<'a>(&'a self, packet: Vec<u8>) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            if *self.closed.lock() {
                return Err(TransportError::Closed);
            }
            // Build an ArrayBuffer view over `packet`'s bytes and post it.
            // Uint8Array::from copies into the JS heap — the browser then
            // owns the buffer.
            let u8 = Uint8Array::from(&packet[..]);
            self.port
                .post_message(&u8.buffer())
                .map_err(|e| TransportError::Io(format!("port.postMessage: {e:?}")))
        })
    }

    fn recv<'a>(&'a self) -> BoxFuture<'a, Result<Bytes, TransportError>> {
        Box::pin(async move {
            match self.inbound_rx.recv_async().await {
                Ok(b) => Ok(b),
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
            // MessagePort.close() detaches the port. Idempotent.
            self.port.close();
            Ok(())
        })
    }

    fn is_closed(&self) -> bool {
        *self.closed.lock()
    }
}

// Same rationale as WebSocketWasmTransport: web-sys types are !Send/!Sync
// by default, wasm32 is single-threaded, WispTransport requires them.
unsafe impl Send for MessagePortTransport {}
unsafe impl Sync for MessagePortTransport {}

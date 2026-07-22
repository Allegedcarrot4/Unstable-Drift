//! wisp-wasm — wasm-bindgen glue for Unstable-Wisp.
//!
//! Exposes JS classes:
//!   - `WispClient`: high-level, fetch/WebSocket-shaped.
//!   - `Wisp`: low-level, libcurl-shaped handle.
//!   - `LibCurl`: libcurl.js-shaped adapter for DuskJS drop-in.
//!   - `WispHTTPSession`: session facade for libcurl.js API parity.
//!
//! Also exposes helpers for consuming MoonBeam's `MoonbeamRelay` as a
//! transport.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::prelude::*;

mod client;
mod handle;
mod libcurl;
mod moonbeam;
mod websocket;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook_install();
}

fn console_error_panic_hook_install() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("{info}");
        web_sys::console::error_1(&JsValue::from_str(&msg));
    }));
}

//! MoonBeam relay handoff helpers.
//!
//! MoonBeam's `MoonbeamRelay.attach()` returns a `MessagePort`. Wisp
//! consumes it as a `MessagePortTransport`. This module wires the JS
//! object handoff — takes an arbitrary JS value, checks it has an
//! `.attach` method, calls it, and returns the `MessagePort`.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::MessagePort;

/// Extract a MessagePort from a MoonBeam relay-like JS object.
///
/// Duck-typing: any JS object with an `attach()` method that returns a
/// `MessagePort` is accepted. The MoonBeam TS relay from v0.2 matches
/// this shape.
///
/// # Errors
///
/// Returns a JS error if `obj.attach` isn't callable or the return value
/// isn't a `MessagePort`.
#[wasm_bindgen(js_name = "attachMoonbeam")]
pub fn attach_moonbeam(obj: JsValue) -> Result<MessagePort, JsValue> {
    let obj_ref: &js_sys::Object = obj
        .dyn_ref::<js_sys::Object>()
        .ok_or_else(|| JsValue::from_str("attachMoonbeam: expected an object"))?;
    let attach_fn = js_sys::Reflect::get(obj_ref, &JsValue::from_str("attach"))?;
    let attach_fn: js_sys::Function = attach_fn
        .dyn_into()
        .map_err(|_| JsValue::from_str("attachMoonbeam: obj.attach is not a function"))?;
    let port = attach_fn.call0(&obj)?;
    let port: MessagePort = port
        .dyn_into()
        .map_err(|_| JsValue::from_str("attachMoonbeam: obj.attach() did not return a MessagePort"))?;
    Ok(port)
}

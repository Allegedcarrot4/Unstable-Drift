//! Browser end-to-end tests.
//!
//! Requires `wasm-pack test --chrome` (headless Chrome + wasm-bindgen-test)
//! and MoonBeam v0.2's `MoonbeamRelay` available in the test harness JS.
//!
//! Setup (documented for the user):
//!   1. `cargo install wasm-pack`
//!   2. Ensure a Chromium binary is available on PATH.
//!   3. `wasm-pack test --headless --chrome drift-wasm`
//!
//! These tests are gated by `#[wasm_bindgen_test]` and will not run under
//! stock `cargo test`.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn drift_wasm_module_loads() {
    drift_wasm::init();
}

#[wasm_bindgen_test]
fn wisp_client_constructs_with_string_url() {
    drift_wasm::init();
    use drift_wasm::{WispClientJs, WispClientOptions};
    let opts = WispClientOptions::new(JsValue::from_str("wss://wisp.mercurywork.shop/"));
    let _client = WispClientJs::new(opts).expect("constructor should succeed");
}

/// Online test: requires a reachable Wisp server + httpbin.
/// Marked `#[ignore]` so it doesn't block CI; run with
/// `wasm-pack test --headless --chrome -- --ignored`.
#[wasm_bindgen_test]
#[ignore]
async fn wisp_client_fetch() {
    drift_wasm::init();
    use drift_wasm::{WispClientJs, WispClientOptions};
    let opts = WispClientOptions::new(JsValue::from_str("wss://wisp.mercurywork.shop/"));
    let client = WispClientJs::new(opts).expect("constructor should succeed");
    let resp = client
        .fetch("http://httpbin.org/get".to_string(), JsValue::UNDEFINED)
        .await
        .expect("fetch should succeed");
    let status = resp.status();
    assert_eq!(status, 200, "expected 200 from httpbin, got {status}");
}

/// Online test: requires a reachable Wisp server.
/// Marked `#[ignore]` so it doesn't block CI; run with
/// `wasm-pack test --headless --chrome -- --ignored`.
#[wasm_bindgen_test]
#[ignore]
async fn wisp_websocket_connect_echo() {
    drift_wasm::init();
    use drift_wasm::{WispClientJs, WispClientOptions};
    let opts = WispClientOptions::new(JsValue::from_str("wss://wisp.mercurywork.shop/"));
    let client = WispClientJs::new(opts).expect("constructor should succeed");
    let result = client
        .connect_websocket(
            "wss://echo.websocket.org".to_string(),
            JsValue::UNDEFINED,
            JsValue::UNDEFINED,
        )
        .await;
    assert!(result.is_ok(), "connectWebSocket should succeed, got: {result:?}");
}

#[wasm_bindgen_test]
fn wisp_websocket_options_rejects_bad_url() {
    use drift_wasm::websocket::parse_ws_url;
    assert!(parse_ws_url("not-a-websocket-url").is_err());
    assert!(parse_ws_url("http://example.com").is_err());
}

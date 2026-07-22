//! Browser end-to-end test.
//!
//! Requires `wasm-pack test --chrome` (headless Chrome + wasm-bindgen-test)
//! and MoonBeam v0.2's `MoonbeamRelay` available in the test harness JS.
//!
//! Setup (documented for the user):
//!   1. `cargo install wasm-pack`
//!   2. Ensure a Chromium binary is available on PATH.
//!   3. `wasm-pack test --headless --chrome wisp-wasm`
//!
//! These tests are gated by `#[wasm_bindgen_test]` and will not run under
//! stock `cargo test`.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn drift_wasm_module_loads() {
    // Bare-bones test — confirms the wasm-bindgen glue links and the
    // panic hook installs cleanly.
    drift_wasm::init();
}

// TODO(Task 20.5 follow-up): once WispStream has an AsyncRead adapter,
// add tests that:
//   1. Construct MoonbeamRelay in JS via a test harness.
//   2. Pass it to WispClient.
//   3. Call fetch() and assert the response.
//   4. Call connectWebSocket() and echo a message.

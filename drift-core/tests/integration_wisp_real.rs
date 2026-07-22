//! Real-wisp-server integration test.
//!
//! Not run by default. Enable with `cargo test --test integration_wisp_real
//! --features integration`.
//!
//! Uses `wss://wisp.mercurywork.shop` as the default endpoint (public wisp
//! server maintained by Mercury Workshop). Override with the
//! `DRIFT_TEST_WISP_URL` env var.
//!
//! `wss://quiet.ampscat.dev` is currently offline; do not use as primary.

#![cfg(not(target_arch = "wasm32"))]
#![cfg(feature = "integration")]

use std::sync::Arc;
use std::time::Duration;

use drift_core::transport::WebSocketTransport;
use drift_core::wisp::{Mux, StreamType};
use tokio::time::timeout;

fn wisp_url() -> String {
    std::env::var("DRIFT_TEST_WISP_URL")
        .unwrap_or_else(|_| "wss://wisp.mercurywork.shop/".to_string())
}

#[tokio::test]
async fn handshake_and_open_stream_to_example_com() {
    let url = wisp_url();
    eprintln!("integration: connecting to {url}");

    // Connect. If the wisp server is unreachable, skip loudly.
    let transport = match timeout(Duration::from_secs(15), WebSocketTransport::connect(&url)).await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            eprintln!("SKIP: could not connect to wisp server {url}: {e}");
            return;
        }
        Err(_) => {
            eprintln!("SKIP: connection to {url} timed out");
            return;
        }
    };

    let mux = Arc::new(Mux::new(transport));

    // Drive the handshake with a timeout.
    match timeout(Duration::from_secs(15), mux.run_handshake(&[])).await {
        Ok(Ok(())) => eprintln!("handshake OK"),
        Ok(Err(e)) => panic!("handshake failed: {e}"),
        Err(_) => panic!("handshake timed out"),
    }
    // (Mux::is_established is #[cfg(test)] only; success of open() below
    // is our proof the handshake completed.)

    // Open a TCP stream to example.com:80.
    let handle = match timeout(
        Duration::from_secs(10),
        mux.open("example.com", 80, StreamType::Tcp),
    )
    .await
    {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => panic!("open stream failed: {e}"),
        Err(_) => panic!("open stream timed out"),
    };
    eprintln!("stream open: id={}", handle.id);

    // Immediately close — proves the round-trip works without needing to
    // wire HTTP through the wisp stream (that's Task 20.5).
    mux.close_stream(handle.id, drift_core::wisp::CloseReason::Voluntary)
        .await
        .expect("close stream");
}

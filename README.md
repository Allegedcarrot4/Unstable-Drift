# Unstable-Drift

A high-performance Wisp network client for Rust and WASM. Drift provides HTTP/1.1, HTTP/2, WebSocket, and raw TCP proxying over the Wisp protocol, with full TLS support and SOCKS/HTTP proxy chaining.

## Badges

![Cargo build](https://img.shields.io/badge/build-passing-brightgreen)
![WASM](https://img.shields.io/badge/wasm-✓-blueviolet)
![License](https://img.shields.io/badge/license-MIT-blue)

## Features

- **Wisp protocol v2.1** — multiplexed TCP/UDP streams over a single WebSocket connection
- **HTTP/1.1 & HTTP/2** — full client implementation with TLS, connection pooling, redirect following, and content decompression (gzip, brotli, deflate)
- **WebSocket** — connect to any WebSocket endpoint through a Wisp relay
- **Proxy chaining** — SOCKS4a, SOCKS5, and HTTP CONNECT proxies in arbitrary chains
- **Cross-platform** — native (tokio) and WASM (wasm-bindgen) targets
- **Direct TCP fallback** — bypass the Wisp relay and connect directly when needed
- **WASM libcurl shim** — drop-in replacement for `curl` in browser environments

## Tech

**Rust** — core protocol, HTTP, TLS, proxy logic  
**wasm-bindgen** — browser bindings  
**tokio** — async runtime (native)  
**ring** — TLS cryptography  

## Architecture

```
┌──────────────────────────────────────────┐
│              drift-cli (CLI)              │
├──────────────────────────────────────────┤
│                drift                      │
│   (high-level client, builder, handle)    │
├──────────────────────────────────────────┤
│              drift-core                   │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌─────────┐ │
│  │ wisp │ │ HTTP │ │ TLS  │ │  Proxy  │ │
│  │ proto│ │1.1/2 │ │      │ │ chain   │ │
│  └──────┘ └──────┘ └──────┘ └─────────┘ │
├──────────────────────────────────────────┤
│             drift-wasm                    │
│  (WASM bindings, WispClient, libcurl     │
│   shim, WebSocket bridge)                │
└──────────────────────────────────────────┘
```

## Installation

### Rust (native)

```toml
[dependencies]
drift = { git = "https://github.com/Allegedcarrot4/Unstable-Drift" }
drift-core = { git = "https://github.com/Allegedcarrot4/Unstable-Drift" }
```

### WASM

```sh
wasm-pack build --target web drift-wasm
```

Or install from npm:

```sh
npm install @unstable/drift
```

### CLI

```sh
cargo install --path drift-cli
```

## Usage / Examples

### Rust — HTTP GET

```rust
use drift::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), drift::Error> {
    let client = ClientBuilder::new()
        .wisp_url("wss://wisp.mercurywork.shop/")
        .build()?;

    let mut handle = client.handle("https://httpbin.org/get");
    let response = handle.perform().await?;
    println!("{}", response.body_text());
    Ok(())
}
```

### Rust — WebSocket through Wisp

```rust
use drift::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), drift::Error> {
    let client = ClientBuilder::new()
        .wisp_url("wss://wisp.mercurywork.shop/")
        .build()?;

    let ws = client.connect_websocket("wss://echo.websocket.org").await?;
    ws.send(b"hello").await?;
    let msg = ws.recv().await?;
    println!("echo: {:?}", msg);
    Ok(())
}
```

### JavaScript / WASM

```js
import { WispClientJs } from "@unstable/drift";

const client = WispClientJs.new({ wispUrl: "wss://wisp.mercurywork.shop/" });
const resp = await client.fetch("https://example.com");
console.log(await resp.text());
```

### CLI

```sh
# HTTP request through Wisp relay
drift --wisp wss://wisp.mercurywork.shop/ https://example.com

# With SOCKS5 proxy
drift --wisp wss://wisp.mercurywork.shop/ --socks5 127.0.0.1:9050 https://example.com

# Direct TCP (no relay)
drift https://example.com
```

## Environment Variables

| Variable | Description |
|---|---|
| `DRIFT_TEST_WISP_URL` | Wisp server URL for integration tests (default `wss://wisp.mercurywork.shop/`) |

## Running Tests

```sh
# All tests (excluding WASM)
cargo test --workspace --exclude drift-wasm

# WASM tests (requires Chrome and wasm-pack)
wasm-pack test --headless --chrome drift-wasm

# Integration tests (requires a Wisp server)
cargo test --workspace --exclude drift-wasm --features integration
```

## FAQ

**What is the Wisp protocol?**  
Wisp is a multiplexing protocol that runs TCP and UDP streams over a single WebSocket connection, commonly used to bypass network restrictions in browser environments.

**Does this work in browsers?**  
Yes — `drift-wasm` targets `wasm32-unknown-unknown` and provides a Wisp client via `wasm-bindgen`.

**Can I chain proxies?**  
Yes. Pass multiple `--proxy` or `--socks5` flags, or call `handle.set_proxy_chain()` programmatically.

## License

MIT

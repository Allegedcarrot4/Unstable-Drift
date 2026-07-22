# Unstable-Drift

**A high-performance Wisp network client. Native Rust + WebAssembly.**

[![npm](https://img.shields.io/npm/v/@nightnetwork/drift)](https://www.npmjs.com/package/@nightnetwork/drift)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Unstable-Drift is a Rust implementation of the [Wisp v2.1 protocol](https://github.com/nicbarker/wisp-protocol) with full HTTP/1.1, HTTP/2, WebSocket, TLS, proxy chain, and compression support. It ships as native Rust crates for server/CLI use and a WebAssembly package (`@nightnetwork/drift`) for browsers.

## Features

- **Wisp v2.1 protocol** — multiplexed TCP streams over a single WebSocket
- **HTTP/1.1 + HTTP/2** — HTTP/2 via patched [`h2-wasm`](https://github.com/r58Playz/h2-wasm) for WASM targets
- **TLS** — rustls-based, works on both native and WASM (via `futures-rustls`)
- **WebSocket upgrade** — client-initiated WS connections over wisp streams
- **Proxy chains** — SOCKS4/4a/5 and HTTP CONNECT proxies of arbitrary depth
- **Compression** — transparent gzip/brotli response decompression
- **MoonBeam relay integration** — route wisp traffic through a `@nightnetwork/moonbeam` relay via `MessagePort` transport
- **MessagePort transport** — use any `MessagePort`-based channel as the underlying wisp transport
- **libcurl-compatible JS API** — drop-in `LibCurl` class for DuskJS and similar consumers
- **WispClient** — high-level reqwest-shaped Rust client with builder pattern
- **`drift` CLI** — curl-shaped command-line tool (~40 flags)

## Crates

| Crate | Purpose |
|---|---|
| `drift-core` | Low-level engine: wisp mux, transports, TLS, HTTP/1.1+2, WebSocket, proxy chains, compression |
| `drift` | High-level client: `WispClient`, `RequestBuilder`, `Response` (reqwest-shaped) |
| `drift-cli` | The `drift` binary with curl-shaped flags |
| `drift-wasm` | wasm-bindgen glue exposing `LibCurl`, `Wisp`, `WispClient`, and `WispHTTPSession` to JS |
| `drift-test-support` | Test utilities: mock wisp server, paired transports |

## Installation

### npm (WASM — browser)

```bash
npm install @nightnetwork/drift
```

### Cargo (Rust — native)

```toml
[dependencies]
drift = { git = "https://github.com/anomalyco/drift" }
drift-core = { git = "https://github.com/anomalyco/drift" }
```

## Quick Start

### WASM with MoonBeam

```js
import { MoonbeamRelay } from '@nightnetwork/moonbeam';
import init, { LibCurl } from '@nightnetwork/drift';

await init();

const lc = new LibCurl();

// Option A: Direct wisp WebSocket
lc.set_websocket('wss://wisp.example.com/');

// Option B: MoonBeam relay (preferred in production)
const relay = await MoonbeamRelay.create({ wispUrl: 'wss://wisp.example.com/' });
lc.set_moonbeam_relay(relay);

// Fetch
const resp = await lc.fetch('https://example.com/', { method: 'GET' });
console.log(resp.status, await resp.text());
```

### WASM with WispClient

```js
import init, { WispClient, WispClientOptions, attachMoonbeam } from '@nightnetwork/drift';
import { MoonbeamRelay } from '@nightnetwork/moonbeam';

await init();

const relay = await MoonbeamRelay.create({ wispUrl: 'wss://wisp.example.com/' });
const port = attachMoonbeam(relay);

const opts = new WispClientOptions(port);
const client = new WispClient(opts);
const resp = await client.fetch('https://example.com/');
console.log(resp.status);
```

### Rust (native)

```rust,no_run
use std::sync::Arc;
use drift::WispClient;
use drift_core::transport::WebSocketTransport;
use drift_core::drift::Mux;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let transport = WebSocketTransport::connect("wss://wisp.example.com/").await?;
let mux = Arc::new(Mux::new(transport));
mux.run_handshake(&[]).await?;

let client = WispClient::builder().mux(mux).build()?;
let resp = client
    .get("https://example.com/")
    .header("x-foo", "bar")
    .send()
    .await?;

println!("{}: {}", resp.status(), resp.text()?);
# Ok(()) }
```

## LibCurl JS API Reference

The `LibCurl` class provides a libcurl.js-compatible interface for browser use.

### `new LibCurl()`

Construct a new instance.

### `lc.load_wasm(url?): Promise<void>`

No-op in Wisp. Kept for API compatibility with libcurl.js. Wisp's WASM is loaded via `init()`.

### `lc.set_websocket(url: string): void`

Set the wisp server WebSocket URL. All subsequent requests route through this endpoint.

### `lc.set_moonbeam_relay(relay: object): void`

Route wisp traffic through a MoonBeam relay instead of a direct WebSocket. `relay` must be a JS object with an `.attach()` method returning a `MessagePort` (matches `@nightnetwork/moonbeam` v0.2+ `MoonbeamRelay`). Calling this clears any previously set WebSocket URL.

### `lc.fetch(url: string, opts?: object): Promise<Response>`

Perform an HTTP fetch. Returns a standard `Response`. Options:
- `method` — HTTP method string (default `"GET"`)
- `headers` — plain object of `{ name: value }` pairs
- `body` — string or `Uint8Array`

### `lc.HTTPSession` (getter)

Returns the `WispHTTPSession` constructor for session-based fetching. Sessions reuse connection state across fetches.

```js
const Session = lc.HTTPSession;
const session = new Session();
const resp = await session.fetch('https://example.com/');
session.close();
```

### `lc.transport` (getter)

Returns `"drift"` — the transport protocol name.

### `lc.version` (getter)

Returns the Wisp libcurl shim version string.

### `lc.WebSocket` (getter)

Currently returns `undefined`. Full WebSocket-over-wisp support is a follow-up.

### `lc.TLSSocket` (getter)

Currently returns `undefined`. Raw TLS socket support is a follow-up.

## WispClient Rust API

`WispClient` provides a high-level, reqwest-shaped interface.

```rust
let client = WispClient::builder()
    .mux(mux)                          // required: wisp Mux
    .user_agent("myapp/1.0")           // optional
    .default_header("x-api-key", key)  // optional, repeatable
    .tls_options(tls_opts)             // optional
    .http_options(http_opts)           // optional
    .tcp_options(tcp_opts)             // optional
    .timeout_options(timeout_opts)     // optional
    .cookie_options(cookie_opts)       // optional
    .dns_options(dns_opts)             // optional
    .build()?;
```

### Request methods

- `client.get(url)` — start a GET request
- `client.post(url)` — start a POST request
- `client.put(url)` — start a PUT request
- `client.delete(url)` — start a DELETE request
- `client.head(url)` — start a HEAD request
- `client.request(method, url)` — start a request with a custom method

All return a `RequestBuilder`. Chain `.header(name, value)`, `.body(bytes)`, then `.send().await`.

### Low-level: `WispHandle`

For libcurl-parity control, use `drift_core::WispHandle` directly:

```rust
let mut handle = WispHandle::new();
handle.set_url("https://example.com/")?;
handle.set_method(Method::Post);
handle.add_header("content-type", "application/json");
handle.set_body(Body::Text("{\"key\":\"value\"}".into()));
handle.set_mux(mux);

let response = handle.perform().await?;
println!("Status: {}", response.status);
```

Table-driven options via `set_option(Opt, OptValue)`:

| Option | Value type | Description |
|---|---|---|
| `TlsVerifyPeer` | `Bool` | Verify TLS peer certificate |
| `TlsVerifyHost` | `Bool` | Verify TLS hostname |
| `TlsMinVersion` | `TlsVersion` | Minimum TLS version |
| `TlsMaxVersion` | `TlsVersion` | Maximum TLS version |
| `HttpFollowRedirects` | `Bool` | Follow HTTP redirects |
| `HttpMaxRedirects` | `U32` | Maximum redirect hops |
| `TcpNodelay` | `Bool` | TCP_NODELAY |
| `TcpKeepalive` | `Bool` | TCP keepalive |
| `TimeoutTotal` | `Duration` / `None` | Total request timeout |
| `TimeoutConnect` | `Duration` | Connection timeout |
| `CookiesEnabled` | `Bool` | Enable cookie jar |
| `UserAgent` | `String` | User-Agent header |
| `Verbose` | `Bool` | Debug logging |
| `MaxResponseSize` | `U64` / `None` | Max response body bytes |

## CLI Usage

```bash
wisp https://example.com/
wisp -X POST -H 'content-type: application/json' -d '{"hi":true}' https://example.com/
wisp --wisp wss://wisp.example.com/ --proxy socks5://bastion:1080 https://example.com/
wisp --help
```

~40 curl-shaped flags supported. Not a full curl clone by design.

## Building

### Native

```bash
cargo build --workspace
```

### WASM

```bash
cargo build -p drift-core --target wasm32-unknown-unknown
cargo build -p drift-wasm --target wasm32-unknown-unknown

# JS-consumable package via wasm-pack:
wasm-pack build --target web drift-wasm
```

## Testing

### Unit tests

```bash
cargo test --workspace
```

### Integration tests (real wisp server)

```bash
cargo test -p drift-core --test integration_wisp_real --features integration
```

Set `DRIFT_TEST_WISP_URL` to override the default endpoint.

### Browser end-to-end

Requires headless Chrome and MoonBeam v0.2:

```bash
wasm-pack test --headless --chrome drift-wasm
```

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                   Consumers                      │
│  drift-cli (curl-shaped)  │  wisp (WispClient)   │
├─────────────────────────┬───────────────────────┤
│                  drift-core                       │
│  ┌─────────┐  ┌──────┐  ┌─────┐  ┌───────────┐ │
│  │WispHandle│  │ HTTP │  │ TLS │  │ Proxy     │ │
│  │(libcurl) │  │1.1+2 │  │rustls│ │SOCKS/HTTP│ │
│  └────┬─────┘  └──┬───┘  └──┬──┘  └─────┬────┘ │
│       └──────┬────┘─────────┘───────────┘       │
│         ┌────▼─────┐                             │
│         │ Wisp Mux │  (v2.1 multiplexer)        │
│         └────┬─────┘                             │
│    ┌─────────┼──────────┐                        │
│    ▼         ▼          ▼                        │
│ WebSocket  MessagePort  (pluggable transport)   │
│ Transport  Transport                             │
└─────────────────────────────────────────────────┘
         │                │
    Direct WS       MoonBeam Relay
```

**drift-core** owns the protocol stack: wisp mux, stream lifecycle, transports, TLS (rustls on native, futures-rustls on WASM), HTTP/1.1 codec, HTTP/2 (h2-wasm), WebSocket upgrade, SOCKS/HTTP CONNECT proxy chains, and gzip/brotli decompression.

**Unstable-Drift** wraps `drift-core` in a reqwest-shaped builder API (`WispClient` → `RequestBuilder` → `Response`).

**drift-wasm** provides wasm-bindgen bindings exposing `LibCurl` (DuskJS-compatible), `Wisp` (low-level handle), `WispClient` (high-level), and `WispHTTPSession` (session-based fetching) to JavaScript.

**drift-cli** is a curl-shaped binary built on `Wisp`.

## Non-goals

- HTTP/3 / QUIC
- SMTP / FTP / LDAP / RTSP / other non-web protocols
- Full curl CLI compatibility (curl-shaped only)
- FIPS mode / aws-lc-rs crypto (WASM-incompatible)
- Pre-transport proxy (proxying between Wisp and the wisp WebSocket itself)
- Dynamic-library plugin loading for custom protocols

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/anomalyco/drift).

## License

Apache-2.0. See [LICENSE](LICENSE).

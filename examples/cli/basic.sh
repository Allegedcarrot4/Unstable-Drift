#!/usr/bin/env bash
set -euo pipefail

echo "=== Basic HTTP request through Wisp ==="
cargo run --bin drift -- --wisp wss://wisp.mercurywork.shop/ https://example.com

echo ""
echo "=== With SOCKS5 proxy ==="
cargo run --bin drift -- --wisp wss://wisp.mercurywork.shop/ --socks5 127.0.0.1:9050 https://example.com

echo ""
echo "=== Direct TCP (no relay) ==="
cargo run --bin drift -- https://httpbin.org/get

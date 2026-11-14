#!/bin/sh
# 构建 WASM 并启动本地调试台
set -e
cd "$(dirname "$0")"
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/waf_debug.wasm web/
echo "WASM 已构建: web/waf_debug.wasm"
cd web
PORT="${1:-8080}"
echo "调试台: http://localhost:$PORT"
python3 -m http.server "$PORT"

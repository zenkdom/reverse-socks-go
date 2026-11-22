#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
chmod +x ./socks-control-linux-amd64 2>/dev/null || true
echo "Starting Reverse SOCKS5 Control Server (Go)..."
./socks-control-linux-amd64 --config config.json

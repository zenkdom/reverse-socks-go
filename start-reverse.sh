#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
chmod +x ./socks-reverse-linux-amd64 2>/dev/null || true
echo "Starting Reverse SOCKS5 Agent (Go)..."
./socks-reverse-linux-amd64 --config socks-reverse/config.json

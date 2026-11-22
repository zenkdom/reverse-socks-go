# Reverse SOCKS5, UDP, HTTP & MTProto Proxy Cluster (Go High-Speed)

[![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version Available](https://img.shields.io/badge/Python%20Version-AsyncIO-blue.svg)](https://github.com/zenkdom/reverse-socks-python)
[![Telegram Fake-TLS 1.3](https://img.shields.io/badge/Telegram-MTProto%20Fake--TLS-blue.svg)](https://telegram.org)

> [!NOTE]
> 🔄 **100% Cross-Compatible Protocol:**  
> This Go implementation and our **[Python Version](https://github.com/zenkdom/reverse-socks-python)** share the exact same binary multiplexing protocol. Any Go reverse agent (`socks-reverse`) can connect to a Python control server, and any Python reverse agent can connect to a Go control server seamlessly.

High-performance reverse proxy cluster engineered in **Go**:
- **Universal Multi-Protocol Listener** (Port `1080`):
  - **SOCKS5 with full TCP & UDP support**: `CONNECT` (0x01), `BIND` (0x02), and `UDP ASSOCIATE` (0x03) per RFC 1928 / RFC 1929. Full compatibility with Telegram VoIP calls, WebRTC, DNS, gaming, and QUIC/HTTP3.
  - **SOCKS4 & SOCKS4a**: support for legacy clients and remote domain resolution.
  - **HTTP & HTTPS (CONNECT) Proxy**: tunneling for HTTPS traffic and direct forward-proxying with Basic authentication.
  - Automatic on-the-fly protocol detection on a single port.
- **MTProto Fake-TLS 1.3 Engine** (Port `8443`):
  - Circumvents DPI/firewall filtering by masquerading as TLS 1.3 to legitimate domains (`google.com`).
  - Active probe defense: scanner probes are forwarded to genuine Google endpoints returning authentic certificates.
  - Support for Obfuscated2 (`Hex32`) and Promo TAGs from `@MTProxybot`.
- **Built-in Web Administration UI** (Port `9001`):
  - Manage SOCKS5 and MTProto credentials with real-time node health monitoring.
  - 1-click `tg://proxy` connect links and clipboard export.
- **Outbound Reverse Node Pool (`socks-reverse`)**:
  - Exit nodes connect back through NAT, CGNAT, and firewalls to register with the control server.
  - Independent round-robin rotation per user and automatic 2-second failover.
- **Multi-Tor Cluster Module (`reverse-multi-tor`)**:
  - Run 10 isolated exit nodes with guaranteed distinct external IPs via Tor `IsolateSOCKSAuth`.

---

## ⚡ Why Go for High-Speed Networking?

1. **Hardware-Accelerated AES-NI Encryption**:
   - The Go standard library `crypto/aes` executes hardware AES-NI CPU instructions directly in assembly, yielding multi-gigabit throughput with negligible CPU utilization.
2. **Zero-Allocation Buffer Pools (`sync.Pool`)**:
   - Pre-allocated 32 KB network buffers eliminate heap allocations in data relay loops, preventing Garbage Collector latency spikes under heavy traffic.
3. **Native Epoll / IOCP Runtime Pollers**:
   - Lightweight goroutines consume mere kilobytes of memory per connection, allowing hundreds of thousands of concurrent TCP/UDP streams on modest VPS hardware.
4. **Optimized Socket Options**:
   - Algorithms like Nagle are disabled (`SetNoDelay(true)`) to minimize latency and packet jitter.
5. **Single Self-Contained Binaries**:
   - No runtime, Python interpreters, or external packages required. Compiles to standalone static binaries for Linux, Windows, and macOS.

---

## 🏗 Architecture

```
                             +---------------------------------------+
                             |           WEB ADMINISTRATOR           |
                             |       http://CONTROL_IP:9001          |
                             |       Default: admin / changeme123    |
                             +-------------------+-------------------+
                                                 |
                                                 | 1-Click Telegram Setup /
                                                 | SOCKS5 User Management
                                                 v
+---------------------------------------+   +---------------------------------------+
|                CLIENTS                |   |             socks-control             |
|    (Browser, curl, Telegram, apps)    |   |           (Written in Go)             |
+-------------------+-------------------+   |                                       |
                    | SOCKS5 / HTTP (Auth)  |   * Port 1080: SOCKS5/4/HTTP Proxy    |
                    +---------------------->|   * Port 8443: MTProto Fake-TLS (TG)  |
                                            |   * Port 9000: Reverse Agent Bridge   |
+---------------------------------------+   |   * Port 9001: Web Admin Panel        |
|            TELEGRAM CLIENT            |   |   * Balancer: Per-User Rotation       |
|        (iOS, Android, Desktop)        |   +-------------------+-------------------+
+-------------------+-------------------+                       ^
                    | MTProto Fake-TLS (8443)                           |
                    | (Masquerading as google.com)                      |
                    +---------------------------------------------------+
                                                                        |
                                                Outbound Tunnels        |
                                +---------------------------------------+---------------------------------------+
                                |                                                                               |
                                | Port 9000                                                             | Port 9000
                                v                                                                               v
                   +-------------------------+                                                     +-------------------------+
                   |      socks-reverse      |                                                     |      socks-reverse      |
                   |      (Exit Node #1)     |                                                     |      (Exit Node #2)     |
                   |      reverse-node-1     |                                                     |      reverse-node-2     |
                   +------------+------------+                                                     +------------+------------+
                                |                                                                               |
                                | Direct Internet Access                                                        | Direct Internet Access
                                v                                                                               v
                   +-------------------------+                                                     +-------------------------+
                   |    Target Websites      |                                                     |   Telegram DataCenters  |
                   |      (Node #1 IP)       |                                                     |       (Node #2 IP)      |
                   +-------------------------+                                                     +-------------------------+
```

---

## 📁 Repository Structure

```text
reverse-socks-go/
├── cmd/
│   ├── socks-control/       # Master Control Server (SOCKS5, MTProto, Bridge, Web UI)
│   ├── socks-reverse/       # Outbound Reverse Exit Node
│   └── reverse-multi-tor/   # Multi-Tor 10-node Cluster Runner
├── pkg/
│   ├── protocol/            # Multiplexing binary protocol, Fake-TLS 1.3, UDP frames
│   ├── control/             # Agent pool manager, per-user rotation, fast failover
│   ├── proxy/               # SOCKS5 (TCP/UDP/BIND), SOCKS4/4a, HTTP/HTTPS engine
│   ├── mtproto/             # MTProto Fake-TLS + Hex32, probe deflection
│   ├── admin/               # Web Admin UI & REST API
│   ├── users/               # SOCKS5 and MTProto user storage
│   ├── agent/               # Reverse agent tunnel execution
│   └── tor/                 # Tor client & stream isolation
├── test/
│   └── all_test.go          # Integration test suite
├── config.example.json      # Configuration template
├── start-control.sh / .bat  # Master startup scripts
└── start-reverse.sh / .bat  # Exit node startup scripts
```

---

## 🚀 Quick Start Guide

### Step 1. Master Server Setup (`socks-control`)

1. Build or download the binary:
   ```bash
   go build -o socks-control ./cmd/socks-control
   ```

2. Copy configuration:
   ```bash
   cp config.example.json config.json
   ```

3. Launch server:
   ```bash
   ./socks-control --config config.json
   ```

---

### Step 2. Outbound Exit Node Setup (`socks-reverse`)

Run an exit node on any machine:

```bash
go build -o socks-reverse ./cmd/socks-reverse

./socks-reverse --host YOUR_CONTROL_SERVER_IP --port 9000 --token SecretProxyToken2026! --agent-id exit-node-1
```

*With Fake-TLS encapsulation:*
```bash
./socks-reverse --host YOUR_CONTROL_SERVER_IP --port 9000 --token SecretProxyToken2026! --agent-id exit-node-1 --fake-tls --fake-tls-domain google.com
```

---

### Step 3. Multi-Tor 10-Node Cluster Module

```bash
go build -o reverse-multi-tor ./cmd/reverse-multi-tor
./reverse-multi-tor --config config.json
```

> ⚠️ *Note on Tor latency:* Tor onion routing introduces significant latency (300–800ms ping). For streaming, gaming, and VoIP, **we recommend deploying standard `socks-reverse` agents on your own VPS servers**.

---

## 🧪 Testing

Run all unit and integration tests:
```bash
go test -v ./test/...
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

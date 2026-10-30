# BugScanX-Go (v2.0.0-go)

High-performance, **Zero-False-Negative** Go rewrite of **BugScanX** for discovering zero-rated / allowed SNI, HTTP/HTTPS, and WebSocket hosts, IPs, CIDRs, and allowed request methods in software testing and bug bounty reconnaissance.

---

## 🚀 Key Improvements Over the Python Version

1. **All 35 HTTP + Newer IETF (`QUERY`, `PRI`) + WebDAV/Bypass Methods Built-In**:
   - **Core RFC 9110 (9)**: `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `OPTIONS`, `TRACE`, `PATCH`, `CONNECT`
   - **Newer IETF & HTTP/2 (2)**: `QUERY` (IETF Safe/Idempotent Query with body support), `PRI` (HTTP/2 Connection Preface)
   - **Extended / WebDAV / Firewall Bypass (24)**: `PROPFIND`, `PROPPATCH`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`, `SEARCH`, `REPORT`, `ACL`, `PURGE`, `LINK`, `UNLINK`, `MKCALENDAR`, `ORDERPATCH`, `VERSION-CONTROL`, `CHECKIN`, `CHECKOUT`, `UNCHECKOUT`, `MKWORKSPACE`, `UPDATE`, `LABEL`, `MERGE`, `BASELINE-CONTROL`, `MKACTIVITY`
   - **Automatic `Content-Length: 0` & Authority-Form Handling**: Prevents servers from returning false `411 Length Required` or hanging on `POST`, `QUERY`, `PROPFIND`, `PUT`, `PATCH`, `REPORT`, `SEARCH`, or `CONNECT`.

2. **Zero-False-Negative Engine (Never Skips Working Hosts or IPs)**:
   - **Multi-DNS Fallback Resolver (`internal/resolver`)**: Queries in-memory cache → OS DNS → Cloudflare (`1.1.1.1`) → Google (`8.8.8.8`) → Quad9 (`9.9.9.9`) over **both UDP and TCP**, ensuring UDP packet loss never drops a valid domain.
   - **Multi-IP Failover**: If a domain resolves to multiple A/AAAA records and the first IP times out, automatically tests secondary IPs.
   - **Smart HTTP ↔ HTTPS Auto-Switch**: Automatically switches protocols if a plain HTTP probe hits a TLS port (e.g., `400 The plain HTTP request was sent to HTTPS port` or raw TLS alert bytes) or vice versa.
   - **Permissive TLS (`TLS 1.0` – `TLS 1.3` + All Cipher Suites)**: Never skips legacy or custom TLS stacks, and complies with RFC 6066 (omits literal IP in SNI unless custom SNI spoofing is specified).
   - **Raw Wire Socket Fallback**: If Go's strict `net/http` parser rejects a non-standard server header or custom verb, automatically falls back to a raw TCP/TLS socket probe.
   - **Fixed WebSocket `101 Switching Protocols` Bug**: Reads headers up to `\r\n\r\n` immediately without waiting for socket `EOF`, capturing 100% of working WebSocket tunnels in `<100ms` + supports `[split]` TCP packet fragmentation.
   - **Complete CIDR & Range Support**: Properly scans `/32` (1 IP), `/31` (2 IPs), standard subnets, and `start-end` IP ranges (`104.16.1.1-104.16.1.254`).

---

## 📱 Install & Run in Termius / Termux (Android & Linux VPS)

### Option 1: One-Line Global Command Installer (`scan`, `bugscanxgo`, `bx`)
Run this single command inside **Termius** (on your Android phone or Linux VPS):
```bash
curl -sL https://raw.githubusercontent.com/HMACreations/bugscanx-go/main/install.sh | bash && source ~/.bashrc 2>/dev/null || true
```
Once installed, open any terminal and simply type:
```bash
scan
# or
bugscanxgo
# or
bugscanx-go
# or
bx
```

### Option 2: Direct Single-Binary Run
```bash
# On Android (ARM64 / Termux / Termius Local Shell):
curl -L https://raw.githubusercontent.com/HMACreations/bugscanx-go/main/dist/bugscanx-android-arm64 -o scan && chmod +x scan && ./scan

# On Linux VPS (x86_64 Ubuntu/Debian):
curl -L https://raw.githubusercontent.com/HMACreations/bugscanx-go/main/dist/bugscanx-linux-amd64 -o scan && chmod +x scan && ./scan
```

### Option 3: Clone Repository & Run Installer
```bash
git clone https://github.com/HMACreations/bugscanx-go.git && cd bugscanx-go && bash install.sh
```

---

## ⚡ Quick Start (Windows / Linux / Android)

### 1. Interactive Menu Mode
```powershell
.\bugscanx.exe
```

### 2. Direct CLI Automation Mode
```powershell
# Scan hosts file with all 17 Core + Modern Bypass methods (GET, HEAD, POST, OPTIONS, QUERY, PROPFIND, etc.)
.\bugscanx.exe -mode direct -file hosts.txt -ports 80,443,8080,8443 -methods bypass -workers 200 -out hits.txt

# Scan a CIDR range excluding 301/302 redirects with all 35 HTTP/WebDAV methods and custom SNI spoofing
.\bugscanx.exe -mode no302 -target 104.16.0.0/24 -ports 80,443 -methods all -sni zero.example.com -out cidr_hits.txt

# Test WebSocket 101 Switching Protocols across hosts/IPs
.\bugscanx.exe -mode proxytest -file hosts.txt -host in1.wstunnel.site -ports 80,443 -out ws_hits.txt
```

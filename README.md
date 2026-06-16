# GateKeeper — Distributed Zero-Trust Edge Access Platform

```text
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                      ║
║   ██████╗  █████╗ ████████╗███████╗██╗  ██╗███████╗███████╗██████╗ ███████╗██████╗  ║
║  ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝██║ ██╔╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗ ║
║  ██║  ███╗███████║   ██║   █████╗  █████╔╝ █████╗  █████╗  ██████╔╝█████╗  ██████╔╝ ║
║  ██║   ██║██╔══██║   ██║   ██╔══╝  ██╔═██╗ ██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██╔══██╗ ║
║  ╚██████╔╝██║  ██║   ██║   ███████╗██║  ██╗███████╗███████╗██║     ███████╗██║  ██║ ║
║   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝ ║
║                                                                                      ║
║                Distributed Zero-Trust Edge Access Platform                           ║
║                                                                                      ║
║   🔒 Cryptographic Request Authentication                                            ║
║   🛡️ Multi-Layer Threat Inspection Engine                                             ║
║   🌐 Secure Tunnel-Based Origin Isolation                                             ║
║   🔑 One-Time Access Engine                                                           ║
║   ⚡ Trusted Reverse Proxy Gateway                                                    ║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

<p align="center">
  <img src="https://img.shields.io/badge/Cloudflare-Workers-orange?style=for-the-badge&logo=cloudflare" />
  <img src="https://img.shields.io/badge/Python-Reverse_Proxy-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Node.js-Dashboard-green?style=for-the-badge&logo=node.js" />
  <img src="https://img.shields.io/badge/Zero_Trust-Architecture-success?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Production_Ready-brightgreen?style=for-the-badge" />
</p>

---

# 📦 Overview

GateKeeper is a lightweight but enterprise-grade distributed edge authentication and secure application access platform built using:

- Cloudflare Workers
- Cloudflare Tunnel
- Custom reverse proxy enforcement
- HMAC request authentication
- KV-based replay protection
- Multi-layer WAF enforcement

The platform protects dashboards, APIs, login systems, and administrative services without exposing origin infrastructure publicly.

---

# 🧠 Core Architecture

```text
Internet
   │
   ▼
┌──────────────────────────────────────┐
│     Threat Inspection Engine         │
│                                      │
│  • Geo filtering                     │
│  • ASN intelligence                  │
│  • Bot detection                     │
│  • AI crawler filtering              │
│  • Rate limiting                     │
└────────────────┬─────────────────────┘
                 ▼
┌──────────────────────────────────────┐
│   Edge Authentication Gateway        │
│                                      │
│  • HMAC validation                   │
│  • Timestamp verification            │
│  • Nonce replay protection           │
│  • OTP validation                    │
│  • Admin authorization               │
└────────────────┬─────────────────────┘
                 ▼
┌──────────────────────────────────────┐
│      Cloudflare Tunnel Transport     │
└────────────────┬─────────────────────┘
                 ▼
┌──────────────────────────────────────┐
│       Secure Origin Gateway          │
│                                      │
│  localhost:8083                      │
│                                      │
│  • Trusted edge validation           │
│  • Internal service routing          │
│  • Protected application forwarding  │
└────────────────┬─────────────────────┘
                 ▼
     ┌───────────┼───────────┐
     ▼           ▼           ▼

 localhost   localhost   localhost

   :8080       :8081       :8082

 Dashboard   Login/Auth      APIs
```

---

# 🔁 Full Request Lifecycle

```text
1. Request enters Cloudflare Edge
2. WAF threat inspection executes
3. Geo restrictions evaluated
4. ASN intelligence checks applied
5. Bot and AI crawler filtering executed
6. Request reaches Edge Authentication Gateway
7. HMAC signature validated
8. Timestamp freshness verified
9. Nonce replay protection enforced
10. OTP/session validation executed
11. Trusted edge headers generated
12. Request routed through Cloudflare Tunnel
13. Secure Origin Gateway validates headers
14. Internal application selected
15. Response securely returned
```

---

# 🛡️ Multi-Layer Threat Inspection Engine

GateKeeper includes layered edge security enforcement before requests reach protected services.

## WAF Enforcement Rules

```text
Rule 1 → Path Validation
Rule 2 → Geo Restriction
Rule 3 → ASN Intelligence Blocking
Rule 4 → Bot Detection
Rule 5 → AI Crawler Filtering
```

## Security Capabilities

- SQL injection filtering
- XSS detection
- Path traversal protection
- AI crawler blocking
- ASN intelligence filtering
- Country restrictions
- Threat scoring
- Replay protection
- Rate limiting
- Suspicious request analysis

---

# 🔐 Cryptographically Signed Request Authentication

Every protected request is validated using HMAC SHA-256 signed headers.

## Required Headers

```text
X-Client-Key
X-Signature
X-Timestamp
X-Nonce
```

## Signature Payload

```text
METHOD:PATH:TIMESTAMP:NONCE
```

## Validation Pipeline

```text
1. Client generates HMAC signature
2. Worker reconstructs payload
3. Signature verified using SECRET_KEY
4. Timestamp freshness checked
5. Nonce uniqueness validated
6. Request authorized
```

---

# 🔄 Replay Protection Engine

GateKeeper prevents replay attacks using KV-backed nonce validation.

## Flow

```text
1. Unique nonce generated per request
2. Nonce stored temporarily in KV
3. Reuse attempt detected
4. Request immediately blocked
```

## KV Namespace Format

```text
nonce:${clientId}:${nonce}
```

---

# 🔑 One-Time Access Engine

GateKeeper includes dynamic temporary access URL management.

## Features

- Temporary secure URLs
- Expiration enforcement
- Usage limits
- Dynamic revocation
- Redirect path control
- Custom identifiers
- KV-based persistence

---

# 🌐 Zero-Trust Tunnel Isolation

Origin infrastructure is never publicly exposed.

All requests must traverse:

```text
Cloudflare Edge
        ↓
Threat Inspection Engine
        ↓
Edge Authentication Gateway
        ↓
Cloudflare Tunnel
        ↓
Secure Origin Gateway
        ↓
Protected Internal Services
```

---

# 🔄 Trusted Origin Enforcement

The Secure Origin Gateway validates trusted edge traffic before forwarding requests internally.

## Trusted Headers

```text
X-CDN-Verified
X-CDN-Client-ID
```

## Origin Validation

The reverse proxy only accepts:

- authenticated Worker traffic
- trusted tunnel requests
- validated edge headers
- approved internal routes

---

# 📡 Public Endpoints

## Public Routes

```text
/health
/status
/robots.txt
```

## Authentication Routes

```text
/api/auth/token
/auth/callback
/auth/logout
```

## Admin Routes

```text
/admin/stats
/admin/clients
/admin/tokens
/admin/otp/create
/admin/otp/update
/admin/otp/revoke
/admin/otp/status
```

## Protected Routes

```text
/
/dashboard
/protected/*
```

---

# 🔑 OTP Administration Examples

## Create OTP

```bash
curl -X POST https://login.support-noreply.help/admin/otp/create \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{
    "clientId": "client-2",
    "expiresIn": 500,
    "maxUses": 1,
    "redirectPath": "/testing",
    "customId": "testing"
  }'
```

## Check OTP Status

```bash
curl -H "X-Admin-Token: $ADMIN_TOKEN" \
"https://login.support-noreply.help/admin/otp/status?custom_id=testing"
```

## Reset Usage Count

```bash
curl -X POST https://login.support-noreply.help/admin/otp/update \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"custom_id":"testing","action":"reset_uses","value":1}'
```

## Extend Expiry

```bash
curl -X POST https://login.support-noreply.help/admin/otp/update \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"custom_id":"testing","action":"extend","value":500}'
```

## Change Redirect Path

```bash
curl -X POST https://login.support-noreply.help/admin/otp/update \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"custom_id":"testing","action":"change_path","value":"/new-path"}'
```

## Revoke OTP

```bash
curl -X POST https://login.support-noreply.help/admin/otp/revoke \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"custom_id":"testing"}'
```

---

# ⚙️ Environment Variables

## Generate SECRET_KEY

```bash
openssl rand -base64 32
```

## SECRET_KEY

```env
SECRET_KEY=base64secret
```

## ALLOWED_CLIENTS

```json
["client-1","client-2"]
```

## AUTH_ENABLED

```env
AUTH_ENABLED=true
```

---

# 🚇 Cloudflare Tunnel Setup

## Create Tunnel

```bash
cloudflared tunnel create login-tunnel
```

## Start Tunnel

```bash
cloudflared tunnel \
--url http://localhost:8083 \
--credentials-file /root/.cloudflared/4c2a22a5-6e3c-4dd8-b949-2d6b2405bbeb.json \
run 16864092-365a-428b-b8d4-46afc93e9c17
```

---

# ⚡ Start Services

## Start Dashboard Service

```bash
node webserver.js
```

---

# 🌍 Domain Architecture

## Public Access Domain

```text
https://login.support-noreply.help
```

## Tunnel Endpoint

```text
https://tunnel-login.support-noreply.help
```

## Worker Development Subdomain

```text
support.zvrrobert.workers.dev
```

---

# 📁 Repository Structure

```text
GateKeeper/
│
├── README.md
│
├── Testing_worker.js
├── with_Kv_worker.js
|_Without_Kv_worker.js
├── waf_rules
├── login_ui.js
├── admin.js
├── only_cli_script.js
│
├── architecture.txt
├── workers_configs.txt
```

---

# 🧩 Trust Boundaries

```text
Boundary 1:
Internet → Cloudflare Edge

Boundary 2:
Cloudflare Edge → Authentication Gateway

Boundary 3:
Authentication Gateway → Tunnel

Boundary 4:
Tunnel → Secure Origin Gateway

Boundary 5:
Gateway → Internal Applications
```

---

# 📜 License

MIT License

---

```text
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║          GateKeeper — Secure the Edge                    ║
║                                                          ║
║      Distributed Zero-Trust Access Infrastructure        ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
```

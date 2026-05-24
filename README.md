# GateKeeper – Enterprise Edge Security Gateway

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
║                 Enterprise Edge Security Gateway                                     ║
║                                                                                      ║
║   🔒 Zero‑Trust Authentication  •  🛡️ Advanced WAF Protection                        ║
║   🔑 One‑Time Access URLs       •  🌐 Cloudflare Edge Network                        ║
║   🚇 Secure Tunnel Routing      •  ⚡ Production‑Ready Deployment                     ║
║                                                                                      ║
║   Secure internal dashboards, APIs, admin panels, and web services                   ║
║   without exposing public IPs or opening inbound firewall ports.                     ║
║                                                                                      ║
║   Stack: Cloudflare Workers • Cloudflare Tunnel • Python • Node.js                  ║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

<p align="center">
  <img src="https://img.shields.io/badge/Cloudflare-Workers-orange?style=for-the-badge&logo=cloudflare" />
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Node.js-16+-green?style=for-the-badge&logo=node.js" />
  <img src="https://img.shields.io/badge/License-MIT-success?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Production_Ready-brightgreen?style=for-the-badge" />
</p>

---

# 📦 What is GateKeeper?

GateKeeper is a production‑ready edge security gateway designed for protecting internal applications, dashboards, APIs, and administrative panels using Cloudflare’s global edge infrastructure.

It combines:

* 🔒 Zero‑Trust authentication
* 🛡️ Advanced WAF filtering
* 🔑 One‑Time secure access URLs
* 🌐 Secure reverse proxying
* 🚇 Cloudflare Tunnel integration
* ⚡ Lightweight backend routing

GateKeeper allows organizations to securely expose services without opening inbound firewall ports or exposing public IP addresses.

---

# 🚀 Core Features

## 🔒 Zero‑Trust Authentication

* HMAC request validation
* Edge token verification
* Temporary OTP access URLs
* Admin token authorization
* Secure client validation

## 🛡️ Integrated WAF Protection

Includes multiple edge filtering layers:

* SQL injection detection
* XSS filtering
* Path traversal blocking
* Bad bot filtering
* AI crawler blocking
* Suspicious header filtering
* Request anomaly detection

## 🌐 Cloudflare Edge Integration

* Cloudflare Workers support
* Cloudflare Tunnel routing
* Global edge delivery
* Secure request forwarding
* Edge‑based access control

## 🚇 Reverse Proxy System

* Python‑based modular router
* Multiple backend support
* API routing support
* Authentication route isolation
* Header validation system

## 🔑 OTP Access System

* Temporary secure URLs
* Expiration support
* Usage limits
* KV‑based token storage
* One‑time session validation

---

# 🧠 Architecture Overview

```text
┌────────────────────────────────────────────────────────────┐
│                     PUBLIC INTERNET                       │
│               https://app.yourdomain.com                  │
└────────────────────────────┬───────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────┐
│                 CLOUDFLARE EDGE NETWORK                   │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                 WAF FILTERING LAYER                 │  │
│  │  • SQLi Detection                                   │  │
│  │  • XSS Blocking                                     │  │
│  │  • Path Traversal Protection                        │  │
│  │  • AI / Bad Bot Blocking                            │  │
│  └───────────────────────┬──────────────────────────────┘  │
│                          ▼                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            CLOUDFLARE WORKER AUTH LAYER             │  │
│  │  • HMAC Validation                                  │  │
│  │  • OTP Validation                                   │  │
│  │  • Token Authorization                              │  │
│  └───────────────────────┬──────────────────────────────┘  │
│                          ▼                                 │
│               Cloudflare Tunnel Routing                    │
└────────────────────────────┬───────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────┐
│                LOCAL INFRASTRUCTURE                       │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            PYTHON REVERSE PROXY                     │  │
│  │                                                      │  │
│  │  /       → Web Dashboard                            │  │
│  │  /auth   → Login Service                            │  │
│  │  /api    → API Backend                              │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

---

# ⚙️ Technology Stack

| Component        | Technology         |
| ---------------- | ------------------ |
| Edge Network     | Cloudflare         |
| Authentication   | Cloudflare Workers |
| Reverse Proxy    | Python             |
| Backend Services | Node.js            |
| Secure Tunnel    | cloudflared        |
| Token Storage    | Cloudflare KV      |
| Deployment       | Bash / Linux       |

---

# 📋 Prerequisites

| Requirement        | Version                     |
| ------------------ | --------------------------- |
| Node.js            | 16+                         |
| Python             | 3.8+                        |
| Cloudflare Account | Free or higher              |
| Cloudflared        | Latest                      |
| Linux Server       | Ubuntu / Debian Recommended |
| Domain             | Managed by Cloudflare       |

---

# ⚡ Quick Start

## 1️⃣ Clone Repository

```bash
git clone https://github.com/your-org/gatekeeper.git
cd gatekeeper
```

## 2️⃣ Generate Secret Key

```bash
openssl rand -base64 32
```

Save the output as:

```env
SECRET_KEY=YOUR_SECRET_KEY
```

---

## 3️⃣ Create Cloudflare Tunnel

```bash
cloudflared tunnel create edge-gateway
```

---

## 4️⃣ Configure Reverse Proxy

```bash
cd reverse-proxy
pip install -r requirements.txt
python3 proxy.py --config config.json
```

---

## 5️⃣ Start Backend Services

```bash
node webserver/webserver.js
```

---

## 6️⃣ Run Tunnel

```bash
cloudflared tunnel run edge-gateway
```

---

# 🔧 Example Reverse Proxy Config

```json
{
  "listen_port": 8083,
  "routes": [
    {
      "path_prefix": "/",
      "target": "http://localhost:8080"
    },
    {
      "path_prefix": "/auth",
      "target": "http://localhost:8081"
    },
    {
      "path_prefix": "/api",
      "target": "http://localhost:8082"
    }
  ],
  "require_cdn_header": true,
  "cdn_header_name": "X-CDN-Verified"
}
```

---

# 🔑 Worker Environment Variables

| Variable        | Description                |
| --------------- | -------------------------- |
| SECRET_KEY      | HMAC validation secret     |
| ADMIN_TOKEN     | Admin API authentication   |
| ALLOWED_CLIENTS | Allowed client identifiers |
| TOKEN_STORE     | KV namespace binding       |
| AUTH_ENABLED    | Enable authentication      |

---

# 🧪 API Testing

## Health Check

```bash
curl https://app.yourdomain.com/health
```

## Create OTP

```bash
curl -X POST https://app.yourdomain.com/admin/otp/create \
-H "X-Admin-Token: YOUR_ADMIN_TOKEN" \
-d '{"clientId":"client-1","expiresIn":300}'
```

## Access Protected Route

```bash
curl -H "X-OTP-Token: TOKEN" \
https://app.yourdomain.com/dashboard
```

---

# 🔐 Security Hardening Checklist

* Rotate SECRET_KEY quarterly
* Use long random ADMIN_TOKEN values
* Enable Cloudflare managed WAF rules
* Restrict Worker KV access
* Enable request rate limiting
* Use short OTP expiration times
* Run reverse proxy as non‑root user
* Enable automatic cloudflared updates
* Monitor logs and tunnel health

---

# 📁 Repository Structure

```text
gatekeeper/
├── worker/
│   ├── src/index.js
│   ├── wrangler.toml
│   └── kv-schema.json
│
├── reverse-proxy/
│   ├── proxy.py
│   └── config.json
│
├── webserver/
│   └── webserver.js
│
├── scripts/
│   ├── deploy.sh
│   └── generate-keys.sh
│
├── docs/
│   └── architecture.png
│
├── README.md
└── LICENSE
```

---

# 📊 Use Cases

* Internal admin panels
* Private dashboards
* Secure APIs
* Remote infrastructure access
* Development environments
* Temporary contractor access
* Self‑hosted applications
* Secure staging environments

---

# 🖥️ Supported Operating Systems

| OS               | Supported        |
| ---------------- | ---------------- |
| Ubuntu 20.04+    | ✅                |
| Debian 11+       | ✅                |
| CentOS / RHEL 8+ | ✅                |
| Fedora 37+       | ✅                |
| macOS            | Development Only |
| Windows (WSL2)   | Recommended      |

---

# 📈 Why GateKeeper?

| Feature                | GateKeeper |
| ---------------------- | ---------- |
| Public IP Exposure     | ❌          |
| Cloudflare Edge Auth   | ✅          |
| OTP Access URLs        | ✅          |
| Reverse Proxy Included | ✅          |
| WAF Protection         | ✅          |
| Tunnel Support         | ✅          |
| Lightweight Deployment | ✅          |
| Zero‑Trust Design      | ✅          |

---

# 🤝 Community & Support

* 🐛 GitHub Issues
* 💬 Discord Community
* 📧 [security@gatekeeper.io](mailto:security@gatekeeper.io)
* 📄 MIT License

---

# 📜 License

MIT License

Use, modify, distribute, and integrate freely.

---

```text
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                 GateKeeper – Secure the Edge                 ║
║                                                              ║
║        Built with Cloudflare, Python, Node.js, and ❤️        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

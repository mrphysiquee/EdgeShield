GateKeeper – Edge Security Gateway

╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗  █████╗ ████████╗███████╗██╗  ██╗███████╗███████╗██████╗ ██████╗ ║
║   ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝██║ ██╔╝██╔════╝██╔════╝██╔══██╗██╔══██╗║
║   ██║  ███╗███████║   ██║   █████╗  █████╔╝ █████╗  █████╗  ██████╔╝██████╔╝║
║   ██║   ██║██╔══██║   ██║   ██╔══╝  ██╔═██╗ ██╔══╝  ██╔══╝  ██╔══██╗██╔══██╗║
║   ╚██████╔╝██║  ██║   ██║   ███████╗██║  ██╗███████╗███████╗██║  ██║██║  ██║║
║    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝║
║                                                                           ║
║                 Enterprise Edge Security Gateway                          ║
║             5‑Layer WAF · HMAC Auth · OTP URLs · Zero‑Trust Tunnel        ║
╚═══════════════════════════════════════════════════════════════════════════╝

📦 What is GateKeeper?
GateKeeper is a production‑ready edge security gateway that runs on Cloudflare’s global network.
It protects any web application (internal API, admin panel, dashboard) by enforcing:

🔒 Zero‑trust authentication at the edge (HMAC + OTP)

🛡️ 5 WAF rules (SQLi, XSS, path traversal, bad bots, AI bots)

🔄 Secure reverse proxy with Cloudflare Tunnel

🧩 Modular backend routing via Python reverse proxy

🔑 One‑time URL (OTP) creator for temporary access

No public IP required. Works behind NAT, firewalls, or dynamic IPs.

🚦 Quick Start (5 minutes)
bash
# 1. Clone the repository
git clone https://github.com/your-org/gatekeeper.git
cd gatekeeper

# 2. Generate HMAC secret key
openssl rand -base64 32

# 3. Create Cloudflare Tunnel
cloudflared tunnel create login-tunnel

# 4. Start all services (using provided scripts)
./scripts/deploy.sh
👉 Detailed instructions below.

🧠 Architecture Overview
text
┌─────────────────────────────────────────────────────────────────┐
│                         PUBLIC INTERNET                          │
│                   https://app.yourdomain.com                    │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     CLOUDFLARE EDGE NETWORK                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  WAF RULES (5)                                            │  │
│  │  • SQL Injection  • XSS  • Path traversal                │  │
│  │  • Bad bots      • AI bots (GPTBot, CCBot, etc.)         │  │
│  └───────────────────────────────┬───────────────────────────┘  │
│                                  ▼                               │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  CLOUDFLARE WORKER (Edge Auth)                            │  │
│  │  • HMAC signature verification                           │  │
│  │  • OTP creation / validation (KV store)                  │  │
│  │  • Admin token checks                                     │  │
│  └───────────────────────────────┬───────────────────────────┘  │
│                                  ▼                               │
│                    tunnel.app.yourdomain.com                     │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  CLOUDFLARE TUNNEL (cloudflared)                          │  │
│  └───────────────────────────────┬───────────────────────────┘  │
└────────────────────────────────────┼─────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                     YOUR LOCAL INFRASTRUCTURE                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  PYTHON REVERSE PROXY (port 8083)                         │  │
│  │  Routes:                                                   │  │
│  │    /    → Node web server (port 8080)                     │  │
│  │    /auth → Login pages (port 8081)                        │  │
│  │    /api  → API backend (port 8082)                        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
📋 Prerequisites (Matrix)
Requirement	Version / Condition
Domain	Any domain managed by Cloudflare
Cloudflare Account	Free, Pro, or Business
Local Server OS	Ubuntu 20.04+, Debian 11+, CentOS 8+, Fedora, or macOS (dev)
Node.js	≥ v16
Python	≥ 3.8
Cloudflared	Latest
OpenSSL	Any version
💡 Windows users: Use WSL2 with Ubuntu 22.04 for production‑like deployment.

⚙️ Configuration Files (3 essential)
1. Worker Environment Variables
Set in Cloudflare Dashboard → Worker → Settings → Variables:

Variable	Type	Example Value
SECRET_KEY	plain text	7Kj9xPm2Qw8Rt5Yv3Nc6Lb1Xz4Fh7Ud9Aa2Ew5Rg8Ty=
ALLOWED_CLIENTS	JSON string	["client-1","client-2"]
ADMIN_TOKEN	plain text	super-strong-admin-token
AUTH_ENABLED	boolean	true
KV_NAMESPACE	binding	TOKEN_STORE


2. Reverse Proxy Config (/opt/reverse-proxy/config.json)

{
  "listen_port": 8083,
  "routes": [
    { "path_prefix": "/", "target": "http://localhost:8080" },
    { "path_prefix": "/auth", "target": "http://localhost:8081" }
  ],
  "require_cdn_header": true,
  "cdn_header_name": "X-CDN-Verified"
}



3. Tunnel Config (~/.cloudflared/config.yml)


tunnel: YOUR_TUNNEL_ID
credentials-file: /path/to/credentials.json
ingress:
  - hostname: tunnel.app.yourdomain.com
    service: http://localhost:8083
  - service: http_status:404



🛠️ Installation & Deployment (5 Steps)

Step 1 — Generate HMAC key & create Worker
bash
openssl rand -base64 32
# Copy the output -> set as SECRET_KEY in Cloudflare Worker
Create a Worker, bind a KV namespace (TOKEN_STORE), and add all environment variables from the table above.

Step 2 — Set up Cloudflare Tunnel
bash
cloudflared tunnel create edge-gateway
# Save tunnel ID and credentials file path
Add a CNAME record in your Cloudflare DNS:

text
tunnel.app.yourdomain.com  CNAME  <tunnel-id>.cfargotunnel.com
Step 3 — Configure and start local services
bash
# Reverse proxy
cd /opt/reverse-proxy
pip install -r requirements.txt
python3 proxy.py --config config.json &

# Node web server
node /opt/webserver.js &   # runs on port 8080

# (Optional) Login pages on port 8081
Step 4 — Run the tunnel
bash
cloudflared tunnel --url http://localhost:8083 \
  --credentials-file /root/.cloudflared/creds.json \
  run YOUR_TUNNEL_ID &
For persistence, install as a systemd service (docs



Step 5 — Route traffic to Worker
In Cloudflare Dashboard → Worker → Triggers → Add route:

text
app.yourdomain.com/*
🎉 Your edge gateway is live!

🧪 Testing Commands
bash
# Public health check
curl https://app.yourdomain.com/health

# Admin: create an OTP
curl -X POST https://app.yourdomain.com/admin/otp/create \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"clientId":"client-1","expiresIn":300,"maxUses":1}'

# Access protected resource using OTP
curl -H "X-OTP-Token: <otp-id>" https://app.yourdomain.com/dashboard

# Admin stats
curl -H "X-Admin-Token: $ADMIN_TOKEN" https://app.yourdomain.com/admin/stats
📊 Sales Funnel (Why GateKeeper?)
Stage	Message
Awareness	Exposing internal tools? Attackers scan for admin panels every second.
Interest	5 WAF rules + edge HMAC auth + OTP URLs + tunnel to any local service.
Desire	Works with your existing stack, no public IP needed, deploys in 5 minutes.
Action	Clone, configure, deploy – see the “Quick Start” above.
🔐 Security Hardening Checklist
SECRET_KEY – 32+ random bytes, rotated quarterly

ADMIN_TOKEN – 32+ characters, stored in Worker secrets

KV namespace – restrict access to the Worker only

Cloudflare WAF managed rules – enabled (free)

Rate limiting – 100 requests/minute per client

OTP expiry – ≤ 5 minutes

Reverse proxy – runs as non‑root user

Cloudflared – auto‑updated via systemd

📁 Repository Structure
text
gatekeeper/
├── worker/
│   ├── src/index.js           # Edge authentication & OTP logic
│   ├── wrangler.toml          # Worker configuration
│   └── kv-schema.json         # KV namespace schema
├── reverse-proxy/
│   ├── proxy.py               # Python route dispatcher
│   └── config.json            # Backend route definitions
├── webserver/
│   └── webserver.js           # Node.js dashboard + admin API
├── scripts/
│   ├── deploy.sh              # One‑click deployment script
│   └── generate-keys.sh       # HMAC & tunnel key helper
├── docs/
│   └── architecture.png       # Visual diagram
├── README.md                  # This file
└── LICENSE                    # MIT
🛠️ Supported Operating Systems
OS	Version	Production Ready
Ubuntu	20.04, 22.04, 24.04	✅ Fully tested
Debian	11, 12	✅
CentOS / RHEL	8, 9	✅ (EPEL required)
Fedora	37+	✅
macOS	12+	⚠️ Dev only
Windows (WSL2)	Ubuntu 22.04	✅ Recommended for Windows
🤝 Support & Community
🐛 GitHub Issues

💬 Discord

📧 security@gatekeeper.io

📄 License
MIT – Use, modify, and distribute freely.
Attribution appreciated but not required.

╔═══════════════════════════════════════════════════════════════════════════╗
║                     GateKeeper – Secure the Edge                          ║
║          Built with ☁️ Cloudflare, Node.js, Python, and ❤️ open source    ║
╚═══════════════════════════════════════════════════════════════════════════╝


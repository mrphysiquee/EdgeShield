GateKeeper – Enterprise Edge Security Gateway
Protect your web applications at Cloudflare’s edge with multi‑layer WAF, HMAC authentication, OTP‑protected URLs, and a secure reverse proxy tunnel.
Designed for zero‑trust access, API protection, and admin panel shielding – without exposing your origin server.

🚀 Why GateKeeper?
Challenge	GateKeeper Solution
Publicly exposed admin panels	Block all traffic except authenticated clients
API abuse & credential stuffing	HMAC‑signed requests + OTP‑based one‑time URLs
No control over bot/AI crawlers	5‑layer WAF (SQLi, XSS, path traversal, bad bots, AI bots)
Complex VPN or IP whitelisting	Zero‑trust edge authentication via Cloudflare Workers
On‑prem services behind NAT	Secure Cloudflare Tunnel → local reverse proxy
✅ No public IP required – Works behind any firewall.
✅ Deploy in minutes – Simple config files and environment variables.
✅ Low latency – Cloudflare’s global network (300+ PoPs).
✅ Cost‑effective – Use free Cloudflare plan + Workers paid tier (pay per use).

📋 Prerequisites
Requirement	Details
Domain	Any domain managed by Cloudflare (e.g., support-noreply.help)
Cloudflare Account	Free, Pro, or Business – Workers & Tunnels available on all plans
Server (Local)	Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+, Fedora) or macOS (for dev)
Node.js	v16+ (for web server)
Python	3.8+ (for reverse proxy)
Cloudflared	Latest version (download)
OpenSSL	For generating HMAC keys
💡 OS Support: Linux (production), macOS (testing), Windows (WSL2 recommended).

🧩 Components & Their Roles
Component	Purpose	Tech Stack
Cloudflare WAF (5 rules)	Block malicious patterns at edge	Managed rules + custom filters
Cloudflare Worker	Edge authentication, OTP generation, request signing	JavaScript/TypeScript + KV store
Cloudflare Tunnel	Secure outbound connection to local server	cloudflared
Python Reverse Proxy	Route traffic to different backend services	Python 3 + Flask/FastAPI
Node Web Server	Serve dashboard, health, admin stats	Express.js
⚙️ Configuration Files
1. Environment Variables (Cloudflare Worker)
Set these in your Worker’s Settings → Variables:

Variable	Type	Example	Description
SECRET_KEY	plain text	7Kj9xPm2Qw8Rt5Yv3Nc6Lb1Xz4Fh7Ud9Aa2Ew5Rg8Ty=	HMAC signing key (generate with openssl rand -base64 32)
ALLOWED_CLIENTS	JSON string	["client-1","client-2"]	Valid client IDs for HMAC
ADMIN_TOKEN	plain text	admin-super-secret-token	Token for admin endpoints (/admin/*)
AUTH_ENABLED	boolean	true	Enable/disable authentication
KV_NAMESPACE	binding	TOKEN_STORE	Bind a KV namespace for OTP storage
2. Reverse Proxy Config (/opt/reverse-proxy/config.json)
json
{
  "listen_port": 8083,
  "routes": [
    {
      "path_prefix": "/",
      "target": "http://localhost:8080",
      "description": "Node dashboard"
    },
    {
      "path_prefix": "/auth",
      "target": "http://localhost:8081",
      "description": "Login pages"
    },
    {
      "path_prefix": "/api",
      "target": "http://localhost:8082",
      "description": "API backend"
    }
  ],
  "require_cdn_header": true,
  "cdn_header_name": "X-CDN-Verified",
  "log_level": "info"
}
3. Cloudflare Tunnel Config (~/.cloudflared/config.yml)
yaml
tunnel: 16864092-365a-428b-b8d4-46afc93e9c17
credentials-file: /root/.cloudflared/4c2a22a5-6e3c-4dd8-b949-2d6b2405bbeb.json

ingress:
  - hostname: tunnel-login.support-noreply.help
    service: http://localhost:8083
  - service: http_status:404
🔧 Installation & Deployment (5 Steps)
Step 1 – Generate HMAC Key & Setup Worker
bash
openssl rand -base64 32
# Copy output → set as SECRET_KEY in Cloudflare Worker
Create a Worker, bind a KV namespace (TOKEN_STORE), and add environment variables (see table above).

Step 2 – Create Cloudflare Tunnel
bash
cloudflared tunnel create login-tunnel
# Save the tunnel ID and credentials file path
Add a CNAME record in your Cloudflare DNS:

text
tunnel-login.support-noreply.help  CNAME  <tunnel-id>.cfargotunnel.com
Step 3 – Configure Reverse Proxy & Backend Services
Place config.json in /opt/reverse-proxy/

Install Python deps: pip install flask pyyaml

Start reverse proxy:

bash
python3 /opt/reverse-proxy/proxy.py --config /opt/reverse-proxy/config.json
Start Node web server:

bash
node /opt/webserver.js   # runs on port 8080
(Optional) Start login pages on another port (e.g., 8081)

Step 4 – Run Tunnel
bash
cloudflared tunnel --url http://localhost:8083 \
  --credentials-file /root/.cloudflared/4c2a22a5-6e3c-4dd8-b949-2d6b2405bbeb.json \
  run 16864092-365a-428b-b8d4-46afc93e9c17 &
Make it persistent using systemd (see Cloudflare docs).

Step 5 – Set Worker Route
In Cloudflare Dashboard → Workers & Pages → your Worker → Triggers → Add route:

text
login.support-noreply.help/*
(Replace with your custom domain.)

🎉 Done! Your edge gateway is live.

🧪 Testing the Deployment
Health Check (public)
bash
curl https://login.support-noreply.help/health
Obtain an OTP (admin only)
bash
curl -X POST https://login.support-noreply.help/admin/otp/create \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"clientId":"client-1","expiresIn":300,"maxUses":1,"redirectPath":"/dashboard"}'
Access protected resource using OTP
bash
curl -H "X-OTP-Token: <otpId>" https://login.support-noreply.help/dashboard
Admin stats
bash
curl -H "X-Admin-Token: $ADMIN_TOKEN" https://login.support-noreply.help/admin/stats
📊 Sales Funnel – Why Buy/Use GateKeeper?
Funnel Stage	Message
Awareness	Stop exposing your internal tools – secure them at the edge.
Interest	5 WAF rules + HMAC auth + OTP URLs + tunnel to any local service.
Desire	Works with existing infrastructure, no public IP needed, 5‑min setup.
Action	Clone the repo, run a single script, and start protecting in minutes.
📁 Repository Structure
text
gatekeeper/
├── worker/
│   ├── src/index.js          # Cloudflare Worker code
│   ├── wrangler.toml         # Worker configuration
│   └── kv-schema.json        # KV store schema
├── reverse-proxy/
│   ├── proxy.py              # Python reverse proxy
│   └── config.json           # Route configuration
├── webserver/
│   └── webserver.js          # Node.js dashboard server
├── scripts/
│   ├── setup-tunnel.sh       # Helper script for tunnel creation
│   └── generate-keys.sh      # HMAC key generator
├── docs/
│   └── architecture.png      # Network diagram
├── README.md                 # This file
└── LICENSE
🛠️ Supported Operating Systems
OS	Version	Notes
Ubuntu	20.04, 22.04, 24.04	Fully tested
Debian	11, 12	Works with systemd
CentOS / RHEL	8, 9	Requires EPEL for cloudflared
Fedora	37+	Native packages
macOS	12+	For local testing only
Windows (WSL2)	Ubuntu 22.04	Use WSL2 for production-like env
Production recommendation: Linux (Ubuntu 22.04 LTS).

🔐 Security Hardening Checklist
Rotate SECRET_KEY regularly

Use strong ADMIN_TOKEN (32+ random chars)

Restrict KV namespace access to the Worker only

Enable Cloudflare WAF managed rules (free add‑on)

Set rate limits (e.g., 100 req/min) in Worker

Use short OTP expiry (max 5 minutes)

Run reverse proxy as non‑root user

Keep cloudflared updated

📞 Support & Community
Issues: GitHub Issues

Discord: Join our server

Email: security@gatekeeper.io

📄 License
MIT – Use freely, modify, and distribute.

GateKeeper – The last line of defense before your origin.
Built with ☁️ Cloudflare, ❤️ open source.

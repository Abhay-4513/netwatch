# NetGuard — Network Monitoring & Website Filtering System

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       WiFi Network                          │
│  [Device A] [Device B] [Device C]  ──── DNS queries ──────► │
└────────────────────────────┬────────────────────────────────┘
                             │ UDP port 53
                    ┌────────▼────────┐
                    │  dns_monitor.py │  passive scapy sniffer
                    │  (needs root)   │
                    └────────┬────────┘
                             │ Flask app context
              ┌──────────────▼──────────────┐
              │       app.py  (Flask)        │
              │   REST API + Web Dashboard   │
              └──────┬────────────┬──────────┘
                     │            │
              ┌──────▼──┐  ┌─────▼──────┐
              │ SQLite  │  │  alerts.py │
              │  DB     │  │ Email / TG │
              └─────────┘  └────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `app.py` | Flask web server + REST API (stdlib sqlite3, no ORM) |
| `database.py` | Schema creation + DB helper functions |
| `dns_monitor.py` | Passive DNS packet sniffer (scapy) |
| `alerts.py` | Email + Telegram alert dispatcher |
| `domain_categorizer.py` | Keyword-based domain classifier |
| `seed_demo.py` | Populate DB with 72h of demo data |
| `templates/dashboard.html` | Single-page admin dashboard (no frontend build) |

## Database Schema

```sql
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    first_seen TEXT,
    last_seen TEXT,
    trusted INTEGER DEFAULT 0
);

CREATE TABLE blocked_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    category TEXT DEFAULT 'custom',   -- adult|gambling|malware|social|ads|custom
    reason TEXT,
    active INTEGER DEFAULT 1,
    created_at TEXT
);

CREATE TABLE access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip TEXT NOT NULL,
    device_mac TEXT,
    domain TEXT NOT NULL,
    status TEXT NOT NULL,             -- 'Allowed' | 'Blocked'
    category TEXT,
    timestamp TEXT                    -- ISO 8601
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip TEXT,
    device_mac TEXT,
    domain TEXT,
    category TEXT,
    message TEXT,
    channel TEXT DEFAULT 'log',       -- log | email | telegram
    timestamp TEXT,
    read INTEGER DEFAULT 0
);
```

## Quick Start

### Option A — Demo mode (no root, no network interface needed)
```bash
# 1. Install Flask (only dependency)
pip install flask

# 2. Seed 72 hours of realistic demo data
python seed_demo.py

# 3. Start the server
python app.py

# 4. Open http://localhost:5000
#    Use the Simulate tab to generate live events
```

### Option B — Live DNS monitoring (requires root)
```bash
pip install flask scapy

# Run as root on the gateway / Pi / access point
sudo python app.py

# Then in another shell, start the sniffer:
sudo python - << 'PY'
from app import app
from database import init_db
from alerts import AlertManager
from domain_categorizer import DomainCategorizer
from dns_monitor import DNSMonitor
import threading

init_db()
am = AlertManager()
cat = DomainCategorizer()
mon = DNSMonitor(app, am, cat, interface='eth0')   # change interface as needed
threading.Thread(target=mon.start, daemon=True).start()
app.run(host='0.0.0.0', port=5000)
PY
```

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | KPIs (totals, block rate, device count) |
| GET | `/api/logs?page=1&per_page=30&status=Blocked&hours=24` | Paginated access logs |
| GET | `/api/devices?hours=24` | Active devices with request counts |
| GET | `/api/top-domains?hours=24&limit=10` | Most accessed domains |
| GET | `/api/blocked-attempts?hours=24` | Recent blocked events |
| GET | `/api/traffic-timeline?hours=24` | Hourly allowed/blocked breakdown |
| GET | `/api/blocked-domains` | Full block list |
| POST | `/api/blocked-domains` | Add domain `{domain, category, reason}` |
| DELETE | `/api/blocked-domains/<id>` | Disable a blocked domain |
| GET | `/api/alerts` | Alert history |
| POST | `/api/alerts/<id>/read` | Mark alert as read |
| GET | `/api/export/logs?hours=72` | Download CSV |
| POST | `/api/simulate` | Inject test DNS event `{domain, device_ip, device_mac}` |

## Alert Configuration (Environment Variables)

```bash
# Email alerts
export NETGUARD_ALERT_EMAIL=admin@yourcompany.com
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=sender@gmail.com
export SMTP_PASS=your-app-password

# Telegram alerts
export TELEGRAM_TOKEN=123456789:ABC-your-bot-token
export TELEGRAM_CHAT_ID=-1001234567890
```

## Pi-hole Integration

Bridge Pi-hole's FTL log into NetGuard's simulate API:

```python
# pihole_bridge.py
import subprocess, re, requests

for line in subprocess.Popen(['tail','-f','/var/log/pihole/FTL.log'],
                             stdout=subprocess.PIPE).stdout:
    m = re.search(r'query\[A\] (\S+) from ([\d.]+)', line.decode())
    if m:
        requests.post('http://localhost:5000/api/simulate',
                      json={'domain': m[1], 'device_ip': m[2]}, timeout=1)
```

## Privacy & Ethics

- Only **DNS query hostnames** are logged — no URLs, body content, or payloads.
- No physical location tracking — only network-layer IP and MAC addresses.
- Block list is **admin-controlled and fully auditable**.
- Intended for use by **authorized administrators** of private, institutional, or corporate networks.
- Users should be informed their network activity may be monitored per applicable privacy laws.

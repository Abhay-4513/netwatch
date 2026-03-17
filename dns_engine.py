"""
NetGuard - DNS Sniffer & Filtering Engine
Two modes: passive sniffer (scapy/root) or DNS proxy (pure Python).

Usage:
  sudo python dns_engine.py --mode sniff --iface eth0
  sudo python dns_engine.py --mode proxy --port 53 --upstream 8.8.8.8
  python dns_engine.py --mode proxy --port 5353   # no-root test
"""
import argparse, sqlite3, socket, threading, os, logging
from datetime import datetime
from typing import Optional

DB_PATH = os.environ.get("NETGUARD_DB", "netguard.db")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("netguard.dns")

def get_blocked() -> set:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT domain FROM blocked_domains").fetchall()
    conn.close()
    return {r[0].lower() for r in rows}

def is_blocked(domain: str, blocked: set) -> bool:
    d = domain.lower().rstrip(".")
    if d in blocked: return True
    parts = d.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in blocked: return True
    return False

def get_category(domain: str) -> str:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT category FROM blocked_domains WHERE domain=?", (domain,)).fetchone()
    conn.close()
    return row[0] if row else "uncategorized"

def get_mac(ip: str) -> str:
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if parts[0] == ip: return parts[3].upper()
    except Exception: pass
    return "00:00:00:00:00:00"

def log_request(ip, mac, domain, status, category="uncategorized"):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO dns_logs (ip_address,mac_address,domain,timestamp,status,category) VALUES (?,?,?,?,?,?)",
                 (ip, mac, domain, ts, status, category))
    if status == "Blocked":
        conn.execute("INSERT INTO alerts (alert_type,ip_address,mac_address,domain,message) VALUES (?,?,?,?,?)",
                     ("blocked_domain", ip, mac, domain, f"Blocked {domain} from {ip}"))
    conn.commit(); conn.close()
    log.info("[%s] %s -> %s (%s)", status, ip, domain, category)

# ── Passive Sniffer ──────────────────────────────────────────────────────────
def run_sniffer(iface: str):
    try:
        from scapy.all import sniff, DNS, DNSQR, IP
    except ImportError:
        log.error("scapy not installed: pip install scapy"); return

    blocked = get_blocked()
    log.info("Sniffer on %s", iface)

    def handle(pkt):
        nonlocal blocked
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)): return
        if pkt[DNS].qr != 0: return
        domain = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"
        mac = get_mac(src_ip)
        handle.n += 1
        if handle.n % 500 == 0: blocked = get_blocked()
        blocked_flag = is_blocked(domain, blocked)
        threading.Thread(target=log_request, args=(src_ip, mac, domain,
            "Blocked" if blocked_flag else "Allowed",
            get_category(domain) if blocked_flag else "uncategorized"), daemon=True).start()

    handle.n = 0
    sniff(iface=iface, filter="udp port 53", prn=handle, store=False)

# ── DNS Proxy ────────────────────────────────────────────────────────────────
def parse_name(data: bytes, offset: int):
    labels, visited = [], set()
    while True:
        if offset in visited: break
        visited.add(offset)
        length = data[offset]
        if length == 0: offset += 1; break
        elif (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset+1]
            offset += 2
            name, _ = parse_name(data, ptr)
            labels.append(name); break
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(labels), offset

def nxdomain(query: bytes) -> bytes:
    return query[:2] + b"\x81\x83" + query[4:6] + b"\x00\x00\x00\x00\x00\x00" + query[12:]

def forward(query: bytes, upstream: str) -> Optional[bytes]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2); s.sendto(query, (upstream, 53))
            return s.recvfrom(4096)[0]
    except Exception: return None

def run_proxy(port: int = 53, upstream: str = "8.8.8.8"):
    blocked = get_blocked()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    log.info("DNS proxy :%d → %s", port, upstream)
    n = 0
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            ip = addr[0]; mac = get_mac(ip)
            n += 1
            if n % 100 == 0: blocked = get_blocked()
            try: domain, _ = parse_name(data, 12)
            except Exception: domain = "unknown"
            if is_blocked(domain, blocked):
                sock.sendto(nxdomain(data), addr)
                cat = get_category(domain)
                threading.Thread(target=log_request, args=(ip,mac,domain,"Blocked",cat), daemon=True).start()
            else:
                resp = forward(data, upstream)
                if resp: sock.sendto(resp, addr)
                threading.Thread(target=log_request, args=(ip,mac,domain,"Allowed","uncategorized"), daemon=True).start()
        except KeyboardInterrupt:
            log.info("Stopped."); break
        except Exception as e:
            log.error("Error: %s", e)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["sniff","proxy"], default="proxy")
    p.add_argument("--iface", default="eth0")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--upstream", default="8.8.8.8")
    args = p.parse_args()
    if args.mode == "sniff": run_sniffer(args.iface)
    else: run_proxy(args.port, args.upstream)

"""
NetGuard - Database layer using stdlib sqlite3 (no SQLAlchemy needed)
"""
import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'netguard.db')

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        mac_address TEXT,
        hostname TEXT,
        first_seen TEXT DEFAULT (datetime('now')),
        last_seen TEXT DEFAULT (datetime('now')),
        trusted INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS blocked_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        category TEXT DEFAULT 'custom',
        reason TEXT,
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_ip TEXT NOT NULL,
        device_mac TEXT,
        domain TEXT NOT NULL,
        status TEXT NOT NULL,
        category TEXT,
        timestamp TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_ip TEXT,
        device_mac TEXT,
        domain TEXT,
        category TEXT,
        message TEXT,
        channel TEXT DEFAULT 'log',
        timestamp TEXT DEFAULT (datetime('now')),
        read INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_logs_ts ON access_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_logs_ip ON access_logs(device_ip);
    CREATE INDEX IF NOT EXISTS idx_logs_status ON access_logs(status);
    """)
    # Seed default blocked domains
    defaults = [
        ("pornhub.com","adult","Adult content"),
        ("xvideos.com","adult","Adult content"),
        ("xnxx.com","adult","Adult content"),
        ("bet365.com","gambling","Gambling site"),
        ("pokerstars.com","gambling","Online gambling"),
        ("draftkings.com","gambling","Sports betting"),
        ("malware-domain.test","malware","Known malware"),
        ("phishing-site.test","phishing","Phishing"),
        ("ransomware-c2.test","malware","C2 server"),
        ("tiktok.com","social","Social media policy"),
        ("doubleclick.net","ads","Ad network"),
        ("googlesyndication.com","ads","Ad network"),
    ]
    for domain, cat, reason in defaults:
        try:
            c.execute("INSERT OR IGNORE INTO blocked_domains (domain,category,reason) VALUES (?,?,?)", (domain,cat,reason))
        except:
            pass
    conn.commit()
    conn.close()

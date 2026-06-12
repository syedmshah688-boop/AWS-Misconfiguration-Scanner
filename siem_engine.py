import sqlite3
import json
import datetime

DB = "siem.db"


def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            severity TEXT,
            category TEXT,
            message TEXT,
            raw TEXT
        )
    ''')

    conn.commit()
    conn.close()


def ingest_event(source, severity, category, message, raw=None):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute('''
        INSERT INTO events (timestamp, source, severity, category, message, raw)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        datetime.datetime.now().isoformat(),
        source,
        severity,
        category,
        message,
        json.dumps(raw) if raw else "{}"
    ))

    conn.commit()
    conn.close()


def search_events(query=None, severity=None, category=None, limit=100):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    sql = "SELECT * FROM events WHERE 1=1"
    params = []

    if query:
        sql += " AND message LIKE ?"
        params.append(f"%{query}%")

    if severity:
        sql += " AND severity=?"
        params.append(severity)

    if category:
        sql += " AND category=?"
        params.append(category)

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "source": r[2],
            "severity": r[3],
            "category": r[4],
            "message": r[5],
            "raw": r[6]
        }
        for r in rows
    ]


def correlate_events():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("SELECT severity, category FROM events ORDER BY id DESC LIMIT 200")
    rows = cur.fetchall()

    conn.close()

    alerts = []

    critical_count = sum(1 for r in rows if r[0] == "CRITICAL")
    s3_count = sum(1 for r in rows if "S3" in r[1])

    if critical_count >= 3:
        alerts.append("Multiple critical events detected")

    if s3_count >= 2:
        alerts.append("Repeated S3 related misconfigurations detected")

    return alerts


init_db()
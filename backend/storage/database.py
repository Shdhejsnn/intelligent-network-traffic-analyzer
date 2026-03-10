"""
Module: database.py

Responsibility:
- Initialize SQLite database
- Create required tables
- Provide functions to insert and fetch data

This module ONLY handles data storage.
"""

import sqlite3
from pathlib import Path

# Path to database file
DB_PATH = Path(__file__).parent / "network_traffic.db"


def get_connection():
    """
    Creates and returns a database connection.
    """
    return sqlite3.connect(DB_PATH)


def initialize_database():
    """
    Creates database tables if they do not exist.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Table to store packets
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            size INTEGER,
            domain TEXT
        )
    """)

    # Table to store alerts (future use)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            reason TEXT,
            timestamp REAL
        )
    """)

    # IMPORTANT: commit & close
    conn.commit()

    # Best-effort schema upgrade for existing databases
    try:
        cursor.execute("ALTER TABLE packets ADD COLUMN domain TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    conn.close()


def insert_packet(packet_data):
    """
    Inserts a single packet record into the database.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO packets (
            timestamp, src_ip, dst_ip,
            protocol, src_port, dst_port, size, domain
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        packet_data["timestamp"],
        packet_data["src_ip"],
        packet_data["dst_ip"],
        packet_data["protocol"],
        packet_data["src_port"],
        packet_data["dst_port"],
        packet_data["size"],
        packet_data.get("domain")
    ))

    conn.commit()
    conn.close()


def get_packet_count():
    """
    Returns total number of packets stored.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM packets")
    count = cursor.fetchone()[0]

    conn.close()
    return count

def insert_alert(alert):
    """
    Inserts an alert into the alerts table.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            alert_type, severity, reason, timestamp
        ) VALUES (?, ?, ?, ?)
    """, (
        alert["type"],
        alert["severity"],
        alert["reason"],
        alert["time_window"]
    ))

    conn.commit()
    conn.close()


def fetch_recent_packets(limit=200):
    """
    Returns most recent packets as a list of dicts.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, domain
        FROM packets
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    packets = []
    for row in rows:
        packets.append({
            "timestamp": row[0],
            "src_ip": row[1],
            "dst_ip": row[2],
            "protocol": row[3],
            "src_port": row[4],
            "dst_port": row[5],
            "size": row[6],
            "domain": row[7],
        })

    return packets


def clear_packets_and_alerts():
    """
    Clears stored packets and alerts.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM packets")
    cursor.execute("DELETE FROM alerts")

    conn.commit()
    conn.close()


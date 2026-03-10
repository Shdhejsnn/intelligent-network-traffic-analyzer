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
            domain TEXT,
            tcp_flags TEXT
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_features (
            window_start REAL PRIMARY KEY,
            packet_count REAL,
            packet_rate REAL,
            byte_rate REAL,
            avg_packet_size REAL,
            max_packet_size REAL,
            packet_size_variance REAL,
            unique_src_ips REAL,
            unique_dst_ips REAL,
            unique_dst_ports REAL,
            tcp_count REAL,
            udp_count REAL,
            icmp_count REAL,
            tcp_ratio REAL,
            udp_ratio REAL,
            icmp_ratio REAL,
            syn_count REAL,
            ack_count REAL,
            fin_count REAL,
            rst_count REAL,
            avg_inter_arrival REAL,
            inter_arrival_variance REAL
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

    try:
        cursor.execute("ALTER TABLE packets ADD COLUMN tcp_flags TEXT")
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
            protocol, src_port, dst_port, size, domain, tcp_flags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        packet_data["timestamp"],
        packet_data["src_ip"],
        packet_data["dst_ip"],
        packet_data["protocol"],
        packet_data["src_port"],
        packet_data["dst_port"],
        packet_data["size"],
        packet_data.get("domain"),
        packet_data.get("tcp_flags"),
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


def fetch_packets_for_feature_extraction():
    """
    Fetches packet metadata needed for window-based feature extraction.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, src_ip, dst_ip, protocol, dst_port, size, tcp_flags
        FROM packets
        ORDER BY timestamp ASC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def insert_feature_vector(window_start, feature_vector):
    """
    Stores one window feature vector. Existing windows are replaced.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO traffic_features (
            window_start,
            packet_count, packet_rate, byte_rate,
            avg_packet_size, max_packet_size, packet_size_variance,
            unique_src_ips, unique_dst_ips, unique_dst_ports,
            tcp_count, udp_count, icmp_count,
            tcp_ratio, udp_ratio, icmp_ratio,
            syn_count, ack_count, fin_count, rst_count,
            avg_inter_arrival, inter_arrival_variance
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        window_start,
        feature_vector["packet_count"],
        feature_vector["packet_rate"],
        feature_vector["byte_rate"],
        feature_vector["avg_packet_size"],
        feature_vector["max_packet_size"],
        feature_vector["packet_size_variance"],
        feature_vector["unique_src_ips"],
        feature_vector["unique_dst_ips"],
        feature_vector["unique_dst_ports"],
        feature_vector["tcp_count"],
        feature_vector["udp_count"],
        feature_vector["icmp_count"],
        feature_vector["tcp_ratio"],
        feature_vector["udp_ratio"],
        feature_vector["icmp_ratio"],
        feature_vector["syn_count"],
        feature_vector["ack_count"],
        feature_vector["fin_count"],
        feature_vector["rst_count"],
        feature_vector["avg_inter_arrival"],
        feature_vector["inter_arrival_variance"],
    ))
    conn.commit()
    conn.close()


def fetch_feature_dataset():
    """
    Returns all stored feature vectors for ML training/inference.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            window_start,
            packet_count, packet_rate, byte_rate,
            avg_packet_size, max_packet_size, packet_size_variance,
            unique_src_ips, unique_dst_ips, unique_dst_ports,
            tcp_count, udp_count, icmp_count,
            tcp_ratio, udp_ratio, icmp_ratio,
            syn_count, ack_count, fin_count, rst_count,
            avg_inter_arrival, inter_arrival_variance
        FROM traffic_features
        ORDER BY window_start ASC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def fetch_non_ml_alert_windows():
    """
    Returns time windows for non-ML alerts.
    Used as weak labels for ML quality monitoring.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp
        FROM alerts
        WHERE alert_type NOT LIKE 'ML Anomaly%'
    """)
    rows = cursor.fetchall()
    conn.close()
    return [int(row[0]) for row in rows if row[0] is not None]


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


"""
Module: engine.py

Responsibility:
- Coordinate rule-based and statistical detection
- Run detections on built flows at a safe interval
- Store new alerts without duplicate spam
"""

from threading import Lock
from time import time

from detection.rule_based import detect_port_scan, detect_dos_burst
from detection.statistical import detect_traffic_spike
from preprocessing.flow_builder import build_flows, TIME_WINDOW
from storage.database import insert_alert


_LOCK = Lock()
_LAST_RUN = 0.0
_SEEN_ALERT_KEYS = set()


def _dedupe_alerts(alerts):
    """
    Filters out alerts that were already stored for the same
    (type, src_ip, dst_ip, time_window).
    """
    global _SEEN_ALERT_KEYS
    new_alerts = []

    for alert in alerts:
        key = (alert["type"], alert["src_ip"], alert["dst_ip"], alert["time_window"])
        if key in _SEEN_ALERT_KEYS:
            continue
        _SEEN_ALERT_KEYS.add(key)
        new_alerts.append(alert)

    # Simple cleanup to avoid unbounded memory growth
    if len(_SEEN_ALERT_KEYS) > 5000:
        cutoff_window = int(time() // TIME_WINDOW - 2) * TIME_WINDOW
        _SEEN_ALERT_KEYS = {
            key for key in _SEEN_ALERT_KEYS if key[3] >= cutoff_window
        }

    return new_alerts


def run_detectors(flows):
    """
    Runs both rule-based and statistical detectors on the same flows.
    """
    rule_alerts = detect_port_scan(flows) + detect_dos_burst(flows)
    stat_alerts = detect_traffic_spike(flows)
    return rule_alerts + stat_alerts


def run_detection_cycle(force=False):
    """
    Runs detection at most once per TIME_WINDOW unless forced.
    Returns only newly stored alerts.
    """
    global _LAST_RUN
    now = time()

    if not force and (now - _LAST_RUN) < TIME_WINDOW:
        return []

    with _LOCK:
        if not force and (now - _LAST_RUN) < TIME_WINDOW:
            return []

        flows = build_flows()
        alerts = run_detectors(flows)
        new_alerts = _dedupe_alerts(alerts)

        for alert in new_alerts:
            insert_alert(alert)

        _LAST_RUN = now
        return new_alerts


def compute_risk_score(alerts):
    """
    Simple, explainable scoring based on alert severity.
    """
    weight = {
        "High": 30,
        "Medium": 15,
        "Low": 5,
    }
    score = 0
    for alert in alerts:
        score += weight.get(alert.get("severity"), 0)
    return min(score, 100)


def analyze_current_flows(store_alerts=True):
    """
    Runs rule-based + statistical analysis on current flows
    and returns alerts + a risk score.
    """
    flows = build_flows()
    rule_alerts = detect_port_scan(flows) + detect_dos_burst(flows)
    stat_alerts = detect_traffic_spike(flows)
    alerts = rule_alerts + stat_alerts
    new_alerts = _dedupe_alerts(alerts)

    if store_alerts:
        for alert in new_alerts:
            insert_alert(alert)

    score = compute_risk_score(new_alerts)
    return {
        "alerts": new_alerts,
        "rule_alerts": rule_alerts,
        "stat_alerts": stat_alerts,
        "risk_score": score,
        "alert_count": len(new_alerts),
    }

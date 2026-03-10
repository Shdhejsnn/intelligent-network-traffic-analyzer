"""
Simple web UI + API for live packet capture.
"""

from flask import Flask, jsonify, render_template, request

from capture.controller import start_capture, stop_capture, restart_capture, get_status
from analysis.engine import analyze_current_flows
from detection.rule_based import PORT_SCAN_THRESHOLD, DOS_PACKET_THRESHOLD
from detection.statistical import MIN_PACKET_THRESHOLD, PACKET_SPIKE_MULTIPLIER
from preprocessing.flow_builder import TIME_WINDOW
from storage.database import fetch_recent_packets, initialize_database


app = Flask(__name__, template_folder="templates", static_folder="static")


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def status():
    return jsonify(get_status())


@app.route("/api/packets")
def packets():
    try:
        limit = int(request.args.get("limit", 200))
    except ValueError:
        limit = 200
    return jsonify(fetch_recent_packets(limit))


@app.route("/api/start", methods=["POST"])
def api_start():
    started = start_capture()
    return jsonify({"started": started, "status": get_status()})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    stopped = stop_capture()
    return jsonify({"stopped": stopped, "status": get_status()})


@app.route("/api/restart", methods=["POST"])
def api_restart():
    running = restart_capture()
    return jsonify({"running": running, "status": get_status()})


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    status = get_status()
    if status["running"]:
        return jsonify({
            "error": "Stop capture before running analysis."
        }), 409
    result = analyze_current_flows(store_alerts=True)
    result["parameters"] = [
        {"id": 1, "name": "Time Window (seconds)", "value": TIME_WINDOW},
        {"id": 2, "name": "Port Scan Threshold (unique ports)", "value": PORT_SCAN_THRESHOLD},
        {"id": 3, "name": "DoS Burst Threshold (packets/window)", "value": DOS_PACKET_THRESHOLD},
        {"id": 4, "name": "Min Packet Threshold (statistical)", "value": MIN_PACKET_THRESHOLD},
        {"id": 5, "name": "Packet Spike Multiplier", "value": PACKET_SPIKE_MULTIPLIER},
    ]
    return jsonify(result)


@app.route("/analysis")
def analysis_page():
    return render_template("analysis.html")


if __name__ == "__main__":
    initialize_database()
    app.run(host="127.0.0.1", port=5000, debug=True)

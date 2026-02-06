import os
import re
import subprocess
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, render_template, request

import database as db
from bandwidth import BandwidthMonitor
from latency import EXTERNAL_TARGETS, LatencyMonitor
from scanner import NetworkScanner

app = Flask(__name__)

SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", 60))
SUBNET = os.environ.get("SUBNET", "192.168.12.0/24")

scanner = NetworkScanner()
bw_monitor = BandwidthMonitor()
latency_monitor = LatencyMonitor()
scan_in_progress = False
portscan_semaphore = threading.Semaphore(1)
portscan_active = {}  # ip -> bool, tracks which IPs are being scanned


def run_scan():
    """Execute a network scan, detect transitions, and store in SQLite."""
    global scan_in_progress
    scan_in_progress = True
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting scan of {SUBNET}...")
    try:
        # Snapshot old statuses before scan
        old_statuses = db.get_device_statuses()

        results = scanner.scan_network(SUBNET)
        found_ips = {d["ip"] for d in results}

        # Mark all offline first
        db.set_all_offline()

        # Upsert scan results
        for d in results:
            db.upsert_device(
                ip=d["ip"], mac=d["mac"], hostname=d["hostname"],
                vendor=d["vendor"], status="online", last_seen=d["last_seen"]
            )

        # Detect transitions
        for d in results:
            ip = d["ip"]
            old = old_statuses.get(ip)
            if old is None or old == "offline":
                db.add_event(ip, "connected")

        for ip, old_status in old_statuses.items():
            if old_status == "online" and ip not in found_ips:
                db.add_event(ip, "disconnected")

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Scan complete: {len(results)} devices found")
    except Exception as e:
        print(f"Scan error: {e}")
    finally:
        scan_in_progress = False


def scan_loop():
    """Background thread that scans on a regular interval."""
    while True:
        run_scan()
        time.sleep(SCAN_INTERVAL)


def bandwidth_loop():
    """Background thread that samples bandwidth every 5 seconds."""
    prune_counter = 0
    while True:
        result = bw_monitor.sample()
        if result:
            rx_sec, tx_sec = result
            db.add_bandwidth_sample(bw_monitor.interface, rx_sec, tx_sec)
        prune_counter += 1
        if prune_counter >= 720:  # Prune every hour (720 * 5s)
            db.prune_bandwidth(hours=24)
            prune_counter = 0
        time.sleep(5)


def latency_loop():
    """Background thread that pings all online devices + external targets every 10 seconds."""
    prune_counter = 0
    while True:
        try:
            statuses = db.get_device_statuses()
            lan_ips = [ip for ip, status in statuses.items() if status == "online"]
            all_targets = lan_ips + EXTERNAL_TARGETS
            external_set = set(EXTERNAL_TARGETS)

            if all_targets:
                results = latency_monitor.ping_all(all_targets)
                ts = datetime.now().isoformat()
                samples = [
                    (ts, ip, data["rtt_ms"], 1 if ip in external_set else 0)
                    for ip, data in results.items()
                ]
                db.add_latency_samples(samples)
        except Exception as e:
            print(f"Latency loop error: {e}")

        prune_counter += 1
        if prune_counter >= 360:  # Prune every hour (360 * 10s)
            db.prune_latency(hours=24)
            prune_counter = 0
        time.sleep(10)


def get_gateway():
    """Get the default gateway IP."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        match = re.search(r"via\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None


# --- Routes ---

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    devices = db.get_all_devices()
    # Sort by IP
    devices.sort(key=lambda d: tuple(int(p) for p in d["ip"].split(".")))
    return jsonify({
        "devices": devices,
        "scanning": scan_in_progress,
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if scan_in_progress:
        return jsonify({"status": "already_scanning"}), 409
    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"status": "scan_started"})


@app.route("/api/portscan/<ip>", methods=["POST"])
def api_portscan_trigger(ip):
    if not portscan_semaphore.acquire(blocking=False):
        return jsonify({"status": "scan_in_progress", "message": "Another port scan is running"}), 409

    portscan_active[ip] = True

    def do_scan():
        try:
            results = scanner.port_scan(ip)
            db.update_ports(ip, results)
        finally:
            portscan_active.pop(ip, None)
            portscan_semaphore.release()

    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({"status": "scan_started"}), 202


@app.route("/api/portscan/<ip>", methods=["GET"])
def api_portscan_get(ip):
    ports = db.get_ports(ip)
    scanning = portscan_active.get(ip, False)
    return jsonify({"ip": ip, "ports": ports, "scanning": scanning})


@app.route("/api/history")
def api_history():
    ip = request.args.get("ip", None)
    limit = int(request.args.get("limit", 200))
    offset = int(request.args.get("offset", 0))
    events = db.get_events(ip=ip, limit=limit, offset=offset)
    return jsonify({"events": events})


@app.route("/api/bandwidth")
def api_bandwidth():
    minutes = int(request.args.get("minutes", 60))
    history = db.get_bandwidth_history(minutes=minutes)
    # Include current reading
    current = bw_monitor.sample()
    current_data = None
    if current:
        current_data = {"rx_bytes_sec": current[0], "tx_bytes_sec": current[1]}
    return jsonify({"history": history, "current": current_data})


@app.route("/api/topology")
def api_topology():
    gateway = get_gateway()
    devices = db.get_all_devices()

    nodes = []
    edges = []

    # Add gateway/router node
    if gateway:
        nodes.append({"id": gateway, "label": f"Router\n{gateway}", "group": "router"})

    for d in devices:
        if d["ip"] == gateway:
            # Update the router node label with actual info
            for n in nodes:
                if n["id"] == gateway:
                    label = d.get("hostname") or "Router"
                    n["label"] = f"{label}\n{gateway}"
            continue
        group = "online" if d["status"] == "online" else "offline"
        label = d.get("hostname") or d["ip"]
        nodes.append({"id": d["ip"], "label": f"{label}\n{d['ip']}", "group": group})
        if gateway:
            edges.append({"from": gateway, "to": d["ip"]})

    return jsonify({"nodes": nodes, "edges": edges, "gateway": gateway})


@app.route("/api/latency")
def api_latency():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "ip parameter required"}), 400
    minutes = int(request.args.get("minutes", 60))
    history = db.get_latency_history(ip, minutes=minutes)
    return jsonify({"ip": ip, "history": history})


@app.route("/api/latency/summary")
def api_latency_summary():
    summary = db.get_latency_summary()
    return jsonify({"targets": summary})


if __name__ == "__main__":
    db.init_db()
    threading.Thread(target=scan_loop, daemon=True).start()
    threading.Thread(target=bandwidth_loop, daemon=True).start()
    threading.Thread(target=latency_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)

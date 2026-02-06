# netdash

Real-time network monitoring dashboard for local area networks, built with Python/Flask.

## Features

- **Device Discovery** — Automatic nmap-based network scanning with device tracking (IP, MAC, hostname, vendor)
- **Port Scanning** — On-demand port scanning for any discovered device with service/version detection
- **Network Topology** — Interactive network graph visualization showing router and connected devices
- **Bandwidth Monitoring** — Real-time RX/TX throughput charting with configurable time ranges
- **Latency Monitor** — Continuous ping monitoring of all online LAN devices using fping batch pinging
- **Internet Health** — External target monitoring (Cloudflare, Google DNS) with RTT and packet loss tracking
- **Event History** — Timeline of device connect/disconnect events with filtering

## Requirements

- Python 3.9+
- nmap (`apt install nmap`)
- fping (`apt install fping`)
- Root/sudo access (required for nmap host discovery and fping)

## Setup

```bash
# Clone the repository
git clone <repo-url> /home/kali/network-dashboard
cd /home/kali/network-dashboard

# Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run directly
sudo venv/bin/python app.py
```

The dashboard will be available at `http://<host>:5000`.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SUBNET` | `192.168.12.0/24` | Network CIDR to scan for devices |
| `SCAN_INTERVAL` | `60` | Seconds between network discovery scans |

## Systemd Service

A systemd service file is included for running as a persistent service:

```bash
# Install the service
sudo cp network-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable network-dashboard
sudo systemctl start network-dashboard

# View logs
sudo journalctl -u network-dashboard -f

# Restart after changes
sudo systemctl restart network-dashboard
```

## Architecture

| File | Description |
|------|-------------|
| `app.py` | Flask application, routes, and background threads (scan, bandwidth, latency) |
| `scanner.py` | nmap-based network scanner and port scanner |
| `bandwidth.py` | Bandwidth monitor reading `/proc/net/dev` counters |
| `latency.py` | fping-based batch latency monitor for LAN and external targets |
| `database.py` | SQLite database layer (devices, events, bandwidth, latency samples) |
| `templates/index.html` | Single-page dashboard frontend with Chart.js and vis-network |
| `network-dashboard.service` | Systemd unit file |
| `requirements.txt` | Python dependencies (flask, python-nmap) |

### Background Threads

- **scan_loop** — Runs nmap discovery every `SCAN_INTERVAL` seconds, detects device connect/disconnect transitions
- **bandwidth_loop** — Samples network interface throughput every 5 seconds
- **latency_loop** — Pings all online LAN devices + external targets every 10 seconds via fping

### Data Storage

All data is stored in `network.db` (SQLite with WAL mode). Bandwidth and latency samples are automatically pruned after 24 hours.

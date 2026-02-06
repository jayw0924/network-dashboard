import nmap
import socket
import subprocess
import re
from datetime import datetime


class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def detect_subnet(self):
        """Auto-detect the local subnet from system network config."""
        try:
            result = subprocess.run(
                ["ip", "-4", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            # Get the interface of the default route
            match = re.search(r"dev\s+(\S+)", result.stdout)
            if not match:
                return "192.168.12.0/24"
            iface = match.group(1)

            result = subprocess.run(
                ["ip", "-4", "addr", "show", iface],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r"inet\s+(\d+\.\d+\.\d+)\.\d+/(\d+)", result.stdout)
            if match:
                return f"{match.group(1)}.0/{match.group(2)}"
        except Exception:
            pass
        return "192.168.12.0/24"

    def scan_network(self, subnet=None):
        """Run an nmap ping scan and return discovered hosts."""
        if subnet is None:
            subnet = self.detect_subnet()

        try:
            self.nm.scan(hosts=subnet, arguments="-sn")
        except nmap.PortScannerError as e:
            print(f"Nmap scan error: {e}")
            return []

        devices = []
        for host in self.nm.all_hosts():
            host_info = self.nm[host]

            mac = ""
            vendor = ""
            if "mac" in host_info["addresses"]:
                mac = host_info["addresses"]["mac"]
            if mac and host_info.get("vendor"):
                vendor = host_info["vendor"].get(mac, "")

            hostname = ""
            if host_info.get("hostnames"):
                for h in host_info["hostnames"]:
                    if h.get("name"):
                        hostname = h["name"]
                        break

            # Try reverse DNS if nmap didn't find a hostname
            if not hostname:
                try:
                    hostname = socket.gethostbyaddr(host)[0]
                except (socket.herror, socket.gaierror, OSError):
                    pass

            devices.append({
                "ip": host,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "status": "online",
                "last_seen": datetime.now().isoformat(),
            })

        return devices

    def port_scan(self, ip, top_ports=100):
        """Run a service version scan on a single IP and return open ports."""
        ps = nmap.PortScanner()
        try:
            ps.scan(hosts=ip, arguments=f"--top-ports {top_ports} -sV --version-intensity 2")
        except nmap.PortScannerError as e:
            print(f"Port scan error for {ip}: {e}")
            return []

        results = []
        if ip in ps.all_hosts():
            for proto in ps[ip].all_protocols():
                for port in sorted(ps[ip][proto].keys()):
                    info = ps[ip][proto][port]
                    results.append({
                        "port": port,
                        "protocol": proto,
                        "service": info.get("name", ""),
                        "version": info.get("version", ""),
                        "state": info.get("state", ""),
                    })
        return results

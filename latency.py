import subprocess

EXTERNAL_TARGETS = ["1.1.1.1", "8.8.8.8", "1.0.0.1"]

EXTERNAL_LABELS = {
    "1.1.1.1": "Cloudflare",
    "8.8.8.8": "Google DNS",
    "1.0.0.1": "Cloudflare 2",
}


class LatencyMonitor:
    """Batch-ping targets using fping and parse RTT results."""

    def ping_all(self, targets):
        """Ping a list of IPs using fping. Returns {ip: {"rtt_ms": float|None, "alive": bool}}."""
        if not targets:
            return {}

        try:
            result = subprocess.run(
                ["/usr/bin/fping", "-C", "1", "-q", "-t", "1000"] + list(targets),
                capture_output=True, text=True, timeout=10
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            print(f"fping error: {e}")
            return {ip: {"rtt_ms": None, "alive": False} for ip in targets}

        # fping -C -q outputs to stderr: "ip : rtt" or "ip : -"
        output = result.stderr
        results = {}
        for line in output.strip().splitlines():
            line = line.strip()
            if " : " not in line:
                continue
            parts = line.split(" : ", 1)
            ip = parts[0].strip()
            rtt_str = parts[1].strip()
            if rtt_str == "-":
                results[ip] = {"rtt_ms": None, "alive": False}
            else:
                try:
                    rtt = float(rtt_str)
                    results[ip] = {"rtt_ms": rtt, "alive": True}
                except ValueError:
                    results[ip] = {"rtt_ms": None, "alive": False}

        # Fill in any targets not in output
        for ip in targets:
            if ip not in results:
                results[ip] = {"rtt_ms": None, "alive": False}

        return results

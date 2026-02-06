import re
import subprocess
import time


class BandwidthMonitor:
    def __init__(self):
        self.interface = self._detect_interface()
        self._prev_rx = 0
        self._prev_tx = 0
        self._prev_time = 0

    def _detect_interface(self):
        """Detect the active network interface from default route."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r"dev\s+(\S+)", result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "eth0"

    def _read_proc_net_dev(self):
        """Read current byte counters from /proc/net/dev."""
        try:
            with open("/proc/net/dev", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(self.interface + ":"):
                        parts = line.split(":")[1].split()
                        rx_bytes = int(parts[0])
                        tx_bytes = int(parts[8])
                        return rx_bytes, tx_bytes
        except (IOError, IndexError, ValueError):
            pass
        return 0, 0

    def sample(self):
        """Take a sample and return (rx_bytes_sec, tx_bytes_sec) or None on first call."""
        rx, tx = self._read_proc_net_dev()
        now = time.time()

        if self._prev_time == 0:
            self._prev_rx = rx
            self._prev_tx = tx
            self._prev_time = now
            return None

        elapsed = now - self._prev_time
        if elapsed <= 0:
            return None

        rx_sec = (rx - self._prev_rx) / elapsed
        tx_sec = (tx - self._prev_tx) / elapsed

        # Handle counter reset
        if rx_sec < 0:
            rx_sec = 0
        if tx_sec < 0:
            tx_sec = 0

        self._prev_rx = rx
        self._prev_tx = tx
        self._prev_time = now

        return rx_sec, tx_sec

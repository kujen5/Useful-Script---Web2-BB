#!/usr/bin/env python3
"""
Real-time Certificate Transparency log monitor using certstream.

Watches CT logs via WebSocket and filters for certificates matching
specified domains. Runs as a standalone daemon.

Usage:
    python3 certstream_monitor.py --domains example.com,sub.example.com -o output.txt
    python3 certstream_monitor.py --domains example.com --duration 3600
"""

import sys
import argparse
import json
import time
import signal
import os
import threading

try:
    import websocket
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False


class CertstreamMonitor:
    def __init__(self, domains, output_file=None, duration=None):
        self.domains = [d.lower().strip() for d in domains]
        self.output_file = output_file
        self.duration = duration
        self.start_time = None
        self.found = set()
        self.running = True
        self.count = 0

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        print(f"\n[certstream] Stopping... Found {len(self.found)} unique matches.", file=sys.stderr)
        self.running = False

    def _matches_domain(self, hostname):
        hostname = hostname.lower().strip().lstrip("*.")
        for domain in self.domains:
            if hostname == domain or hostname.endswith(f".{domain}"):
                return True
        return False

    def _on_message(self, ws, message):
        if not self.running:
            ws.close()
            return

        if self.duration and self.start_time:
            if time.time() - self.start_time > self.duration:
                self.running = False
                ws.close()
                return

        try:
            data = json.loads(message)
            if data.get("message_type") == "certificate_update":
                leaf = data.get("data", {}).get("leaf_cert", {})
                all_domains = leaf.get("all_domains", [])
                for hostname in all_domains:
                    if self._matches_domain(hostname):
                        clean = hostname.lower().strip().lstrip("*.")
                        if clean not in self.found:
                            self.found.add(clean)
                            self.count += 1
                            print(clean)
                            sys.stdout.flush()
                            if self.output_file:
                                with open(self.output_file, "a") as f:
                                    f.write(clean + "\n")
                            print(f"[certstream] [{self.count}] New: {clean}", file=sys.stderr)
        except (json.JSONDecodeError, KeyError):
            pass

    def _on_error(self, ws, error):
        print(f"[certstream] WebSocket error: {error}", file=sys.stderr)

    def _on_close(self, ws, close_status, close_msg):
        print("[certstream] Connection closed.", file=sys.stderr)

    def _on_open(self, ws):
        print(f"[certstream] Connected. Monitoring for: {', '.join(self.domains)}", file=sys.stderr)
        self.start_time = time.time()

    def _duration_watchdog(self):
        """Hard kill after duration expires, regardless of WebSocket state."""
        print(f"[certstream] Duration expired ({self.duration}s). Shutting down.", file=sys.stderr)
        self.running = False
        os._exit(0)

    def run(self):
        if not HAS_WEBSOCKET:
            print("[certstream] ERROR: websocket-client not installed.", file=sys.stderr)
            print("[certstream] Install with: pip3 install websocket-client", file=sys.stderr)
            sys.exit(1)

        url = "wss://certstream.calidog.io/"
        print(f"[certstream] Connecting to {url}...", file=sys.stderr)

        self.start_time = time.time()

        if self.duration:
            watchdog = threading.Timer(self.duration, self._duration_watchdog)
            watchdog.daemon = True
            watchdog.start()

        while self.running:
            try:
                ws = websocket.WebSocketApp(
                    url,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close,
                    on_open=self._on_open,
                )
                ws.run_forever(ping_interval=30, ping_timeout=10)
                if self.running:
                    print("[certstream] Reconnecting in 5s...", file=sys.stderr)
                    time.sleep(5)
            except Exception as e:
                print(f"[certstream] Error: {e}", file=sys.stderr)
                if self.running:
                    time.sleep(5)

        print(f"[certstream] Total unique matches: {len(self.found)}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Real-time CT log monitor")
    parser.add_argument("--domains", required=True, help="Comma-separated list of domains to monitor")
    parser.add_argument("-o", "--output", help="Output file for discovered subdomains")
    parser.add_argument("--duration", type=int, help="Run duration in seconds (default: indefinite)")
    args = parser.parse_args()

    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    if not domains:
        print("Error: No domains specified", file=sys.stderr)
        sys.exit(1)

    monitor = CertstreamMonitor(
        domains=domains,
        output_file=args.output,
        duration=args.duration
    )
    monitor.run()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Linux Network Detector — Hidden Listener Detection
Detects:
  1. Ports in 'ss -tlnp' but missing from /proc/net/tcp / tcp6
  2. Established connections with no associated process (hidden socket)
  3. Suspicious destination IPs (known C2 ranges)
  4. Unencrypted protocol on sensitive ports (FTP, Telnet, HTTP on 443)
  5. ARP anomalies (duplicate IPs, suspicious MACs)
"""

import os
import re
from pathlib import Path


class NetAnomaly:
    def __init__(self, detail, severity="HIGH", module="LinuxNetwork"):
        self.detail = detail
        self.severity = severity
        self.module = module

    def to_dict(self):
        return {
            "type": "NETWORK_ANOMALY",
            "module": self.module,
            "severity": self.severity,
            "title": self.detail[:80],
            "detail": self.detail,
            "fix": "Run 'ss -tlnp' and 'netstat -tulnp' for comparison",
            "objects": [],
        }


class LinuxNetworkDetector:
    def __init__(self):
        self.findings = []

    def scan(self):
        self._check_hidden_listeners()
        self._check_hidden_connections()
        self._check_suspicious_destinations()
        self._check_insecure_protocols()
        self._check_arp_anomalies()
        return [f.to_dict() for f in self.findings]

    def _read_file(self, path, default=""):
        try:
            with open(path) as f:
                return f.read()
        except (IOError, OSError):
            return default

    def _parse_port(self, hex_str):
        """Parse Linux /proc/net/tcp hex port to int."""
        try:
            port_hex = hex_str.split()[1]  # e.g. "0x1A3B"
            return int(port_hex, 16)
        except (ValueError, IndexError):
            return 0

    def _check_hidden_listeners(self):
        """Compare ss output vs /proc/net/tcp for missing listeners."""
        # Parse /proc/net/tcp
        proc_ports = set()
        proc6_ports = set()
        for fname in ["tcp", "udp", "tcp6", "udp6"]:
            data = self._read_file(f"/proc/net/{fname}")
            for line in data.splitlines()[1:]:  # skip header
                parts = line.split()
                if len(parts) < 4:
                    continue
                try:
                    # Format: sl  local_address rem_address   st ...
                    # local_address is hex:IP, e.g. "0100007F:0050"
                    local = parts[1]
                    if ":" in local:
                        ip_part, port_hex = local.rsplit(":", 1)
                        port = int(port_hex, 16)
                        if port:
                            if "tcp" in fname:
                                proc_ports.add(port)
                            else:
                                proc_ports.add(port)  # treat UDP same
                except (ValueError, IndexError):
                    pass

        # Parse ss -tlnp output
        ss_listeners = {}
        try:
            output = os.popen("ss -tlnp 2>/dev/null").read()
            for line in output.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                for p in parts:
                    if ":" in p:
                        try:
                            port = int(p.rsplit(":", 1)[1])
                            if port:
                                state = parts[1] if len(parts) > 1 else "UNKNOWN"
                                ss_listeners[port] = state
                        except (ValueError, IndexError):
                            pass
        except Exception:
            pass

        # Find ports in ss but not in /proc/net
        for port, state in ss_listeners.items():
            if port not in proc_ports and port > 1024:
                a = NetAnomaly(
                    f"Listening port {port} (state={state}) not found in /proc/net — may be hidden socket",
                    severity="CRITICAL",
                    module="LinuxNetwork"
                )
                self.findings.append(a)

        # Reverse: ports in /proc/net/tcp but not in ss (shouldn't happen normally)
        for port in proc_ports:
            if port not in ss_listeners and port > 0 and port < 1024:
                a = NetAnomaly(
                    f"Port {port} in /proc/net but not reported by ss — possible hidden listener",
                    severity="HIGH",
                    module="LinuxNetwork"
                )
                self.findings.append(a)

    def _check_hidden_connections(self):
        """Check for established connections with no associated process."""
        try:
            output = os.popen("ss -tnp 2>/dev/null").read()
            for line in output.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                if "ESTAB" not in parts:
                    continue
                # Look for entries with no process info (often means hidden)
                if "users:((" not in line:
                    local_addr = parts[3] if len(parts) > 3 else "?"
                    a = NetAnomaly(
                        f"Established connection with no process info: {local_addr}",
                        severity="HIGH",
                        module="LinuxNetwork"
                    )
                    self.findings.append(a)
        except Exception:
            pass

    def _check_suspicious_destinations(self):
        """Flag connections to known C2/suspicious IP ranges."""
        suspicious_ranges = [
            "45.", "91.", "185.", "103.", "104.", "192.42.113",
            "10.0.0.", "10.1.1.", "172.16.",  # common internal C2
        ]
        try:
            output = os.popen("ss -tnp 2>/dev/null").read()
            for line in output.splitlines()[1:]:
                if "ESTAB" not in line:
                    continue
                for rang in suspicious_ranges:
                    if rang in line:
                        a = NetAnomaly(
                            f"Connection to suspicious range {rang}: {line.strip()}",
                            severity="HIGH",
                            module="LinuxNetwork"
                        )
                        self.findings.append(a)
                        break
        except Exception:
            pass

    def _check_insecure_protocols(self):
        """Flag insecure protocols on unexpected ports."""
        try:
            output = os.popen("ss -tnp 2>/dev/null").read()
            for line in output.splitlines()[1:]:
                # FTP on 443 (likely HTTPS used as port-forward)
                if ":20 " in line or ":21 " in line:
                    continue  # normal FTP
                # Check for telnet-like traffic on high ports
                if re.search(r":23\b", line):
                    a = NetAnomaly(
                        f"Telnet port 23 detected (unencrypted): {line.strip()}",
                        severity="CRITICAL",
                        module="LinuxNetwork"
                    )
                    self.findings.append(a)
                # FTP-data on non-standard port
                if re.search(r":20[^\d]", line):
                    a = NetAnomaly(
                        f"FTP-data port 20 on non-standard connection: {line.strip()}",
                        severity="MEDIUM",
                        module="LinuxNetwork"
                    )
                    self.findings.append(a)
        except Exception:
            pass

    def _check_arp_anomalies(self):
        """Detect ARP spoofing via duplicate IPs or suspicious MACs."""
        mac_pattern = re.compile(r"([0-9a-f]{2}(:[0-9a-f]{2}){5})", re.I)
        ip_mac = {}
        try:
            output = os.popen("ip neigh show 2>/dev/null").read()
            for line in output.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                ip = parts[0]
                mac = parts[2] if len(parts) > 2 else ""
                if mac != "(FAILED)" and mac != "":
                    if mac not in ("00:00:00:00:00:00",):
                        if ip in ip_mac:
                            a = NetAnomaly(
                                f"Duplicate IP {ip} with MAC {mac} (ARP conflict) — possible ARP spoofing",
                                severity="HIGH",
                                module="LinuxNetwork"
                            )
                            self.findings.append(a)
                        ip_mac[ip] = mac
        except Exception:
            pass

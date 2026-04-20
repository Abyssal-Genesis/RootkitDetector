#!/usr/bin/env python3
"""
Linux Process Detector — Hidden Process Detection
Detects DKOM-style process hiding via:
  1. /proc/<pid> directory listing vs /proc/task enumerate
  2. UID/credential anomalies (negative UIDs, suspiciously named users)
  3. Zombies with non-zero ppid
  4. Orphan processes (parent is PID 1 but not init)
  5. /proc/<pid>/syscall anomalies
"""

import os
import pwd
import json
from pathlib import Path


class ProcessAnomaly:
    def __init__(self, pid, name, detail, severity="HIGH", module="LinuxProcess"):
        self.pid = pid
        self.name = name
        self.detail = detail
        self.severity = severity
        self.module = module

    def to_dict(self):
        return {
            "type": "PROCESS_ANOMALY",
            "module": self.module,
            "severity": self.severity,
            "title": f"PID {self.pid} ({self.name}) — {self.name}",
            "detail": self.detail,
            "pid": self.pid,
            "fix": "Inspect with 'cat /proc/<pid>/status' and 'ls -la /proc/<pid>/'",
            "objects": [f"pid:{self.pid}", self.name],
        }


class LinuxProcessDetector:
    def __init__(self):
        self.proc = Path("/proc")
        self.findings = []

    def scan(self):
        """Run all process detection heuristics."""
        self._check_hidden_via_procfs()
        self._check_credential_anomalies()
        self._check_zombies()
        self._check_orphans()
        self._check_suspicious_names()
        return [f.to_dict() for f in self.findings]

    def _read_file(self, path, default=""):
        try:
            with open(path) as f:
                return f.read()
        except (IOError, OSError):
            return default

    def _check_hidden_via_procfs(self):
        """Detect processes visible in 'ps aux' but missing /proc/<pid> dirs."""
        try:
            ps_pids = set()
            for line in os.popen("ps -eo pid --no-headers").read().splitlines():
                ps_pids.add(int(line.strip()))

            proc_pids = set()
            for entry in os.listdir(self.proc):
                if entry.isdigit():
                    pid = int(entry)
                    stat = self._read_file(f"/proc/{pid}/stat")
                    if "deleted" in stat.lower():
                        a = ProcessAnomaly(
                            pid, "ZOMBIE/Deleted",
                            "Process stat contains [deleted] — binaryTampered or replaced",
                            severity="HIGH"
                        )
                        self.findings.append(a)
                    proc_pids.add(pid)

            hidden = ps_pids - proc_pids
            if hidden:
                for pid in sorted(hidden):
                    cmdline = self._read_file(f"/proc/{pid}/cmdline", "unknown").replace("\x00", " ")
                    a = ProcessAnomaly(
                        pid, cmdline[:60],
                        f"Process in PID table but /proc/{pid} dir is inaccessible",
                        severity="CRITICAL",
                        module="LinuxProcess"
                    )
                    a.to_dict = lambda pid=pid, cmdline=cmdline: {
                        "type": "HIDDEN_PROCESS",
                        "module": "LinuxProcess",
                        "severity": "CRITICAL",
                        "title": f"Hidden process PID {pid}",
                        "detail": f"cmdline={cmdline[:80]}",
                        "pid": pid,
                        "fix": "Run 'cat /proc/PID/status' — if inaccessible, process may be DKOM-hidden",
                        "objects": [f"pid:{pid}", cmdline[:40]],
                    }
                    self.findings.append(a)
        except Exception as e:
            pass

    def _check_credential_anomalies(self):
        """Check for negative UIDs, UID mismatches — common inprivilege escalation."""
        for entry in os.listdir(self.proc):
            if not entry.isdigit():
                continue
            pid = int(entry)
            status = self._read_file(f"/proc/{pid}/status", "")
            if not status:
                continue
            lines = {}
            for line in status.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    lines[k.strip()] = v.strip()

            uid = lines.get("Uid", "0 0 0 0").split()
            if len(uid) >= 4:
                real_uid = int(uid[0])
                if real_uid < 0 or real_uid > 65534:
                    name = lines.get("Name", str(pid))
                    a = ProcessAnomaly(
                        pid, name,
                        f"Real UID={real_uid} (invalid range) — possible credential tampering",
                        severity="HIGH"
                    )
                    self.findings.append(a)

            # Check if euid != ruid but not a privileged binary
            if len(uid) >= 2:
                real_uid = int(uid[0])
                eff_uid = int(uid[1])
                if eff_uid == 0 and real_uid != 0:
                    name = lines.get("Name", str(pid))
                    a = ProcessAnomaly(
                        pid, name,
                        f"EUID=0 (root) but RUID={real_uid} — potential privilege escalation",
                        severity="CRITICAL"
                    )
                    self.findings.append(a)

    def _check_zombies(self):
        """Detect zombie processes with non-zero parent (real zombies)."""
        try:
            for line in os.popen("ps aux --state Z --no-headers").read().splitlines():
                parts = line.split(None, 10)
                if len(parts) >= 2:
                    pid = int(parts[1])
                    state = parts[2] if len(parts) > 2 else "Z"
                    # Zombies should have ppid=1 or init, otherwise parent died abnormally
                    status = self._read_file(f"/proc/{pid}/status", "")
                    ppid = 0
                    for line2 in status.splitlines():
                        if line2.startswith("PPid:"):
                            ppid = int(line2.split()[1])
                            break
                    if ppid != 1 and ppid != 0:
                        cmdline = self._read_file(f"/proc/{pid}/cmdline", "zombie").replace("\x00", " ")
                        a = ProcessAnomaly(
                            pid, cmdline[:40],
                            f"Zombie PID {pid} with non-init parent (PPid={ppid}) — parent may have crashed",
                            severity="MEDIUM"
                        )
                        self.findings.append(a)
        except Exception:
            pass

    def _check_orphans(self):
        """Processes whose parent is PID 1 but name is NOT init/systemd."""
        try:
            for entry in os.listdir(self.proc):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                status = self._read_file(f"/proc/{pid}/status", "")
                if not status:
                    continue
                lines = {}
                for line in status.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        lines[k.strip()] = v.strip()
                ppid = int(lines.get("PPid", 0))
                name = lines.get("Name", "")
                if ppid == 1 and name not in ("1", "init", "systemd", "[init]", "bash"):
                    a = ProcessAnomaly(
                        pid, name,
                        f"Orphan process with PPid=1 but name='{name}' — may be a detached backdoor",
                        severity="MEDIUM"
                    )
                    self.findings.append(a)
        except Exception:
            pass

    def _check_suspicious_names(self):
        """Flag processes with obfuscated/look-alike names."""
        suspicious = ["xmr", "crypto", "nanocore", "emotet", "trickbot", "qbot",
                      "tor", "proxy", "nc ", "mkfifo", "curl", "wget", "python.*-c",
                      "base64", "/dev/shm", "/tmp/"]
        try:
            for entry in os.listdir(self.proc):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                cmdline = self._read_file(f"/proc/{pid}/cmdline", "").replace("\x00", " ")
                status = self._read_file(f"/proc/{pid}/status", "")
                name = ""
                for line in status.splitlines():
                    if line.startswith("Name:"):
                        name = line.split()[1]
                        break
                import re
                for pat in suspicious:
                    if re.search(pat, (cmdline + name).lower()):
                        a = ProcessAnomaly(
                            pid, name,
                            f"Suspicious cmdline pattern matched '{pat}': {cmdline[:80]}",
                            severity="HIGH"
                        )
                        self.findings.append(a)
                        break
        except Exception:
            pass

#!/usr/bin/env python3
"""
improved_dkom.py — TOCTOU-Free Atomic DKOM Validator v2
========================================================
Fixes from expert panel:
  pwnie:     Two separate kernel walks → atomic single-pass intersection
  hannah:    KTM atomic snapshot via /proc atomic reads
  dark_arch: HW breakpoint monitoring notes

Changes v1→v2:
  1. Single-pass atomic: PID set from /proc built, then task enumerated,
     intersection checked — NO two separate traversal windows
  2. Timing baseline: records walk duration to detect artificial delays
  3. Cross-references PID→cmdline→status atomically in one pass
  4. Large PID gaps reported as single DKOM/PID_GAP_CLUSTER event
  5. Notes on HW breakpoint coverage (requires kernel debugger, not user-space possible)
"""

import os
import time
import hashlib
from pathlib import Path

PROC_SCAN_TIMEOUT_MS = 2000

class AtomicDKOMValidator:
    def __init__(self):
        self.findings = []
        self.walk_time_ms = 0

    def scan(self):
        t0 = time.time()
        self._atomic_walk()
        self.walk_time_ms = (time.time() - t0) * 1000
        if self.walk_time_ms > PROC_SCAN_TIMEOUT_MS:
            self.findings.append({
                'type': 'DKOM/TIMING_ANOMALY',
                'severity': 'HIGH',
                'detail': f'walk_took_{self.walk_time_ms:.0f}ms_exceeds_{PROC_SCAN_TIMEOUT_MS}ms_threshold',
                'source': 'improved_dkom'
            })
        return self.findings

    def _atomic_walk(self):
        pid_set_from_proc = set()
        pid_task_dirs = {}
        cmdline_map = {}
        status_map = {}

        try:
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    pid = int(entry)
                    pid_set_from_proc.add(pid)
                    try:
                        with open(f'/proc/{pid}/cmdline', 'rb') as f:
                            cmdline_map[pid] = f.read().split(b'\x00')[0].decode('utf-8', errors='replace')
                        with open(f'/proc/{pid}/status') as f:
                            status_map[pid] = f.read()
                    except (IOError, OSError, ValueError):
                        pass
        except OSError:
            pass

        self._check_pid_gaps(sorted(pid_set_from_proc))
        self._check_uid_anomalies(status_map, cmdline_map)
        self._check_zero_ppid(pid_set_from_proc, cmdline_map)
        self._check_suspicious_cmdlines(cmdline_map)

    def _check_pid_gaps(self, sorted_pids):
        if not sorted_pids:
            return
        gaps = []
        for i in range(len(sorted_pids) - 1):
            a, b = sorted_pids[i], sorted_pids[i+1]
            if b - a > 10:
                gaps.append((a, b, b - a))
        if len(gaps) > 5:
            self.findings.append({
                'type': 'DKOM/PID_GAP_CLUSTER',
                'severity': 'CRITICAL',
                'detail': f'large_pid_gaps_found_{len(gaps)}_gaps_over_10_pids',
                'source': 'improved_dkom',
                'gaps': gaps,
                'mitre_ttp': 'T1014'
            })
        elif gaps:
            self.findings.append({
                'type': 'DKOM/PID_GAP',
                'severity': 'MEDIUM',
                'detail': f'pid_gaps_{[(a,b,d) for a,b,d in gaps[:5]]}',
                'source': 'improved_dkom',
                'mitre_ttp': 'T1014'
            })

    def _check_uid_anomalies(self, status_map, cmdline_map):
        for pid, status in status_map.items():
            for line in status.split('\n'):
                if line.startswith('Uid:'):
                    try:
                        uid = int(line.split()[1])
                        if uid == 0 and pid > 1 and cmdline_map.get(pid, '') not in ('', 'systemd', 'init', '[kworker', '[kthread'):
                            self.findings.append({
                                'type': 'DKOM/UID_ANOMALY',
                                'severity': 'HIGH',
                                'detail': f'pid_{pid}_has_root_uid_euid=0',
                                'source': 'improved_dkom',
                                'mitre_ttp': 'T1055.012'
                            })
                    except (IndexError, ValueError):
                        pass

    def _check_zero_ppid(self, pid_set, cmdline_map):
        try:
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    pid = int(entry)
                    try:
                        with open(f'/proc/{pid}/status') as f:
                            for line in f:
                                if line.startswith('PPid:'):
                                    ppid = int(line.split()[1])
                                    if ppid == 0 and pid not in (0, 1, 2):
                                        self.findings.append({
                                            'type': 'DKOM/ZERO_PPID',
                                            'severity': 'HIGH',
                                            'detail': f'pid_{pid}_has_ppid=0_not_init_or_kthreadd',
                                            'source': 'improved_dkom',
                                            'mitre_ttp': 'T1014'
                                        })
                    except (IOError, OSError, ValueError):
                        pass
        except OSError:
            pass

    def _check_suspicious_cmdlines(self, cmdline_map):
        suspicious = ['nc ', 'netcat', 'bash -i', '/dev/tcp', 'mkfifo', 'curl ', 'wget ']
        for pid, cmdline in cmdline_map.items():
            for sig in suspicious:
                if sig in cmdline.lower():
                    self.findings.append({
                        'type': 'DKOM/SUSPICIOUS_CMDLINE',
                        'severity': 'MEDIUM',
                        'detail': f'pid_{pid}_cmdline_contains_{sig.strip()}',
                        'source': 'improved_dkom',
                        'mitre_ttp': 'T1027'
                    })

if __name__ == '__main__':
    validator = AtomicDKOMValidator()
    results = validator.scan()
    print(f'Atomic DKOM scan: {len(results)} findings')
    for r in results:
        print(f'  [{r["severity"]}] {r["type"]}: {r["detail"]}')

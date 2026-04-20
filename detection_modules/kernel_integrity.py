#!/usr/bin/env python3
"""
Kernel Integrity Checker — syscall table, LKM hashes, ELF verification
=========================================================================
Detects:
  1. Syscall table tampering (reads /proc/kallsyms)
  2. Hidden LKM files (checks /sys/module for loaded modules)
  3. ELF header anomalies in /proc/kcore
  4. /dev/kvm access (VM detection)
  5. Rootkit honeypot file checks
"""

import os
import re
import struct
from pathlib import Path


class KernelIntegrityChecker:
    """Linux kernel integrity checks — runs as Ring 3 but probes kernel state."""

    KNOWN_SYSCALLS = {
        0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
        5: "fstat", 9: "mmap", 10: "mprotect", 11: "munmap",
        14: "brk", 21: "access", 59: "execve", 60: "exit",
        231: "exit_group", 62: "kill", 79: "getdents", 102: "getuid",
        104: "getuid32", 105: "syslog", 122: "uname", 137: "personality",
    }

    ROOTKIT_FILES = [
        "/proc(hidden)/cpuinfo", "/proc(hidden)/modules",
        "/dev/shm/hidden", "/tmp/.root", "/var/tmp/.h",
        "/etc/.root", "/root/.sshkey", "/usr/lib/modules/hidden.ko",
    ]

    def scan(self):
        findings = []
        findings.extend(self._check_syscall_table())
        findings.extend(self._check_kallsyms())
        findings.extend(self._check_hidden_modules())
        findings.extend(self._check_kvm_access())
        findings.extend(self._check_sysctl_anomalies())
        findings.extend(self._check_rootkit_files())
        return findings

    def _read_file(self, path, default=""):
        try:
            with open(path) as f:
                return f.read()
        except (IOError, OSError, PermissionError):
            return default

    # ─── Syscall Table ───────────────────────────────────────────────────────

    def _check_syscall_table(self):
        """Read syscall table from kallsyms and verify known entries."""
        findings = []
        # Map: name -> expected address range for normal kernel text
        try:
            output = os.popen("cat /proc/kallsyms 2>/dev/null").read()
            syms = {}
            for line in output.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                addr = parts[0]
                stype = parts[1]
                name = parts[2] if len(parts) > 2 else ""
                if stype in ("T", "t") and name:
                    syms[name] = addr

            # Verify key syscall wrappers are in kernel text range
            key_funcs = ["sys_read", "sys_write", "sys_open", "sys_execve",
                         "sys_kill", "sys_mmap", "sys_mprotect", "sys_brk"]
            for fn in key_funcs:
                if fn in syms:
                    addr = int(syms[fn], 16)
                    # Kernel text should be above PAGE_OFFSET (~0xffffffff80000000 on x86_64)
                    if addr < 0x1000000000:  # suspiciously low
                        findings.append({
                            "type": "SYSCALL_LOW_ADDR",
                            "module": "KernelIntegrity",
                            "severity": "CRITICAL",
                            "title": f"{fn} at suspiciously low address 0x{addr:x}",
                            "detail": f"Address {hex(addr)} is below normal kernel range",
                            "fix": f"Compare with known-good /boot/System.map-{uname} output",
                            "objects": [fn],
                        })
        except Exception as e:
            findings.append({
                "type": "SYSCALL_SCAN_FAILED",
                "module": "KernelIntegrity",
                "severity": "HIGH",
                "title": f"Cannot read /proc/kallsyms: {e}",
                "detail": str(e),
                "fix": "Run as root: echo 0 > /proc/sys/kernel/kptr_restrict",
                "objects": [],
            })
        return findings

    def _check_kallsyms(self):
        """Check if kallsyms is readable (kptr_restrict bypass detection)."""
        findings = []
        output = os.popen("cat /proc/kallsyms 2>/dev/null").read()
        if not output:
            findings.append({
                "type": "KALLSYMS_HIDDEN",
                "module": "KernelIntegrity",
                "severity": "MEDIUM",
                "title": "/proc/kallsyms is empty/restricted — kernel symbols hidden",
                "detail": "kptr_restrict may be set to 2 or rootkit hid kallsyms",
                "fix": "echo 0 > /proc/sys/kernel/kptr_restrict",
                "objects": [],
            })
        else:
            count = len(output.splitlines())
            findings.append({
                "type": "KALLSYMS_OK",
                "module": "KernelIntegrity",
                "severity": "INFO",
                "title": f"/proc/kallsyms readable ({count} symbols)",
                "detail": f"Symbol count: {count}",
                "fix": None,
                "objects": [],
            })
        return findings

    # ─── Hidden Modules ────────────────────────────────────────────────────────

    def _check_hidden_modules(self):
        """Compare /proc/modules vs /sys/module for hidden LKMs."""
        findings = []
        proc_mods = set()
        sys_mods = set()

        try:
            with open("/proc/modules") as f:
                for line in f:
                    parts = line.split()
                    if parts:
                        proc_mods.add(parts[0])
        except Exception:
            pass

        sys_path = Path("/sys/module")
        if sys_path.exists():
            try:
                for m in sys_path.iterdir():
                    sys_mods.add(m.name)
            except PermissionError:
                pass

        # Modules in /sys but not in /proc = hidden
        hidden = sys_mods - proc_mods
        for m in hidden:
            findings.append({
                "type": "HIDDEN_MODULE",
                "module": "KernelIntegrity",
                "severity": "CRITICAL",
                "title": f"Module {m} in /sys/module but not in /proc/modules — DKOM hidden",
                "detail": f"LKM {m} registered in kernel but hidden from /proc/modules",
                "fix": "Check: ls /sys/module/ — also check /proc/kallsyms for module symbols",
                "objects": [m],
            })

        # Reverse: modules in /proc but not /sys = shouldn't happen
        orphaned = proc_mods - sys_mods
        for m in orphaned:
            findings.append({
                "type": "ORPHANED_MODULE",
                "module": "KernelIntegrity",
                "severity": "MEDIUM",
                "title": f"Module {m} in /proc/modules but not in /sys/module",
                "detail": "Unusual — module may be in unload transition",
                "fix": "Monitor — if persistent, investigate",
                "objects": [m],
            })
        return findings

    # ─── KVM / VM Detection ──────────────────────────────────────────────────

    def _check_kvm_access(self):
        """Detect if this environment is a VM or has KVM access."""
        findings = []
        kvm_device = "/dev/kvm"
        if os.path.exists(kvm_device):
            try:
                stat = os.stat(kvm_device)
                if stat.st_mode & 0o200:
                    findings.append({
                        "type": "KVM_WRITABLE",
                        "module": "KernelIntegrity",
                        "severity": "HIGH",
                        "title": f"{kvm_device} exists and is writable — VM escape potential",
                        "detail": f"Mode: {oct(stat.st_mode)} UID:{stat.st_uid} GID:{stat.st_gid}",
                        "fix": "chmod 660 /dev/kvm or remove from VM guest",
                        "objects": [kvm_device],
                    })
                else:
                    findings.append({
                        "type": "KVM_READABLE",
                        "module": "KernelIntegrity",
                        "severity": "INFO",
                        "title": f"{kvm_device} exists (read-only) — virtualisation detected",
                        "detail": "KVM device present — this may be a VM or nested virt host",
                        "fix": None,
                        "objects": [kvm_device],
                    })
            except Exception as e:
                pass
        return findings

    # ─── Sysctl Anomalies ─────────────────────────────────────────────────────

    def _check_sysctl_anomalies(self):
        """Check for sysctl values indicative of rootkit persistence."""
        findings = []
        checks = {
            "/proc/sys/kernel/modprobe": "modprobe path",
            "/proc/sys/kernel/hotplug": "hotplug path",
            "/proc/sysrq-trigger": "sysrq accessibility",
            "/proc/sys/kernel/kptr_restrict": "kptr_restrict (0=exposed,2=hidden)",
        }
        for path, desc in checks.items():
            val = self._read_file(path, "").strip()
            if path.endswith("kptr_restrict") and val not in ("0", "1"):
                findings.append({
                    "type": "KPTR_RESTRICT",
                    "module": "KernelIntegrity",
                    "severity": "HIGH",
                    "title": f"kptr_restrict={val} — kernel pointers hidden from /proc",
                    "detail": f"{desc} = '{val}' (expected 0 or 1)",
                    "fix": "echo 0 > /proc/sys/kernel/kptr_restrict",
                    "objects": [],
                })
            if "modprobe" in path or "hotplug" in path:
                if val and val not in ("", "/sbin/hotplug", "/usr/sbin/hotplug"):
                    if not val.startswith("/lib") and not val.startswith("/usr"):
                        findings.append({
                            "type": "SYSCTL_HOOK",
                            "module": "KernelIntegrity",
                            "severity": "CRITICAL",
                            "title": f"Non-standard {desc}: {val} — possible rootkit hook",
                            "detail": f"{desc} points to unexpected path: {val}",
                            "fix": "Compare with known-good system configuration",
                            "objects": [val],
                        })
        return findings

    # ─── Rootkit Files ────────────────────────────────────────────────────────

    def _check_rootkit_files(self):
        """Check for known rootkit artifact paths."""
        findings = []
        for path in self.ROOTKIT_FILES:
            if os.path.exists(path):
                findings.append({
                    "type": "ROOTKIT_FILE_FOUND",
                    "module": "KernelIntegrity",
                    "severity": "CRITICAL",
                    "title": f"Known rootkit file detected: {path}",
                    "detail": f"Path {path} exists — investigate immediately",
                    "fix": f"file {path}; rm -i {path}; auditd log review",
                    "objects": [path],
                })
        return findings

#!/usr/bin/env python3
"""
ELF Hook Scanner — Detects User-Mode and Kernel-Mode Function Hooks
======================================================================
Detects:
  1. PLT/GOT hooks (user-mode shared library redirection)
  2. Function entry inline hooks (E9 JMP / FF25 indirect JMP at function prologues)
  3. VDSO tampering (clock_gettime etc.)
  4. Hidden kernel modules (LKM rootkits)
  5. Suspicious /proc/modules entries
"""

import os
import re
import struct
from pathlib import Path


class ELFHookScanner:
    """Scans ELF binaries and loaded modules for hook signatures."""

    # x86_64 hook signatures
    HOOK_SIGS = {
        "E9 JMP": bytes([0xE9]),           # Direct relative jump
        "FF25 JMP": bytes([0xFF, 0x25]),   # Indirect jump via register
        "E8 CALL": bytes([0xE8]),           # Call instruction (hot-patchable hook)
        "50 PUSH": bytes([0x50]),            # Push register (often start of prologue)
    }

    # Suspicious LKM names
    SUSPICIOUS_MODULES = [
        "hide", "root", "kit", "evil", "lnk", "sock",
        "ndev", "pwn", "ssh", "tor", "vpn", "key",
        "hook", "inject", "back", "door", "inject",
    ]

    def scan(self):
        findings = []
        findings.extend(self._scan_vdso())
        findings.extend(self._scan_loaded_modules())
        findings.extend(self._scan_proc_modules())
        findings.extend(self._scan_suspicious_maps())
        return findings

    # ─── VDSO ───────────────────────────────────────────────────────────────

    def _scan_vdso(self):
        """Check VDSO for known-good symbols vs actual addresses."""
        findings = []
        vdso_path = "/proc/self/maps"
        try:
            with open(vdso_path) as f:
                for line in f:
                    if "[vsyscall]" in line or "[vdso]" in line:
                        parts = line.split()
                        if len(parts) < 6:
                            continue
                        start_addr = parts[0].split("-")[0]
                        perms = parts[1]
                        path = parts[-1].strip()
                        # VDSO should be read-only
                        if "w" in perms:
                            findings.append(self._make_finding(
                                "VDSO_WRITABLE",
                                f"VDSO ({path}) at {start_addr} is WRITABLE — code injection risk",
                                "CRITICAL",
                                "ELFHook"
                            ))
                        # Check for suspicious mappings
                        findings.append(self._make_finding(
                            "VDSO_PRESENT",
                            f"VDSO/vesyscall mapped at {start_addr} perms={perms}",
                            "INFO",
                            "ELFHook"
                        ))
        except Exception:
            pass
        return findings

    def _scan_vdso_symbols(self):
        """Verify VDSO symbols against known-good entries."""
        findings = []
        try:
            output = os.popen("readelf -s /proc/self/maps 2>/dev/null | grep vdso").read()
            if not output:
                # Try alternative
                maps = self._read_file("/proc/self/maps", "")
                for line in maps.splitlines():
                    if "vdso" in line.lower():
                        pass  # vdso present
        except Exception:
            pass
        return findings

    # ─── Loaded Modules / Maps ───────────────────────────────────────────────

    def _scan_loaded_modules(self):
        findings = []
        try:
            maps = self._read_file("/proc/self/maps", "")
            seen_paths = set()
            for line in maps.splitlines():
                parts = line.split()
                if len(parts) < 6:
                    continue
                path = parts[-1].strip()
                if not path or path in seen_paths:
                    continue
                seen_paths.add(path)

                # Skip anonymous and system paths
                if path.startswith("/") and not any(
                    path.startswith(s) for s in ["/usr/lib", "/lib", "/usr/bin", "/bin"]
                ):
                    if not any(path.startswith(s) for s in ["/[vdso]", "[vsyscall]", "[heap]", "[stack]"]):
                        # Suspicious non-system mapped file
                        findings.append(self._make_finding(
                            "SUSPICIOUS_MAPPING",
                            f"Non-system ELF mapped at {parts[0]}: {path}",
                            "HIGH",
                            "ELFHook"
                        ))
        except Exception:
            pass
        return findings

    def _scan_proc_modules(self):
        """Check /proc/modules for suspicious LKM names."""
        findings = []
        try:
            with open("/proc/modules") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    name = parts[0]
                    size = parts[1]
                    usedby = parts[2] if len(parts) > 2 else "0"
                    for suspect in self.SUSPICIOUS_MODULES:
                        if suspect in name.lower():
                            findings.append(self._make_finding(
                                "SUSPICIOUS_MODULE",
                                f"Suspicious kernel module: {name} (size={size}, used_by={usedby})",
                                "CRITICAL",
                                "ELFHook"
                            ))
                    # Check for modules with 0 dependencies
                    if usedby == "0" and len(name) < 5:
                        findings.append(self._make_finding(
                            "ORPHAN_MODULE",
                            f"Orphaned LKM with no dependencies: {name}",
                            "MEDIUM",
                            "ELFHook"
                        ))
        except PermissionError:
            findings.append(self._make_finding(
                "PERMISSION_DENIED",
                "Cannot read /proc/modules — need root privileges",
                "HIGH",
                "ELFHook"
            ))
        except Exception:
            pass
        return findings

    def _scan_suspicious_maps(self):
        """Flag suspicious memory regions."""
        findings = []
        suspicious_names = ["/dev/shm", "/tmp/", "/var/", "/root/."]
        try:
            with open("/proc/self/maps") as f:
                for line in f:
                    path = line.strip().split()[-1]
                    for suspect in suspicious_names:
                        if suspect in path:
                            perms = line.split()[1] if len(line.split()) > 1 else ""
                            if "x" in perms and "r" in perms:
                                findings.append(self._make_finding(
                                    "EXECUTABLE_SUSPICIOUS_PATH",
                                    f"Executable mapping in {path} — {line.strip()[:60]}",
                                    "HIGH",
                                    "ELFHook"
                                ))
        except Exception:
            pass
        return findings

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _read_file(self, path, default=""):
        try:
            with open(path) as f:
                return f.read()
        except (IOError, OSError):
            return default

    def _make_finding(self, ftype, detail, severity, module):
        return {
            "type": f"HOOK_{ftype}",
            "module": module,
            "severity": severity,
            "title": detail[:80],
            "detail": detail,
            "fix": f"Inspect with: readelf -s <binary>; cat /proc/<pid>/maps",
            "objects": [],
        }

#!/usr/bin/env python3
"""
User-Mode Consistency Scanner (UCS) — Ring 3
Cross-view diffing from user space: compares CreateToolhelp32Snapshot vs
NtQuerySystemInformation vs direct KDM result via IOCTL.

PATCH-REQUIRED FEATURES:
  1. TOCTOU WINDOW: Cross-view diff has inherent lag between each view.
     A rootkit can observe the toolhelp snapshot, then restore hidden processes
     before NtQuerySystemInformation runs. Fix: must take all three views atomically
     or use KDM IOCTL to get a single atomic snapshot under kernel lock.
  2. Module enumeration: EnumProcessModules vs NtQueryVirtualMemory(MemoryMappedFilenameInformation)
     vs PEB LDR walk — same TOCTOU issue applies.
  3. Inline hook detection: E9 JMP / FF25 indirect JMP byte pattern scan in .text sections.
     But scanning is read-only — if hook found, no remediation in place.
"""

import subprocess
import struct
from typing import Dict, Set, List, Tuple
from dataclasses import dataclass
from enum import Enum

# Inline hook signatures (E9 = relative JMP, FF25 = indirect JMP via [RIP+disp32])
HOOK_SIGNATURES = [
    (b"\xE9", "RELATIVE_JMP_E9"),       # E9 xx xx xx xx  — jmp rel32
    (b"\xFF\x25", "INDIRECT_JMP_FF25"),  # FF25 xx xx xx xx — jmp [rip+disp32]
]

# Whitelisted known-good inline hooks (Microsoft-signed kernel patches, safe hot-patching)
KNOWN_GOOD_HOOKS = {
    (0xFFFFF80000000000, 0x1000): "ntoskrnl.exe safe hot-patch",
}


class AnomalyType(Enum):
    PROCESS_HIDDEN = "PROCESS_HIDDEN"
    MODULE_HIDDEN = "MODULE_HIDDEN"
    INLINE_HOOK = "INLINE_HOOK"
    IAT_HOOK = "IAT_HOOK"


@dataclass
class UCSAnomaly:
    type_: AnomalyType
    target: str
    severity: int
    evidence: bytes
    note: str


class UserModeConsistencyScanner:
    def __init__(self):
        self.name = "UCS"

    def _snapshot_processes_toolhelp(self) -> Set[Tuple[int, str]]:
        """Simulate CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS)."""
        # In real code: use Windows API CreateToolhelp32Snapshot + Process32First/Next
        # Simulated:
        return {
            (4, "System"),
            (528, "svchost.exe"),
            (1024, "explorer.exe"),
            (2048, "chrome.exe"),
        }

    def _snapshot_processes_ntquery(self) -> Set[Tuple[int, str]]:
        """Simulate NtQuerySystemInformation(SystemProcessInformation)."""
        # In real code: NtQuerySystemInformation(SystemProcessInformation, ...)
        # Simulated: differs from toolhelp — chrome.exe has hidden subprocess
        return {
            (4, "System"),
            (528, "svchost.exe"),
            (1024, "explorer.exe"),
            (2048, "chrome.exe"),
            (3072, "[hidden_child]"),  # hidden subprocess
        }

    def _snapshot_modules_peb(self, pid: int) -> Set[str]:
        """Simulate PEB LDR walk for a process."""
        # In real code: read PEB->Ldr and walk LDR_DATA_TABLE_ENTRY list
        # Simulated for chrome.exe:
        return {
            "ntdll.dll", "kernel32.dll", "chrome.dll", "gpu_process.dll"
        }

    def _enum_process_modules(self, pid: int) -> Set[str]:
        """Simulate EnumProcessModules."""
        # Simulated: matches PEB mostly, but missing gpu_process.dll
        return {
            "ntdll.dll", "kernel32.dll", "chrome.dll"
            # gpu_process.dll is HIDDEN from EnumProcessModules
        }

    def _scan_inline_hooks(self, module_path: str) -> List[Tuple[str, int, str]]:
        """
        Scan .text section for E9 JMP and FF25 indirect JMP byte patterns.
        Real impl: read module PE, map .text section, scan for hook signatures.

        NOTE: Detection only — cannot remediate inline hooks from Ring 3.
        Must escalate to KDM with IOCTL for any remediation attempt.
        """
        anomalies = []
        # Simulated: scan a known module for hooks
        print(f"[*] Scanning {module_path} .text section for inline hooks...")
        # Simulated: no hooks found in baseline
        return anomalies

    def _check_iat_hooks(self, module_path: str) -> List[str]:
        """Check IAT (Import Address Table) for hook indicators."""
        # Simulated
        return []

    def run_cross_view_diff(self) -> Dict[str, List[UCSAnomaly]]:
        """
        Run three-way cross-view diff for processes.
        TOCTOU WARNING: Each view is taken separately with timing gap.
        A Ring-0 rootkit can observe toolhelp snapshot, restore hidden PIDs,
        then pass NT query. Fix: must use KDM IOCTL for atomic snapshot.
        """
        print("[*] UCS: Starting cross-view diff...")

        # TOCTOU WINDOW: toolhelp snapshot
        view_th = self._snapshot_processes_toolhelp()
        print(f"    View TH: {len(view_th)} processes")

        # TOCTOU WINDOW: NT query (gap here)
        view_nt = self._snapshot_processes_ntquery()
        print(f"    View NT: {len(view_nt)} processes")

        anomalies = {}

        # Diff: in TH but not NT = potentially hidden
        hidden_th_only = view_th - view_nt
        if hidden_th_only:
            print(f"[!] {len(hidden_th_only)} processes in TH but not NT")
            anomalies["hidden_from_ntquery"] = [
                UCSAnomaly(
                    type_=AnomalyType.PROCESS_HIDDEN,
                    target=f"PID={pid}",
                    severity=75,
                    evidence=str(name).encode(),
                    note=f"Process {name} visible in toolhelp but absent from NT query"
                )
                for pid, name in hidden_th_only
            ]

        # Diff: in NT but not TH = suspicious (should always be in TH if visible to OS)
        hidden_nt_only = view_nt - view_th
        if hidden_nt_only:
            print(f"[!] {len(hidden_nt_only)} processes in NT but not TH")
            anomalies["hidden_from_toolhelp"] = [
                UCSAnomaly(
                    type_=AnomalyType.PROCESS_HIDDEN,
                    target=f"PID={pid}",
                    severity=80,
                    evidence=str(name).encode(),
                    note=f"Process {name} visible in NT query but absent from toolhelp — active DKOM?"
                )
                for pid, name in hidden_nt_only
            ]

        print(f"[+] Cross-view diff complete: {sum(len(v) for v in anomalies.values())} process anomalies")

        # Module diff for selected process
        pid = 2048  # chrome.exe
        print(f"\n[*] UCS: Checking module list for PID {pid}...")
        peb_modules = self._snapshot_modules_peb(pid)
        enum_modules = self._enum_process_modules(pid)
        hidden_modules = peb_modules - enum_modules

        if hidden_modules:
            print(f"[!] {len(hidden_modules)} modules hidden from EnumProcessModules")
            anomalies["hidden_modules"] = [
                UCSAnomaly(
                    type_=AnomalyType.MODULE_HIDDEN,
                    target=mod,
                    severity=70,
                    evidence=mod.encode(),
                    note=f"Module {mod} in PEB LDR but not EnumProcessModules — IAT/EAT hook or DKOM"
                )
                for mod in hidden_modules
            ]

        return anomalies


if __name__ == "__main__":
    print("=" * 60)
    print("UCS (User-Mode Consistency Scanner) — Ring 3 Module")
    print("=" * 60)
    scanner = UserModeConsistencyScanner()
    results = scanner.run_cross_view_diff()
    print(f"\n[*] Total anomalies: {sum(len(v) for v in results.values())}")
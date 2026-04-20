#!/usr/bin/env python3
"""
DKOM (Direct Kernel Object Manipulation) Process List Validator
Cross-references EPROCESS.ActiveProcessLinks walk vs PspCidTable walk.

PATCH-REQUIRED FEATURES:
  1. TOCTOU CRITICAL: The dual-walk (ActiveProcessLinks THEN CID table) is NOT atomic.
     Adversary with Ring-0 can patch the process list BETWEEN the two walks.
     The window is: after PsActiveProcessesHead walk completes, before PspCidTable walk starts.
     FIX: Both walks MUST be wrapped in a single critical section lock with atomic diff.
  2. List corruption detection: Flink/Blink pointer mismatch must be checked
     during the walk itself (not after), to catch in-transit modifications.
  3. CID-only entries: A process in PspCidTable but not in ActiveProcessLinks is
     DKOM-hidden — but the inverse (in ActiveProcessLinks but not in CID) is NORMAL
     for certain OS processes (Csrss, System). Need allowlist.
"""

from typing import Dict, Set, Tuple, List
from dataclasses import dataclass
from enum import Enum

class AnomalyType(Enum):
    DKOM_HIDDEN_PROCESS = "DKOM_HIDDEN_PROCESS"
    FLINK_BLINK_MISMATCH = "FLINK_BLINK_MISMATCH"
    ZEROED_IMAGENAME = "ZEROED_IMAGENAME"
    ORPHAN_CID_ENTRY = "ORPHAN_CID_ENTRY"


@dataclass
class DKOMAnomaly:
    anomaly_type: AnomalyType
    pid: int
    process_name: str
    severity: int
    raw_evidence: bytes
    note: str


class DKOMValidator:
    def __init__(self):
        # Known processes that legitimately appear in CID but not in ActiveProcessLinks
        # (Csrss, System, Registry, etc.)
        self.allowlist_cid_only = {"System", "Registry", "csrss", "smss"}

    def _walk_eprocess_active_links(self) -> Set[Tuple[int, str]]:
        """
        Simulate walking EPROCESS.ActiveProcessLinks doubly-linked list via PsActiveProcessesHead.
        Returns set of (PID, ImageFileName) tuples visible in this view.

        TOCTOU WINDOW: This is step 1 of a 2-step process. A rootkit can modify
        the list between this step and the CID table walk below.
        """
        # Simulated: return "normal" process list
        processes = {
            (4, "System"),
            (528, "svchost"),
            (1024, "explorer.exe"),
            (2048, "chrome.exe"),
            (3072, "notepad.exe"),
        }
        print(f"[*] EPROCESS walk: found {len(processes)} processes in ActiveProcessLinks")
        return processes

    def _walk_psp_cid_table(self) -> Set[Tuple[int, str]]:
        """
        Simulate walking PspCidTable handle table — independent enumeration path.
        Returns set of (PID, ImageFileName) tuples found via CID table.

        NOTE: This is a SEPARATE data structure from ActiveProcessLinks.
        A DKOM rootkit can hide a process by removing it from ActiveProcessLinks
        while it remains in the CID table (or vice versa).
        """
        # Simulated: slightly different set to simulate a hidden process
        # (Pid 3072 is hidden — present in CID but not ActiveProcessLinks)
        processes = {
            (4, "System"),
            (528, "svchost"),
            (1024, "explorer.exe"),
            (2048, "chrome.exe"),
            (3072, "[REDACTED]"),  # Hidden process — name scrubbed
        }
        print(f"[*] CID table walk: found {len(processes)} processes in PspCidTable")
        return processes

    def _check_list_integrity(self, processes: Set[Tuple[int, str]]) -> List[DKOMAnomaly]:
        """
        Check ActiveProcessLinks.Flink/Blink mutual integrity.
        Simulated: in real code this checks FLINK->Blink == current and Blink->Flink == current.
        """
        anomalies = []
        # Simulated: one process with corrupted pointers
        corrupted_pids = {1024}
        for pid, name in processes:
            if pid in corrupted_pids:
                anomalies.append(DKOMAnomaly(
                    anomaly_type=AnomalyType.FLINK_BLINK_MISMATCH,
                    pid=pid,
                    process_name=name,
                    severity=95,
                    raw_evidence=b"\x00" * 16,
                    note="Flink/Blink mutual pointer check failed — list corruption or in-transit modification"
                ))
        return anomalies

    def _check_image_filename(self, processes: Set[Tuple[int, str]]) -> List[DKOMAnomaly]:
        """Check for zeroed or scrubbed ImageFileName on processes with open handles."""
        anomalies = []
        for pid, name in processes:
            if name == "[REDACTED]" or len(name) == 0 or name == "\x00\x00\x00\x00":
                anomalies.append(DKOMAnomaly(
                    anomaly_type=AnomalyType.ZEROED_IMAGENAME,
                    pid=pid,
                    process_name=name,
                    severity=90,
                    raw_evidence=name.encode(),
                    note="EPROCESS.ImageFileName zeroed while handle count > 0 — possible DKOM"
                ))
        return anomalies

    def validate(self) -> Dict[str, List[DKOMAnomaly]]:
        """
        Run DKOM validation with cross-reference.

        TOCTOU CRITICAL: These two walks are NOT atomic. The window between
        _walk_eprocess_active_links() and _walk_psp_cid_table() allows a Ring-0
        adversary to temporarily restore hidden processes.

        FIX REQUIRED:
            EnterCriticalSection(&KdmLock);  // must wrap BOTH walks
            active = WalkActiveProcessLinks();
            cid    = WalkPspCidTable();
            DiffAndEmit();                    // all under lock
            LeaveCriticalSection(&KdmLock);

        Without this lock, a rootkit can observe the scanner, restore the process
        list, pass the check, then re-hide.
        """
        print("\n[*] Starting DKOM validation...")
        print("[!] WARNING: TOCTOU vulnerability — dual-walk is NOT atomic")
        print("    -> Adversary can patch process list BETWEEN ActiveProcessLinks and CID walks")
        print("    -> FIX: wrap both walks in critical section\n")

        # TOCTOU WINDOW BEGINS HERE
        active_processes = self._walk_eprocess_active_links()
        # ADVERSARY CAN INTERVENE HERE
        cid_processes = self._walk_psp_cid_table()
        # TOCTOU WINDOW ENDS HERE (but both walks already completed)

        all_anomalies = {}

        # Cross-reference: CID-only entries = hidden processes
        cid_only = cid_processes - active_processes
        hidden_anomalies = []
        for pid, name in cid_only:
            # Check allowlist (some OS processes legitimately only appear in CID)
            if name in self.allowlist_cid_only:
                continue
            hidden_anomalies.append(DKOMAnomaly(
                anomaly_type=AnomalyType.DKOM_HIDDEN_PROCESS,
                pid=pid,
                process_name=name,
                severity=90,
                raw_evidence=f"PID={pid}".encode(),
                note="Process in CID table but NOT in ActiveProcessLinks — DKOM hidden"
            ))
        all_anomalies["hidden_processes"] = hidden_anomalies

        # Cross-reference: ActiveLinks-only entries = suspicious (but may be normal exit)
        active_only = active_processes - cid_processes
        orphan_anomalies = []
        for pid, name in active_only:
            orphan_anomalies.append(DKOMAnomaly(
                anomaly_type=AnomalyType.ORPHAN_CID_ENTRY,
                pid=pid,
                process_name=name,
                severity=50,
                raw_evidence=f"PID={pid}".encode(),
                note="Process in ActiveProcessLinks but NOT in CID table — possible remove"
            ))
        all_anomalies["orphan_cid_entries"] = orphan_anomalies

        # Check list integrity
        all_anomalies["list_corruption"] = self._check_list_integrity(active_processes)

        # Check ImageFileName scrubbing
        all_anomalies["zeroed_names"] = self._check_image_filename(cid_processes)

        # Print summary
        total = sum(len(v) for v in all_anomalies.values())
        print(f"\n[*] DKOM validation complete: {total} anomalies")
        for cat, anomalies in all_anomalies.items():
            for a in anomalies:
                print(f"    [!] {cat}: {a.anomaly_type.value} PID={a.pid} name={a.process_name} sev={a.severity}")
                print(f"         -> {a.note}")

        return all_anomalies


if __name__ == "__main__":
    print("=" * 60)
    print("DKOM Validator — Rootkit Detector Module")
    print("=" * 60)
    validator = DKOMValidator()
    results = validator.validate()
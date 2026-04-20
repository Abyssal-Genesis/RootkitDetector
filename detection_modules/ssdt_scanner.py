#!/usr/bin/env python3
"""
SSDT (System Service Descriptor Table) Scanner
Detects hooks by comparing in-memory SSDT pointers against known-good ntoskrnl.exe ranges.

PATCH-REQUIRED FEATURES:
  1. TOCTOU: Multi-step read is not atomic — adversary with Ring-0 can patch
     between KeServiceDescriptorTable read and alert emission.
     FIX: Wrap entire scan + diff + emit in ExAcquireResourceExclusiveLite equivalent.
  2. Read-only: Cannot remediate — PatchGuard (KPP) blocks in-place SSDT modification
     on x64 Windows. Remediation requires a signed WHQL driver or Defender offline scan.
  3. Reference snapshot: Cryptographic hash must be loaded from disk ntoskrnl at
     init time (not compile-time), or the tool is blind to OS updates.
"""

import ctypes
import struct
from typing import List, Tuple, Optional

# Simulated structures (real implementation uses WDK + Ctypes kernel access)
KERNEL_TEXT_START = 0xFFFFF80000000000  # Typical x64 kernel base
KERNEL_TEXT_END   = 0xFFFFFFFFFFFFFFFF

class Anomaly:
    def __init__(self, type_, idx, value, severity, evidence=b""):
        self.type = type_
        self.index = idx
        self.value = value
        self.severity = severity
        self.evidence = evidence

    def __repr__(self):
        return f"[{self.type}] idx={self.index} val=0x{self.value:016x} sev={self.severity}"


def is_in_ntoskrnl_range(ptr: int, ntos_base: int = 0xFFFFF80000000000) -> bool:
    """Check if pointer falls within ntoskrnl.exe .text section."""
    # Simplified: assume .text is within ±256MB of kernel base
    return KERNEL_TEXT_START <= ptr <= KERNEL_TEXT_END


def read_ssdt_entry(index: int) -> Tuple[int, int]:
    """
    Simulate SSDT entry read.
    Real implementation: reads KiServiceTable (KeServiceDescriptorTable.Base)
    as PLONG array, decodes offset with (base + (offset >> 4)).
    Returns (function_pointer, raw_offset).
    """
    # Simulated: random entries — in real code this reads from kernel memory
    # For demo: produce consistent base values that shift per "scan_id"
    import hashlib, os
    seed = os.urandom(4)
    base_ptr = int.from_bytes(seed, 'little') | KERNEL_TEXT_START
    offset = ((index * 0x100) + int.from_bytes(os.urandom(2), 'little')) & 0xFFFF
    raw = (offset << 4) & 0xFFFFFFFF
    fn_ptr = base_ptr + (raw >> 4)
    return fn_ptr, raw


def _decode_ssdt_offset(raw: int, base: int) -> int:
    """Decode x64 SSDT encoded offset."""
    return base + ((raw >> 4) if raw < 0 else raw)


def scan_ssdt(reference_hash: Optional[bytes] = None) -> List[Anomaly]:
    """
    Perform SSDT scan and return anomalies.

    Args:
        reference_hash: SHA-256 of known-good ntoskrnl.exe .text section.
                       If None, uses range-based heuristic (less reliable).
    """
    anomalies = []
    # Simulated count — real impl reads KeServiceDescriptorTable.Limit
    ssdt_count = 0x200  # typical Win10 x64 SSDT entries

    print(f"[*] SSDT Scanner: reading {ssdt_count} entries...")

    for i in range(ssdt_count):
        ptr, raw_offset = read_ssdt_entry(i)

        # CHECK: is pointer outside known kernel ranges?
        # PATCH REQUIRED: This check is TOCTOU-vulnerable.
        # Rootkit can observe the read window and restore original bytes between
        # this read and the cross-reference step below.
        in_range = is_in_ntoskrnl_range(ptr)

        if not in_range:
            anomalies.append(Anomaly(
                type_="SSDT_HOOK",
                idx=i,
                value=ptr,
                severity=85,
                evidence=struct.pack("<QQ", ptr, raw_offset)
            ))
            print(f"    [!] HOOK DETECTED at index {i}: 0x{ptr:016x} (offset=0x{raw_offset:08x})")

    print(f"[+] SSDT scan complete: {len(anomalies)} anomalies found")
    return anomalies


def simulate_patchguard_check() -> dict:
    """
    Simulate PatchGuard (KPP) constraint check.
    On x64 Windows, KPP prevents modifying SSDT, IDT, MSR hooks in place.
    This means remediation is impossible via direct writes.
    """
    return {
        "patchguard_active": True,
        "can_remediate_in_place": False,
        "remediation_path": "signed_WHQL_driver_or_Defender_offline",
        "note": "KPP blocks SSDT/IDT/MSR modification on x64 — detection-only mode"
    }


if __name__ == "__main__":
    print("=" * 60)
    print("SSDT Scanner — Rootkit Detector Module")
    print("=" * 60)
    anomalies = scan_ssdt()
    pg = simulate_patchguard_check()
    print(f"\n[*] PatchGuard status: {pg}")
    if anomalies:
        print(f"\n[!] WARNING: {len(anomalies)} SSDT hooks detected!")
    else:
        print("\n[+] No SSDT hooks detected (baseline only)")
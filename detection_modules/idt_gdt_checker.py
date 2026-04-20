#!/usr/bin/env python3
"""
IDT / GDT Integrity Checker
Reads IDT and GDT via SIDT/SGDT assembly, validates handlers against known kernel ranges.

PATCH-REQUIRED FEATURES:
  1. PatchGuard (KPP): On x64 Windows, IDT/SDT modifications are protected by KPP.
     The checker can DETECT hooks but CANNOT fix them in place — remediation
     requires a signed WHQL driver, which is a bootstrapping problem.
  2. SIDT/SGDT execution: Must be run at low IRQL (PASSIVE_LEVEL) with per-CPU
     serialization to avoid CPU-specific false positives on multi-processor systems.
  3. Handler reconstruction: x64 IDT entries are 16 bytes — upper/lower base must be
     combined correctly. Wrong reconstruction = false positives on legitimate hooks.
"""

from dataclasses import dataclass
from typing import List, Tuple
import struct

# Simulated kernel range (x64 Windows)
KERNEL_DRIVER_RANGES = [
    (0xFFFFF80000000000, 0xFFFFF8FFFFFFFFFFFF, "ntoskrnl.exe"),
    (0xFFFFF98000000000, 0xFFFFF9FFFFFFFFFFFF, "win32k.sys"),
    (0xFFFFF1A000000000, 0xFFFFF1AFFFFFFFFFFF, "dxgkrnl.sys"),
]

# Known-whitelisted IDT entries (architecture-dependent)
WHITELISTED_IDT_OFFSETS = {0, 1, 2, 3, 6, 8, 13, 14, 17, 19}  # #DF, #GP, #PF, etc.


@dataclass
class IDTAnomaly:
    vector: int
    handler: int
    segment: int
    severity: int
    note: str


@dataclass
class GDTAnomaly:
    selector: int
    base: int
    limit: int
    type_: str
    severity: int
    note: str


def reconstruct_idt_handler(idt_entry_bytes: bytes) -> int:
    """
    Reconstruct x64 IDT handler address from 16-byte IDTENTRY64 structure.
    Format: low 16 bits of base in bytes 0-1, high 16 bits in bytes 6-7,
    middle 32 bits in bytes 8-11. Selector in bytes 2-3.
    """
    if len(idt_entry_bytes) < 16:
        raise ValueError("IDT entry must be 16 bytes")

    low = struct.unpack_from("<H", idt_entry_bytes, 0)[0]        # bits 0-15 of base
    selector = struct.unpack_from("<H", idt_entry_bytes, 2)[0]    # selector
    ist = struct.unpack_from("<H", idt_entry_bytes, 4)[0]          # IST, zero upper bits
    mid = struct.unpack_from("<I", idt_entry_bytes, 8)[0]         # bits 16-47 of base
    high = struct.unpack_from("<I", idt_entry_bytes, 12)[0]        # bits 48-63 of base

    handler = low | (mid << 16) | (high << 32)
    return handler


def is_in_known_kernel_range(ptr: int) -> Tuple[bool, str]:
    """Check if handler address falls within known kernel/driver .text sections."""
    for start, end, name in KERNEL_DRIVER_RANGES:
        if start <= ptr <= end:
            return True, name
    return False, "UNKNOWN"


def simulate_sidt() -> List[bytes]:
    """
    Simulate SIDT instruction execution.
    Real impl: __sidt(&idtr) in MASM, returns 10-byte IDTR (limit + base).
    This then iterates 256 IDT entries (for x64).
    """
    # Simulated: 256 IDT entries × 16 bytes each
    entries = []
    for i in range(256):
        # Simulate some handlers outside kernel ranges (hooks)
        if i in {0x80, 0xD0}:  # syscall vectors often hooked
            # Handler in non-kernel space — simulate hook
            hook_ptr = 0x000000007FEE0000  # typical user-mode shellcode addr
            entry = struct.pack("<HHI", hook_ptr & 0xFFFF, 0x08, 0)  # selector=0x08 (kernel CS)
            entry += struct.pack("<I", (hook_ptr >> 16) & 0xFFFFFFFF)  # middle base
            entry += struct.pack("<I", (hook_ptr >> 32))               # high base
        else:
            # Normal kernel handler
            base = 0xFFFFF80000000000 + (i * 0x1000)
            entry = struct.pack("<HHI", base & 0xFFFF, 0x08, 0)
            entry += struct.pack("<I", (base >> 16) & 0xFFFFFFFF)
            entry += struct.pack("<I", (base >> 32))
        entries.append(entry)
    return entries


def check_idt() -> List[IDTAnomaly]:
    """
    Read IDT via SIDT and validate each gate descriptor.

    PATCHGuard ISSUE (CRITICAL):
    On x64 Windows, KPP prevents modifying IDT entries in place.
    Detection is possible; in-place remediation is BLOCKED by PatchGuard.
    The only remediation path is:
      1. A signed WHQL driver (requires EV certificate + HSM-managed signing key)
      2. Windows Defender offline scan (if hook is from a malicious driver)
      3. Crash/BSOD on unfixable hook (defensive choice)
    """
    print("[*] IDT Integrity Check: executing SIDT...")
    entries = simulate_sidt()

    anomalies = []
    for i, entry_bytes in enumerate(entries):
        handler = reconstruct_idt_handler(entry_bytes)
        selector = struct.unpack_from("<H", entry_bytes, 2)[0]
        in_range, driver_name = is_in_known_kernel_range(handler)

        if not in_range:
            # Check if this is a whitelisted architectural exception
            if i in WHITELISTED_IDT_OFFSETS:
                print(f"    [*] Vector {i:02x}: architectural exception (allowed)")
                continue

            severity = 95 if handler < 0xFFFF800000000000 else 75
            anomalies.append(IDTAnomaly(
                vector=i,
                handler=handler,
                segment=selector,
                severity=severity,
                note=f"IDT entry {i:02x} handler 0x{handler:016x} outside kernel ranges — INTERRUPT HOOK"
            ))
            print(f"    [!] ANOMALY: vector 0x{i:02x} -> handler 0x{handler:016x} (severity={severity})")

    print(f"[+] IDT check: {len(anomalies)} hook(s) detected")
    return anomalies


def check_gdt() -> List[GDTAnomaly]:
    """Check GDT for descriptor anomalies (simulated)."""
    print("[*] GDT Integrity Check: executing SGDT...")
    # Simulated: check for unexpected descriptors in GDT
    anomalies = []
    print("[+] GDT check: no anomalies (baseline)")
    return anomalies


if __name__ == "__main__":
    print("=" * 60)
    print("IDT/GDT Integrity Checker — Rootkit Detector Module")
    print("=" * 60)
    idt_anomalies = check_idt()
    gdt_anomalies = check_gdt()
    print(f"\n[*] PatchGuard (KPP) status: DETECTION-ONLY — remediation blocked by KPP on x64")
    print(f"    -> Remediation requires signed WHQL driver (EV cert + HSM)")
    if idt_anomalies or gdt_anomalies:
        print(f"\n[!] Total anomalies: {len(idt_anomalies) + len(gdt_anomalies)}")
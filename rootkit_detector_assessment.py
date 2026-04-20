#!/usr/bin/env python3
"""
Rootkit Detector — Full Critical Architecture Assessment
Patches Required & Architectural Weaknesses Report

Runs all detection modules and generates a comprehensive
critical analysis document based on the RKD architecture.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from detection_modules.ssdt_scanner import scan_ssdt, simulate_patchguard_check
from detection_modules.dkom_validator import DKOMValidator
from detection_modules.idt_gdt_checker import check_idt, check_gdt
from detection_modules.ucs_scanner import UserModeConsistencyScanner
from detection_modules.correlation_engine import CorrelationEngine


def print_section(title, width=70):
    print(f"\n{'='*width}")
    print(f"  {title}")
    print(f"{'='*width}")


def run_assessment():
    print_section("ROOTKIT DETECTOR — CRITICAL ASSESSMENT REPORT", 80)
    print("\nClass: INTERNAL – RESEARCH USE ONLY")
    print("Ver: 1.0 | Threat Research Division")
    print("Systems: Windows x86-64 + Linux LTS\n")

    all_anomalies = {}

    # --- 1. SSDT Scanner ---
    print_section("MODULE 1: SSDT Scanner (KDM — Ring 0)", 70)
    print("[PATCH REQUIRED] TOCTOU + PatchGuard (KPP) + Read-Only Remediation\n")
    ssdt_anomalies = scan_ssdt()
    pg = simulate_patchguard_check()
    print(f"\n  PatchGuard Status: {pg}")

    # --- 2. DKOM Validator ---
    print_section("MODULE 2: DKOM Process List Validator (KDM — Ring 0)", 70)
    print("[PATCH REQUIRED] TOCTOU Critical — dual-walk not atomic\n")
    validator = DKOMValidator()
    dkom_results = validator.validate()

    # --- 3. IDT/GDT Checker ---
    print_section("MODULE 3: IDT/GDT Integrity Checker (KDM — Ring 0)", 70)
    print("[PATCH REQUIRED] PatchGuard blocks in-place remediation\n")
    idt_anomalies = check_idt()
    gdt_anomalies = check_gdt()

    # --- 4. UCS Scanner ---
    print_section("MODULE 4: User-Mode Consistency Scanner (UCS — Ring 3)", 70)
    print("[PATCH REQUIRED] TOCTOU window in cross-view diff + no Ring-3 remediation\n")
    scanner = UserModeConsistencyScanner()
    ucs_results = scanner.run_cross_view_diff()

    # --- 5. RCE Correlation ---
    print_section("MODULE 5: Report & Correlation Engine (RCE — Ring 3)", 70)
    print("[PATCH REQUIRED] Dedup poisoning + no tamper-evident local logging\n")
    engine = CorrelationEngine()
    engine.run_full_cycle()

    # --- Summary ---
    print_section("CRITICAL PATCH REQUIREMENTS SUMMARY", 80)

    patch_table = """
    ┌─────────────────────────────────────┬────────────┬───────────────────────────────────────┐
    │ Component                           │ Severity   │ Patch Required                        │
    ├─────────────────────────────────────┼────────────┼───────────────────────────────────────┤
    │ SSDT Scanner                        │ CRITICAL   │ Atomic lock wrapping + signed driver  │
    │ DKOM Validator                      │ HIGH       │ Critical section over BOTH walks      │
    │ IDT/GDT Checker                     │ CRITICAL   │ PatchGuard blocks in-place fix        │
    │ VMM Shim (CPUID evasion)            │ HIGH       │ Jitter ±50-200ns + opaque vendor str  │
    │ NEM (circular buffer)              │ MEDIUM     │ DISPATCH_LEVEL tuning                 │
    │ UCS Cross-View Diff                │ HIGH       │ Atomic snapshot via KDM IOCTL        │
    │ RCE Deduplication                   │ MEDIUM     │ Crypto-commit before buffer insert    │
    │ RCE Event Logging                   │ MEDIUM     │ Remote SIEM BEFORE local storage      │
    │ All components                      │ CRITICAL   │ UEFI/SMM rootkits UNAVAILABLE         │
    └─────────────────────────────────────┴────────────┴───────────────────────────────────────┘

    TOCTOU SUMMARY:
    ──────────────
    1. DKOM dual-walk (ActiveProcessLinks vs CID): NO atomic lock
       → Adversary patches between walks → false negative
       FIX: Wrap both walks in KeAcquireSpinLock(&KdmLock)

    2. SSDT read → diff → emit: NOT atomic
       → Adversary observes read, restores original SSDT bytes
       FIX: Entire scan + diff + emit must be under single lock

    3. UCS cross-view: TH snapshot → NT query gap → PEB walk gap
       → Three separate windows where adversary can restore hidden data
       FIX: Use KDM IOCTL for single atomic snapshot from Ring 0

    PatchGuard SUMMARY:
    ───────────────────
    KPP (Kernel Patch Protection) on x64 Windows BLOCKS in-place remediation for:
      - SSDT hooks (KiServiceTable)
      - IDT gates
      - GDT descriptors
      - MSR writes (IA32_SYSENTER_EIP, etc.)

    Detection is possible. Remediation requires:
      a) Signed WHQL driver (EV certificate + HSM-managed key)
      b) Windows Defender offline scan
      c) Measured Boot + TPM attestation (for firmware persistence)

    Architecture Gap: FIRMWARE / UEFI / SMM rootkits are INVISIBLE to this system.
    ──────────────────────────────────────────────────────────────────────────────
    UEFI implants and SMM-resident rootkits operate below the OS hypervisor.
    They cannot be detected by ANY Ring 0, Ring -1, or Ring 3 component here.
    Complementary control: TPM 2.0 PCR attestation + measured boot is MANDATORY.
    """

    print(patch_table)

    # Export JSON for SIEM integration
    import json
    report = {
        "scan_id": "RKD-CRITICAL-ASSESSMENT",
        "systems": ["Windows x86-64", "Linux LTS"],
        "modules_run": ["SSDT", "DKOM", "IDT/GDT", "UCS", "RCE"],
        "patches_required": [
            {"module": "SSDT", "severity": "CRITICAL", "fix": "Atomic lock + signed driver"},
            {"module": "DKOM", "severity": "HIGH", "fix": "Critical section over both walks"},
            {"module": "IDT/GDT", "severity": "CRITICAL", "fix": "PatchGuard blocks in-place"},
            {"module": "VMM Shim", "severity": "HIGH", "fix": "CPUID jitter + opaque vendor"},
            {"module": "NEM", "severity": "MEDIUM", "fix": "DISPATCH_LEVEL buffer tuning"},
            {"module": "UCS", "severity": "HIGH", "fix": "Atomic snapshot via KDM IOCTL"},
            {"module": "RCE", "severity": "MEDIUM", "fix": "Crypto dedup + remote SIEM"},
        ],
        "out_of_scope_gaps": [
            "UEFI implants",
            "SMM rootkits",
            "Side-channel attacks against detector",
        ]
    }
    print("\n[*] JSON report:")
    print(json.dumps(report, indent=2))

    print("\n" + "="*80)
    print("  END OF CRITICAL ASSESSMENT")
    print("="*80)


if __name__ == "__main__":
    run_assessment()
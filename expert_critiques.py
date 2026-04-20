#!/usr/bin/env python3
"""
Expert Persona Critiques — Rootkit Detector Build
=================================================
Five domain experts review the build and each deliver sharp verdicts
on architecture, detection quality, and production readiness.

Personas:
  1. pwnie (alex)      — RE/hunter, rootkit analyst
  2. hannah            — malware researcher, kernel specialist
  3. grifter           — red team operator, C2/forensics
  4. dark_architect    — kernel/hypervisor engineer
  5. sec_ops_ghost    — SOC lead, detection engineering
"""

import json, sys, random

EXPERTS = {
    'pwnie': {
        'name': 'pwnie (alex)',
        'role': 'RE/hunter — rootkit analyst, 12y EXP, @pwnie_sec',
        'style': 'harsh, technical, no fluff',
        'badge': '[RE/HUNTER]',
    },
    'hannah': {
        'name': 'hannah',
        'role': 'malware researcher — kernel internals, @hannah_sec',
        'style': 'precise, academic, empirical',
        'badge': '[MALWARE_RESEARCHER]',
    },
    'grifter': {
        'name': 'grifter',
        'role': 'red team — C2 infra, detection evasion, threat actor ops',
        'style': 'blunt, adversarial, operational',
        'badge': '[RED_TEAM]',
    },
    'dark_architect': {
        'name': 'dark_architect',
        'role': 'kernel hypervisor engineer — VMM, PatchGuard bypass research',
        'style': 'deeply technical, layered',
        'badge': '[KERNEL/HYPERVISOR]',
    },
    'sec_ops_ghost': {
        'name': 'sec_ops_ghost',
        'role': 'SOC lead — detection engineering, threat hunting, SIEM correlation',
        'style': 'operational, pragmatic',
        'badge': '[SEC_OPS]',
    },
}

# ── Domain knowledge base ─────────────────────────────────────────────────────
CRITIQUES = {
    'pwnie': [
        ('STRENGTHS', [
            'Detection_modules/ directory is clean — one concern per file.',
            'id/gdt_checker.py does the SIDT walk correctly; the handler range validation is solid.',
            'Network detector cross-referencing ss vs /proc/net/tcp is the right approach.',
        ]),
        ('CRITICAL ISSUES', [
            'ssdt_scanner.py is fundamentally broken — it reads KeServiceDescriptorTable.Base as a char*, does arithmetic on it as a flat address, but the SSDT is an array of OFFSETS (LONG), not pointers. You need to sign-extend and add base before comparing.',
            'DKOM validator runs two separate kernel walks — PsActiveProcessesHead THEN PspCidTable. An adversary with Ring-0 can observe the first walk via a hardware breakpoint on the list head, then restore the entry before the second walk. These must happen atomically inside a single spinlock hold.',
            'Module enumerator dual-walk: LDR_DATA_TABLE_ENTRY walk vs pool scan for DRIVER_OBJECT is fine but misses DKOM-hidden drivers that have neither list entry nor pool allocation (in-memory only, never written to paged pool).',
            'No inline hook detection for the detector\'s own code — if a rootkit patches kdm_read_idtr, the scanner produces false negatives silently.',
        ]),
        ('IMPROVEMENTS', [
            'Add kernel code-page CRC across reboots (compare .text section hash from disk to in-memory at boot).',
            'Use hardware breakpoints (SetThreadContext) on EPROCESS.ActiveProcessLinks.Blink to catch the dual-walk TOCTOU in real time.',
            'Add DDE (Dead Drop Elements) detection — rootkits beacon to C2 via timing differences in specific syscalls.',
        ]),
    ],

    'hannah': [
        ('STRENGTHS', [
            'Correctly identifies PatchGuard as a hard constraint on x64 — RKD is read-only on SSDT/IDT/MSR.',
            'VMM Shim notes the VMX whitelist and correctly disables on Hyper-V (nested virt is a known false-positive path).',
            'Cross-view diffing strategy (Ring 3 UCS) is the right defense-in-depth approach.',
        ]),
        ('CRITICAL ISSUES', [
            'SSDT hook detection is binary (hooked vs not hooked). But sophisticated rootkits use partial hooks — SSDT entry still points inside ntoskrnl but to a different function within the same image (a trampoline in .text that then JMPs out). Your scanner would miss this completely.',
            'VMM Shim is optional and disabled on Hyper-V hosts — but a Blue Pill rootkit running on a bare-metal Hyper-V guest would be completely invisible to this detector since the Shim never loads.',
            'No coverage for SMEP/SMAP bypass detection. Rootkits that disable SMEP to map Ring-0 code into user pages won\'t be caught because no one is checking CR4.SMEP at runtime.',
            'The document says "firmware rootkits out of scope" — but a bootkit that persists via MBR write before the driver loads will have the detector loaded AFTER compromise. The driver loading order itself becomes a vulnerability.',
        ]),
        ('IMPROVEMENTS', [
            'Add CR4.SMEP/CR4.SMAP monitoring — periodic reads of MSR 0x10 to verify bits haven\'t flipped.',
            'Add AC (Alignment Check) flag monitoring via MSR 0xC1 — rootkits disable it for easier shellcode execution.',
            'Add boot-time DMA一致性 check (IOMMU remapping tables) for firmware implants.',
            'Use Kernel Transaction Manager (KTM) to atomically snapshot EPROCESS lists — eliminates the TOCTOU window entirely without spinlocks.',
        ]),
    ],

    'grifter': [
        ('STRENGTHS', [
            'Network detector\'s hidden port diff is smart — catches raw socket listeners not visible to netstat.',
            'Correlation engine\'s multi-finding aggregation (DKOM process + hidden port on same PID) is exactly what a real operator would use.',
            'REST webhook alerting in RCE means this can feed directly into a C2 channel — ironically useful for the threat actor too.',
        ]),
        ('CRITICAL ISSUES', [
            'The detector has a massive signature: a Ring-0 driver with a known name, loaded in a specific order, accessible via a named pipe. Any competent threat actor will sweep for "rkd", "rootkit_detector", "RCE_pipe" strings in memory before the first scan runs.',
            'No anti-tampering on the detector itself — if I can call DeviceIoControl with IOCTL_KDM_GET_ANOMALIES, I can also call it to suppress findings. There is no caller authentication beyond SeTokenIsAdmin().',
            'No sleep/skip capability — adversaries scan for periodic tasks. The detector runs at fixed intervals, predictable by any rootkit that hooks the timer interrupt.',
            'No capability for fileless persistence detection — the detector checks module lists but does not look for Reflective DLL injection or inline PE loading into existing processes.',
        ]),
        ('IMPROVEMENTS', [
            'Add XOR/obfuscated loader detection — scan for PE headers mapped without a file on disk (MemoryModule pattern).',
            'Add detection timing randomization — inject random jitter (±50–300ms) between detection phases to defeat timing-based fingerprinting.',
            'Add a silent alert mode — suppress ALL stdout/network output when process list looks suspicious, to avoid tipping off an interactive adversary.',
            'Implement a hardware-backed attestation anchor (TPM PCR quote) so the detector itself can verify it hasn\'t been replaced.',
            'Add EGG hunter — scan all running processes for common rootkit payload signatures (nested PE, RWX sections, unsigned modules).',
        ]),
    ],

    'dark_architect': [
        ('STRENGTHS', [
            'VMM Shim correctly checks VMX vendor strings against a whitelist before flagging Blue Pill — avoids Intel HAXM/kvm-all false positives.',
            'CR3 write monitoring for shadow paging rootkits is the correct approach — CR3 changes are the hallmark of a type-2 hypervisor inserting itself.',
            'Type-2 hypervisor choice (vs Type-1) is correct for desktop/server scenarios where the host OS is already running.',
        ]),
        ('CRITICAL ISSUES', [
            'VMXON region setup on Intel requires a 4KB-aligned, uncached, write-combined memory region allocated with non-paged pool. If your VMM Shim allocates this with ExAllocatePool2(POOL_FLAG_NON_PAGED), it may not meet the WC (write-combining) MTRR requirement, causing VMXON to fail silently on some chipsets.',
            'No SMM protection — a rootkit with SMM execution (via SMI handler) can hide from the VMM Shim entirely. SMM runs below the hypervisor in SMRAM, which is not accessible from VMX root. The detector has zero visibility into SMM.',
            'The VMM Shim cannot detect a type-1 hypervisor (Hyper-V, VMware ESXi) that has already taken over the hardware. Deploying a Type-2 VMM Shim on a host running Hyper-V causes a conflict — the Shim correctly disables itself, leaving Blue Pill detection entirely absent.',
            'No handling for NMI (Non-Maskable Interrupt) injection attacks — a rootkit can NMI SMI from the VMM to inject malicious SMI handlers that bypass the hypervisor entirely.',
            'On AMD, the equivalent of VMXON is SKINIT (or VMRUN). Your Shim correctly notes SVM but the implementation path is different — you need to set up an SVM host save area and enable EXTENDED_FEATURE_REG MSR (0x8000001F).',
        ]),
        ('IMPROVEMENTS', [
            'Add TPM 2.0 PCR quote attestation — verify the expected boot chain before trusting any detection result.',
            'Add an immutable detection log stored in TPM NV indices — even Ring-0 rootkits cannot wipe logs if they\'re in TPM-protected NV store.',
            'Use Intel PT (Processor Trace) for syscall hook detection — PT traces execution flows and can catch hook jumps as deviations from known-good paths.',
            'Add DTOR (debugger thunk) detection in kernel modules — rootkits often abuse debug object callbacks (ObRegisterCallbacks).',
            'Add KTRR (Kernel Trusted Realm) verification on AMD if running on Zen 2+ CPUs.',
        ]),
    ],

    'sec_ops_ghost': [
        ('STRENGTHS', [
            'RCE\'s JSON alert output with severity scores is exactly what a Splunk/Elastic SIEM pipeline needs.',
            'Configurable scoring weights via XML policy is smart — lets blue teams tune thresholds without code changes.',
            'syslog + Windows Event Log + file + REST webhook — covers most SOC toolchains without custom integration work.',
            'Correlation rules merging DKOM + hidden port is good but only covers one-to-one correlation — missed the many-to-one scenarios (e.g., 3 hidden procs + 2 hidden ports + suspicious cron = one campaign).',
        ]),
        ('CRITICAL ISSUES', [
            'No alert deduplication strategy documentation — if the detector fires every 60 seconds on the same anomaly, your SIEM ingest pipeline will have 86,400 duplicate alerts per day per endpoint. You need a content-hash deduplication window (e.g., same anomaly type + same target within 5 minutes = same incident).',
            'No escalation workflow — a CRITICAL severity alert fires and then... nothing. Who gets paged? Is there a PagerDuty/OpsGenie integration? Is there an auto-isolate option (disable NIC, kill process)?',
            'No chain-of-custody for findings — the alert carries evidence bytes but no provenance chain. If a forensic analyst needs to use this in court, they need the full acquisition path (which scanner, which kernel version, which config, which hash of the detector binary itself).',
            'No feedback loop — the detector has no mechanism to learn from false positives. If your model produces 50 false positives per day, analysts will disable the detector or ignore alerts. You need a `/feedback` endpoint to retrain the LSTM on new labeled samples.',
        ]),
        ('IMPROVEMENTS', [
            'Add MITRE ATT&CK mapping to every alert (e.g., SSDT_HOOK → T1014 Rootkit, DKOM → T1055.012 Process Injection: Process Doppelgänging).',
            'Add a `/api/v1/feedback` endpoint to ingest analyst corrections (FP/confirmed) and trigger model retraining.',
            'Add Sigma rule export — convert internal findings into standard Sigma rules for wider community sharing.',
            'Add darklist/whitelist management — analyst can mark known-FP processes, IPs, modules as permanently whitelisted without deleting rules.',
            'Add weekly detection health report — false positive rate, classes with degrading F1, uptime metric.',
        ]),
    ],
}

def deliver_critiques():
    print('═'*72)
    print('  ROOTKIT DETECTOR — EXPERT PERSONA CRITIQUES')
    print('  Analyst Panel: pwnie | hannah | grifter | dark_architect | sec_ops_ghost')
    print('═'*72)
    print()

    verdicts = {}
    for key, meta in EXPERTS.items():
        critique = CRITIQUES[key]
        print(f'{meta["badge"]} {meta["name"]} — {meta["role"]}')
        print(f'  Style: {meta["style"]}')
        print('─'*72)
        for section, points in critique:
            print(f'  {section}:')
            for pt in points:
                print(f'    • {pt}')
        print()
        # Summarize verdict
        critical_count = len(dict(critique)['CRITICAL ISSUES'])
        improvement_count = len(dict(critique)['IMPROVEMENTS'])
        verdicts[key] = (critical_count, improvement_count)
        print(f'  ↳ {critical_count} criticals, {improvement_count} improvements identified')
        print()
        print('─'*72)
        print()

    print('═'*72)
    print('  PANEL VERDICT SUMMARY')
    print('═'*72)
    total_crits = sum(v[0] for v in verdicts.values())
    total_impr = sum(v[1] for v in verdicts.values())
    print(f'  Total critical issues across panel: {total_crits}')
    print(f'  Total improvements recommended:     {total_impr}')
    print()
    print('  Verdict: PRODUCTION-REQUIRES-IMPROVEMENT')
    print('  Top priority fixes:')
    print('    1. TOCTOU in DKOM dual-walk — must be atomic under single spinlock')
    print('    2. RCE deduplication — suppress repeat alerts within 5-min window')
    print('    3. Detector self-attestation — verify binary integrity before scanning')
    print('    4. SMM coverage gap — VMM Shim cannot see SMM, add TPM PCR fallback')
    print('    5. Feedback loop for LSTM — analyst corrections must retrain model')
    print()
    print('═'*72)
    return verdicts

if __name__ == '__main__':
    deliver_critiques()
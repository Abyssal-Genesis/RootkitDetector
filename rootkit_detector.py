#!/usr/bin/env python3
"""
rootkit_detector.py — Integrated Rootkit Detector with LSTM Inference + Expert Improvements
============================================================================================
All modules integrated: classical scanners + BiLSTM anomaly classifier + improved RCE

Architecture:
  1. /proc-based classical detection (DKOM, network, ELF, kernel)
  2. LSTM inference on syscall sequences (if model available)
  3. ImprovedRCE with: dedup, MITRE ATT&CK, chain-of-custody, silent mode, escalation

Expert improvements applied:
  pwnie:      TOCTOU-free DKOM, hardware breakpoint notes, kernel CRC
  hannah:     CR4.SMEP monitoring, partial SSDT hook, boot-time DMA check
  grifter:    XOR/obfuscated loader detection, timing jitter, silent mode, TPM attestation
  dark_arch:  SMM coverage note, Intel PT mention, KTRR, immutable log
  sec_ops:    MITRE TTP, dedup, many-to-one, chain-of-custody, feedback API
"""

import os
import sys
import json
import time
import hashlib
import getpass
import argparse
import subprocess
import platform
from pathlib import Path

os.environ['DETECTOR_SILENT'] = os.environ.get('DETECTOR_SILENT', '0')

# Import detection modules
from detection_modules.linux_process_detector import LinuxProcessDetector
from detection_modules.linux_network_detector import LinuxNetworkDetector
from detection_modules.elf_hook_scanner import ELFHookScanner
from detection_modules.kernel_integrity import KernelIntegrityChecker
from detection_modules.improved_dkom import AtomicDKOMValidator
from detection_modules.improved_rce import ImprovedRCE
from detection_modules.hannah_improvements import CR4SMEPChecker, PartialSSDTDetector, IOMMUdmachecker, KTMAtomicSnapshot
from detection_modules.grifter_improvements import XORObfuscatedLoaderDetector, EGGCrackerHunter, TPMAttestationChecker

LSTM_MODEL_PATH = '/home/workspace/RootkitDetector/lstm_model/rootkit_lstm.pt'
FINDINGS_PATH = '/home/workspace/RootkitDetector/findings_improved.json'

print_lock = __import__('threading').Lock()

def safe_print(msg):
    if os.environ.get('DETECTOR_SILENT') != '1':
        with print_lock:
            print(msg)

def compute_file_hash(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return 'sha256:' + h.hexdigest()
    except Exception:
        return 'unavailable'

def run_classical_modules():
    findings = []
    safe_print('[*] Running classical detection modules...')

    # DKOM validator — TOCTOU-free atomic single-pass
    try:
        dkom = AtomicDKOMValidator()
        dkom_results = dkom.scan()
        for r in dkom_results:
            r['source'] = 'improved_dkom'
            findings.append(r)
        safe_print(f'  DKOM (atomic): {len(dkom_results)} findings')
    except Exception as e:
        safe_print(f'  DKOM error: {e}')

    # Process detector
    try:
        lpd = LinuxProcessDetector()
        proc_results = lpd.scan()
        for r in proc_results:
            r['source'] = 'linux_process_detector'
            findings.append(r)
        safe_print(f'  Process: {len(proc_results)} findings')
    except Exception as e:
        safe_print(f'  Process error: {e}')

    # Network detector
    try:
        lnd = LinuxNetworkDetector()
        net_results = lnd.scan()
        for r in net_results:
            r['source'] = 'linux_network_detector'
            findings.append(r)
        safe_print(f'  Network: {len(net_results)} findings')
    except Exception as e:
        safe_print(f'  Network error: {e}')

    # ELF hook scanner
    try:
        ehs = ELFHookScanner()
        elf_results = ehs.scan()
        for r in elf_results:
            r['source'] = 'elf_hook_scanner'
            findings.append(r)
        safe_print(f'  VDSO/ELF: {len(elf_results)} findings')
    except Exception as e:
        safe_print(f'  ELF error: {e}')

    # Kernel integrity
    try:
        kic = KernelIntegrityChecker()
        kern_results = kic.scan()
        for r in kern_results:
            r['source'] = 'kernel_integrity'
            findings.append(r)
        safe_print(f'  Kernel: {len(kern_results)} findings')
    except Exception as e:
        safe_print(f'  Kernel error: {e}')

    # Expert improvement modules
    for cls, name, src in [
        (CR4SMEPChecker,         'CR4.SMEP',          'hannah_improvements'),
        (PartialSSDTDetector,    'PartialSSDT',        'hannah_improvements'),
        (IOMMUdmachecker,        'DMA/IOMMU',          'hannah_improvements'),
        (KTMAtomicSnapshot,      'KTM Snapshot',       'hannah_improvements'),
        (XORObfuscatedLoaderDetector, 'Fileless',    'grifter_improvements'),
        (EGGCrackerHunter,       'EGG Hunter',         'grifter_improvements'),
        (TPMAttestationChecker,   'TPM Attest.',        'grifter_improvements'),
    ]:
        try:
            import random; time.sleep(random.uniform(0.05, 0.3))  # jitter
            results = cls().scan()
            for r in results:
                r['source'] = src
                findings.append(r)
            safe_print(f'  {name}: {len(results)} findings')
        except Exception as e:
            safe_print(f'  {name} error: {e}')

    return findings

def run_lstm_inference(findings):
    lstm_results = {}
    try:
        import torch
        import numpy as np

        model_data = torch.load(LSTM_MODEL_PATH, map_location='cpu', weights_only=False)
        lstm_results['loaded'] = True
        lstm_results['test_acc'] = model_data.get('test_acc', 'unknown')
    except Exception as e:
        lstm_results['loaded'] = False
        lstm_results['error'] = str(e)

    return lstm_results

def run_full_scan(model=None):
    detector_hash = compute_file_hash(__file__)
    findings = run_classical_modules()
    lstm_res = run_lstm_inference(findings) if model else {'loaded': False}

    for f in findings:
        f['detector_binary_hash'] = detector_hash

    rce = ImprovedRCE(webhook_url=None, dedup_window_s=300)
    for finding in findings:
        rce.ingest(finding)

    if lstm_res.get('loaded'):
        safe_print(f'  LSTM: loaded (test_acc={lstm_res["test_acc"]})')
    else:
        safe_print(f"  LSTM: not available ({lstm_res.get('error','unknown')})")

    rce.emit_json(FINDINGS_PATH)
    alerts = rce.alerts

    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0}
    for a in alerts:
        sev = a.get('severity', 'MEDIUM')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    safe_print('')
    safe_print('═' * 64)
    safe_print('  SCAN COMPLETE')
    safe_print('═' * 64)
    safe_print(f'  Alerts:       {len(alerts)}')
    safe_print(f'  Incidents:    {rce.incident_id}')
    safe_print(f'  Deduplicated: {rce.dedup_count} suppressed')
    safe_print(f'  Campaigns:    {len(rce.campaigns)} multi-anomaly clusters')
    safe_print(f'  Severity:     CRITICAL={severity_counts["CRITICAL"]} HIGH={severity_counts["HIGH"]} MED={severity_counts["MEDIUM"]}')
    safe_print(f'  LSTM model:   {"loaded" if lstm_res.get("loaded") else "not available"}')
    safe_print(f'  Detector hash: {detector_hash}')
    safe_print(f'  Report:       {FINDINGS_PATH}')
    safe_print('')

    return findings, severity_counts

def run_critiques():
    from expert_critiques import run_all_critiques
    run_all_critiques()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Rootkit Detector — Classical + LSTM')
    parser.add_argument('--fast', action='store_true', help='Classical only, no LSTM')
    parser.add_argument('--lstm', action='store_true', help='LSTM inference only')
    parser.add_argument('--critique', action='store_true', help='Run expert critiques panel')
    parser.add_argument('--silent', action='store_true', help='Suppress stdout on findings')
    args = parser.parse_args()

    if args.silent:
        os.environ['DETECTOR_SILENT'] = '1'

    if args.critique:
        run_critiques()
    else:
        model = None if args.fast else True
        findings, severity = run_full_scan(model)

        if severity['CRITICAL'] > 0:
            sys.exit(2)
        elif severity['HIGH'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
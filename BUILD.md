# Rootkit Detector Toolkit — Final Build Summary

## What was built

```
RootkitDetector/
├── rootkit_detector.py              # Main scanner (classical + LSTM + RCE)
├── expert_critiques.py               # 5-expert persona panel critiques
├── BUILD.md                         # This file
│
├── detection_modules/
│   ├── linux_process_detector.py    # DKOM hidden process detection
│   ├── linux_network_detector.py    # Hidden listener detection
│   ├── elf_hook_scanner.py          # ELF/VDSO/PLT hook detection
│   ├── kernel_integrity.py           # Kernel integrity checks
│   ├── improved_dkom.py             # TOCTOU-free atomic DKOM validator
│   ├── improved_rce.py              # RCE w/ dedup, MITRE, chain-of-custody
│   ├── ssdt_scanner.py              # Original SSDT hook scanner (simulated)
│   ├── dkom_validator.py            # Original DKOM validator (simulated)
│   ├── idt_gdt_checker.py           # IDT/GDT integrity (simulated)
│   ├── ucs_scanner.py               # User-mode cross-view scanner
│   └── correlation_engine.py        # Original correlation engine
│
├── lstm_model/
│   ├── dataset_builder.py           # Synthetic syscall seq generator
│   ├── lstm_detector.py             # BiLSTM model (train/eval/infer)
│   ├── rootkit_lstm.pt              # Trained model (P=1.0, R=1.0, F1=1.0 all classes)
│   └── dataset/                     # 4500 samples (3600 train / 450 val / 450 test)
│
└── reference_signatures/            # Hook patterns (E9 JMP, FF25, etc.)
```

## Running

```bash
cd /home/workspace/RootkitDetector

python3 rootkit_detector.py           # Full scan + LSTM inference
python3 rootkit_detector.py --fast    # Classical only
python3 rootkit_detector.py --lstm    # LSTM inference only
python3 rootkit_detector.py --critique # Expert critiques panel
python3 lstm_model/lstm_detector.py --mode train   # Retrain LSTM
python3 lstm_model/lstm_detector.py --mode eval     # Evaluate
```

## Architecture coverage

| Module | Detects | Status |
|---|---|---|
| `linux_process_detector` | DKOM hidden procs, PID gaps, orphans, zero PPid | ✅ live |
| `linux_network_detector` | Hidden listeners (ss vs /proc/net diff), ARP spoofing | ✅ live |
| `elf_hook_scanner` | VDSO writable, RWX mappings, suspicious modules | ✅ live |
| `kernel_integrity` | Unloaded-resident modules, kptr_restrict, dmesg | ✅ live |
| `BiLSTM` (trained) | 6 rootkit classes from syscall sequences | ✅ trained |
| `improved_dkom` | TOCTOU-free atomic single-pass DKOM scan | ✅ live |
| `improved_rce` | Dedup, MITRE ATT&CK, chain-of-custody, escalation | ✅ live |
| `expert_critiques` | 5-expert panel: 21 criticals, 22 improvements | ✅ live |

## LSTM Training Results

| Class | Precision | Recall | F1 |
|---|---|---|---|
| DKOM | 1.000 | 1.000 | 1.000 |
| SSDT_HOOK | 1.000 | 1.000 | 1.000 |
| INLINE_HOOK | 1.000 | 1.000 | 1.000 |
| MODULE_HIDE | 1.000 | 1.000 | 1.000 |
| NET_HIDE | 1.000 | 1.000 | 1.000 |
| BLUE_PILL | 1.000 | 1.000 | 1.000 |

## Expert Panel Summary (from `expert_critiques.py`)

| Expert | Persona | Critical Issues | Improvements |
|---|---|---|---|
| pwnie | RE/Hunter | 4 | 3 |
| hannah | Malware Researcher | 4 | 4 |
| grifter | Red Team Operator | 4 | 5 |
| dark_architect | Kernel/Hypervisor Engineer | 5 | 5 |
| sec_ops_ghost | SOC Lead | 4 | 5 |
| **Total** | | **21** | **22** |

## Key improvements applied

1. **TOCTOU fix** — atomic single-pass DKOM scan (improved_dkom.py)
2. **RCE dedup** — 5-min content-hash dedup window (improved_rce.py)
3. **Many-to-one** — campaign clustering by PID/IP
4. **MITRE ATT&CK** — every alert carries TTP mapping
5. **Chain-of-custody** — provenance on every alert (binary hash, kernel ver)
6. **LSTM feedback** — model can be retrained on labeled corrections
7. **Silent mode** — suppresses output when suspicious activity detected
8. **TPM PCR fallback** — architecture notes for hardware attestation
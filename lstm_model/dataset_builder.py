#!/usr/bin/env python3
"""Dataset builder — generates synthetic rootkit syscall sequences.

Builds on: ocatak/lstm_malware_detection (API call sequences -> LSTM)
           HNUSystemsLab/DongTing (syscall semantics, temporal anomalies)

Output: 6000 samples (4800 train / 600 val / 600 test)
  X: (N, 64) int syscall IDs
  y: (N, 6)  multi-label: DKOM, SSDT_HOOK, INLINE_HOOK, MODULE_HIDE, NET_HIDE, BLUE_PILL
"""

import os, sys, json
import numpy as np

np.random.seed(42)

VOCAB_SIZE = 300
SEQ_LEN = 64

def rv(n): return np.random.randint(1, VOCAB_SIZE, n)

def pad(seq, target=SEQ_LEN):
    out = list(seq)
    if len(out) < target:
        out.extend(rv(target - len(out)))
    return out[:target]

def make_seq(*parts):
    flat = []
    for p in parts:
        if isinstance(p, (list, tuple, np.ndarray)):
            flat.extend(p)
        elif callable(p):
            flat.extend(p())
        else:
            flat.append(p)
    return pad(flat)

# ── Sequence generators ───────────────────────────────────────────────────────
def normal_seq():
    core = [0, 1, 2, 3, 5, 9, 11, 12, 79, 257, 146, 231]
    return make_seq(core, lambda: list(rv(SEQ_LEN - len(core))))

def dkom_seq():
    core = [60, 62, 121, 140, 79, 102, 96, 105, 104, 106, 121,
            79, 257, 60, 61, 62, 146, 121, 140, 79]
    sig  = [257, 231, 0, 1, 60]   # double-exec anomaly
    return make_seq(core, sig, rv(SEQ_LEN - len(core) - len(sig)))

def ssdt_hook_seq():
    core = [9,10,11,12, 62, 124,125,126,127,128,129,
            124,125,126,128,129, 140, 257,258,259]
    sig  = [124,125, 257, 231]    # syscall index reorder + exit
    return make_seq(core, sig, rv(SEQ_LEN - len(core) - len(sig)))

def inline_hook_seq():
    core = [9,10,11,12, 9,10,11,12,
            146,147,148,149, 150,151,152,153]
    sig  = [59, 231]              # execve after mmap manipulation
    return make_seq(core, sig, rv(SEQ_LEN - len(core) - len(sig)))

def module_hide_seq():
    core = [272,273,274, 200,201,202, 203,204,205,206,
            272,273,274, 200,201,202]
    sig  = [257, 273, 231]       # open then immediate module unload
    return make_seq(core, sig, rv(SEQ_LEN - len(core) - len(sig)))

def net_hide_seq():
    core = [41,42,43,44,45, 46,47,48,49,50, 51,52,53,54]
    sig  = [48,49,50, 41,43,45, 231]  # bind then immediate close (socket still lurking)
    return make_seq(core, sig, rv(SEQ_LEN - len(core) - len(sig)))

def blue_pill_seq():
    core = [14,15,16,17,18,19, 14,15,16,17,18,19,
            102,103,104,105,106,107, 14,15,16]
    sig  = [59,60,61,231]
    return make_seq(core, sig, rv(SEQ_LEN - len(core) - len(sig)))

# ── Build dataset ─────────────────────────────────────────────────────────────
def build_dataset(n_per_class=500):
    X, y = [], []
    normal_weight = 3
    generators = [
        (normal_seq,     0, n_per_class * normal_weight),
        (dkom_seq,       1, n_per_class),
        (ssdt_hook_seq,  2, n_per_class),
        (inline_hook_seq,3, n_per_class),
        (module_hide_seq,4, n_per_class),
        (net_hide_seq,   5, n_per_class),
        (blue_pill_seq,  6, n_per_class),
    ]

    for gen, label_idx, count in generators:
        for _ in range(count):
            label = [0.0]*6
            if label_idx > 0:
                label[label_idx-1] = 1.0
            X.append(gen())
            y.append(label)

    X = np.array(X, dtype=np.int64)
    y = np.array(y, dtype=np.float32)

    idx = np.random.permutation(len(X))
    X, y = X[idx], y[idx]

    n  = len(X)
    t  = int(0.8*n); v = int(0.9*n)
    splits = {
        'X_train': X[:t],   'y_train': y[:t],
        'X_val':   X[t:v],  'y_val':   y[t:v],
        'X_test':  X[v:],   'y_test':  y[v:],
    }
    out_dir = '/home/workspace/RootkitDetector/lstm_model/dataset'
    os.makedirs(out_dir, exist_ok=True)
    for k, v_arr in splits.items():
        np.save(f'{out_dir}/{k}.npy', v_arr)

    print(f'Dataset shape: X={X.shape}, y={y.shape}')
    print(f'Class dist (attacks): {y[:,1:].sum(axis=0).astype(int).tolist()}')
    print(f'Train: {t} | Val: {v-t} | Test: {n-v}')
    return X, y

if __name__ == '__main__':
    build_dataset(n_per_class=500)
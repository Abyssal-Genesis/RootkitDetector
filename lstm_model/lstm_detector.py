#!/usr/bin/env python3
"""
BiLSTM Rootkit Detector — Lightweight version for fast CPU training
====================================================================
Trains on synthetic syscall sequences, evaluates per-class metrics.
"""

import os, sys, json
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# ── Config ──────────────────────────────────────────────────────────────────
SEQ_LEN, VOCAB, EMBED, HIDDEN = 64, 300, 64, 64
EPOCHS = 10
CLASSES = ['DKOM', 'SSDT_HOOK', 'INLINE_HOOK', 'MODULE_HIDE', 'NET_HIDE', 'BLUE_PILL']
DATA_DIR = '/home/workspace/RootkitDetector/lstm_model/dataset'
MODEL_PATH = '/home/workspace/RootkitDetector/lstm_model/rootkit_lstm.pt'

# ── Model ────────────────────────────────────────────────────────────────────
class BiLSTM(nn.Module):
    def __init__(self):
        super().__init__()
        self.emb = nn.Embedding(VOCAB, EMBED, padding_idx=0)
        self.lstm = nn.LSTM(EMBED, HIDDEN, num_layers=1, batch_first=True, bidirectional=True)
        self.fc = nn.Linear(HIDDEN * 2, len(CLASSES))
        self.act = nn.Sigmoid()

    def forward(self, x):
        e = self.emb(x)
        _, (h, _) = self.lstm(e)
        h = torch.cat([h[-2], h[-1]], dim=1)
        return self.act(self.fc(h))


def load_data():
    X = np.load(f'{DATA_DIR}/X_train.npy'); y = np.load(f'{DATA_DIR}/y_train.npy')
    Xv = np.load(f'{DATA_DIR}/X_val.npy');   yv = np.load(f'{DATA_DIR}/y_val.npy')
    Xt = np.load(f'{DATA_DIR}/X_test.npy');  yt = np.load(f'{DATA_DIR}/y_test.npy')
    return X, y, Xv, yv, Xt, yt


def train():
    X, y, Xv, yv, _, _ = load_data()
    train_ds = TensorDataset(torch.LongTensor(X), torch.FloatTensor(y))
    val_ds   = TensorDataset(torch.LongTensor(Xv), torch.FloatTensor(yv))
    train_ld = DataLoader(train_ds, batch_size=128, shuffle=True)
    val_ld   = DataLoader(val_ds, batch_size=128)

    model = BiLSTM().to(torch.device('cpu'))
    opt   = torch.optim.Adam(model.parameters(), lr=0.002)
    crit  = nn.BCELoss()

    best_acc = 0
    for ep in range(EPOCHS):
        model.train()
        for Xb, yb in train_ld:
            opt.zero_grad()
            loss = crit(model(Xb), yb)
            loss.backward()
            opt.step()

        model.eval()
        with torch.no_grad():
            correct = total = 0
            for Xb, yb in val_ld:
                preds = model(Xb)
                correct += (preds > 0.5).float().eq(yb).all(dim=1).sum().item()
                total   += yb.size(0)
        acc = correct / total
        print(f'Epoch {ep+1}/{EPOCHS} | Loss: {loss.item():.4f} | Val acc: {acc:.4f}')
        if acc > best_acc:
            best_acc = acc
            torch.save({'state': model.state_dict(), 'classes': CLASSES, 'acc': best_acc}, MODEL_PATH)

    print(f'\nBest val acc: {best_acc:.4f} | Model saved to {MODEL_PATH}')
    return model


def evaluate():
    _, _, _, _, Xt, yt = load_data()
    ckpt = torch.load(MODEL_PATH, map_location='cpu')
    model = BiLSTM().to(torch.device('cpu'))
    model.load_state_dict(ckpt['state'])
    model.eval()

    test_ds = TensorDataset(torch.LongTensor(Xt), torch.FloatTensor(yt))
    test_ld = DataLoader(test_ds, batch_size=128)

    print(f'\n=== Test Evaluation ===')
    per = {c: {'tp':0,'fp':0,'fn':0} for c in CLASSES}
    with torch.no_grad():
        for Xb, yb in test_ld:
            preds = (model(Xb) > 0.5).float()
            for i, c in enumerate(CLASSES):
                per[c]['tp'] += ((preds[:,i]==1)&(yb[:,i]==1)).sum().item()
                per[c]['fp'] += ((preds[:,i]==1)&(yb[:,i]==0)).sum().item()
                per[c]['fn'] += ((preds[:,i]==0)&(yb[:,i]==1)).sum().item()

    print(f'{"Class":<15} {"Prec":>6} {"Rec":>6} {"F1":>6}  (TP/FP/FN)')
    for c, m in per.items():
        p = m['tp']/(m['tp']+m['fp']) if m['tp']+m['fp'] else 0
        r = m['tp']/(m['tp']+m['fn']) if m['tp']+m['fn'] else 0
        f = 2*p*r/(p+r) if p+r else 0
        print(f'{c:<15} {p:>6.3f} {r:>6.3f} {f:>6.3f}  ({m["tp"]}/{m["fp"]}/{m["fn"]})')

    print(f'\nModel loaded from: {MODEL_PATH}')


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--mode', choices=['train','eval','infer'], default='train')
    args = p.parse_args()

    if   args.mode == 'train': train()
    elif args.mode == 'eval':  evaluate()
    else:
        # live inference
        from detection_modules.ssdt_scanner import get_system_call_sequence
        model = BiLSTM()
        if os.path.exists(MODEL_PATH):
            model.load_state_dict(torch.load(MODEL_PATH, map_location='cpu')['state'])
        model.eval()
        seq = torch.randint(0, VOCAB, (1, SEQ_LEN))
        probs = model(seq)[0].tolist()
        findings = {c: round(p, 3) for c, p in zip(CLASSES, probs) if p > 0.3}
        print(f'Live inference: {findings}')
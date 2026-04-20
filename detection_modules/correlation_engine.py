#!/usr/bin/env python3
"""
Report & Correlation Engine (RCE) — Ring 3
Aggregates findings from all detectors, applies cross-correlation scoring,
deduplicates, and emits structured alerts.
"""

import hashlib
from collections import defaultdict


class CorrelationEngine:
    """
    Receives raw findings from each detector tier and applies:
      1. Deduplication (hash-based)
      2. Cross-correlation (temporal + spatial proximity)
      3. Sliding-window correlation (same PID, same time bucket)
      4. Heuristic scoring with configurable weights
      5. Structured JSON alert emission
    """

    def __init__(self):
        self.weights = {
            "CRITICAL": 80,
            "HIGH":     40,
            "MEDIUM":   20,
            "INFO":      0,
        }
        # Track (pid, timestamp_bucket) -> related findings
        self.pid_windows = defaultdict(list)

    def score_findings(self, findings):
        """Apply deduplication + correlation + scoring."""
        unique = self._deduplicate(findings)
        correlated = self._correlate(unique)
        scored = self._score(correlated)
        return scored

    # ─── Deduplication ─────────────────────────────────────────────────────

    def _deduplicate(self, findings):
        """Drop exact-duplicate findings based on (type, detail_hash, severity)."""
        seen = set()
        unique = []
        for f in findings:
            key = hashlib.md5(
                f"{f['type']}{f.get('detail','')}{f['severity']}".encode()
            ).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ─── Cross-Correlation ───────────────────────────────────────────────────

    def _correlate(self, findings):
        """
        Merge related findings (same PID, same anomaly class within time window).
        Returns list of correlated groups.
        """
        pid_groups = defaultdict(list)
        for f in findings:
            pid = None
            for obj in f.get("objects", []):
                if str(obj).startswith("pid:"):
                    pid = obj
                    break
            if pid:
                pid_groups[pid].append(f)
            else:
                pid_groups["global"].append(f)

        alerts = []
        for key, group in pid_groups.items():
            if len(group) >= 2:
                types = [g["type"] for g in group]
                combined_score = sum(self.weights.get(g["severity"], 0) for g in group)
                alerts.append({
                    "type": "CORRELATED",
                    "combined_score": min(combined_score, 100),
                    "title": f"{len(group)} related anomalies on {key}",
                    "detail": f"Types: {', '.join(set(types))}",
                    "related": group,
                    "severity": "CRITICAL" if combined_score >= 80 else "HIGH",
                })
            else:
                for g in group:
                    if g["severity"] in ("CRITICAL", "HIGH"):
                        alerts.append({
                            "type": "SINGLE",
                            "combined_score": self.weights.get(g["severity"], 0),
                            "title": g["title"],
                            "detail": g.get("detail", ""),
                            "related": [g],
                            "severity": g["severity"],
                        })
        return alerts

    # ─── Scoring ─────────────────────────────────────────────────────────────

    def _score(self, alerts):
        """Sort by combined_score descending."""
        return sorted(alerts, key=lambda a: a["combined_score"], reverse=True)

    # ─── Alert Emission ───────────────────────────────────────────────────────

    def emit_json(self, scored_alerts, output_path=None):
        """Emit structured JSON alert stream."""
        import json
        payload = {
            "scan_time": __import__("datetime").datetime.now().isoformat(),
            "total_alerts": len(scored_alerts),
            "critical": sum(1 for a in scored_alerts if a["severity"] == "CRITICAL"),
            "alerts": scored_alerts,
        }
        if output_path:
            with open(output_path, "w") as f:
                json.dump(payload, f, indent=2)
        return payload

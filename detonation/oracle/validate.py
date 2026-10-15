#!/usr/bin/env python3
"""CI validation: lldb ground truth (x27, region base) vs oracle inference.
Run AFTER a census job: parses cal10.txt curve (L, x27-fa delta) + lldb dumps,
scores the engine's estimate error."""
import re, sys, json
def load_curve(path):
    rows = []
    for ln in open(path, errors='replace'):
        m = re.match(r'L=\s*(\d+) site=\S+ fa=([0-9a-f]+) x11=[0-9a-f]+ x16=\S+ x27=([0-9a-f]+)', ln.strip())
        if m:
            L, fa, x27 = int(m.group(1)), int(m.group(2), 16), int(m.group(3), 16)
            rows.append((L, x27 - fa, x27))
    return rows
if __name__ == "__main__":
    rows = load_curve(sys.argv[1] if len(sys.argv) > 1 else "cal10.txt")
    if not rows:
        print(json.dumps({"error": "no curve rows"})); sys.exit(0)
    deltas = [d for _, d, _ in rows]
    # region-base distance estimate: MAX delta seen = closest-to-base sample
    est_base_dist = max(deltas)
    print(json.dumps({
        "samples": len(rows),
        "delta_min": hex(min(deltas)),
        "delta_max": hex(est_base_dist),
        "x27_range": [hex(min(r[2] for r in rows)), hex(max(r[2] for r in rows))],
        "note": "delta_max = lower bound of x27-above-base; boundary probes refine"
    }, indent=1))

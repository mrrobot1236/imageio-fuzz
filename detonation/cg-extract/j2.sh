#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_j1.py
ls -la j1.pdf j1.ttf || exit 1
# B) groomed survivor: trace write path end-to-end
JMODE=survive lldb -b \
  -o "breakpoint set -n aa_cache_render" \
  -o "process launch -- j1.pdf" \
  -o "command script import ../cg-extract/jtrace2.py" \
  -o "detach" -o "quit" \
  ./render > j2_survive.txt 2>&1 || true
grep -cE "\[hit" j2_survive.txt || echo 0
# A) crash variant: fault + memory forensics
JMODE=crash lldb -b \
  -o "breakpoint set -n aa_cache_render" \
  -o "process launch -- trigger.pdf" \
  -o "command script import ../cg-extract/jtrace2.py" \
  -o "detach" -o "quit" \
  ./render > j2_crash.txt 2>&1 || true
tail -6 j2_crash.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/j2_*.txt findings/
ls -la findings/

#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_j1.py
ls -la j1.pdf
# B) groomed survivor: SBProcess.Continue() trace through write path
JMODE=survive lldb -b \
  -o "breakpoint set -n aa_cache_render" \
  -o "process launch -- j1.pdf" \
  -o "command script import $PWD/../cg-extract/jtrace3.py" \
  -o "detach" -o "quit" \
  ./render > j5_survive.txt 2>&1 || true
grep -cE "\[hit" j5_survive.txt || echo 0
# A) crash variant: fault + memory forensics
JMODE=crash lldb -b \
  -o "breakpoint set -n aa_cache_render" \
  -o "process launch -- trigger.pdf" \
  -o "command script import $PWD/../cg-extract/jtrace3.py" \
  -o "detach" -o "quit" \
  ./render > j5_crash.txt 2>&1 || true
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/j5_*.txt findings/
ls -la findings/

#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_j1.py
ls -la j1.pdf
# K1a: node/accumulator map, ASLR off, crash path (the walk engages there)
JMODE=map lldb -b \
  -o "breakpoint set -n aa_cache_render" \
  -o "process launch -- trigger.pdf" \
  -o "command script import $PWD/../cg-extract/jtrace4.py" \
  -o "detach" -o "quit" \
  ./render > k1_map.txt 2>&1 || true
grep -cE "\[k1|\[chain|\[acc" k1_map.txt || echo 0
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/k1_map.txt findings/
ls -la findings/

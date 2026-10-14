#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_cal.py
ls -la cal_*.pdf
for X in 5 15 25 35 45 55; do
  JMODE=cal lldb -b \
    -o "breakpoint set -n aa_cache_render" \
    -o "process launch -- cal_$X.pdf" \
    -o "command script import $PWD/../cg-extract/jtrace4.py" \
    -o "detach" -o "quit" \
    ./render > cal_$X.txt 2>&1 || true
  echo "--- cal_$X: $(grep -cE '\[cal|\[W |\[head|\[chain' cal_$X.txt) events"
done
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/cal_*.txt findings/
ls -la findings/ | head -12

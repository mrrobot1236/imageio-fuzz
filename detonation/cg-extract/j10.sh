#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_k2.py
for TAG in m1 z0 p4 p64 wild; do
  ./venv/bin/python gen_pdf.py k2_${TAG}.pdf k2_${TAG}.ttf
done
ls -la k2_*.pdf
for TAG in m1 z0 p4 p64 wild; do
  lldb -b \
    -o "breakpoint set -n aa_cache_render" \
    -o "process launch -- k2_${TAG}.pdf" \
    -o "command script import $PWD/../cg-extract/jtrace5.py" \
    -o "detach" -o "quit" \
    ./render > k2_${TAG}.txt 2>&1 || true
  echo "--- k2_$TAG: $(grep -cE '\[k2|\[W |\[head|\[BEFORE|\[AFTER' k2_${TAG}.txt) events"
done
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/k2_*.txt findings/
ls findings/ | head

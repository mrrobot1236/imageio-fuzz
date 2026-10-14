#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_l2.py
for TAG in s71 s100 s140 s200 s248 s320 s400 s512 wild; do
  ./venv/bin/python gen_pdf.py k2_${TAG}.pdf k2_${TAG}.ttf
  ./render k2_${TAG}.pdf >/dev/null 2>&1; echo "plain $TAG rc=$?" >> sweep_summary.txt
done
for TAG in s71 s100 s140 s200 s248 s320 s400 s512; do
  lldb -b \
    -o "breakpoint set -n aa_cache_render" \
    -o "process launch -- k2_${TAG}.pdf" \
    -o "command script import $PWD/../cg-extract/jtrace6.py" \
    -o "detach" -o "quit" \
    ./render > l2_${TAG}.txt 2>&1 || true
  echo "--- l2_$TAG: $(grep -cE '\[W ' l2_${TAG}.txt) W, fault=$(grep -c FAULT l2_${TAG}.txt)"
done
cat sweep_summary.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/l2_*.txt detonation/cve-2026-86950/sweep_summary.txt findings/
ls findings/ | wc -l

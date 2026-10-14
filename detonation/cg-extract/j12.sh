#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
clang -O2 -g -o render2 render2.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_k2.py
for TAG in m256 m64 m16 m4 z0 p4 p16 p64 p128 p256 p512 p1k wild; do
  ./venv/bin/python gen_pdf.py k2_${TAG}.pdf k2_${TAG}.ttf
  ./render k2_${TAG}.pdf > /dev/null 2> rc_${TAG}.txt; RC=$?
  ./render2 k2_${TAG}.pdf png_${TAG}.png > /dev/null 2> r2_${TAG}.txt; RC2=$?
  echo "L=$TAG rc=$RC rc2=$RC2 png=$(md5 -q png_${TAG}.png 2>/dev/null)"
  echo "L=$TAG rc=$RC rc2=$RC2 png=$(md5 -q png_${TAG}.png 2>/dev/null)" >> sweep_summary.txt
done
./render trigger.pdf >/dev/null 2>&1; echo "trigger rc=$?" | tee -a sweep_summary.txt
./render2 trigger.pdf png_trigger.png >/dev/null 2>&1; echo "trigger png=$(md5 -q png_trigger.png 2>/dev/null)" | tee -a sweep_summary.txt
cat sweep_summary.txt
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/png_*.png detonation/cve-2026-86950/sweep_summary.txt findings/
ls findings/ | wc -l

#!/bin/bash
# Phase N: patched-build comparison on macOS 26 (26.7.1+ has the aa_cache_render fix)
set -x
mkdir -p findings26
sw_vers > findings26/os.txt
sysctl -n machdep.cpu.brand_string >> findings26/os.txt 2>/dev/null || true
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation 2>> ../../findings26/os.txt
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_k2.py > findings26/gen.txt 2>&1 || true
for TAG in m256 p64 p1k wild; do
  ./venv/bin/python gen_pdf.py k2_${TAG}.pdf k2_${TAG}.ttf 2>> ../../findings26/gen.txt
  ./render k2_${TAG}.pdf >/dev/null 2>&1
  echo "plain26 $TAG rc=$?" >> ../../findings26/verdict.txt
done
lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_wild.pdf" \
  -k "register read" -k "thread backtrace all" -o "quit" ./render > ../../findings26/l26_wild.txt 2>&1 || true
grep -m1 "stop reason" ../../findings26/l26_wild.txt >> ../../findings26/verdict.txt || true
cat ../../findings26/verdict.txt || true

#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_k2.py > gen_m1.txt 2>&1
./venv/bin/python gen_pdf.py k2_wild.pdf k2_wild.ttf
ls -la k2_wild.ttf k2_wild.pdf
# M1: ASLR variance — 3 LLDBPLAIN wild runs with fault forensics
for I in 1 2 3; do
  lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_wild.pdf" \
    -k "register read" -k "thread backtrace all" \
    -k "memory read --size 8 --count 20 --format x \$x2-0x40" \
    -k "memory read --size 8 --count 20 --format x \$x27" \
    -k "memory region \$x2" -k "memory region \$x27" \
    -o "quit" ./render > m1_wild_$I.txt 2>&1 || true
  grep -m1 "stop reason = EXC" m1_wild_$I.txt >> m1_summary.txt || echo "wild_$I: no fault" >> m1_summary.txt
done
# M1: full traced census run (regions + W-delta marching)
lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_wild.pdf" \
  -o "command script import $PWD/../cg-extract/jtrace8.py" -o "detach" -o "quit" \
  ./render > m1_trace.txt 2>&1 || true
grep -c "\[W " m1_trace.txt > m1_wcount.txt || true
cat m1_summary.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/m1_*.txt findings/
ls findings/ | wc -l

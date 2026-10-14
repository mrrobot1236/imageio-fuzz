#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_k2.py
for TAG in m1 z0 p4 p64 wild; do ./venv/bin/python gen_pdf.py k2_${TAG}.pdf k2_${TAG}.ttf; done
./venv/bin/python gen_pdf.py regen_trigger.pdf trigger.ttf
# byte comparisons
cmp -s trigger.ttf k2_wild.ttf && echo "CMP ttf: IDENTICAL" || echo "CMP ttf: DIFFER"
cmp -s trigger.pdf regen_trigger.pdf && echo "CMP pdf: IDENTICAL" || echo "CMP pdf: DIFFER"
md5 trigger.pdf regen_trigger.pdf k2_wild.pdf
# A) PLAIN runs, no lldb at all
for F in trigger.pdf regen_trigger.pdf k2_wild.pdf k2_p64.pdf; do
  ./render $F > plain_${F}.txt 2>&1; echo "PLAIN $F exit=$?"; cat plain_${F}.txt | tail -2
done
# B) lldb entry-bp only, no python, let it crash naturally
for F in trigger.pdf k2_wild.pdf; do
  lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- $F" \
    -o "continue" -o "thread backtrace all" -o "register read" -o "quit" \
    ./render > lldbplain_${F}.txt 2>&1 || true
  echo "LLDBPLAIN $F: $(grep -cE 'BAD_ACCESS|survived' lldbplain_${F}.txt) marks"
  grep -E "BAD_ACCESS|survived" lldbplain_${F}.txt | head -3
done
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/{plain_*.txt,lldbplain_*.txt} findings/ 2>/dev/null
ls findings/ | tail -10

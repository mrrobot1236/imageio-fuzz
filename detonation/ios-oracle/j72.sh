#!/bin/bash
# ORACLE-PDF v1 calibration: gen bands -> thumbnail-scan each on macOS 26 CG
set -x
cd detonation/ios-oracle
clang -O2 -fobjc-arc -o thumbscan thumbscan.c -framework ImageIO -framework CoreGraphics -framework Foundation || exit 9
python3 -m venv venv 2>/dev/null || true
./venv/bin/pip -q install fonttools
./venv/bin/python gen_oracle_v1.py > bands.txt 2>&1
cat bands.txt
: > scan_results.txt
for f in oracle_v1_*.pdf; do
  for run in 1 2; do
    ./thumbscan "$f" >> scan_results.txt 2>&1
    echo "$f run$run exit=$?" >> scan_results.txt
  done
done
cat scan_results.txt
cd ../..
mkdir -p findings/ios-oracle
cp detonation/ios-oracle/oracle_v1_*.pdf findings/ios-oracle/ 2>/dev/null
cp detonation/ios-oracle/{scan_results.txt,bands.txt} findings/ios-oracle/ 2>/dev/null
ls findings/ios-oracle/ | wc -l

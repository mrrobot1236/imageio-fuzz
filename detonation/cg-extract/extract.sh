#!/bin/bash
# CoreGraphics/ImageIO live in the dyld shared cache on macOS 14+. Extract with dyld_shared_cache_util.
set -x
mkdir -p out
sw_vers > out/os.txt
CACHE="/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
[ -f "$CACHE" ] || CACHE=$(ls /System/Library/dyld/dyld_shared_cache_arm64e* 2>/dev/null | grep -v '\.' | head -1)
ls -la "$(dirname "$CACHE")" >> out/os.txt 2>&1
echo "cache=$CACHE" >> out/os.txt
U=$(xcrun -f dyld_shared_cache_util 2>/dev/null)
echo "util=$U" >> out/os.txt
rm -rf xout && mkdir -p xout
"$U" -extract "$PWD/xout" "$CACHE" com.apple.CoreGraphics com.apple.ImageIO 2>&1 | tee -a out/os.txt
"$U" -extract "$PWD/xout" "$CACHE" CoreGraphics ImageIO 2>&1 | tee -a out/os.txt
find xout -type f -exec ls -la {} \; >> out/os.txt 2>&1
CG=""; IIO=""
for f in xout/CoreGraphics xout/com.apple.CoreGraphics; do [ -f "$f" ] && CG="$f"; done
for f in xout/ImageIO xout/com.apple.ImageIO; do [ -f "$f" ] && IIO="$f"; done
echo "CG=$CG IIO=$IIO" >> out/os.txt
if [ -n "$CG" ]; then lipo -info "$CG" >> out/os.txt 2>&1; nm -gU "$CG" 2>/dev/null | grep -E "aa_|glyph|Glyph" > out/cg_syms.txt; fi
if [ -n "$IIO" ]; then nm -gU "$IIO" 2>/dev/null | grep -iE "pdf|thumbnail" > out/iio_syms.txt; fi
cat out/os.txt
tar czf detonation_cgpack.tgz -C out . || tar czf cgpack.tgz -C out .
mkdir -p ../..//detonation/cg-extract/final
cp detonation_cgpack.tgz ../detonation/cg-extract/final/cgpack.tgz 2>/dev/null || cp cgpack.tgz ../detonation/cg-extract/final/cgpack.tgz
ls -la ../detonation/cg-extract/final/

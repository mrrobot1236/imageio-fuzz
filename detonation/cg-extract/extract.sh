#!/bin/bash
# CoreGraphics/ImageIO live in the dyld shared cache on macOS 14+. Extract with dyld_shared_cache_util.
set -x
mkdir -p out
sw_vers > out/os.txt
CACHE="/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
[ -f "$CACHE" ] || CACHE=$(ls /System/Library/dyld/dyld_shared_cache_arm64e* 2>/dev/null | head -1)
echo "cache=$CACHE" >> out/os.txt
U=$(xcrun -f dyld_shared_cache_util 2>/dev/null || echo /Applications/Xcode_15.4.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/dyld_shared_cache_util)
"$U" -extract "$PWD/out" "$CACHE" CoreGraphics ImageIO >> out/os.txt 2>&1 || \
"$U" -extract "$PWD/out" "$CACHE" com.apple.CoreGraphics com.apple.ImageIO >> out/os.txt 2>&1
ls -la out/ >> out/os.txt
CG=""; IIO=""
for f in out/CoreGraphics out/com.apple.CoreGraphics; do [ -f "$f" ] && CG="$f"; done
for f in out/ImageIO out/com.apple.ImageIO; do [ -f "$f" ] && IIO="$f"; done
echo "CG=$CG IIO=$IIO" >> out/os.txt
[ -n "$CG" ] && { lipo -info "$CG" >> out/os.txt 2>&1; nm -gU "$CG" 2>/dev/null | grep -E "aa_|glyph|Glyph" > out/cg_syms.txt; }
[ -n "$IIO" ] && nm -gU "$IIO" 2>/dev/null | grep -iE "pdf|thumbnail" > out/iio_syms.txt
tar czf cgpack.tgz -C out .
ls -la cgpack.tgz

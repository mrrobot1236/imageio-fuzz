#!/bin/bash
# Ship the runner's CoreGraphics + ImageIO binaries back for static RE (aa_cache_render store-path hunt)
set -e
mkdir -p out
CG=/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics
IIO=/System/Library/Frameworks/ImageIO.framework/ImageIO
sw_vers > out/os.txt
otool -l $CG | grep -A3 "LC_UUID" | head -8 >> out/os.txt || true
cp $CG out/CoreGraphics; cp $IIO out/ImageIO
# fat binary? thin to arm64e slice for analysis
lipo -info out/CoreGraphics | tee out/lipo.txt
otool -p _aa_cache_render -tV out/CoreGraphics > out/cg_disasm_stub.txt 2>/dev/null || true
nm -gU out/CoreGraphics 2>/dev/null | grep -E "aa_|glyph|Glyph" > out/cg_syms.txt || true
nm -gU out/ImageIO 2>/dev/null | grep -iE "pdf|thumbnail" > out/iio_syms.txt || true
tar czf cgpack.tgz -C out . 
ls -la cgpack.tgz

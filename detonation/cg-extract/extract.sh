#!/bin/bash
set -x
CACHE="/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
ls -la "$(dirname "$CACHE")" | head
# radare2 understands dyld shared cache format natively
which r2 || brew install -q radare2 2>&1 | tail -2
which r2
# 1) export symbol scan
/usr/bin/dyld_info -exports "$CACHE" 2>/dev/null | grep -iE "^\s*0x.*(_aa_|GlyphBitmap|GlyphBuilder)" | head -40 > exports.txt
r2 -q -c "is~aa_" "$CACHE" 2>/dev/null | head -40 > r2_syms.txt
r2 -q -c "is~Glyph" "$CACHE" 2>/dev/null | head -60 >> r2_syms.txt
cat exports.txt r2_syms.txt
# 2) disassemble aa_cache_render (+ call-site family) straight from the cache
r2 -q -c "s sym._aa_cache_render; pd 800" "$CACHE" > aa_cache_render.asm 2>/dev/null
wc -l aa_cache_render.asm
r2 -q -c "s sym._aa_cache_render8; pd 800" "$CACHE" > aa_cache_render8.asm 2>/dev/null
ls -la *.txt *.asm

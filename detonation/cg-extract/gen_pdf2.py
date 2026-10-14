#!/usr/bin/env python3
"""PDF with trigger font + N spray fonts embedded (spray fonts parsed by CG, unused in content)."""
import sys

def build(path, font="k2_wild.ttf", nspray=0, trigger="trigger.ttf"):
    tf = open(font, "rb").read()
    sprays = [open(f"spray_{i:02d}.ttf","rb").read() for i in range(nspray)]
    objs = []
    def add(b): objs.append(b); return len(objs)
    cat_id = add(b"")            # 1 catalog
    pgs_id = add(b"")            # 2 pages
    pg_id  = add(b"")            # 3 page
    f1_id  = add(b"")            # 4 trigger font
    d1_id  = add(b"")            # 5 trigger descriptor
    s_ids = []; sd_ids = []
    for i in range(nspray):      # font + descriptor per spray
        s_ids.append(add(b"")); sd_ids.append(add(b""))
    c_id  = add(b"")             # content stream
    # trigger font objs (mirror gen_pdf.py structure)
    objs[f1_id-1] = b"<< /Type /Font /Subtype /TrueType /BaseFont /Trigger /FirstChar 65 /LastChar 65 /Widths [1000] /FontDescriptor %d 0 R /Encoding /WinAnsiEncoding >>" % d1_id
    objs[d1_id-1] = b"<< /Type /FontDescriptor /FontName /Trigger /Flags 4 /FontBBox [0 0 32000 40] /ItalicAngle 0 /Ascent 100 /Descent -100 /CapHeight 40 /StemV 80 /FontFile2 %d 0 R >>" % (d1_id+1000)  # placeholder, fix below
    # stream for trigger font
    sf_id = add(b"")
    objs[d1_id-1] = b"<< /Type /FontDescriptor /FontName /Trigger /Flags 4 /FontBBox [0 0 32000 40] /ItalicAngle 0 /Ascent 100 /Descent -100 /CapHeight 40 /StemV 80 /FontFile2 %d 0 R >>" % sf_id
    objs[sf_id-1] = b"<< /Length %d /Length1 %d >>\nstream\n" % (len(tf), len(tf)) + tf + b"\nendstream"
    for i in range(nspray):
        sp = sprays[i]
        objs[s_ids[i]-1] = b"<< /Type /Font /Subtype /TrueType /BaseFont /SPRAY%02d /FirstChar 65 /LastChar 65 /Widths [100] /FontDescriptor %d 0 R /Encoding /WinAnsiEncoding >>" % (i, sd_ids[i])
        ss_id = add(b"")
        objs[sd_ids[i]-1] = b"<< /Type /FontDescriptor /FontName /SPRAY%02d /Flags 4 /FontBBox [0 0 100 100] /ItalicAngle 0 /Ascent 100 /Descent -100 /CapHeight 100 /StemV 80 /FontFile2 %d 0 R >>" % (i, ss_id)
        objs[ss_id-1] = b"<< /Length %d /Length1 %d >>\nstream\n" % (len(sp), len(sp)) + sp + b"\nendstream"
    content = b"BT /F1 1024 Tf 5 5 Td (A) Tj ET"
    objs[c_id-1] = b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream"
    objs[cat_id-1] = b"<< /Type /Catalog /Pages %d 0 R >>" % pgs_id
    objs[pgs_id-1] = b"<< /Type /Pages /Kids [%d 0 R] /Count 1 >>" % pg_id
    font_refs = b" ".join(b"/F%d %d 0 R" % (i+2, s_ids[i]) for i in range(nspray))
    objs[pg_id-1] = b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 200 200] /Resources << /Font << /F1 %d 0 R " % (pgs_id, f1_id) + font_refs + b" >> >> /Contents %d 0 R >>" % c_id
    out = b"%PDF-1.7\n"
    offsets = []
    for i, o in enumerate(objs):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % (i+1) + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % (len(objs)+1) + b"0000000000 65535 f \n"
    for off in offsets: out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF" % (len(objs)+1, cat_id, xref)
    open(path, "wb").write(out)
    print(path, len(out), "nspray", nspray)

if __name__ == "__main__":
    build(sys.argv[1], nspray=int(sys.argv[2]) if len(sys.argv)>2 else 0)

import sys; sys.path.insert(0, '.')
from sweep import gen_font_h, gen_pdf
gen_font_h('cal.ttf', n=12, dx=40, upm=16384, k=32, line_len=38, n_lines=1, neg_y=False)
for x in (5, 15, 25, 35, 45, 55):
    gen_pdf('cal_%d.pdf' % x, 'cal.ttf', ptsize=1024, k=32, ftf=128, final_x=x, final_y=5)
print('cal variants OK')

#!/usr/bin/env python3
"""Oracle-greedy structural mutator. No coverage needed: novelty = new (status, painted-bucket, hash16).
usage: mutate.py <seeddir> <outdir> <rounds> <per_round> <harness> [log]"""
import sys, os, re, random, subprocess, hashlib, shutil, time

seeddir, outdir, rounds, per_round, harness = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
budget = float(sys.argv[6]) if len(sys.argv) > 6 else 1e9
t0 = time.time()
os.makedirs(outdir, exist_ok=True)
R = random.Random(int(os.environ.get('SEED', '1337')))
OBJ = re.compile(rb'(\d+) 0 obj\n(.*?)\nendobj\n', re.S)

def parse(b):
    return [(int(m.group(1)), m.group(2)) for m in OBJ.finditer(b)], OBJ.sub(b'\x00MARK\x00', b)

def serial(objs):
    out = b'%PDF-1.7\n'; offs = {}
    for num, body in objs:
        offs[num] = len(out); out += b'%d 0 obj\n' % num + body + b'\nendobj\n'
    start = len(out); top = max(offs) + 1
    out += b'xref\n0 %d\n0000000000 65535 f \n' % top
    for n in range(1, top):
        out += (b'%010d 00000 n \n' % offs[n]) if n in offs else b'0000000000 65535 f \n'
    out += b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (top, start)
    return out

def bump_nums(objs): pass

MUT = []
def mut(f): MUT.append(f); return f

@mut
def m_trunc_stream(objs):
    i = R.randrange(len(objs)); n,b = objs[i]
    if b'stream\n' in b:
        head, tail = b.split(b'stream\n',1)
        objs[i] = (n, head + b'stream\n' + tail[:max(1,len(tail)//3)] + b'\nendstream')
    return objs

@mut
def m_len_lie(objs):
    i = R.randrange(len(objs)); n,b = objs[i]
    objs[i] = (n, re.sub(rb'/Length (\d+)', lambda m: b'/Length %d' % (int(m.group(1)) + R.choice([-7,1,999,10**6])), b, count=1))
    return objs

@mut
def m_drop_obj(objs):
    if len(objs) > 3: objs.pop(R.randrange(3, len(objs)))
    return objs

@mut
def m_dup_obj(objs):
    i = R.randrange(len(objs)); n,b = objs[i]; new = max(x for x,_ in objs)+1
    objs.append((new, b)); return objs

@mut
def m_repoint(objs):
    nums = [n for n,_ in objs]; i = R.randrange(len(objs)); n,b = objs[i]
    a = R.choice(nums); b2 = R.choice(nums)
    objs[i] = (n, re.sub(rb'\b%d 0 R\b' % a, b'%d 0 R' % b2, b, count=1))
    return objs

@mut
def m_key_typo(objs):
    keys = [b'/Width', b'/Height', b'/BitsPerComponent', b'/ColorSpace', b'/Filter', b'/Subtype', b'/Length']
    i = R.randrange(len(objs)); n,b = objs[i]; k = R.choice(keys)
    objs[i] = (n, b.replace(k, k[:-1], 1)); return objs

@mut
def m_huge_num(objs):
    i = R.randrange(len(objs)); n,b = objs[i]
    objs[i] = (n, re.sub(rb'(/Width|/Height|/Columns) (\d+)', lambda m: m.group(1) + b' ' + R.choice([b'2147483647', b'268435456', b'-1', b'0']), b, count=1))
    return objs

@mut
def m_type_flip(objs):
    i = R.randrange(len(objs)); n,b = objs[i]
    objs[i] = (n, b.replace(b'/Subtype /Image', b'/Subtype /Form', 1).replace(b'/Subtype /Form', b'/Subtype /Image', 1)); return objs

@mut
def m_junk_dict(objs):
    i = R.randrange(len(objs)); n,b = objs[i]
    objs[i] = (n, b.replace(b'<<', b'<< /X#00y ' + os.urandom(3).hex().encode() + b' ', 1)); return objs

@mut
def m_nest_arr(objs):
    i = R.randrange(len(objs)); n,b = objs[i]; d = R.choice([32, 128, 512])
    objs[i] = (n, b.replace(b'/BitsPerComponent', b'/Decode ' + b'['*d + b'0 1' + b']'*d + b' /BitsPerComponent', 1)); return objs

@mut
def m_double_objstm(objs):
    return objs

def mutate_once(b):
    objs, _ = parse(b)
    if not objs: return b
    for _ in range(R.choice([1,1,2,3])):
        R.choice(MUT)(objs)
    out = serial(objs)
    # 20%: add an offset lie on top
    if R.random() < 0.2:
        i = out.rfind(b'startxref'); j = out.find(b'\n', i+10)
        try: out = out[:i+10] + b'%d' % (int(out[i+10:j]) + R.choice([-13, 9, 40, -200])) + out[j:]
        except ValueError: pass
    return out

def classify(path):
    try:
        p = subprocess.run([harness, path], capture_output=True, text=True, timeout=40)
        out = (p.stdout or '').strip().split()
        err = p.stderr or ''
    except subprocess.TimeoutExpired:
        return 'TIMEOUT', 0, '0'*16, 'timeout'
    if 'AddressSanitizer' in err or 'SEGV' in err or 'deadly signal' in err or 'runtime error' in err:
        return 'CRASH', 0, hashlib.sha1(err.encode()).hexdigest()[:16], err[:400]
    if not out: return 'FAIL', 0, '0'*16, err[:200]
    status = out[0]; painted = int(out[2]) if len(out) > 2 else 0
    h = out[3] if len(out) > 3 else '0'*16
    return status, painted, h, ''

def bucket(p):
    return 0 if p == 0 else 1 if p < 40 else 2 if p < 400 else 3 if p < 4000 else 4

seeds = sorted(f for f in os.listdir(seeddir) if f.endswith('.pdf'))
seen = set(); corpus = []
base_units = {}
for s in seeds:
    st, p, h, _ = classify(os.path.join(seeddir, s))
    seen.add((st, bucket(p), h[:12])); corpus.append(open(os.path.join(seeddir, s), 'rb').read())
print(f'# seeds={len(seeds)} baseline_classes={len(seen)}', flush=True)

stats = {'CRASH': 0, 'TIMEOUT': 0, 'new': 0, 'runs': 0}
stop = False
for r in range(rounds):
    if stop: break
    for k in range(per_round):
        if time.time() - t0 > budget: stop = True; break
        src = R.choice(corpus)
        cand = mutate_once(src)
        name = f'r{r:02d}_{k:03d}'
        path = os.path.join(outdir, name + '.pdf')
        open(path, 'wb').write(cand)
        st, p, h, err = classify(path)
        stats['runs'] += 1
        key = (st, bucket(p), h[:12])
        novel = key not in seen
        if novel:
            seen.add(key); corpus.append(cand); stats['new'] += 1
            shutil.copyfile(path, os.path.join(outdir, 'N_' + name + '.pdf'))
            with open(os.path.join(outdir, 'NOVEL.log'), 'a') as f:
                f.write(f'{name} {st} painted={p} h={h} bytes={len(cand)}\n')
            print(f'NOVEL {name} {st} painted={p} h={h} bytes={len(cand)}', flush=True)
        if st in ('CRASH', 'TIMEOUT'):
            stats[st] += 1
            keep = os.path.join(outdir, 'KEEP_' + st + '_' + name + '.pdf')
            shutil.copyfile(path, keep)
            print(f'{st} {name} painted={p} :: {err[:200]}', flush=True)
        if not novel and st not in ('CRASH','TIMEOUT'):
            os.unlink(path)
    print(f'-- round {r}: runs={stats["runs"]} new={stats["new"]} crash={stats["CRASH"]} timeout={stats["TIMEOUT"]} classes={len(seen)}', flush=True)
print('=== SUMMARY %s' % stats, flush=True)

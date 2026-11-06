#!/usr/bin/env python3
"""Static verifier for packet RE-001-node115-lu-opt-groups56-60-leaves.

Byte reads only; never executes the node binary. Exit 0 iff every check
passes. Failure propagation uses `ok = check(...) and ok` (never the
`ok = fail(...) or ok` form, which cannot propagate a failure).
"""
import glob as _glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = 'RE-001-node115-lu-opt-groups56-60-leaves'
BIN_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BIN_SIZE = 105896032
TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300

LEAVES = [
    # name, node, start, end, kind, value_slot
    ('prof_leak', 0x64deba0, 0x6374170, 0x63741f6, 'byte', 0x6713603),
    ('prof_leak_error', 0x64debc8, 0x6374200, 0x6374286, 'byte', 0x6713602),
    ('prof_accum', 0x64debf0, 0x6373da0, 0x6373e26, 'byte', 0x6713601),
    ('prof_recent_alloc_max', 0x64dec18, 0x6374290, 0x63744a7, 'u64', 0x6715910),
    ('prof_stats', 0x64dec40, 0x63744b0, 0x6374536, 'byte', 0x6717690),
]

SKIP_KEYS = ('census', 'cited', 'survey', 'callers', 'largest_caller_fde')


def find_root(start):
    cur = os.path.abspath(start)
    while True:
        if os.path.exists(os.path.join(cur, 'artifacts', 'node', '115', 'hl-node')):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def main():
    tool_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.environ.get('HL273_ROOT') or find_root(tool_dir)
    if root is None:
        print('FAIL: repo root not found')
        return 1
    bin_path = os.environ.get('HL273_BIN') or os.path.join(
        root, 'artifacts', 'node', '115', 'hl-node')
    packet = os.path.join(root, 'research', 'work-items', SLUG)
    data = open(bin_path, 'rb').read()
    npass = 0
    nfail = 0

    def check(cond, msg):
        nonlocal npass, nfail
        if cond:
            npass += 1
        else:
            nfail += 1
            print('FAIL:', msg)
        return cond

    ok = True
    # 1. binary identity
    ok = check(hashlib.sha256(data).hexdigest() == BIN_SHA256,
               'binary sha256') and ok
    ok = check(len(data) == BIN_SIZE, 'binary size') and ok

    # 2. records.json shape and values (all computed programmatically)
    rec = json.load(open(os.path.join(packet, 'records.json')))
    by_name = {}
    for e in rec.get('exhibits', []):
        by_name[e['name']] = e
    ok = check(len(by_name) == 5, 'records exhibit count') and ok
    tot_b = 0
    tot_s = 0
    for name, node, s, e, kind, slot in LEAVES:
        ex = by_name.get(name)
        ok = check(ex is not None, f'records has {name}') and ok
        if ex is None:
            continue
        rng = ex['range']
        rs, re_ = (int(rng[0], 16), int(rng[1], 16)) if isinstance(rng, list) \
            else tuple(int(x, 16) for x in rng.split('..'))
        ok = check(rs == s and re_ == e, f'{name} range') and ok
        ok = check(ex['bytes'] == e - s, f'{name} bytes') and ok
        ok = check(ex['start_dec'] == s and ex['end_dec'] == e,
                   f'{name} decimal range') and ok
        ok = check(ex['node'] == hex(node), f'{name} node') and ok
        ok = check(ex['value_kind'] == kind, f'{name} kind') and ok
        ok = check(ex['value_slot'] == hex(slot), f'{name} slot') and ok
        tot_b += ex['bytes']
        tot_s += ex['strict']
    ok = check(rec['totals']['bytes'] == tot_b == 1071, 'total bytes') and ok
    ok = check(rec['totals']['strict'] == tot_s == 291, 'total strict') and ok
    ok = check(rec['leaves_remaining_after'] == 111, 'leaves remaining') and ok

    # 3. .rela.dyn: node+0x08 name addend and node+0x20 handler addend
    rela = {}
    out = subprocess.run(['readelf', '-r', bin_path],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == 'R_X86_64_RELATIVE':
            rela[int(parts[0], 16)] = int(parts[3], 16)

    def name_at(va):
        end = data.index(b'\0', va)
        return data[va:end].decode()

    for name, node, s, e, kind, slot in LEAVES:
        ok = check(rela.get(node + 0x08) is not None,
                   f'{name} name rela present') and ok
        if rela.get(node + 0x08) is not None:
            ok = check(name_at(rela[node + 0x08]) == name,
                       f'{name} name resolves') and ok
        ok = check(rela.get(node + 0x20) == s,
                   f'{name} handler slot resolves') and ok

    # 4. .eh_frame FDE bounds (pcrel sdata4, fixed 4-byte range fields)
    sout = subprocess.run(['readelf', '-S', bin_path],
                          capture_output=True, text=True).stdout
    m = re.search(r'\.eh_frame\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)',
                  sout)
    eh_addr, eh_off, eh_size = (int(m.group(1), 16), int(m.group(2), 16),
                                int(m.group(3), 16))
    fdes = {}
    pos = eh_off
    end = eh_off + eh_size
    while pos < end:
        if pos + 8 > end:
            break
        length = struct.unpack_from('<I', data, pos)[0]
        if length == 0 or length == 0xffffffff:
            break
        cie_id = struct.unpack_from('<I', data, pos + 4)[0]
        if cie_id != 0:
            field_addr = eh_addr + (pos + 8 - eh_off)
            init = struct.unpack_from('<i', data, pos + 8)[0]
            start = field_addr + init
            rng = struct.unpack_from('<I', data, pos + 12)[0]
            fdes[start] = start + rng
        pos += 4 + length
    for name, node, s, e, kind, slot in LEAVES:
        ok = check(fdes.get(s) == e, f'{name} eh_frame FDE bounds') and ok
    # correction cross-check: the FDE packet #272 called a non-opt function
    # in its gap note is exactly group 58's handler, now claimed here.
    ok = check(fdes.get(0x6373da0) == 0x6373e26,
               'gap FDE 0x6373da0 is prof_accum handler') and ok

    # 5. exhibits: bytes, objdump regeneration, strict recount, structure
    def instr_lines(path):
        res = []
        for line in open(path, errors='replace'):
            mm = re.match(r'^\s*[0-9a-f]+:\t[0-9a-f ]+\t([a-z]\S*)', line)
            if mm:
                res.append(line.strip())
        return res

    text = data[TEXT_OFF:TEXT_OFF + 0x4fd7700]
    for name, node, s, e, kind, slot in LEAVES:
        raw = open(os.path.join(packet, f'{name}.hex'), 'rb').read()
        ok = check(raw == data[s - 0x1000:s - 0x1000 + (e - s)],
                   f'{name} hex bytes') and ok
        regen = subprocess.run(
            ['objdump', '-d', '--start-address', hex(s),
             '--stop-address', hex(e), bin_path],
            capture_output=True, text=True).stdout
        stored = open(os.path.join(packet, f'{name}.objdump.txt'),
                      errors='replace').read()
        regen_ins = [l.strip() for l in regen.splitlines()
                     if re.match(r'^\s*[0-9a-f]+:\t', l)]
        stored_ins = [l.strip() for l in stored.splitlines()
                      if re.match(r'^\s*[0-9a-f]+:\t', l)]
        ok = check(regen_ins == stored_ins, f'{name} objdump regen') and ok
        strict = sum(1 for l in stored.splitlines()
                     if re.match(r'^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]', l))
        ok = check(strict == by_name[name]['strict'],
                   f'{name} strict recount') and ok
        # structure: exactly 1 ret, exactly 1 call to __stack_chk_fail,
        # all jump targets inside the FDE
        mnems = []
        for l in stored.splitlines():
            mm = re.match(r'^\s*([0-9a-f]+):\t[0-9a-f ]+\t(\S+)', l)
            if mm:
                mnems.append((int(mm.group(1), 16), mm.group(2), l))
        ok = check(sum(1 for _, mn, _ in mnems if mn == 'ret') == 1,
                   f'{name} single ret') and ok
        calls = [l for _, mn, l in mnems if mn == 'call']
        ok = check(len(calls) == 1 and '__stack_chk_fail' in calls[0],
                   f'{name} only stack_chk_fail call') and ok
        bad = []
        for addr, mn, l in mnems:
            if mn in ('jmp', 'je', 'jne', 'jb', 'jae', 'ja', 'jbe', 'jl',
                      'jge', 'jle', 'jg', 'js', 'jns'):
                tm = re.search(r'\b(637[0-9a-f]{4})\b', l)
                if tm and not (s <= int(tm.group(1), 16) < e):
                    bad.append(l.strip())
        ok = check(not bad, f'{name} jumps contained') and ok
        # value-load triple: rip-relative lea whose comment target is slot
        lea_targets = re.findall(
            r'lea\s+0x[0-9a-f]+\(%rip\),%\w+\s+#\s*([0-9a-f]+)', stored)
        ok = check(hex(slot) in lea_targets or
                   format(slot, 'x') in lea_targets,
                   f'{name} value lea target') and ok
        if kind == 'byte':
            ok = check('cmp    $0x1,' in stored or 'cmp $0x1,' in stored,
                       f'{name} byte size compare') and ok
        else:
            ok = check('cmp    $0x8,' in stored or 'cmp $0x8,' in stored,
                       f'{name} u64 size compare') and ok
        # whole-.text raw E8 census: 0 direct rel32 entries to handler
        hits = 0
        i = 0
        while True:
            i = text.find(b'\xe8', i)
            if i < 0:
                break
            if i + 5 <= len(text):
                rel = struct.unpack_from('<i', text, i + 1)[0]
                if TEXT_VA + i + 5 + rel == s:
                    hits += 1
            i += 1
        ok = check(hits == 0, f'{name} E8 census zero') and ok

    # 6. disjointness: range-only collector, cited/census excluded,
    # deduplicated by real packet slug
    def collect(obj, out):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in SKIP_KEYS or k == 'fde':
                    continue
                if k in ('exhibits', 'windows'):
                    items = v if isinstance(v, list) else (
                        v.values() if isinstance(v, dict) else [])
                    for it in items:
                        if isinstance(it, dict):
                            if 'range' in it:
                                r = it['range']
                                out.append(
                                    (int(r[0], 16), int(r[1], 16))
                                    if isinstance(r, list) else tuple(
                                        int(x, 16) for x in r.split('..')))
                            elif 'start' in it and 'end' in it:
                                out.append((int(it['start'], 16),
                                            int(it['end'], 16)))
                else:
                    collect(v, out)
        elif isinstance(obj, list):
            for v in obj:
                collect(v, out)

    roots = os.environ.get('HL273_PRIOR_ROOTS')
    if roots:
        roots = roots.split(os.pathsep)
    else:
        roots = _glob.glob(os.path.join(root, 'research', 'work-items')) + \
            _glob.glob('/home/hatch/workspace/hl-wt-calls*/research/work-items')
    seen_slugs = set()
    priors = []
    for rdir in roots:
        for rec_path in _glob.glob(os.path.join(rdir, '*', 'records.json')):
            slug = os.path.basename(os.path.dirname(rec_path))
            if slug == SLUG or slug in seen_slugs:
                continue
            seen_slugs.add(slug)
            try:
                collect(json.load(open(rec_path)), priors)
            except Exception:
                pass
    mine = [(s, e) for _, _, s, e, _, _ in LEAVES]
    for a, b in mine:
        for p, q in priors:
            ok = check(not (a < q and p < b),
                       f'disjoint vs prior {hex(p)}..{hex(q)}') and ok
    for i in range(len(mine)):
        for j in range(i + 1, len(mine)):
            a, b = mine[i]
            p, q = mine[j]
            ok = check(not (a < q and p < b), 'pairwise disjoint') and ok
    # explicit anchors (also covered by the general check)
    for anchor in [(0x63b8820, 0x63b8d85), (0x63ec890, 0x63ec8a3),
                   (0x63d9700, 0x63d987b), (0x63721c0, 0x6372246),
                   (0x63737c0, 0x6373846), (0x6373850, 0x6373a5a),
                   (0x6373a60, 0x6373ae6), (0x6373b80, 0x6373d97)]:
        for a, b in mine:
            ok = check(not (a < anchor[1] and anchor[0] < b),
                       f'disjoint vs anchor {hex(anchor[0])}') and ok

    # 7. MANIFEST hashes
    man = open(os.path.join(packet, 'MANIFEST.sha256')).read().splitlines()
    nman = 0
    for line in man:
        line = line.strip()
        if not line:
            continue
        h, path = line.split(None, 1)
        full = os.path.normpath(os.path.join(packet, path))
        ok = check(os.path.exists(full), f'MANIFEST path exists {path}') \
            and ok
        if os.path.exists(full):
            ok = check(hashlib.sha256(open(full, 'rb').read()).hexdigest() == h,
                       f'MANIFEST hash {path}') and ok
            nman += 1
    ok = check(nman == 15, 'MANIFEST entry count') and ok

    print(f'VERIFIER {"OK" if ok else "FAIL"}: {npass} PASS, {nfail} FAIL'
          f' ({len(seen_slugs)} prior dirs scanned)')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())

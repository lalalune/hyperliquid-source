#!/usr/bin/env python3
"""Static node #94 net_utils NodePort port arithmetic, checked from authenticated bytes.

Question: at every site that turns a NodePort endpoint into a TCP port, which
base port is used, how is a local-validator index folded in, and what happens
when the result does not fit in a u16?

Only the Python standard library is used.  Sites are found as the only .text
occurrences of `mov r16,1000; mul r16; jo rel32` and bounded by parsed
.eh_frame FDEs.  The six-entry u16 port table is found by value in every
file-backed section and must be referenced by exactly the table-shaped sites.
Overflow branches are followed to their panic stubs, whose Location records
and GOT-slot relocations (.rela.dyn) are decoded.  Nothing is executed.
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = 'artifacts/node/94/hl-node'
PORTS = (4001, 4002, 4003, 4004, 3998, 3999)
STRIDE = 1000
LOCALHOST_LE = 0x0100007f
NODE_PORT_RS = b'/home/ubuntu/hl/code_Mainnet/net_utils/src/node_port.rs'
MUL_LOCATION = (23, 63)
ADD_LOCATION = (28, 14)
PANIC_TEXT = {'mul': b'attempt to multiply with overflow', 'add': b'attempt to add with overflow'}
EXPECTED_SITES = {  # FDE -> shape, base port (None: indexed by discriminant)
    0x1fd4570: ('const_cmp', 4001), 0x2037ac0: ('table', None), 0x2039060: ('const_cmp', 4002),
    0x22c54a0: ('table', None), 0x43831e0: ('table', None), 0x43848f0: ('const_cmp', 4004),
    0x4387f40: ('const_cmp', 4002), 0x438ed70: ('jump_table', None), 0x454c2b0: ('const_cmp', 4003),
    0x47b4950: ('jump_table', None),
}

MUL = re.compile(rb'\x66([\xb8-\xbf])\xe8\x03\x66\xf7([\xe0-\xe7])\x0f\x80(....)', re.S)
TABLE = re.compile(rb'\x48\x8d([\x15\x35])(....)\x0f\xb7([\x0c\x34])([\x4a\x4e])', re.S)
CONST_CMP = re.compile(rb'\x0f\xb7\xc8\x81\xf9(....)\x0f\x87(....)\x05(....)\xb9\x7f\x00\x00\x01', re.S)
ARM_BASE = re.compile(rb'\x66\xbe(..)', re.S)
DISPATCH = re.compile(rb'\x48\x8d\x35(....)\x48\x63\x0c\x8e\x48\x01\xf1\xff\xe1', re.S)
SPLIT_IP = re.compile(rb'[\xba\xbf]\x00\x00\x00\x01[\xb8\xbe]\x7f\x00\x00\x00', re.S)
ADD16 = re.compile(rb'\x66\x01([\xc8\xf1])\x0f\x82(....)', re.S)
PANIC_STUB = re.compile(rb'((?:[\x40\x41][\xb0-\xb7].)?)\x48\x8d\x3d(....)\xff\x15(....)', re.S)


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        self.text = next((s for s in self.secs if s['name'] == '.text' and s['type'] != 8), None)
        require(self.text is not None, 'no file-backed .text')
        rela = next((s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4), None)
        require(rela is not None and rela['size'] % 24 == 0, 'no well-formed .rela.dyn')
        self.relative = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)

    def offset(self, va, size=1):
        hits = [s for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(hits) == 1, f'VA {va:#x}+{size} is not in exactly one file-backed section')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def section_of(self, va):
        hits = [s['name'] for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va < s['address'] + s['size']]
        return hits[0] if len(hits) == 1 else None

    def fde_of(self, va):
        hits = [f for f in self.fdes if f[0] <= va < f[1]]
        require(len(hits) == 1, f'{va:#x} is not inside exactly one FDE')
        return hits[0]

    def text_bytes(self):
        t = self.text
        return t['address'], self.data[t['offset']:t['offset'] + t['size']]


def rel32(va_end, raw):
    return va_end + struct.unpack('<i', raw)[0]


def panic_stub(img, va, kind):
    """`lea rdi,[rip+Location]; call [rip+slot]` with the slot relocated to a const panic helper."""
    m = PANIC_STUB.match(img.read(va, 16))
    require(m is not None, f'{kind} overflow target {va:#x} is not lea rdi,[Location]; call [slot]')
    pre = len(m.group(1))
    loc = rel32(va + pre + 7, m.group(2))
    slot = rel32(va + pre + 13, m.group(3))
    require(slot in img.relative, f'panic slot {slot:#x} has no R_X86_64_RELATIVE entry')
    helper = img.relative[slot]
    path_ptr = img.relative.get(loc)
    require(path_ptr is not None, f'Location {loc:#x} path pointer is not relocated')
    path_len, line, col = struct.unpack('<QII', img.read(loc + 8, 16))
    require(img.read(path_ptr, path_len) == NODE_PORT_RS, f'Location {loc:#x} does not name node_port.rs')
    want = MUL_LOCATION if kind == 'mul' else ADD_LOCATION
    require((line, col) == want, f'{kind} Location {loc:#x} is line {line} col {col}')
    # helper: push rbp; mov rbp,rsp; mov rdx,rdi; lea rdi,[rip+msg]; mov esi,(len << 1) | 1
    h = img.read(helper, 19)
    require(h[:10] == bytes.fromhex('554889e54889fa488d3d') and h[14] == 0xbe, f'panic helper {helper:#x} shape changed')
    msg = rel32(helper + 14, h[10:14])
    enc = struct.unpack('<I', img.read(helper + 15, 4))[0]
    text = PANIC_TEXT[kind]
    require(enc == (len(text) << 1) | 1 and img.read(msg, len(text)) == text,
            f'panic helper {helper:#x} message is not {text!r}')
    return {'stub': hex(va), 'byte_flag_store_before': m.group(1).hex() or None, 'location': hex(loc), 'line': line, 'col': col, 'slot': hex(slot),
            'helper': hex(helper), 'message': text.decode()}


def find_tables(img):
    pat = struct.pack('<6H', *PORTS)
    out = []
    for s in img.secs:
        if s['type'] == 8 or not s['address']:
            continue
        blob = img.data[s['offset']:s['offset'] + s['size']]
        out += [s['address'] + m.start() for m in re.finditer(re.escape(pat), blob)]
    return sorted(out)


def table_refs(img, tables):
    base, text = img.text_bytes()
    refs = {}
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        o = m.start()
        if o + 7 <= len(text):
            tgt = base + o + 7 + struct.unpack_from('<i', text, o + 3)[0]
            if tgt in tables:
                refs.setdefault(tgt, []).append(base + o)
    return refs


def jump_table(img, fde, join, mul_va):
    """`lea rsi,[JT]; movsxd rcx,[rsi+rcx*4]; add rcx,rsi; jmp rcx` whose six arms load `mov si,port` and reach `join`."""
    blob = img.read(fde[0], fde[1] - fde[0])
    found = []
    for m in DISPATCH.finditer(blob):
        va = fde[0] + m.start()
        jt = rel32(va + 7, m.group(1))
        arms = [jt + struct.unpack('<i', img.read(jt + 4 * i, 4))[0] for i in range(len(PORTS))]
        if all(fde[0] <= a < fde[1] and img.read(a, 2) == b'\x66\xbe' for a in arms):
            found.append((va, jt, arms))
    require(len(found) == 1, f'site {mul_va:#x}: {len(found)} six-arm port dispatches in FDE {fde[0]:#x}')
    va, jt, arms = found[0]
    ports = []
    for a in arms:
        ports.append(struct.unpack('<H', img.read(a + 2, 2))[0])
        nxt = img.read(a + 4, 5)
        if a + 4 == join:
            continue
        if nxt[0] == 0xe9:
            require(rel32(a + 9, nxt[1:5]) == join, f'arm {a:#x} does not reach join {join:#x}')
        else:
            require(nxt[0] == 0xeb and a + 6 + struct.unpack('<b', nxt[1:2])[0] == join, f'arm {a:#x} does not reach join')
    require(tuple(ports) == PORTS, f'jump-table ports {ports} at {jt:#x}')
    require(img.section_of(jt) == '.rodata', f'jump table {jt:#x} not in .rodata')
    return {'shape': 'jump_table', 'base_port': None, 'dispatch': hex(va), 'jump_table': hex(jt),
            'arms': [hex(a) for a in arms], 'port_by_discriminant': ports, 'join': hex(join),
            'fallthrough_arm': hex(join - 4)}


def check_site(img, mul_va, tables):
    fde = img.fde_of(mul_va)
    lo = max(fde[0], mul_va - 0x40)
    win = img.read(lo, min(fde[1], mul_va + 0x60) - lo)
    at = mul_va - lo
    m = MUL.match(win, at)
    require(m is not None and m.group(1)[0] - 0xb8 == m.group(2)[0] - 0xe0, f'mul at {mul_va:#x} is not mov r16,1000; mul r16')
    after = at + m.end() - m.start()
    movzx = win[at - 3:at] in (b'\x0f\xb6\xc0', b'\x0f\xb6\xc1')
    rec = {'fde': hex(fde[0]), 'mul': hex(mul_va), 'index_movzx_byte': hex(mul_va - 3) if movzx else None,
           'mul_overflow': panic_stub(img, rel32(lo + after, m.group(3)), 'mul')}
    tail = win[after:]
    cmp_ = CONST_CMP.match(tail)
    if cmp_:
        bound, base = (struct.unpack('<I', cmp_.group(i))[0] for i in (1, 3))
        require(bound == 0xffff - base, f'site {mul_va:#x}: bound {bound:#x} is not 0xffff - {base}')
        ja_end = lo + after + 3 + 6 + 6
        rec.update(shape='const_cmp', base_port=base, add_check=f'product > {bound:#x}',
                   add_overflow=panic_stub(img, rel32(ja_end, cmp_.group(2)), 'add'), local_ip='127.0.0.1')
        return rec
    ips = list(SPLIT_IP.finditer(tail, 0, 0x14))
    adds = list(ADD16.finditer(tail, 0, 0x50))
    require(len(ips) == 1 and len(adds) == 1, f'site {mul_va:#x}: no unique local-IP build and checked u16 add')
    add = adds[0]
    add_overflow = panic_stub(img, rel32(lo + after + add.end(), add.group(2)), 'add')
    head = win[:at]
    t = list(TABLE.finditer(head))
    if t:
        tm = t[-1]
        tbl = rel32(lo + tm.start() + 7, tm.group(2))
        require(tbl in tables, f'site {mul_va:#x}: table LEA {tbl:#x} is not a port table')
        rec.update(shape='table', table=hex(tbl), table_lea=hex(lo + tm.start()), base_port=None)
    else:
        b = list(ARM_BASE.finditer(head))
        require(len(b) == 1, f'site {mul_va:#x}: no unique mov si,port arm')
        rec.update(jump_table(img, fde, lo + b[0].start() + 4, mul_va))
    rec.update(add_check='u16 add carry (jb)', add=hex(lo + after + add.start()), add_overflow=add_overflow,
               local_ip='127.0.0.1')
    return rec


def analyse(data):
    img = Image(data)
    base, text = img.text_bytes()
    muls = [base + m.start() for m in MUL.finditer(text)]
    tables = find_tables(img)
    require(len(tables) == 3 and all(img.section_of(t) == '.rodata' for t in tables),
            f'port table census {[hex(t) for t in tables]}')
    refs = table_refs(img, set(tables))
    require(sorted(refs) == tables and all(len(v) == 1 for v in refs.values()), 'port table reference census changed')
    sites = [check_site(img, va, set(tables)) for va in muls]
    got = {int(s['fde'], 16): (s['shape'], s['base_port']) for s in sites}
    require(len(sites) == len(got) == len(EXPECTED_SITES) and got == EXPECTED_SITES,
            f'site census changed: {sorted((hex(k), v) for k, v in got.items())}')
    table_owner = sorted(img.fde_of(v[0])[0] for v in refs.values())
    require(table_owner == sorted(k for k, v in EXPECTED_SITES.items() if v[0] == 'table'), 'table owners changed')
    for s in sites:
        if s['shape'] == 'table':
            require(refs[int(s['table'], 16)] == [int(s['table_lea'], 16)], f'table LEA mismatch at {s["mul"]}')
    return {'tables': [{'va': hex(t), 'ports': list(PORTS), 'lea': hex(refs[t][0])} for t in tables],
            'sites': sites, 'model': model_summary()}


def local_port(base, index):
    """Observed: u16 product with overflow panic, then u16 add with overflow panic."""
    product = index * STRIDE
    if product > 0xffff:
        return 'panic: attempt to multiply with overflow'
    if base + product > 0xffff:
        return 'panic: attempt to add with overflow'
    return base + product


def reference_port(base, index):
    """can1357 node_port.rs `validator_port`: checked_mul/checked_add returning Err(PortOverflow)."""
    product = STRIDE * index
    if product > 0xffff or base + product > 0xffff:
        return 'Err(PortOverflow)'
    return base + product


def model_summary():
    rows = []
    for p in PORTS:
        ok = [i for i in range(256) if isinstance(local_port(p, i), int)]
        mul_panics = [i for i in range(256) if local_port(p, i) == 'panic: attempt to multiply with overflow']
        rows.append({'base': p, 'max_index_ok': max(ok), 'first_add_panic': min(set(range(256)) - set(ok) - set(mul_panics)),
                     'first_mul_panic': min(mul_panics), 'max_port': local_port(p, max(ok)),
                     'reference_agrees_on_success': all(local_port(p, i) == reference_port(p, i) for i in ok),
                     'reference_errors_where_binary_panics': all(reference_port(p, i) == 'Err(PortOverflow)'
                                                                 for i in range(256) if i not in ok)})
    return {'indices': '0..=255', 'rows': rows}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--binary', type=Path, default=ROOT / TARGET)
    ap.add_argument('--out', type=Path)
    args = ap.parse_args(argv)
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == TARGET)
    try:
        check(args.binary, identity)
        result = analyse(args.binary.read_bytes())
    except (EvidenceError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    result['target_sha256'] = identity['sha256']
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'records.json').write_text(text)
    print(json.dumps({'sites': len(result['sites']), 'tables': len(result['tables']),
                      'shapes': sorted({s['shape'] for s in result['sites']})}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())

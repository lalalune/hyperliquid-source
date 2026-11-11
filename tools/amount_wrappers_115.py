#!/usr/bin/env python3
"""Reconstruct the node #115 price/size amount wrappers around the decimal scaler slot.

Seven function bodies call the decimal->u64 scaler (GOT slot 0x64e6468 -> 0x421e9d0)
with mode 2 (half-even) and a digit count taken from a constant, an argument, a pair
table or an asset-id table.  Each body is executed for real on the captured bytes
(scaler and its helpers included) and compared with the Python models below.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import decimal_scaled_u64 as cpu  # noqa: E402

TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SLOT = 0x64e6468
PANIC_SLOTS = (0x64df830, 0x64df848, 0x64df620)
OK, SCALE_ERR, WRAP_ERR = 0x1a2, 0xac, 0xad
BOUND = 0x7ffffffffffffffe
OUT = cpu.INPUT + 0x1000
DEC = cpu.INPUT + 0x2000
CTX = cpu.INPUT + 0x3000
PAIRS = cpu.INPUT + 0x4000
TABLE = cpu.INPUT + 0x8000
REC = cpu.INPUT + 0x6000
STRIDE = 0x158
# name -> (entry, class, twin of)
WRAPPERS = (
    ('w1', 0x46aa250, 'const6'),
    ('w2a', 0x274b760, 'digits'),
    ('w2b', 0x57c70c0, 'digits'),
    ('w3a', 0x2891af0, 'pair'),
    ('w3b', 0x5a00b00, 'pair'),
    ('w4a', 0x3be28a0, 'asset'),
    ('w4b', 0x5a00cc0, 'asset'),
    ('w5', 0x3c42660, 'assetrec'),
)
DEX_NUMBER = 3
ARRAY_LEN = 40
TABLE_LEN = 24


class Error(Exception):
    pass


def lcg(seed):
    state = seed & cpu.U64
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & cpu.U64
        yield state >> 17


def put(m, addr, value, size=8):
    for j, byte in enumerate(value.to_bytes(size, 'little')):
        m.mem[addr + j] = byte


def zero(m, addr, size):
    for j in range(size):
        m.mem[addr + j] = 0


# ---- models -------------------------------------------------------------------------

def scaler_model(flags, lo, mid, hi, mode, digits):
    """Decimal (flags, 96-bit mantissa) * 10**digits rounded by mode 2 -> ('ok', n) or ('err',)."""
    if flags & 0x7f00ffff or not 0 <= (flags >> 16 & 0xff) <= 28:
        raise Error('decimal outside the canonical domain')
    mant = lo | (mid << 32) | (hi << 64)
    scale = (flags >> 16) & 0xff
    if digits > 19:
        return ('err',)
    num = mant * 10 ** digits
    den = 10 ** scale
    q, r = divmod(num, den)
    if mode == 2:
        twice = 2 * r
        if twice > den or (twice == den and q & 1):
            q += 1
    elif r:
        return ('err',)
    if q > BOUND or flags >> 31 and q:
        return ('err',)
    return ('ok', q)


def wrap_model(result, collapse_zero):
    if result[0] == 'err':
        return (WRAP_ERR, None) if collapse_zero else (SCALE_ERR, None)
    if collapse_zero and result[1] == 0:
        return (WRAP_ERR, None)
    return (OK, result[1])


def model(kind, case, mut=None):
    """Expected (tag, value) or 'panic' for one case of a wrapper class."""
    flags, lo, mid, hi = case['dec']
    rnd = 2
    if mut == 'mode_half_up':
        rnd = 3
    if kind == 'const6':
        digits = 6 if mut != 'digits7' else 7
    elif kind == 'digits':
        digits = case['digits'] & 0xff
    elif kind == 'pair':
        idx = case['index']
        if idx >= ARRAY_LEN:
            return 'panic'
        a, b = case['pairs'][idx]
        if a >= TABLE_LEN or b >= TABLE_LEN:
            return 'panic'
        base = case['table'][b][1]
        quote = case['table'][a][0]
        if base < quote:
            return 'panic'
        digits = base - quote
        if mut == 'swap_pair':
            digits = case['table'][a][1] - case['table'][b][0] & 0xff
    else:
        ident = case['asset']
        hi_part, lo_part = divmod(ident, 10000)
        if mut == 'div_1000':
            hi_part, lo_part = divmod(ident, 1000)
        if hi_part != DEX_NUMBER or lo_part >= ARRAY_LEN:
            return 'panic'
        sz = case['sizes'][lo_part]
        if sz >= 7:
            return 'panic'
        digits = 6 - sz
        if mut == 'digits_plus1':
            digits += 1
    if rnd == 3:
        res = half_up(flags, lo, mid, hi, digits)
    else:
        res = scaler_model(flags, lo, mid, hi, 2, digits)
    if kind == 'const6':
        if mut == 'zero_pass':
            return wrap_model(res, False)
        return (res[0] == 'err' and (SCALE_ERR, None)) or (OK, res[1])
    collapse = mut != 'zero_pass'
    out = wrap_model(res, collapse)
    if mut == 'err_tag_keep' and res[0] == 'err':
        return (SCALE_ERR, None)
    return out


def half_up(flags, lo, mid, hi, digits):
    mant = lo | (mid << 32) | (hi << 64)
    if digits > 19:
        return ('err',)
    num = mant * 10 ** digits
    den = 10 ** ((flags >> 16) & 0xff)
    q, r = divmod(num, den)
    if 2 * r >= den:
        q += 1
    return ('err',) if q > BOUND or flags >> 31 and q else ('ok', q)


# ---- execution ----------------------------------------------------------------------

def make_machine(image, kind, case):
    m = cpu.Machine(image)
    image.panic_targets = {image.slots[s] for s in PANIC_SLOTS}
    sp = cpu.STACK + 0x800
    zero(m, cpu.STACK, 0x1000)
    zero(m, OUT, 0x100)
    put(m, sp, cpu.RETURN_MARK)
    m.set_reg(cpu.RSP, sp)
    m.set_reg(cpu.RDI, OUT)
    flags, lo, mid, hi = case['dec']
    put(m, DEC, flags, 4)
    put(m, DEC + 4, hi, 4)
    put(m, DEC + 8, lo, 4)
    put(m, DEC + 12, mid, 4)
    if kind == 'const6':
        m.set_reg(cpu.RSI, DEC)
    elif kind == 'digits':
        m.set_reg(cpu.RSI, DEC)
        m.set_reg(cpu.RDX, case['digits'])
    elif kind == 'pair':
        zero(m, CTX, 0x40)
        zero(m, PAIRS, ARRAY_LEN * 32)
        zero(m, TABLE, TABLE_LEN * STRIDE)
        put(m, CTX + 8, PAIRS)
        put(m, CTX + 0x10, ARRAY_LEN)
        put(m, CTX + 0x20, TABLE)
        put(m, CTX + 0x28, TABLE_LEN)
        for i, (a, b) in enumerate(case['pairs']):
            put(m, PAIRS + 32 * i, a)
            put(m, PAIRS + 32 * i + 8, b)
        for i, (quote, base) in enumerate(case['table']):
            m.mem[TABLE + STRIDE * i + 0x48] = quote
            m.mem[TABLE + STRIDE * i + 0x49] = base
        m.set_reg(cpu.RSI, CTX)
        m.set_reg(cpu.RDX, case['index'])
        m.set_reg(cpu.RCX, DEC)
    else:
        zero(m, CTX, 0x60)
        zero(m, REC, 0x20)
        zero(m, PAIRS, ARRAY_LEN * 32)
        put(m, CTX + 8, PAIRS)
        put(m, CTX + 0x10, ARRAY_LEN)
        put(m, CTX + 0x50, DEX_NUMBER)
        for i, sz in enumerate(case['sizes']):
            m.mem[PAIRS + 32 * i + 0x1d] = sz
        if kind == 'assetrec':
            # record: context pointer at +0, the 16-byte decimal copied at +8
            put(m, REC, CTX)
            for j in range(16):
                m.mem[REC + 8 + j] = m.mem[DEC + j]
            m.set_reg(cpu.RSI, REC)
        else:
            m.set_reg(cpu.RSI, CTX)
            m.set_reg(cpu.RCX, DEC)
        m.set_reg(cpu.RDX, case['asset'])
    return m


def execute(image, entry, kind, case):
    m = make_machine(image, kind, case)
    try:
        m.run(entry)
    except cpu.Done as done:
        if done.args[0] == 'panic':
            return 'panic'
        return read_result(m, kind, case)
    raise Error('run ended without a stop')


# ---- case generation ----------------------------------------------------------------

def make_decimal(rng, digits):
    pick = next(rng) % 12
    scale = next(rng) % 10 if pick < 9 else next(rng) % 29
    if pick == 0:
        mant = 0
    elif pick == 1:
        mant = next(rng) % 1000
    elif pick == 2:  # tie at the output digit
        extra = 1 + next(rng) % 4
        scale = min(28, digits + extra)
        k = scale - digits
        mant = (next(rng) % 100000) * 10 ** k + 5 * 10 ** (k - 1) if k >= 1 else 5
    elif pick == 3:  # near the u64 bound
        mant = (BOUND + next(rng) % 5 - 2) * 10 ** (scale % 4) // 10 ** (digits % 7)
        scale = scale % 4 if digits < 7 else scale
    elif pick == 4:
        mant = next(rng) | (next(rng) << 32) | (next(rng) << 64)
        mant &= (1 << 96) - 1
    else:
        mant = next(rng) % 10 ** (3 + next(rng) % 14)
    sign = 0x80000000 if next(rng) % 11 == 0 else 0
    return (sign | scale << 16, mant & 0xffffffff, mant >> 32 & 0xffffffff, mant >> 64 & 0xffffffff)


def make_case(kind, seed):
    rng = lcg(seed)
    case = {}
    sizes = [next(rng) % 9 for _ in range(ARRAY_LEN)]
    table = [(next(rng) % 4, next(rng) % 9) for _ in range(TABLE_LEN)]
    pairs = [(next(rng) % (TABLE_LEN + 2), next(rng) % (TABLE_LEN + 2)) for _ in range(ARRAY_LEN)]
    if kind == 'const6':
        digits = 6
    elif kind == 'digits':
        digits = next(rng) % 24
        case['digits'] = digits
    elif kind == 'pair':
        index = next(rng) % (ARRAY_LEN + 2)
        if index < ARRAY_LEN and next(rng) % 6:
            a, b = pairs[index]
            pairs[index] = (a % TABLE_LEN, b % TABLE_LEN)
        case.update(index=index, pairs=pairs, table=table)
        digits = 4
    else:
        lo_part = next(rng) % (ARRAY_LEN + 2)
        hi_part = DEX_NUMBER if next(rng) % 7 else next(rng) % 6
        case.update(asset=hi_part * 10000 + lo_part, sizes=sizes)
        digits = 6 - sizes[lo_part % ARRAY_LEN]
    case['dec'] = make_decimal(rng, max(0, min(digits, 19)))
    return case


def cases(kind, count, base):
    for i in range(count):
        yield make_case(kind, base + i * 7919)


def battery(kind, count=24):
    return [make_case(kind, 424242 + 31 * i) for i in range(count)]


# ---- controls -----------------------------------------------------------------------

MODEL_MUTANTS = ('mode_half_up', 'digits7', 'swap_pair', 'div_1000', 'digits_plus1', 'zero_pass',
                 'err_tag_keep')


def text_offset(image, va):
    return va - image.text_va + image.text_off


def byte_mutants(image):
    """(label, entry, kind, [(va, old, new)]) patch lists drawn from fixed byte patterns."""
    rows = []
    d = image.data

    def find(entry, pattern, nth=0, span=0x240):
        off = text_offset(image, entry)
        at = -1
        for _ in range(nth + 1):
            at = d.find(pattern, off if at < 0 else at + 1, off + span)
        if at < 0:
            raise Error('pattern missing at %#x' % entry)
        return at - off + entry

    for name, entry, kind in WRAPPERS:
        if kind == 'const6':
            rows.append((name + ':mode1', entry, kind, [(find(entry, b'\xba\x02\x00\x00\x00') + 1, 2, 1)]))
            rows.append((name + ':mode0', entry, kind, [(find(entry, b'\xba\x02\x00\x00\x00') + 1, 2, 0)]))
            rows.append((name + ':digits', entry, kind, [(find(entry, b'\xb9\x06\x00\x00\x00') + 1, 6, 5)]))
            continue
        rows.append((name + ':mode', entry, kind, [(find(entry, b'\xba\x02\x00\x00\x00') + 1, 2, 0)]))
        rec = kind == 'assetrec'
        zero_test = b'\x4d\x85\xff\x0f\x84' if rec else b'\x48\x85\xc0\x0f\x84'
        ok_test = b'\x66\x81\x7c\x24\x10\xa2\x01' if rec else b'\x66\x81\x3c\x24\xa2\x01'
        wrap = b'\x66\xb8\xad\x00' if rec else b'\x66\xc7\x03\xad\x00'
        rows.append((name + ':zero_je', entry, kind, [(find(entry, zero_test) + 4, 0x84, 0x85)]))
        rows.append((name + ':ok_tag', entry, kind, [(find(entry, ok_test) + (5 if rec else 4), 0xa2, 0xa3)]))
        rows.append((name + ':wrap_tag', entry, kind, [(find(entry, wrap) + (2 if rec else 3), 0xad, 0xae)]))
        if kind == 'pair':
            rows.append((name + ':borrow', entry, kind, [(find(entry, b'\x0f\x82') + 1, 0x82, 0x83)]))
            rows.append((name + ':offset', entry, kind, [(find(entry, b'\x0f\xb6\x44\x06\x49') + 4, 0x49, 0x48)]))
        if kind == 'assetrec':
            rows.append((name + ':id_slot', entry, kind, [(find(entry, b'\x4c\x89\x73\x08') + 3, 8, 0x20)]))
            rows.append((name + ':value_slot', entry, kind, [(find(entry, b'\x4c\x89\x7b\x10') + 3, 0x10, 0x20)]))
            rows.append((name + ':rec_decimal', entry, kind, [(find(entry, b'\x48\x8d\xb4\x24\xe0') + 4, 0xe0, 0xd0)]))
        if kind in ('asset', 'assetrec'):
            rows.append((name + ':sz7', entry, kind, [(find(entry, b'\x3c\x07') + 1, 7, 8)]))
            rows.append((name + ':dex', entry, kind, [(find(entry, b'\x48\x3b\x51\x50' if kind == 'assetrec' else b'\x48\x3b\x56\x50') + 3, 0x50, 0x48)]))
    return rows


# ---- driver -------------------------------------------------------------------------

def run(out_dir):
    data = TARGET.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise Error('target digest differs')
    image = cpu.Image(data)
    if image.slots.get(SLOT) != 0x421e9d0:
        raise Error('scaler slot does not name 0x421e9d0')
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    per_class = {}
    total = 0
    steps = 0
    sample = open(out / 'wrapper-samples.tsv', 'w')
    sample.write('wrapper\tcase\tdecimal\tinputs\ttag\tvalue\tsteps\n')
    lines = ['wrapper\tentry\tkind\tcases\tok\tpanic\terr\tzero_value\tmax_steps']
    classes = {}
    for name, entry, kind in WRAPPERS:
        base = {'w1': 1000, 'w2a': 2000, 'w2b': 2000, 'w3a': 3000, 'w3b': 3000, 'w4a': 4000, 'w4b': 4000, 'w5': 5000}[name]
        stats = dict(ok=0, panic=0, err=0, zero=0, max=0)
        n = 0
        for case in cases(kind, 3000, base):
            want = model(kind, case)
            m_steps = [0]
            got = execute_counted(image, entry, kind, case, m_steps)
            if got != want:
                raise Error('%s mismatch %r %r %r' % (name, case['dec'], got, want))
            n += 1
            if n % 20 == 1:
                sample.write(sample_row(name, n, kind, case, got, m_steps[0]))
            stats['max'] = max(stats['max'], m_steps[0])
            steps += m_steps[0]
            if got == 'panic':
                stats['panic'] += 1
            elif got[0] == OK:
                stats['ok'] += 1
            else:
                stats['err'] += 1
            if got != 'panic' and got[1] == 0:
                stats['zero'] += 1
        total += n
        classes[name] = n
        lines.append('\t'.join(map(str, (name, hex(entry), kind, n, stats['ok'], stats['panic'], stats['err'], stats['zero'], stats['max']))))
    # twin bodies must agree with each other case by case
    detected = 0
    controls = 0
    ctl_lines = ['control\tclass\tdetected']
    for mut in MODEL_MUTANTS:
        for name, entry, kind in WRAPPERS:
            if name not in ('w1', 'w2a', 'w3a', 'w4a', 'w5'):
                continue
            if mut in ('swap_pair',) and kind != 'pair' or mut in ('div_1000', 'digits_plus1') and kind not in ('asset', 'assetrec'):
                continue
            if mut == 'digits7' and kind != 'const6':
                continue
            if mut in ('zero_pass', 'err_tag_keep') and kind == 'const6':
                continue
            hit = False
            for case in battery(kind, 400):
                if model(kind, case, mut) != execute(image, entry, kind, case):
                    hit = True
                    break
            controls += 1
            detected += hit
            ctl_lines.append('model:%s\t%s\t%d' % (mut, name, hit))
    for label, entry, kind, edits in byte_mutants(image):
        bad = cpu.Image(patch_bytes(data, image, edits))
        hit = False
        for case in battery(kind, 400):
            try:
                got = execute(bad, entry, kind, case)
            except (cpu.ToolError, Error, ValueError, KeyError, IndexError):
                hit = True
                break
            if got != model(kind, case):
                hit = True
                break
        controls += 1
        detected += hit
        ctl_lines.append('bytes:%s\t%s\t%d' % (label, kind, hit))
    for label, bad in range_controls():
        controls += 1
        detected += bad
        ctl_lines.append('range:%s\t-\t%d' % (label, bad))
    sample.close()
    (out / 'wrapper-cases.tsv').write_text('\n'.join(lines) + '\n')
    (out / 'controls.tsv').write_text('\n'.join(ctl_lines) + '\n')
    (out / 'measure.json').write_text(json.dumps(
        {'cases': total, 'negative_controls': controls, 'negative_detected': detected,
         'machine_steps': steps}, indent=1, sort_keys=True) + '\n')
    return total, controls, detected


def sample_row(name, n, kind, case, got, steps):
    flags, lo, mid, hi = case['dec']
    if kind == 'const6':
        inputs = '-'
    elif kind == 'digits':
        inputs = 'digits=%d' % case['digits']
    elif kind == 'pair':
        inputs = 'index=%d' % case['index']
        if case['index'] < ARRAY_LEN:
            a, b = case['pairs'][case['index']]
            inputs += ' pair=%d,%d' % (a, b)
            if a < TABLE_LEN and b < TABLE_LEN:
                inputs += ' quote48=%d base49=%d' % (case['table'][a][0], case['table'][b][1])
    else:
        inputs = 'asset=%d' % case['asset']
    tag, value = (None, None) if got == 'panic' else got
    return '%s\t%d\t%08x:%08x:%08x:%08x\t%s\t%s\t%s\t%d\n' % (
        name, n, flags, hi, mid, lo, inputs, 'panic' if got == 'panic' else hex(tag),
        '-' if value is None else value, steps)


def read_result(m, kind, case):
    tag = m.load(OUT, 2)
    if kind == 'assetrec':
        # ok keeps the asset id at +8 and the value at +16; on tag 0xad the +8 word is the
        # scaler's error payload or the id (not modelled, so only the tag is compared)
        if tag == OK and m.load(OUT + 8, 8) != case['asset']:
            raise Error('asset id not echoed at +8')
        return (tag, m.load(OUT + 16, 8) if tag == OK else None)
    return (tag, m.load(OUT + 8, 8) if tag == OK else None)


def execute_counted(image, entry, kind, case, box):
    m = make_machine(image, kind, case)
    try:
        m.run(entry)
    except cpu.Done as done:
        box[0] = m.steps
        if done.args[0] == 'panic':
            return 'panic'
        return read_result(m, kind, case)
    raise Error('run ended without a stop')


def patch_bytes(data, image, edits):
    buf = bytearray(data)
    for va, old, new in edits:
        off = text_offset(image, va)
        if buf[off] != old:
            raise Error('patch precondition failed at %#x' % va)
        buf[off] = new
    return bytes(buf)


def range_controls():
    rows = []
    for label, args in (('scale29', (29 << 16, 1, 0, 0)), ('reserved_bits', (0x00000001, 1, 0, 0)),
                        ('scale_neg', (0xff << 16, 1, 0, 0))):
        try:
            scaler_model(*args, 2, 6)
            rows.append((label, False))
        except Error:
            rows.append((label, True))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    print(run(args.out))


if __name__ == '__main__':
    main()

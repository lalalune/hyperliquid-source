#!/usr/bin/env python3
"""Static node #94 isolated-margin ntli carrier study. Does not run the target."""
import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK = (1 << 64) - 1
SIGN = 1 << 63
FUNCS = {
    'variant_dispatch': (0x3358d10, 0x335ad16, 'dbf919eede702a1373d91bd12a14cb43facc17a7bc44f5f20e0c561a5292b9b8'),
    'action_reader': (0x3a75470, 0x3a75fb0, '05d996bc228efee458120dd861abad4c1ac99fefee7e09a4a58df2f217b8a8ca'),
    'signed_value_reader': (0x3b3fa20, 0x3b3fb75, '5a177a5caf3392f021b455e3f81605a3da57ece09c21cfb32893061455b3cefa'),
    'action_writer': (0x374b200, 0x374b446, '7f6c70c0cd2602915198b7b01485ccd070411bea8fdb543020d23fbcd4817f7c'),
    'signed_digits': (0x3bec4a0, 0x3bec674, 'a88465f9def49f1b8d064797cc033842000c571fd7154a458174c32cc8f97a99'),
}
# Reviewed, fixed byte windows; complete FDE hashes guard omitted bytes too.
WINDOWS = {
 0x335938f: ('dispatch_success_and_variant', '807c2420090f85eb1600000f104424280f114308b898000000e926180000'),
 0x3359369: ('dispatch_type_and_reader', '488d15f60124fd4c8d0591883902488d7c24204889e6b91a00000041b903000000e8e1c07100'),
 0x3a75489: ('reader_container_tags', '0fb60683f8144889742418898424040100000f84c003000083f8150f85ba090000'),
 0x3a75520: ('reader_key_dispatch', '4889ef488db42490000000e8c019a7ff0fb64c24400fb644244180f9090f85d90400000fb6c089c0488d0d414db3fc486304814801c8ffe0'),
 0x3a75558: ('asset_duplicate_guard', '41bf050000004585ed0f85cc050000'),
 0x3a756d6: ('bool_field_guard', '440fb6e84183fd01755880fb020f85'),
 0x3a75738: ('ntli_field_guard', '4585ed8b4424140f84ee0300004183fd020f853404000041bd01000000f68424dc0000'),
 0x3a757bf: ('ntli_reader_call', '4889eee859a20c00be200000004c89ff31d2ff153988cf01eb12488dbc24e0000000488d742420e8'),
 0x3a757fb: ('ntli_value_and_presence', '488b8424e80000004889842408010000b001898424d8000000c78424dc00000000000000e9'),
 0x3a75a7c: ('missing_bool_name', '89c5488d05e602b4fc48898424e000000048c78424e800000005000000488d84'),
 0x3a75b90: ('missing_asset_name', '488d05a9f4b3fc48898424e000000048c78424e800000005000000488d8424e000'),
 0x3a75cd5: ('reader_success_tag', '488b442408c60009e910010000'),
 0x3a75a65: ('missing_field_order', '8b44241441f6c5010f841d01000080fb020f8578010000'),
 0x3a75b33: ('duplicate_field_name', '488d0506f5b3fc48894424204c897c2428488d442420'),
 0x3a75c00: ('missing_ntli_name', '488d05754379fc48898424e000000048c78424e800000004'),
 0x3a75c64: ('reader_payload_layout', '488b442408488b8c240801000048894808896810885814'),
 0x3a75e52: ('duplicate_bool_name', '41bf05000000488d050cffb3fce9d6fcffff488d'),
 0x3a75e89: ('duplicate_ntli_name', '41bf04000000488d05e64079fce99ffcffff'),
 0x3b3fa2a: ('signed_reader_jump', '0fb606ffc883f8070f87db000000488d0dcd23a7fc486304814801c8ff'),
 0x3b3fa48: ('u8_i8_loads', '0fb64601e9a0000000480fbe4601e9'),
 0x3b3fa5b: ('u32_u64_guard', '8b4604e98e000000488b46084885c00f89810000004989f64889'),
 0x3b3fada: ('i64_u16_i16_i32_loads', '488b4608eb110fb74602eb0b480fbf4602eb0448634604'),
 0x3b3faf1: ('signed_reader_success_and_cleanup', '4889442418c6442410094889f7e85dde03000fb64424103c097526'),
 0x374b211: ('writer_type', '488d154ee3e4fc488d7c2410b91a00000041b803000000e8535655000f'),
 0x374b265: ('writer_asset', '488d4b08488d3508cae4fc4889e7ba05000000e8239253004885c00f856101000080'),
 0x374b290: ('writer_bool', '488d4b0c488d35b1dbe4fc4889e7ba05000000e8489f54004885c00f8536010000'),
 0x374b2bb: ('writer_ntli', '488d35baecabfc4889e7ba04000000e8f1365500803c24010f841d010000488b33'),
 0x374b2d9: ('writer_raw_word', '488b334c8b7c24'),
 0x374b30a: ('writer_digit_call', '498b3fe88e114a0041c6472001'),
 0x3bec4ae: ('signed_magnitude_and_threshold', '4889f148f7d9480f48ce41bc140000004881f9102700000f82bd000000bf14000000'),
 0x3bec4cb: ('reciprocal_and_table', 'bf1400000049b84b598638d6c56d344c8d0dacd39cfc6666666666662e0f1f'),
 0x3bec4f0: ('division_and_remainder', '4889c849f7e04989fc4983c4fc0f805701000048c1ea0b4c69d2102700004889c84c29d04189c241c1ea'),
 0x3bec514: ('two_digit_quotient', '4189c241c1ea02450fb7d24569da7b14000041c1eb11470fb7145966468914244d89e24983c2020f80'),
 0x3bec555: ('four_digit_loop_limit', '4883c7fc4881f9ffe0f5054889d1778b4883fa637726'),
 0x3bec565: ('leading_digits', '4883fa6377264883fa0a735c49ffcc0f80e000000080ca3042881424'),
 0x3bec5d7: ('final_pair_and_sign', '488d05afd29cfc0fb7045066428904244885f6790a49ffcc706942c604242d'),
 0x3bec5ec: ('sign_and_capacity', '49ffcc706942c604242d4983fc14775e41be140000004d29e6488b034c8b7b104c29f84939c677274a8d3424488b7b'),
 0x3bec614: ('copy_digits', '4a8d3424488b7b084c01ff4c89f2ff15b819b8014d01f74c897b104883c4285b415c415e415fc3b9010000'),
 0x3bec63b: ('growth_and_retry', 'b90100000041b8010000004889df4c89fe4c89f2e8aca36eff4c8b7b10ebba'),
}
TAG_TARGETS = [0x3b3fa48, 0x3b3fae0, 0x3b3fa5b, 0x3b3fa63,
               0x3b3fa51, 0x3b3fae6, 0x3b3faed, 0x3b3fada]
TAG_SHAPES = [('u8',1,False), ('u16',2,False), ('u32',4,False), ('u64_checked',8,False),
              ('i8',1,True), ('i16',2,True), ('i32',4,True), ('i64',8,True)]
# Only the selected direct edges are decoded; this is not an exhaustive CFG.
BRANCHES = [0x3a7549b, 0x3a754a4, 0x3a7553d, 0x3a75561, 0x3a756de, 0x3a756e3,
            0x3a7573f, 0x3a75749, 0x3a7575d, 0x3a757f5, 0x3a75a6d, 0x3a75a76,
            0x3a75bee, 0x3a75bfe, 0x3a75c51, 0x3b3fa32, 0x3b3fa6a,
            0x374b234, 0x374b280, 0x374b2ab, 0x374b2d3, 0x374b2f2,
            0x3bec4c5, 0x3bec4fd, 0x3bec53b, 0x3bec563, 0x3bec569,
            0x3bec56f, 0x3bec5d1, 0x3bec5ea, 0x3bec5ef, 0x3bec5fa, 0x3bec612]


def checked_target(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node #94 digest mismatch')
    return data


class Image:
    def __init__(self, data):
        self.data = checked_target(data)
        self.sections = sections(data)
        _, self.index = unwind_index(data)
        _, self.fdes = eh_frame_records(data, self.sections)
        self.by_start = {}
        for f in self.fdes:
            if f['start'] in self.by_start:
                raise ValueError('duplicate FDE start')
            self.by_start[f['start']] = f
        self.index_by_start = {f['start']: f for f in self.index}
        if len(self.index_by_start) != len(self.index):
            raise ValueError('duplicate unwind start')
        self.relative = self.relocations()

    def offset(self, va, size):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size < 0:
            raise ValueError('invalid address or length')
        hits = [s for s in self.sections if s['type'] != 8 and s['size'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(hits) != 1:
            raise ValueError('address is not unambiguously file-backed')
        s = hits[0]
        return s['offset'] + va - s['address']

    def read(self, va, size):
        p = self.offset(va, size)
        return self.data[p:p + size]

    def relocations(self):
        sec = next(s for s in self.sections if s['name'] == '.rela.dyn')
        if sec['type'] == 8 or sec['size'] % 24:
            raise ValueError('invalid relocation section')
        result = {}
        for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', self.data, p)
            if info & 0xffffffff == 8:
                if where in result:
                    raise ValueError('duplicate relative relocation')
                result[where] = addend
        return result

    def fde(self, name):
        start, end, digest = FUNCS[name]
        f = self.by_start.get(start)
        idx = self.index_by_start.get(start)
        if f is None or f['end'] != end or idx is None or idx['fde'] != f['fde']:
            raise ValueError('FDE extent or index mismatch')
        raw = self.read(start, end - start)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('function body digest mismatch')
        return dict(start=hex(start), end=hex(end), fde=hex(f['fde']),
                    file_offset=hex(self.offset(start, len(raw))), size=len(raw),
                    sha256=digest, bytes_hex=raw.hex())

    def branch(self, va):
        raw = self.read(va, 6)
        if 0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb:
            size = 2
            displacement = struct.unpack_from('<b', raw, 1)[0]
        elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
            size = 6
            displacement = struct.unpack_from('<i', raw, 2)[0]
        elif raw[0] == 0xe9:
            size = 5
            displacement = struct.unpack_from('<i', raw, 1)[0]
        else:
            raise ValueError('not a selected direct branch')
        return {'va': hex(va), 'bytes': raw[:size].hex(), 'fallthrough': hex(va + size),
                'target': hex(va + size + displacement)}

    def rip_lea(self, va):
        raw = self.read(va, 7)
        if raw[0] not in (0x48, 0x4c) or raw[1] != 0x8d or (raw[2] & 0xc7) != 0x05:
            raise ValueError('not a 64-bit RIP-relative lea')
        return va + 7 + struct.unpack_from('<i', raw, 3)[0]

    def direct_call(self, va):
        raw = self.read(va, 5)
        if raw[0] != 0xe8:
            raise ValueError('not a direct call')
        return va + 5 + struct.unpack_from('<i', raw, 1)[0]

    def table_targets(self, va, n):
        return [va + struct.unpack_from('<i', self.read(va + 4 * i, 4))[0] for i in range(n)]


def check_window(raw, expected):
    if raw != bytes.fromhex(expected):
        raise ValueError('instruction window mismatch')


def presence_walk(image, asset, side, ntli):
    """Walk only the three final field-presence predicates from target bytes."""
    for value in (asset, side, ntli):
        if type(value) is not bool:
            raise ValueError('presence flags must be booleans')
    checks = [(0x3a75a69, '41f6c501'), (0x3a75a6d, '0f841d010000'),
              (0x3a75a73, '80fb02'), (0x3a75a76, '0f8578010000'),
              (0x3a75bf6, 'f68424d800000001'), (0x3a75bfe, '7564')]
    for va, expected in checks:
        check_window(image.read(va, len(bytes.fromhex(expected))), expected)
    if not asset:
        return image.branch(0x3a75a6d)['target']
    if not side:
        return image.branch(0x3a75a76)['fallthrough']
    if ntli:
        return image.branch(0x3a75bfe)['target']
    return image.branch(0x3a75bfe)['fallthrough']


def duplicate_walk(image, field, seen):
    """Walk a selected duplicate-field guard; input state is symbolic."""
    if type(seen) is not bool:
        raise ValueError('presence flag must be boolean')
    choices = {'asset': (0x3a7555e, '4585ed', 0x3a75561, '0f85cc050000'),
               'isBuy': (0x3a756e0, '80fb02', 0x3a756e3, '0f8569070000'),
               'ntli': (0x3a75755, 'f68424dc00000001', 0x3a7575d, '0f8426070000')}
    if field not in choices:
        raise ValueError('unknown field')
    guard, guard_bytes, branch, branch_bytes = choices[field]
    check_window(image.read(guard, len(bytes.fromhex(guard_bytes))), guard_bytes)
    check_window(image.read(branch, len(bytes.fromhex(branch_bytes))), branch_bytes)
    edge = image.branch(branch)
    return edge['target'] if seen else edge['fallthrough']


def decode_tag(tag, payload):
    if not isinstance(tag, int) or not isinstance(payload, bytes):
        raise ValueError('bad tag or payload')
    if not 1 <= tag <= 8:
        return ('fallback', None)
    _, width, signed = TAG_SHAPES[tag - 1]
    if len(payload) != width:
        raise ValueError('bad payload width')
    value = int.from_bytes(payload, 'little', signed=signed)
    if tag == 4 and value >= SIGN:
        return ('diagnostic', None)
    return ('accepted', value)


def decode_instruction_load(raw, payload):
    """Interpret the target's selected integer load opcode, not a general decoder."""
    forms = [(bytes.fromhex('0fb64601'), 1, False),
             (bytes.fromhex('0fb74602'), 2, False),
             (bytes.fromhex('8b4604'), 4, False),
             (bytes.fromhex('480fbe4601'), 1, True),
             (bytes.fromhex('480fbf4602'), 2, True),
             (bytes.fromhex('48634604'), 4, True)]
    for prefix, width, signed in forms:
        if raw.startswith(prefix):
            if len(payload) != width:
                raise ValueError('bad payload width')
            return ('accepted', int.from_bytes(payload, 'little', signed=signed))
    if raw.startswith(bytes.fromhex('488b46084885c00f8981000000')):
        if len(payload) != 8:
            raise ValueError('bad payload width')
        value = int.from_bytes(payload, 'little')
        return ('diagnostic', None) if value >= SIGN else ('accepted', value)
    if raw.startswith(bytes.fromhex('488b4608eb11')):
        if len(payload) != 8:
            raise ValueError('bad payload width')
        return ('accepted', int.from_bytes(payload, 'little', signed=True))
    raise ValueError('unknown integer load opcode')


def format_lift(bits, pairs, multiplier):
    """Lift of selected magnitude, quotient and digit-table operations; not an emulator."""
    if not isinstance(bits, int) or not 0 <= bits <= MASK or len(pairs) != 200:
        raise ValueError('invalid input or digit table')
    signed = bits if bits < SIGN else bits - (1 << 64)
    magnitude = -signed if signed < 0 else signed
    chunks = []
    x = magnitude
    while x >= 10000:
        quotient = (x * multiplier) >> 75
        rem = x - quotient * 10000
        if not 0 <= rem < 10000:
            raise ValueError('invalid reciprocal quotient')
        hi = ((rem >> 2) * 0x147b) >> 17
        if hi > 99 or rem - hi * 100 > 99:
            raise ValueError('invalid digit pair')
        chunks.append(pairs[2*hi:2*hi+2] + pairs[2*(rem-hi*100):2*(rem-hi*100)+2])
        x = quotient
    if x >= 100:
        hi = ((x >> 2) * 0x147b) >> 17
        lo = x - hi * 100
        prefix = (bytes([48 + hi]) if hi < 10 else pairs[2*hi:2*hi+2]) + pairs[2*lo:2*lo+2]
    elif x >= 10:
        prefix = pairs[2*x:2*x+2]
    else:
        prefix = bytes([48 + x])
    return (b'-' if signed < 0 else b'') + prefix + b''.join(reversed(chunks))


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(header)
        w.writerows(rows)


def read_fields(image):
    rows = []
    for i, expected in enumerate((b'asset', b'isBuy', b'ntli')):
        p = 0x56f1c08 + 16*i
        address = image.relative.get(p)
        length = struct.unpack('<Q', image.read(p + 8, 8))[0]
        if address is None or length > 64 or image.read(address, length) != expected:
            raise ValueError('field relocation or text mismatch')
        rows.append((i, hex(p), hex(address), length, expected.decode('ascii')))
    return rows


def read_pairs(image):
    pairs = image.read(0x5b988d, 200)
    if pairs != b''.join(f'{i:02}'.encode('ascii') for i in range(100)):
        raise ValueError('digit table mismatch')
    return pairs


def generate(data, out):
    image = Image(data)
    funcs = {name: image.fde(name) for name in sorted(FUNCS)}
    windows = []
    for va, (label, expected) in sorted(WINDOWS.items()):
        raw = image.read(va, len(bytes.fromhex(expected)))
        check_window(raw, expected)
        windows.append((hex(va), hex(image.offset(va, len(raw))), label, raw.hex()))
    branches = [image.branch(v) for v in BRANCHES]
    writer_specs = [(0x374b234,'initializer tag differs from 2','decode fields','return initializer result'),
                    (0x374b280,'asset writer returns nonzero','return helper result','continue to side'),
                    (0x374b2ab,'side writer returns nonzero','return helper result','continue to ntli'),
                    (0x374b2d3,'ntli key builder returns tag 1','call error helper','load ntli word'),
                    (0x374b2f2,'available output capacity is at most 1','grow and retry','append separator'),
                    (0x3bec612,'digit length exceeds available capacity','grow and retry','copy digits')]
    writer_edges = []
    for va, predicate, taken, fallthrough in writer_specs:
        edge = image.branch(va)
        writer_edges.append((hex(va), edge['bytes'], predicate, edge['target'], taken,
                             edge['fallthrough'], fallthrough))
    targets = image.table_targets(0x5b1e0c, 8)
    if targets != TAG_TARGETS or image.table_targets(0x5aa290, 3) != [0x3a75558, 0x3a756e0, 0x3a75755]:
        raise ValueError('jump table mismatch')
    call_specs = [(0x335938a, 0x3a75470, 'dispatch to action reader'),
                  (0x3a757c2, 0x3b3fa20, 'boxed value to signed reader'),
                  (0x3a757e6, 0x3b3fa20, 'inline value to signed reader'),
                  (0x374b30d, 0x3bec4a0, 'ntli word to digit writer')]
    calls = []
    for site, target, description in call_specs:
        if image.direct_call(site) != target:
            raise ValueError('direct call target mismatch')
        calls.append((hex(site), hex(target), image.read(site, 5).hex(), description))
    rip_specs = [(0x3359369,0x599566,'dispatch action name'),
                 (0x374b211,0x599566,'writer action name'),
                 (0x374b269,0x597c78,'writer asset key'),
                 (0x374b294,0x598e4c,'writer side key'),
                 (0x374b2bb,0x209f7c,'writer notional key'),
                 (0x3a75b90,0x5b5040,'missing asset'),
                 (0x3a75a7e,0x5b5d6b,'missing side'),
                 (0x3a75c00,0x209f7c,'missing notional'),
                 (0x3a75e58,0x5b5d6b,'duplicate side'),
                 (0x3a75e8f,0x209f7c,'duplicate notional'),
                 (0x3a75b5a,0x1e0fd5,'duplicate formatting descriptor'),
                 (0x3a75c34,0x1df8f3,'missing formatting descriptor'),
                 (0x3bec4da,0x5b988d,'digit pair table')]
    refs = []
    for site, target, description in rip_specs:
        if image.rip_lea(site) != target:
            raise ValueError('RIP-relative reference mismatch')
        refs.append((hex(site), hex(target), image.read(site, 7).hex(), description))
    fields = read_fields(image)
    text_specs = [('action',0x599566,b'UpdateIsolatedMarginAction'),
                  ('asset',0x5b5040,b'asset'), ('side',0x5b5d6b,b'isBuy'),
                  ('notional',0x209f7c,b'ntli'),
                  ('missing_prefix',0x1df8f4,b'missing field `'),
                  ('duplicate_prefix',0x1e0fd6,b'duplicate field `')]
    texts = []
    for label, address, expected in text_specs:
        raw = image.read(address, len(expected))
        if raw != expected:
            raise ValueError('text mismatch')
        texts.append((label, hex(address), hex(image.offset(address, len(raw))), len(raw), raw.hex(), raw.decode('ascii')))
    title = image.read(0x599566, 26)
    if title != b'UpdateIsolatedMarginAction':
        raise ValueError('action title mismatch')
    pairs = read_pairs(image)
    magic = struct.unpack('<Q', image.read(0x3bec4d2, 8))[0]
    divisor = struct.unpack('<I', image.read(0x3bec4c1, 4))[0]
    pair_magic = struct.unpack('<I', image.read(0x3bec522, 4))[0]
    loop_limit = struct.unpack('<I', image.read(0x3bec55c, 4))[0]
    variant = struct.unpack('<I', image.read(0x33593a4, 4))[0]
    if (divisor, pair_magic, loop_limit, variant) != (10000, 0x147b, 99999999, 0x98):
        raise ValueError('arithmetic or variant immediate mismatch')
    if magic != 0x346dc5d63886594b:
        raise ValueError('reciprocal mismatch')
    # Both algebra checks have explicit, finite domains or exact integer bounds.
    error = magic * 10000 - (1 << 75)
    proof_bound = (SIGN // 10000) * error + 9999 * magic
    if not 0 <= error or not proof_bound < 1 << 75:
        raise ValueError('reciprocal proof bound failed')
    if any((((r >> 2) * 0x147b) >> 17) != r // 100 for r in range(10000)):
        raise ValueError('two-digit quotient proof failed')
    cases = sorted({0, 1, 9, 10, 99, 100, 9999, 10000, SIGN - 1, SIGN, MASK} |
                   {v for k in range(1, 19) for v in (10**k-1, 10**k, 10**k+1) if v < SIGN} |
                   {(1 << 64) - v for v in (1, 9, 10, 99, 100, 9999, 10000, SIGN - 1)})
    digit_rows = []
    for bits in cases:
        signed = bits if bits < SIGN else bits - (1 << 64)
        got = format_lift(bits, pairs, magic).decode('ascii')
        if got != str(signed):
            raise ValueError('digit lift disagrees with independent decimal formatting')
        digit_rows.append((hex(bits), signed, got, len(got)))
    tag_rows = []
    for tag, (name, width, signed) in enumerate(TAG_SHAPES, 1):
        values = {0, (1 << (width*8)) - 1, 1, 1 << (width*8-1), (1 << (width*8-1))-1}
        for bits in sorted(values):
            payload = bits.to_bytes(width, 'little')
            status, value = decode_tag(tag, payload)
            actual = decode_instruction_load(image.read(targets[tag-1], 16), payload)
            if actual != (status, value):
                raise ValueError('integer load differs from independent tag model')
            tag_rows.append((tag, name, hex(targets[tag-1]), payload.hex(), status,
                             '' if value is None else value))
    presence_rows = []
    for mask in range(8):
        asset, side, ntli = (bool(mask & 1), bool(mask & 2), bool(mask & 4))
        first = ('asset' if not asset else 'isBuy' if not side else
                 'ntli' if not ntli else 'payload')
        observed = presence_walk(image, asset, side, ntli)
        expected = {'asset': '0x3a75b90', 'isBuy': '0x3a75a7c',
                    'ntli': '0x3a75c00', 'payload': '0x3a75c64'}[first]
        if observed != expected:
            raise ValueError('presence walk mismatch')
        presence_rows.append((int(asset), int(side), int(ntli), observed, first))
    duplicate_rows = []
    duplicate_targets = {'asset': '0x3a75b33', 'isBuy': '0x3a75e52', 'ntli': '0x3a75e89'}
    for field in ('asset', 'isBuy', 'ntli'):
        for seen in (False, True):
            target = duplicate_walk(image, field, seen)
            if (target == duplicate_targets[field]) != seen:
                raise ValueError('duplicate walk mismatch')
            duplicate_rows.append((field, int(seen), target, 'duplicate' if seen else 'value'))
    evidence = {'artifact_sha256': DIGEST, 'coordinate_system': 'linked ELF virtual address',
                'functions': funcs, 'action_title': title.decode('ascii'),
                'field_table_va': hex(0x56f1c08), 'digit_table_va': hex(0x5b988d),
                'digit_table_bytes': pairs.hex(), 'reciprocal': hex(magic),
                'chunk_divisor': divisor, 'pair_multiplier': pair_magic,
                'loop_limit': loop_limit, 'variant_tag': variant,
                'reciprocal_error': error, 'reciprocal_bound': proof_bound,
                'reciprocal_denominator': 1 << 75, 'pair_quotient_cases': 10000,
                'selected_windows': len(windows), 'selected_branches': len(branches), 'direct_calls': len(calls),
                'rip_relative_refs': len(refs), 'text_records': len(texts),
                'writer_edges': len(writer_edges),
                'numeric_tag_rows': len(tag_rows), 'digit_model_rows': len(digit_rows),
                'presence_model_rows': len(presence_rows), 'duplicate_model_rows': len(duplicate_rows),
                'target_execution': False}
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_tsv(out / 'windows.tsv', ['va','file_offset','interpretation','bytes'], windows)
    write_tsv(out / 'branches.tsv', ['va','bytes','fallthrough','target'],
              [(x['va'],x['bytes'],x['fallthrough'],x['target']) for x in branches])
    write_tsv(out / 'calls.tsv', ['site','target','bytes','meaning'], calls)
    write_tsv(out / 'writer-edges.tsv', ['branch','bytes','taken_when','target','taken_effect','fallthrough','fallthrough_effect'], writer_edges)
    write_tsv(out / 'rip-references.tsv', ['site','target','bytes','meaning'], refs)
    write_tsv(out / 'texts.tsv', ['meaning','va','file_offset','length','bytes','ascii'], texts)
    write_tsv(out / 'fields.tsv', ['field_index','relocation_slot','text_va','length','text'], fields)
    write_tsv(out / 'presence-cases.tsv', ['asset_seen','isBuy_seen','ntli_seen','target','first_missing_or_payload'], presence_rows)
    write_tsv(out / 'duplicate-cases.tsv', ['field','already_seen','target','outcome'], duplicate_rows)
    write_tsv(out / 'tag-cases.tsv', ['tag','shape','target','payload_le','model_outcome','model_value'], tag_rows)
    write_tsv(out / 'digit-cases.tsv', ['input_bits','signed_value','lifted_digits','length'], digit_rows)
    return evidence


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    generate(BINARY.read_bytes(), args.out)

if __name__ == '__main__':
    main()

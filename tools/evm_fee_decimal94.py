#!/usr/bin/env python3
"""Statically bind the node 94 fee-error decimal path; never run the target."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
U64 = (1 << 64) - 1
U256 = (1 << 256) - 1
FUNCTIONS = {
    0x4e4c710: ('outer tagged wrapper', 0x4e4c81f, 'e2f2291ee494f5bd370db0d8d63ea8da544f49c45b2974a3a382f9a3111d7991'),
    0x4e46e20: ('outer error dispatch', 0x4e47608, '418e6844df71f6ea60edef32d7f993b37597e3da87afec6ca31d7f57c782ff58'),
    0x4e58610: ('transaction error dispatch', 0x4e58836, '1926f6b2b233598592f762dee1cb1447b3cf368dde16ba72301719096c634a3e'),
    0x4e589e0: ('wide integer display', 0x4e58c36, '76ebebfab91db01c3f9ebec3a1cfe6cf433b4264accc13c3c66888767220dd02'),
    0x4e581c0: ('radix chunk construction', 0x4e58470, '93d1c96e453ba9a512eb98e68ac061d25eee68a351536c57464e10d5edf22dd3'),
    0x4e58c40: ('bounded display buffer writer', 0x4e58ca6, 'b8416e427ac73ce92c05fcfdfffdbd660a19032cdce674abc83ea53b3b09f0b1'),
}
# Whole bodies are checked as well: these slices make the reasoning reviewable.
ANCHORS = {
    'wrapper tag and tails': (0x4e4c710, '4883ec18488b0f488d47084885c9741283f901751a4889c74883c418ff25aea692004889c74883c418ff2519a69200'),
    'outer tail': (0x4e46ede, '4883c7084883c438ff25fcfe9200'),
    'inner dispatch': (0x4e58610, '4883ec38488b07488d0d929196fb486304814801c8ffe0'),
    'two payload pointers': (0x4e58627, '488b470848894424084883c020488d0da503000048894c2410488944241848894c2420488b3e488b7608488d1587203afb488d4c'),
    'zero test': (0x4e589f1, '488b4708480b4718488b0f480b4f104809c10f8439010000'),
    'radix immediate': (0x4e58a1a, '48b80000e8890423c78a48894424400f10'),
    'chunk call': (0x4e58a3a, '488d7c2458488d742420e877f7ffff'),
    'most significant chunk': (0x4e58a69, '4a8b44f1f84889442418488d4424184889442420488b05ac5f91'),
    'other chunk width': (0x4e58b0f, '48c74424300000000066c744243813004889ef488d35af248f004c89ea4889d9'),
    'zero literal': (0x4e58b42, '4c8d05a38e96fbba0100000041b901000000'),
    'nonzero divisor and high limb': (0x4e581ce, '4c8b76204d85f60f84520200004889f3488b6e184889e8'),
    'second limb divide': (0x4e58204, '4c8b63104c89e74889d64c89f231c9ff158f5f91004989c7490fafc64c89e648'),
    'two low limb divides': (0x4e58226, '4c8b2b488b5b084889df4c89f231c9ff156d5f91004889442410490fafc64889de4829c64c89ef4c89f231c9ff15505f91004889442408'),
    'first remainder store': (0x4e58280, '488b4c2408490fafce4929cd4c892848c744241804'),
    'following remainder store': (0x4e582c0, '4c89e2490fafd6488b4c24084829d14a890cf849ffc7'),
    'loop high divide': (0x4e582ef, '48894424504889e84c09f048c1e82074104889e831d249f7f64889c1eb0c0f1f0089e831d241f7f689c14889c84c09f0'),
    'loop limb divides': (0x4e58347, '4c89ff4889d64c89f231c94c8b254f5e910041ffd44889442448490fafc64c89fe4829c64c89ef4c89f231c941ffd44889442440490fafc64c89ee4829c64c89ed4c8b6c24084c89ef4c89f231c941ffd44989c44909ef'),
    'loop terminate test': (0x4e5839b, '4909ef4d09ef488b4424104909c7743f4889c54c8b7c24384c3b7c2418488b4424500f'),
    'capacity and growth': (0x4e583ab, '4889c54c8b7c24384c3b7c2418488b4424500f85fdfeffffba01000000b90800000041b808000000488d7c24184c89fee860fdffff488b442420e9d6feffff'),
    'empty chunk vector': (0x4e58402, '488b44243048c7000000000048c740080800000048c7401000000000'),
    'buffer bounds': (0x4e58c48, '488bbf000100004989ff4901d772354981ff00010000771c4889d34c01f7ff'),
    'buffer status': (0x4e58c7c, '4981ff010100000f93c05b415e415fc3'),
}
BRANCHES = {
    0x4e4c71e: (0x74, 0x4e4c732),
    0x4e4c723: (0x75, 0x4e4c73f),
    0x4e589f1 + 18: (0x84, 0x4e58b42),
    0x4e581d5: (0x84, 0x4e5842d),
    0x4e58266: (0x84, 0x4e58402),
    0x4e583a9: (0x74, 0x4e583ea),
    0x4e583bd: (0x85, 0x4e582c0),
    0x4e58ab9: (0x85, 0x4e58bd5),
    0x4e58b34: (0x85, 0x4e58bd5),
    0x4e58ba0: (0x73, 0x4e58bfc),
    0x4e58c55: (0x72, 0x4e58c8c),
    0x4e58c5e: (0x77, 0x4e58c7c),
}
SLOTS = {0x5776de0: 0x4e46e20, 0x5776de8: 0x4e58610, 0x576e1a8: 0x565f5a0,
         0x576e008: 0x1571d90, 0x576e048: 0x157aa10, 0x576e1b8: 0x157b440, 0x576ea30: 0x1570900,
         0x576e2d8: 0x15723b0, 0x574aff0: 0x4e58c40}


class EvidenceError(ValueError):
    pass


def authenticate(data, expected=SHA256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise EvidenceError('artifact SHA-256 mismatch')
    return actual


def read_selected_relocations(data, section, slots):
    if section['size'] % 24:
        raise EvidenceError('invalid relative relocation section')
    found = {}
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, off)
        if where in slots:
            if where in found:
                raise EvidenceError('duplicate relocation slot')
            if info != 8:
                raise EvidenceError('selected slot is not a symbol-free RELATIVE relocation')
            found[where] = addend
    return found


class Image:
    def __init__(self, data):
        authenticate(data)
        self.data = bytearray(data)
        self.sections = [s for s in elf_index.sections(data) if s['type'] != 8 and s['size']]
        _, records = fde_extents.eh_frame_records(data)
        _, indexed = elf_index.unwind_index(data)
        self.fdes = {}
        for r in records:
            if r['start'] in FUNCTIONS:
                if r['start'] in self.fdes:
                    raise EvidenceError('duplicate FDE start')
                self.fdes[r['start']] = r
        self.indexed = {r['start']: r['fde'] for r in indexed if r['start'] in FUNCTIONS}
        rela = [s for s in self.sections if s['name'] == '.rela.dyn']
        if len(rela) != 1 or rela[0]['size'] % 24:
            raise EvidenceError('invalid relative relocation section')
        self.reloc = read_selected_relocations(data, rela[0], SLOTS)

    def offset(self, va, size=1):
        if type(va) is not int or type(size) is not int or size < 0:
            raise EvidenceError('invalid read range')
        hits = [s['offset'] + va - s['address'] for s in self.sections
                if s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(hits) != 1:
            raise EvidenceError('address range lacks unique file-backed section')
        return hits[0]

    def read(self, va, size):
        off = self.offset(va, size)
        return bytes(self.data[off:off + size])

    def u32(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]

    def branch(self, va):
        b = self.read(va, 2)
        if b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
            return b[1], va + 6 + struct.unpack('<i', self.read(va + 2, 4))[0], self.read(va, 6)
        if 0x70 <= b[0] <= 0x7f:
            return b[0], va + 2 + struct.unpack('<b', b[1:])[0], b
        raise EvidenceError('unsupported branch opcode')

    def rel32(self, va, prefix):
        if self.read(va, len(prefix)) != prefix:
            raise EvidenceError('relative instruction opcode changed')
        length = len(prefix) + 4
        return va + length + struct.unpack('<i', self.read(va + len(prefix), 4))[0]

    def validate(self):
        if self.reloc != SLOTS:
            raise EvidenceError('relative relocation mismatch')
        if set(self.fdes) != set(FUNCTIONS) or set(self.indexed) != set(FUNCTIONS):
            raise EvidenceError('selected FDE or index missing')
        rows = []
        for start, (role, end, digest) in sorted(FUNCTIONS.items()):
            f = self.fdes[start]
            if f['end'] != end or self.indexed[start] != f['fde']:
                raise EvidenceError('FDE extent/index mismatch')
            sec = [s for s in self.sections if s['flags'] & 4 and s['address'] <= start and end <= s['address'] + s['size']]
            if len(sec) != 1:
                raise EvidenceError('function is not uniquely file-backed executable code')
            body = self.read(start, end - start)
            if hashlib.sha256(body).hexdigest() != digest:
                raise EvidenceError('function bytes changed')
            rows.append({'role': role, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                         'fde_va': hex(f['fde']), 'file_offset': hex(self.offset(start, len(body))),
                         'length': len(body), 'sha256': digest, 'body_hex': body.hex()})
        for name, (va, h) in ANCHORS.items():
            if self.read(va, len(bytes.fromhex(h))) != bytes.fromhex(h):
                raise EvidenceError('instruction anchor changed: ' + name)
        for va, expected in BRANCHES.items():
            op, target, _ = self.branch(va)
            if (op, target) != expected:
                raise EvidenceError('branch changed')
        if self.rel32(0x4e4c72c, b'\xff\x25') != 0x5776de0:
            raise EvidenceError('wrapper tail edge changed')
        if self.rel32(0x4e46ee6, b'\xff\x25') != 0x5776de8:
            raise EvidenceError('outer dispatch edge changed')
        if self.rel32(0x4e58634, b'\x48\x8d\x0d') != 0x4e589e0:
            raise EvidenceError('display binding changed')
        if self.rel32(0x4e58a44, b'\xe8') != 0x4e581c0:
            raise EvidenceError('chunk edge changed')
        if self.rel32(0x4e58b42, b'\x4c\x8d\x05') != 0x7c19ec or self.read(0x7c19ec, 1) != b'0':
            raise EvidenceError('zero display changed')
        if self.read(0x7c19bc, 43) != b"called `Result::unwrap()` on an `Err` value":
            raise EvidenceError('format failure text changed')
        if self.read(0x20ab40, 8) != bytes.fromhex('d320000069010000'):
            raise EvidenceError('format descriptor changed')
        if self.table_target(0x7c111c, 36) != 0x4e46ede:
            raise EvidenceError('outer dispatch table changed')
        if self.table_target(0x7c17b0, 0) != 0x4e58627:
            raise EvidenceError('inner dispatch table changed')
        if self.read(0x1fa6df, 69) != b'\x23sender does not have enough funds (\xc0\x1d) to cover transaction fees: \xc0\x00':
            raise EvidenceError('error message changed')
        return rows

    def table_target(self, table, index):
        if type(index) is not int or index < 0 or index > 255:
            raise EvidenceError('bad byte table index')
        disp = struct.unpack('<i', self.read(table + 4 * index, 4))[0]
        return table + disp


def wrapper_route(word):
    if type(word) is not int or not 0 <= word <= U64:
        raise EvidenceError('wrapper tag must be u64')
    if word == 0:
        return 'zero'
    if (word & 0xffffffff) == 1:
        return 'transaction'
    return 'other'


def quotient_limbs(limbs, divisor):
    """Lift the checked four-limb unsigned divide sequence, little-endian limbs."""
    if len(limbs) != 4 or any(type(x) is not int or not 0 <= x <= U64 for x in limbs):
        raise EvidenceError('expected four u64 limbs')
    if type(divisor) is not int or not 1 <= divisor <= U64:
        raise EvidenceError('expected nonzero u64 divisor')
    quotient, remainder, transitions = [0] * 4, 0, []
    for i in (3, 2, 1, 0):
        before = remainder
        n = (before << 64) | limbs[i]
        q, remainder = divmod(n, divisor)
        if q > U64 or remainder >= divisor:
            raise EvidenceError('long division invariant failed')
        quotient[i] = q
        transitions.append((i, before, limbs[i], q, remainder))
    return quotient, remainder, transitions


def split_chunks(value, divisor):
    if type(value) is not int or not 0 <= value <= U256:
        raise EvidenceError('u256 outside range')
    if type(divisor) is not int or not 2 <= divisor <= U64:
        raise EvidenceError('chunk radix must be between 2 and u64 max')
    limbs = [(value >> (64 * i)) & U64 for i in range(4)]
    chunks, traces = [], []
    while any(limbs):
        limbs, rem, steps = quotient_limbs(limbs, divisor)
        chunks.append(rem)
        traces.append(steps)
    return chunks, traces


def format_lift(value, divisor, width):
    if type(width) is not int or not 1 <= width <= 19 or divisor != 10 ** width:
        raise EvidenceError('radix and decimal width disagree')
    chunks, traces = split_chunks(value, divisor)
    if not chunks:
        return '0', chunks, traces
    return str(chunks[-1]) + ''.join(str(x).zfill(width) for x in reversed(chunks[:-1])), chunks, traces


def bounded_write(old_length, incoming_length):
    """Lift the buffer size decision; ordinary nonaliasing memory is assumed."""
    if any(type(n) is not int or not 0 <= n <= U64 for n in (old_length, incoming_length)):
        raise EvidenceError('buffer lengths must be u64')
    total = old_length + incoming_length
    if total > U64:
        return 'overflow', old_length
    if total > 256:
        return 'error', old_length
    return 'write', total


def compact_template(image, va):
    pos, pieces = 0, []
    for _ in range(8):
        marker = image.read(va + pos, 1)[0]
        pos += 1
        if marker == 0:
            return pieces
        if marker == 0xc0:
            pieces.append({'argument': sum('argument' in p for p in pieces)})
            continue
        if marker >= 0x80:
            raise EvidenceError('unsupported template marker')
        text = image.read(va + pos, marker).decode('ascii')
        pieces.append({'literal': text})
        pos += marker
    raise EvidenceError('unterminated compact template')


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(data, out):
    image = Image(data)
    functions = image.validate()
    radix = int.from_bytes(image.read(0x4e58a1c, 8), 'little')
    width = int.from_bytes(image.read(0x4e58b1d, 2), 'little')
    if radix != 10 ** width or radix <= 1 << 32:
        raise EvidenceError('unexpected display radix')
    parts = compact_template(image, 0x1fa6df)
    if parts != [{'literal': 'sender does not have enough funds ('}, {'argument': 0},
                 {'literal': ') to cover transaction fees: '}, {'argument': 1}]:
        raise EvidenceError('compact error template changed')
    values = sorted({0, 1, 9, 10, radix - 1, radix, radix + 1, radix * radix - 1,
                     radix * radix, radix * radix + 1, radix ** 3 - 1, radix ** 3,
                     radix ** 4 - 1, radix ** 4, (1 << 64) - 1, 1 << 64,
                     (1 << 128) - 1, 1 << 128, (1 << 192) - 1, 1 << 192,
                     (1 << 255) - 1, 1 << 255, U256})
    rows, trace_rows = [], []
    for value in values:
        rendered, chunks, traces = format_lift(value, radix, width)
        if rendered != str(value):
            raise EvidenceError('independent integer decimal check failed')
        rows.append([str(value), hex(value), len(chunks), ','.join(map(str, chunks)), rendered])
        for iteration, steps in enumerate(traces):
            for limb, rem_in, limb_value, quotient, rem_out in steps:
                trace_rows.append([hex(value), iteration, limb, hex(rem_in), hex(limb_value), hex(quotient), hex(rem_out)])
    out.mkdir(parents=True, exist_ok=True)
    (out / 'functions.json').write_text(json.dumps({'input_sha256': SHA256, 'functions': functions}, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_tsv(out / 'anchors.tsv', ['name', 'va', 'bytes'],
              [[name, hex(va), image.read(va, len(bytes.fromhex(h))).hex()] for name, (va, h) in sorted(ANCHORS.items(), key=lambda x: x[1][0])])
    write_tsv(out / 'branches.tsv', ['site_va', 'opcode', 'target_va', 'bytes'],
              [[hex(va), hex(image.branch(va)[0]), hex(image.branch(va)[1]), image.branch(va)[2].hex()] for va in sorted(BRANCHES)])
    write_tsv(out / 'dispatch.tsv', ['table', 'index', 'entry_va', 'target_va', 'target_inside_fde'],
              [[name, i, hex(table + i * 4), hex(image.table_target(table, i)), int(start <= image.table_target(table, i) < end)]
               for name, table, count, start, end in [('outer', 0x7c111c, 37, 0x4e46e20, 0x4e47608), ('inner', 0x7c17b0, 15, 0x4e58610, 0x4e58836)] for i in range(count)])
    tags = [0, 1, 2, (1 << 32), (1 << 32) + 1, U64]
    write_tsv(out / 'wrapper-cases.tsv', ['raw_tag', 'lifted_route'], [[hex(t), wrapper_route(t)] for t in tags])
    buffer_rows = []
    for old, incoming in [(0, 0), (0, 256), (255, 1), (256, 1), (0, 257), (U64, 1)]:
        action, result_length = bounded_write(old, incoming)
        buffer_rows.append([old, incoming, action, result_length])
    write_tsv(out / 'buffer-cases.tsv', ['old_length', 'incoming_length', 'lifted_action', 'result_length'], buffer_rows)
    pairs = [(0, 0), (0, radix), (radix + 1, 1), (U256, radix + 1)]
    pair_rows = []
    for funds, fee in pairs:
        left = format_lift(funds, radix, width)[0]
        right = format_lift(fee, radix, width)[0]
        pair_rows.append([hex(funds), hex(fee), parts[0]['literal'] + left + parts[2]['literal'] + right])
    write_tsv(out / 'pair-cases.tsv', ['first_value_hex', 'second_value_hex', 'conditional_model_text'], pair_rows)
    errors = []
    for i in range(15):
        target = image.table_target(0x7c17b0, i)
        if i == 0:
            text = ''.join(p.get('literal', '{}') for p in parts)
        elif i == 1:
            text = ''.join(p.get('literal', '{}') for p in compact_template(image, 0x1f93cd))
        else:
            if image.read(target + 11, 3) != b'\x48\x8d\x35' or image.read(target + 18, 1) != b'\xba':
                raise EvidenceError('error display arm changed')
            literal = image.rel32(target + 11, b'\x48\x8d\x35')
            length = image.u32(target + 19)
            if length > 128:
                raise EvidenceError('error string length too large')
            text = image.read(literal, length).decode('ascii')
        errors.append([i, hex(target), text])
    write_tsv(out / 'error-arms.tsv', ['tag', 'target_va', 'literal_or_template'], errors)
    write_tsv(out / 'vectors.tsv', ['value_decimal', 'value_hex', 'chunk_count', 'chunks_low_first', 'model_decimal'], rows)
    write_tsv(out / 'limb-trace.tsv', ['value_hex', 'round', 'limb_high_to_low', 'remainder_in', 'limb', 'quotient_limb', 'remainder_out'], trace_rows)
    proof = {'radix': radix, 'width': width, 'format_descriptor_hex': image.read(0x20ab40, 8).hex(),
             'format_flag_word': hex(image.u32(0x20ab41)),
             'format_flag_0x01000000_set': bool(image.u32(0x20ab41) & 0x1000000),
             'dynamic_width_argument': int.from_bytes(image.read(0x20ab45, 2), 'little'),
             'template': parts, 'wrapper_tag': image.read(0x4e4c722, 1)[0],
             'outer_tag': next(i for i in range(37) if image.table_target(0x7c111c, i) == 0x4e46ede),
             'inner_tag': next(i for i in range(15) if image.table_target(0x7c17b0, i) == 0x4e58627),
             'low_payload_offset': 0, 'high_payload_offset': image.read(0x4e58633, 1)[0],
             'buffer_capacity': image.u32(0x4e58c5a), 'max_u256_decimal_digits': len(str(U256)),
             'max_chunks': len(split_chunks(U256, radix)[0]), 'u256_max': str(U256),
             'initial_capacity_chunks': image.u32(0x4e58294),
             'first_value_needing_five_chunks': str(radix ** 4),
             'five_chunk_u256_inputs': str((1 << 256) - radix ** 4),
             'boundary_vectors': len(rows), 'limb_steps': len(trace_rows),
             'radix_four_below_2_to_256': radix ** 4 < 1 << 256,
             'radix_five_above_2_to_256': radix ** 5 > 1 << 256,
             'slot_relocations': {hex(k): hex(v) for k, v in sorted(image.reloc.items())},
             'interpretation': 'Static lift and independent arithmetic comparison; no captured instructions executed.'}
    (out / 'proof.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    return proof


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    result = generate(BINARY.read_bytes(), args.out)
    print(json.dumps({'vectors': result['boundary_vectors'], 'limb_steps': result['limb_steps'], 'max_chunks': result['max_chunks']}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (EvidenceError, ValueError, OSError, struct.error) as exc:
        print('evm_fee_decimal94:', exc, file=sys.stderr)
        raise SystemExit(1)

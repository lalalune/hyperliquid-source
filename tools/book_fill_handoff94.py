#!/usr/bin/env python3
"""Extract node 94 fill-vector handoff witnesses from ELF bytes, without executing it."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

# Both modules are the repository's shared ELF and DWARF decoders.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Start, end and full-body digest are a narrow allowlist, not a function census.
BODIES = {
    0x4484510: (0x44845aa, '1a96e953aea4ad52cb740d692d59d901c9e59e013862ca5b2160f9ad44ca4092'),
    0x44850d0: (0x448516a, '6f544b88a1f3e122c5d254f85128a9734df44f9f266447daca82089107e7de91'),
    0x454d800: (0x454d8a9, '6d859e682526c01f6b60de6d75854cf9e74bd5eb6424c48d60fb912c88496b1c'),
    0x454dca0: (0x454dd49, '5625d3aef7932a1ae85022f89827c715e1d50323013ece01054c9f1a0772fd65'),
    0x4847b70: (0x4847d0b, 'ea6ca4538135848a53d3d1a069c9f8d637c7f1eff425ad52ba6a7b7fa2b51f16'),
    0x47dcfd0: (0x47dd5a2, 'a43a063eb93f9347e1478586401ffe2a7270df19932ad41870509d12a953254c'),
}
CONTEXT = {
    (0x4d13b21, 0x4d13b81): '942b7267dae1ec5a069c08fc0b7d1e1edad506f681f6bc6febd4d160f67d9bd7',
    (0x4d13bb2, 0x4d13c47): '720312cbaf743813d4b35987f95536f5d5c1e8addbae2d3f17778882966742e9',
    (0x4d13c20, 0x4d13f9f): 'e0b699459ae4ad6c78223a48b763f0a17b52ead5d0283d25be678314cd23daee',
    (0x4d13f9f, 0x4d14190): '7484ad5b54e70d816ac41c0dccb4d4f0ede66872ae589ad872845b4950ad4556',
    (0x4d14614, 0x4d14659): 'fabbda4cca918a5b1323f6451467381e136ad28fc23b0a9e64c5efd38cca4951',
    (0x4d13efd, 0x4d13f9f): '8302eefdbb14db773244f1f28e23725d85ac61f10c19c4c5940607747434e3da',
    (0x4d163b1, 0x4d16411): '5437a5f0314d84290cd61a96f1fe1512d550bd040a0ef3231426beb64fd5a15c',
    (0x4d164b0, 0x4d1682f): 'fce307e146a6b6306f97c760c7163ed300819af4256e81288bbe7fb908bf5cb4',
    (0x4d1678d, 0x4d1682f): '9047edaf19e9a27a402a9517fab20578df51884090ff4f24aef8bea1b7f5288e',
    (0x4d16442, 0x4d164d7): 'b262a5b494eec800cc7a46c691863ece0861625d641ffe1c8dd13009769be36e',
    (0x4d16815, 0x4d1682f): 'bda9442b1a01cd419dc8012752305adad1fbbe852c6f05fc42dc4c002b1cbddf',
}
CALLS = {
    0x4d13b41: 0x4308460, 0x4d163d1: 0x430abf0,
    0x4d13c1b: 0x4484510, 0x4d164ab: 0x44850d0,
    0x448454b: 0x454dca0, 0x448510b: 0x454d800,
    0x454d84a: 0x444d7d0, 0x454dcea: 0x444d7d0,
    0x4d13f9a: 0x4847b70, 0x4d1682a: 0x4847b70,
    0x4847c4e: 0x47dcfd0,
    0x454d8a4: 0x5660110, 0x454dd44: 0x5660110,
    0x4d14617: 0x4308460, 0x4d14654: 0x4471d80,
}
BRANCHES = [
    0x4d13b7b, 0x4d13c3e, 0x4d13f10, 0x4d1640b, 0x4d164ce, 0x4d167a0,
    0x4484557, 0x448458b, 0x4485117, 0x448514b,
    0x454d88d, 0x454dd2d,
    0x4847b99, 0x4847ba9, 0x4847bc2, 0x4847bd1, 0x4847bf3, 0x4847cc5,
    0x47dcfe4, 0x47dd004, 0x47dd016, 0x47dd02d, 0x47dd035, 0x47dd06b,
    0x47dd08f, 0x47dd0ab, 0x47dd0db, 0x47dd105, 0x47dd232, 0x47dd24d,
    0x47dd25e, 0x47dd26e, 0x47dd289, 0x47dd2ce, 0x47dd2da, 0x47dd305, 0x47dd315,
]
SLOTS = {
    0x448459b: 0x576e010, 0x448515b: 0x576e010,
    0x454d89b: 0x576e010, 0x454dd3b: 0x576e010,
    0x4847ba0: 0x576dfb8, 0x4847bb9: 0x576dfd8, 0x4847d05: 0x576dfb8,
}
# Whole instruction byte windows support the layout/branch interpretation.
WITNESSES = [
    ('adapter_initial_status', 0x4484518, 5),
    ('adapter_compare_status', 0x4484555, 4),
    ('adapter_error_tag', 0x4484573, 16),
    ('adapter_release_size', 0x4484583, 30),
    ('collector_vector_inputs', 0x454d811, 15),
    ('collector_length_conversion', 0x454d84f, 34),
    ('collector_unwind_release', 0x454d883, 38),
    ('clone_length_and_guard', 0x4847b81, 32),
    ('clone_allocation', 0x4847ba6, 34),
    ('clone_row_tail', 0x4847bf9, 53),
    ('clone_row_call', 0x4847c46, 13),
    ('clone_record_copy', 0x4847c8a, 65),
    ('clone_empty_and_header', 0x4847cd7, 17),
    ('leg1_tag0', 0x47dcfe1, 9),
    ('leg1_tag_e4', 0x47dcffd, 13),
    ('leg1_tag28', 0x47dd012, 10),
    ('leg1_tag60', 0x47dd025, 22),
    ('leg1_tag88', 0x47dd05c, 21),
    ('leg2_tag_f8', 0x47dd22b, 9),
    ('leg2_tag_1dc', 0x47dd246, 9),
    ('leg2_tag_120', 0x47dd257, 9),
    ('leg2_tag_158', 0x47dd2c3, 25),
    ('leg2_tag_180', 0x47dd2fe, 9),
    ('leg1_output_tags', 0x47dd39b, 38),
    ('leg1_output_60', 0x47dd3e8, 9),
    ('leg1_output_88', 0x47dd416, 12),
    ('leg1_output_e4', 0x47dd472, 11),
    ('leg2_output_f8', 0x47dd48c, 7),
    ('leg2_output_120', 0x47dd4b7, 7),
    ('leg2_output_158', 0x47dd4f7, 7),
    ('leg2_output_180', 0x47dd525, 7),
    ('leg2_output_1dc', 0x47dd570, 10),
]


def authenticate(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('target SHA-256 mismatch')


def file_offset(data, secs, va, size, *, executable=True):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid range')
    matches = [s for s in secs if s['type'] != 8 and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('range is not in one file-backed section')
    sec = matches[0]
    off = sec['offset'] + va - sec['address']
    if off + size > len(data):
        raise ValueError('range exceeds file')
    return off


def read_va(data, secs, va, size):
    off = file_offset(data, secs, va, size)
    return data[off:off + size]


def decode_branch(code, va):
    if len(code) >= 2 and 0x70 <= code[0] <= 0x7f:
        size, cc, disp = 2, code[0] & 15, struct.unpack_from('<b', code, 1)[0]
    elif len(code) >= 6 and code[0] == 0x0f and 0x80 <= code[1] <= 0x8f:
        size, cc, disp = 6, code[1] & 15, struct.unpack_from('<i', code, 2)[0]
    else:
        raise ValueError('unsupported or truncated conditional branch')
    return size, cc, va + size + disp


def direct_call(code, va):
    if len(code) != 5 or code[0] != 0xe8:
        raise ValueError('expected near relative call')
    return va + 5 + struct.unpack_from('<i', code, 1)[0]


def indirect_slot(code, va):
    if len(code) != 6 or code[:2] != b'\xff\x15':
        raise ValueError('expected RIP-relative indirect call')
    return va + 6 + struct.unpack_from('<i', code, 2)[0]


def relative_relocations(data, secs, wanted):
    """Read only the selected x86-64 RELATIVE slots; do not simulate loading."""
    selected = [s for s in secs if s['name'] == '.rela.dyn']
    if len(selected) != 1:
        raise ValueError('missing or ambiguous relocation section')
    sec = selected[0]
    if sec['type'] != 4 or sec['size'] % 24 or sec['offset'] + sec['size'] > len(data):
        raise ValueError('invalid relocation section')
    records = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        if slot in records or info != 8:
            raise ValueError('duplicate or unsupported selected relocation')
        records[slot] = {'slot_va': hex(slot), 'type': info & 0xffffffff,
                         'symbol_index': info >> 32, 'addend': hex(addend),
                         'file_offset': hex(off), 'bytes': data[off:off + 24].hex()}
    if set(records) != set(wanted):
        raise ValueError('missing selected relocation')
    return [records[slot] for slot in sorted(records)]


def masked_pair(data, secs, a, b, masks):
    a_end, _ = BODIES[a]
    b_end, _ = BODIES[b]
    left = bytearray(read_va(data, secs, a, a_end - a))
    right = bytearray(read_va(data, secs, b, b_end - b))
    if len(left) != len(right):
        raise ValueError('paired extents differ')
    diffs = [i for i, (x, y) in enumerate(zip(left, right)) if x != y]
    for begin, end in masks:
        if not 0 <= begin < end <= len(left):
            raise ValueError('invalid comparison mask')
        left[begin:end] = right[begin:end] = bytes(end - begin)
    if left != right:
        raise ValueError('paired bodies differ outside masks')
    return {'left_va': hex(a), 'right_va': hex(b), 'length': len(left),
            'masked_byte_ranges_half_open': [[hex(x), hex(y)] for x, y in masks],
            'differing_byte_offsets': [hex(x) for x in diffs],
            'masked_sha256': hashlib.sha256(left).hexdigest()}


def masked_window_pair(data, secs, a, b, size, masks):
    left = bytearray(read_va(data, secs, a, size))
    right = bytearray(read_va(data, secs, b, size))
    diffs = [i for i, (x, y) in enumerate(zip(left, right)) if x != y]
    for begin, end in masks:
        if not 0 <= begin < end <= size:
            raise ValueError('invalid comparison mask')
        left[begin:end] = right[begin:end] = bytes(end - begin)
    if left != right:
        raise ValueError('paired windows differ outside masks')
    return {'left_va': hex(a), 'right_va': hex(b), 'length': size,
            'masked_byte_ranges_half_open': [[hex(x), hex(y)] for x, y in masks],
            'differing_byte_offsets': [hex(x) for x in diffs],
            'masked_sha256': hashlib.sha256(left).hexdigest()}


def evidence(data, *, check_identity=True):
    if check_identity:
        authenticate(data)
    secs = sections(data)
    # The header index and decoded FDE must independently agree for every selected start.
    _, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {}
    for f in fdes:
        if f['start'] in BODIES:
            by_start.setdefault(f['start'], []).append(f)
    index_by_start = {x['start']: x for x in index if x['start'] in BODIES}
    body_rows = []
    for start in sorted(BODIES):
        end, expected = BODIES[start]
        found = by_start.get(start, [])
        hdr = index_by_start.get(start)
        if len(found) != 1 or hdr is None:
            raise ValueError('missing or ambiguous selected FDE')
        fde = found[0]
        if fde['end'] != end or hdr['fde'] != fde['fde']:
            raise ValueError('FDE and unwind index mismatch')
        raw = read_va(data, secs, start, end - start)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise ValueError('selected body bytes mismatch')
        body_rows.append({'start_va': hex(start), 'end_va_exclusive': hex(end),
                          'file_offset': hex(file_offset(data, secs, start, len(raw))),
                          'length': len(raw), 'fde_va': hex(fde['fde']),
                          'lsda_va': None if fde['lsda'] is None else hex(fde['lsda']),
                          'unwind_index': hdr['index'], 'sha256': digest, 'bytes': raw.hex()})
    windows = []
    for (start, end), expected in sorted(CONTEXT.items()):
        raw = read_va(data, secs, start, end - start)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise ValueError('context window bytes mismatch')
        windows.append({'start_va': hex(start), 'end_va_exclusive': hex(end),
                        'file_offset': hex(file_offset(data, secs, start, len(raw))), 'sha256': digest, 'bytes': raw.hex()})
    calls = []
    for va, expected in sorted(CALLS.items()):
        raw = read_va(data, secs, va, 5)
        target = direct_call(raw, va)
        if target != expected:
            raise ValueError('direct call target mismatch')
        calls.append({'va': hex(va), 'bytes': raw.hex(), 'target_va': hex(target)})
    branches = []
    for va in sorted(BRANCHES):
        code = read_va(data, secs, va, 6)
        length, condition, target = decode_branch(code, va)
        branches.append({'va': hex(va), 'bytes': code[:length].hex(),
                         'condition_code': hex(condition), 'target_va': hex(target)})
    slots = []
    for va, expected in sorted(SLOTS.items()):
        raw = read_va(data, secs, va, 6)
        slot = indirect_slot(raw, va)
        if slot != expected:
            raise ValueError('indirect call slot mismatch')
        slots.append({'va': hex(va), 'bytes': raw.hex(), 'slot_va': hex(slot)})
    witnesses = []
    for label, va, size in WITNESSES:
        raw = read_va(data, secs, va, size)
        witnesses.append({'label': label, 'va': hex(va), 'file_offset': hex(file_offset(data, secs, va, size)),
                          'bytes': raw.hex()})
    # Decode selected immediate operands from their instruction bytes.
    stride_insn = read_va(data, secs, 0x4847b85, 7)
    limit_insn = read_va(data, secs, 0x4847b8c, 10)
    inverse_insn = read_va(data, secs, 0x454d85b, 10)
    status_insn = read_va(data, secs, 0x4484518, 5)
    error_insn = read_va(data, secs, 0x4484576, 10)
    if (stride_insn[:3] != bytes.fromhex('4d69f5') or limit_insn[:2] != bytes.fromhex('48b8')
            or inverse_insn[:2] != bytes.fromhex('48b9') or status_insn[:4] != bytes.fromhex('c6442407')
            or error_insn[:2] != bytes.fromhex('48b8')):
        raise ValueError('unexpected immediate instruction')
    stride = struct.unpack_from('<I', stride_insn, 3)[0]
    limit = struct.unpack_from('<Q', limit_insn, 2)[0]
    inverse = struct.unpack_from('<Q', inverse_insn, 2)[0]
    sentinel = status_insn[4]
    error = struct.unpack_from('<Q', error_insn, 2)[0]
    if stride != 0x228 or limit != ((1 << 63) - 1) // stride or (inverse * (stride // 8)) % (1 << 64) != 1:
        raise ValueError('inconsistent arithmetic constants')
    return {'artifact_sha256': SHA256, 'coordinate_system': 'linked virtual addresses; file offsets are zero based',
            'selected_fdes': body_rows, 'context_windows': windows,
            'constants': {'record_stride_bytes': stride, 'max_records': limit,
                          'length_inverse_mod_2_64': hex(inverse),
                          'adapter_initial_status_byte': sentinel, 'adapter_error_tag_u64': hex(error)},
            'masked_pairs': [masked_pair(data, secs, 0x4484510, 0x44850d0, [(60, 64), (141, 145)]),
                             masked_pair(data, secs, 0x454d800, 0x454dca0, [(75, 79), (157, 161), (165, 169)])],
            'masked_host_windows': [
                masked_window_pair(data, secs, 0x4d13b21, 0x4d163b1, 0x60, [(0x21, 0x25)]),
                masked_window_pair(data, secs, 0x4d13bb2, 0x4d16442, 0x95, [(0x6a, 0x6e)]),
                masked_window_pair(data, secs, 0x4d13efd, 0x4d1678d, 0xa2, [(0x9e, 0xa2)])],
            'direct_calls': calls, 'conditional_branches': branches, 'indirect_call_slots': slots,
            'relative_relocations': relative_relocations(data, secs, set(SLOTS.values())),
            'instruction_witnesses': witnesses}


def write_outputs(result, output):
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_text(json.dumps(result, indent=2, ensure_ascii=True) + '\n', encoding='ascii')
    for filename, key, columns in [
        ('calls.tsv', 'direct_calls', ('va', 'bytes', 'target_va')),
        ('branches.tsv', 'conditional_branches', ('va', 'bytes', 'condition_code', 'target_va')),
        ('witnesses.tsv', 'instruction_witnesses', ('label', 'va', 'file_offset', 'bytes')),
    ]:
        with (output / filename).open('w', encoding='ascii', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns, delimiter='\t', lineterminator='\n')
            writer.writeheader()
            writer.writerows(result[key])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = evidence(TARGET.read_bytes())
    write_outputs(result, args.out)


if __name__ == '__main__':
    main()

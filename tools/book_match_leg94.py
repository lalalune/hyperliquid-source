#!/usr/bin/env python3
"""Extract a node #94 matching-leg builder and its error-drop dispatch from ELF bytes."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are selected, independently disassembled instruction starts and unwind
# starts, not a claim that all calls or all functions have been enumerated.
FUNCTIONS = (
    ('leg_builder', 0x49e4210, 0x49e4449, 'e8bbc736dc4b4b357f76d70d03c6906bd7eb6da039177ce2d53abfc3b7d66213'),
    ('error_drop', 0x4a0e490, 0x4a0ea22, '1a5c5b54005617254d265474c796331d62d59cdcc39b3294dfe422b0f57a1c57'),
)
# Table size comes from its immediately preceding bounds check. Nested tables
# are kept separate; a row is a possible dispatch entry, not a live fixture.
TABLES = (
    ('top_003a', 0x703154, 193, '8c8137267cf0f9ec0803637dc07bcecdd46ad1245b08327b537e9f01ef618334'),
    ('top_014b', 0x703458, 40, '2f53c89074b21686a1e82f5317c4e5518e388018d4afedddd61df7ebf85158f0'),
    ('nested_014b_byte08', 0x7034f8, 32, 'ddbb78964a8f5cc56dcf64f81a80a0e3a0182b1a4a86dc5b5f08a1ce3e55789d'),
    ('nested_014b_03_word10', 0x7035a0, 14, '3ffa83937aa23496e56aad5fa1c977124c8282733bf368d5885a4fa43bf1069c'),
    ('nested_00bb_byte08', 0x7035d8, 7, 'ae64d9c336341e1a058fa02132ee1c343b646438ea08e22e4a2f13b1b45e4e21'),
    ('nested_014b_10_word10', 0x703578, 5, 'f294eb7e6328743aa8fd3db9d2a261148f34642d9230f9a99a0c2eee1bc0bff4'),
    ('nested_014b_10_04_word18', 0x70358c, 5, '643ca0071b7bf2dea3c8f5e4f4c590da8f2fb5f2995202f5c5641b7de0892c18'),
)
# LEA and compare sites independently bind each table base and maximum index.
TABLE_INSTRUCTIONS = (
    (0x4a0e4a6, 0x4a0e49e, bytes.fromhex('81f9'), 4),
    (0x4a0e4e8, 0x4a0e4df, bytes.fromhex('83f8'), 1),
    (0x4a0e506, 0x4a0e4fc, bytes.fromhex('4883f8'), 1),
    (0x4a0e524, 0x4a0e51a, bytes.fromhex('4883f8'), 1),
    (0x4a0e5f4, 0x4a0e5ea, bytes.fromhex('4883f8'), 1),
    (0x4a0e7b3, 0x4a0e7a5, bytes.fromhex('4883f9'), 1),
    (0x4a0e7fd, 0x4a0e7f3, bytes.fromhex('4883f8'), 1),
)
# Labels describe the selected encoded branches, not inferred source names.
BRANCHES = (
    ('caller_slot_oob', 0x430e33a, 0x4310e6e),
    ('caller_slot_vacant', 0x430e357, 0x4310e6e),
    ('different_side', 0x49e4286, 0x49e42cd),
    ('same_side_to_write', 0x49e42c8, 0x49e43c9),
    ('aux_disabled', 0x49e42d4, 0x49e4311),
    ('aux_error', 0x49e4305, 0x49e4315),
    ('aux_success', 0x49e430f, 0x49e4384),
    ('aux_disabled_to_fields', 0x49e4313, 0x49e4389),
    ('drop_second_range', 0x4a0e4a4, 0x4a0e4da),
    ('drop_outside_ranges', 0x4a0e4e2, 0x4a0e6b0),
    ('drop_zero_length', 0x4a0e4bd, 0x4a0e6b0),
    ('drop_negative_length', 0x4a0e575, 0x4a0e6b0),
    ('drop_positive_length', 0x4a0e57b, 0x4a0e4c3),
    ('drop_pair_first_empty', 0x4a0e5a1, 0x4a0e5b8),
    ('drop_pair_second_empty', 0x4a0e5bf, 0x4a0e6b0),
    ('drop_pair_second_tail', 0x4a0e5cd, 0x4a0e4c7),
    ('drop_nested_buffer_empty', 0x4a0e60b, 0x4a0e6b0),
    ('drop_nested_buffer_tail', 0x4a0e615, 0x4a0e4c7),
)
CALLS = (
    ('selected_leg_zero', 0x430ed8d, 0x49e4210),
    ('selected_leg_one', 0x430eda7, 0x49e4210),
    ('optional_auxiliary', 0x49e42f6, 0x4ae0df0),
    ('error_cleanup', 0x49e437d, 0x4a0e490),
)
# Whole spans cover the selected body and preserve the exact bytes used for
# instruction-level observations; they are not disassembler output.
SPANS = (
    ('select_and_common_call', 0x49e4210, 0x49e427b),
    ('same_side_inputs', 0x49e427b, 0x49e42cd),
    ('auxiliary_gate_and_result', 0x49e42cd, 0x49e4315),
    ('error_copy_and_cleanup', 0x49e4315, 0x49e4389),
    ('fallback_and_result_stores', 0x49e4389, 0x49e4449),
    ('drop_top_first_dispatch', 0x4a0e490, 0x4a0e4b6),
    ('drop_length_and_tail', 0x4a0e4b6, 0x4a0e4da),
    ('drop_signed_length', 0x4a0e56e, 0x4a0e586),
    ('drop_virtual_tail', 0x4a0e586, 0x4a0e59a),
    ('drop_two_buffers', 0x4a0e59a, 0x4a0e5d2),
    ('drop_nested_buffer', 0x4a0e604, 0x4a0e61a),
    ('drop_top_second_dispatch', 0x4a0e4da, 0x4a0e4f8),
    ('drop_nested_byte08_dispatch', 0x4a0e4f8, 0x4a0e516),
    ('drop_nested_word10_dispatch', 0x4a0e516, 0x4a0e534),
    ('drop_nested_tag_bb_dispatch', 0x4a0e5e6, 0x4a0e604),
    ('drop_nested_word10_second_dispatch', 0x4a0e7a1, 0x4a0e7c3),
    ('drop_nested_word18_dispatch', 0x4a0e7f0, 0x4a0e80d),
    ('caller_slot_guard', 0x430e32f, 0x430e360),
    ('caller_save_slot', 0x430e47c, 0x430e481),
    ('caller_restore_to_context', 0x430eb81, 0x430ecfe),
    ('caller_pair', 0x430ed7b, 0x430edac),
)

# Each prefix identifies a decoded result store. Displacements are read from
# the following bytes; widths come from the checked instruction form.
FIELD_STORES = (
    ('callback_pair', 0x49e43ce, '0f114b', 1, 16),
    ('selected_user_first', 0x49e43d7, '0f118b', 4, 16),
    ('selected_user_last', 0x49e43e2, '89b3', 4, 4),
    ('choice_word', 0x49e43ef, '488993', 4, 8),
    ('choice_block_a', 0x49e43f6, '0f1143', 1, 16),
    ('choice_block_b', 0x49e43fe, '0f1183', 4, 16),
    ('choice_byte', 0x49e440a, '8893', 4, 1),
    ('choice_block_c', 0x49e441a, '0f1143', 1, 16),
    ('choice_block_d', 0x49e441e, '0f114b', 1, 16),
    ('choice_block_e', 0x49e4427, '488953', 1, 8),
    ('option_tag', 0x49e4433, '48894b', 1, 8),
    ('option_payload', 0x49e4437, '488943', 1, 8),
)

class EvidenceError(ValueError):
    pass


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_identity(data, expected=TARGET_SHA256):
    if digest(data) != expected:
        raise EvidenceError('node #94 SHA-256 mismatch')


def mapping(data, secs, va, size, executable=False):
    if size <= 0 or va < 0:
        raise EvidenceError('invalid VA or size')
    candidates = [s for s in secs if s['type'] != 8 and
                  s['address'] <= va and va + size <= s['address'] + s['size'] and
                  (not executable or s['flags'] & 4)]
    if len(candidates) != 1:
        raise EvidenceError('range has no unique file-backed mapping')
    s = candidates[0]
    off = s['offset'] + va - s['address']
    if off + size > len(data):
        raise EvidenceError('range exceeds input')
    return off, s['name']


def read_va(data, secs, va, size, executable=False):
    off, _ = mapping(data, secs, va, size, executable)
    return data[off:off + size]


def decode_branch(data, secs, site, expected_target):
    first = read_va(data, secs, site, 1, True)[0]
    if first in (0xeb, *range(0x70, 0x80)):
        raw = read_va(data, secs, site, 2, True)
        disp = struct.unpack_from('<b', raw, 1)[0]
    elif first == 0xe9:
        raw = read_va(data, secs, site, 5, True)
        disp = struct.unpack_from('<i', raw, 1)[0]
    elif first == 0x0f:
        raw = read_va(data, secs, site, 6, True)
        if not 0x80 <= raw[1] <= 0x8f:
            raise EvidenceError('not a near conditional branch')
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise EvidenceError('unexpected branch opcode')
    target = site + len(raw) + disp
    if target != expected_target:
        raise EvidenceError('branch target changed')
    return raw, target


def decode_call(data, secs, site, expected_target):
    raw = read_va(data, secs, site, 5, True)
    if raw[0] != 0xe8:
        raise EvidenceError('not a direct call')
    target = site + 5 + struct.unpack_from('<i', raw, 1)[0]
    if target != expected_target:
        raise EvidenceError('call target changed')
    return raw, target


def decode_table(data, secs, va, count, expected_hash, bounds):
    raw = read_va(data, secs, va, 4 * count)
    if digest(raw) != expected_hash:
        raise EvidenceError('dispatch table bytes changed')
    rows = []
    for index in range(count):
        disp = struct.unpack_from('<i', raw, index * 4)[0]
        target = va + disp
        if not bounds[0] <= target < bounds[1]:
            raise EvidenceError('dispatch target outside drop FDE')
        mapping(data, secs, target, 1, True)
        rows.append((index, disp, target))
    return rows


def relative_relocation(data, secs, target_slot):
    result = []
    for s in secs:
        if s['type'] != 4:
            continue
        if s['size'] % 24:
            raise EvidenceError('partial ELF64 Rela record')
        for pos in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if slot == target_slot:
                result.append((info, addend))
    if len(result) != 1 or result[0][0] != 8:
        raise EvidenceError('expected one R_X86_64_RELATIVE relocation')
    return result[0][1]


def require_bytes(data, secs, va, expected):
    raw = read_va(data, secs, va, len(expected), True)
    if raw != expected:
        raise EvidenceError('instruction bytes changed')
    return raw


def decision(selector, side, flag, status, payload):
    """Derived truth table for the two observed selector values, not target execution.

    Zero-tag pointer payloads are represented by None, not modeled as zero.
    The external auxiliary and cleanup calls are represented only by their edges.
    """
    if selector not in (0, 1) or not 0 <= side <= 255 or not 0 <= flag <= 255:
        raise ValueError('selector, side or flag out of range')
    if not 0 <= status <= 0xffff or not 0 <= payload <= 0xffffffffffffffff:
        raise ValueError('status or payload out of range')
    if selector == side:
        return ('slot', 0, None, False, False)
    if flag == 0:
        return ('fallback', 0, None, False, False)
    if status == 0x186:
        return ('fallback', 1, payload, True, False)
    return ('fallback', 1, 0, True, True)


def tabular(head, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(head)
    writer.writerows(rows)
    return out.getvalue()


def collect(data, authenticate=True):
    if authenticate:
        verify_identity(data)
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    evidence_functions = []
    for name, start, end, expected_hash in FUNCTIONS:
        found = [f for f in fdes if f['start'] == start]
        if len(found) != 1 or found[0]['end'] != end:
            raise EvidenceError('selected FDE changed or is ambiguous')
        off, section = mapping(data, secs, start, end - start, True)
        raw = read_va(data, secs, start, end - start, True)
        if digest(raw) != expected_hash:
            raise EvidenceError('selected function bytes changed')
        evidence_functions.append({'label': name, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                                   'fde_va': hex(found[0]['fde']), 'section': section,
                                   'file_offset': hex(off), 'byte_count': len(raw),
                                   'sha256': digest(raw), 'raw_hex': raw.hex()})

    # Fixed bytes anchor the data offsets and immediates used by the truth
    # table; decode integer operands from the target, not a text disassembler.
    checks = (
        (0x430e337, bytes.fromhex('483b01')),
        (0x430e34b, bytes.fromhex('4869c0f8000000')),
        (0x430e352, bytes.fromhex('41833c0402')),
        (0x430e47c, bytes.fromhex('4c89642450')),
        (0x430eb81, bytes.fromhex('4c8b642450')),
        (0x430ebb3, bytes.fromhex('4c8b642450')),
        (0x430ecf6, bytes.fromhex('4c89a42478030000')),
        (0x49e4229, bytes.fromhex('ba14000000')),
        (0x49e427b, bytes.fromhex('498b4618')),
        (0x49e427f, bytes.fromhex('4038a8c2000000')),
        (0x49e42cd, bytes.fromhex('498b4620')),
        (0x49e42d1, bytes.fromhex('803800')),
        (0x49e42fb, bytes.fromhex('6681bc24e80000008601')),
        (0x49e4384, bytes.fromhex('b901000000')),
        (0x49e43e8, bytes.fromhex('48c70301000000')),
        (0x49e442b, bytes.fromhex('48c7436002000000')),
        (0x4a0e49b, bytes.fromhex('8d48c6')),
        (0x4a0e49e, bytes.fromhex('81f9c0000000')),
        (0x4a0e4da, bytes.fromhex('05b5feffff')),
        (0x4a0e4df, bytes.fromhex('83f827')),
        (0x4a0e5c9, bytes.fromhex('48c1e604')),
    )
    for va, raw in checks:
        require_bytes(data, secs, va, raw)
    second_buffer_shift = read_va(data, secs, 0x4a0e5c9, 4)[3]
    slot_stride = struct.unpack_from('<I', read_va(data, secs, 0x430e34b, 7), 3)[0]
    vacant_tag = read_va(data, secs, 0x430e352, 5)[4]
    slot_pointer_context_offset = read_va(data, secs, 0x49e427b, 4)[3]
    auxiliary_pointer_context_offset = read_va(data, secs, 0x49e42cd, 4)[3]
    selector_stride = struct.unpack_from('<I', read_va(data, secs, 0x49e4229, 5), 1)[0]
    side_offset = struct.unpack_from('<I', read_va(data, secs, 0x49e427f, 7), 3)[0]
    success = struct.unpack_from('<H', read_va(data, secs, 0x49e42fb, 10), 8)[0]
    if (second_buffer_shift, slot_stride, vacant_tag, slot_pointer_context_offset,
            auxiliary_pointer_context_offset, selector_stride, side_offset, success) != (4, 0xf8, 2, 0x18, 0x20, 0x14, 0xc2, 0x186):
        raise EvidenceError('leg operands changed')

    branch_rows = []
    for name, site, target in BRANCHES:
        raw, actual = decode_branch(data, secs, site, target)
        branch_rows.append((name, hex(site), raw.hex(), hex(actual)))
    call_rows = []
    for name, site, target in CALLS:
        raw, actual = decode_call(data, secs, site, target)
        call_rows.append((name, hex(site), raw.hex(), hex(actual)))
    # FF 15 disp32, followed by the dynamic RELA record, determines the target.
    indirect_site = 0x49e4275
    raw = read_va(data, secs, indirect_site, 6, True)
    if raw[:2] != b'\xff\x15':
        raise EvidenceError('expected an indirect RIP-relative call')
    slot = indirect_site + 6 + struct.unpack_from('<i', raw, 2)[0]
    addend = relative_relocation(data, secs, slot)
    if (slot, addend) != (0x5773d68, 0x372f930):
        raise EvidenceError('callback relocation changed')
    call_rows.append(('common_callback_via_rela', hex(indirect_site), raw.hex(), hex(addend)))

    # The length-controlled arm tail-jumps through a second RELA-backed slot.
    drop_site = 0x4a0e4d4
    drop_raw = read_va(data, secs, drop_site, 6, True)
    if drop_raw[:2] != b'\xff\x25':
        raise EvidenceError('expected an indirect RIP-relative tail jump')
    drop_slot = drop_site + 6 + struct.unpack_from('<i', drop_raw, 2)[0]
    drop_addend = relative_relocation(data, secs, drop_slot)
    if (drop_slot, drop_addend) != (0x576e010, 0x54c8cb0):
        raise EvidenceError('cleanup relocation changed')
    call_rows.append(('length_guarded_cleanup_tail', hex(drop_site), drop_raw.hex(), hex(drop_addend)))
    pair_site = 0x4a0e5af
    pair_raw = read_va(data, secs, pair_site, 6, True)
    if pair_raw[:2] != b'\xff\x15':
        raise EvidenceError('expected a RIP-relative cleanup call')
    pair_slot = pair_site + 6 + struct.unpack_from('<i', pair_raw, 2)[0]
    if pair_slot != drop_slot:
        raise EvidenceError('two-buffer cleanup slot changed')
    call_rows.append(('first_buffer_cleanup_call', hex(pair_site), pair_raw.hex(), hex(drop_addend)))

    table_rows = []
    for (name, va, count, expected_hash), (lea, cmp_site, prefix, width) in zip(TABLES, TABLE_INSTRUCTIONS):
        op = read_va(data, secs, lea, 7, True)
        if op[:2] != b'\x48\x8d' or op[2] not in (0x05, 0x0d, 0x15):
            raise EvidenceError('unexpected table LEA')
        base = lea + 7 + struct.unpack_from('<i', op, 3)[0]
        cmp_raw = read_va(data, secs, cmp_site, len(prefix) + width, True)
        if not cmp_raw.startswith(prefix):
            raise EvidenceError('unexpected table bound instruction')
        maximum = int.from_bytes(cmp_raw[len(prefix):], 'little')
        if (base, maximum + 1) != (va, count):
            raise EvidenceError('table base or bound changed')
        for index, disp, target in decode_table(data, secs, va, count, expected_hash,
                                                (FUNCTIONS[1][1], FUNCTIONS[1][2])):
            table_rows.append((name, hex(va), index, hex(va + 4 * index), disp, hex(target)))
    span_rows = []
    for name, start, end in SPANS:
        off, section = mapping(data, secs, start, end - start, True)
        raw = read_va(data, secs, start, end - start, True)
        span_rows.append((name, hex(start), hex(end), section, hex(off), raw.hex()))

    field_rows = []
    for label, site, prefix_hex, disp_size, width in FIELD_STORES:
        prefix = bytes.fromhex(prefix_hex)
        raw = read_va(data, secs, site, len(prefix) + disp_size, True)
        if not raw.startswith(prefix):
            raise EvidenceError('unexpected result store opcode')
        offset = int.from_bytes(raw[len(prefix):], 'little')
        field_rows.append((label, hex(site), raw.hex(), hex(offset), width))
    summary = {'target_sha256': digest(data), 'coordinate_system': 'linked ELF virtual address',
               'functions': evidence_functions,
               'second_buffer_shift': second_buffer_shift,
               'slot_stride': slot_stride, 'vacant_tag': vacant_tag,
               'slot_pointer_context_offset': slot_pointer_context_offset,
               'auxiliary_pointer_context_offset': auxiliary_pointer_context_offset,
               'selector_stride': selector_stride, 'slot_side_offset': side_offset,
               'auxiliary_success_u16': success,
               'callback': {'site_va': hex(indirect_site), 'relocation_slot_va': hex(slot),
                            'rela_type': 8, 'addend_va': hex(addend)},
               'cleanup_tail': {'site_va': hex(drop_site), 'relocation_slot_va': hex(drop_slot),
                                'rela_type': 8, 'addend_va': hex(drop_addend)},
               'tables': [{'name': n, 'base_va': hex(a), 'entries': c, 'sha256': h}
                          for n, a, c, h in TABLES],
               'limitations': 'FDEs are unwind ranges. Pattern and table records are static; external helpers and unwinding side effects are not executed.'}
    return {
        'evidence.json': json.dumps(summary, indent=2, sort_keys=True) + '\n',
        'branches.tsv': tabular(('label', 'site_va', 'bytes', 'target_va'), branch_rows),
        'calls.tsv': tabular(('label', 'site_va', 'bytes', 'target_va'), call_rows),
        'dispatch.tsv': tabular(('table', 'base_va', 'index', 'entry_va', 'signed_disp', 'target_va'), table_rows),
        'spans.tsv': tabular(('label', 'start_va', 'end_va_exclusive', 'section', 'file_offset', 'bytes'), span_rows),
        'fields.tsv': tabular(('label', 'site_va', 'bytes', 'result_offset', 'width'), field_rows),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    outputs = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, contents in outputs.items():
        (args.out / name).write_text(contents, encoding='utf-8', newline='\n')


if __name__ == '__main__':
    try:
        main()
    except (EvidenceError, OSError, struct.error) as error:
        print('book_match_leg94: {}'.format(error), file=sys.stderr)
        raise SystemExit(1)

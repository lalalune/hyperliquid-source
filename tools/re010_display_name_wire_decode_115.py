#!/usr/bin/env python3
"""Extract the node #115 SetDisplayName wire-name to payload-decoder edge.

This digest-specific static profile reads ELF bytes, relocations and unwind
records. It does not execute or emulate the captured node.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BINARY = ROOT / 'artifacts/node/115/hl-node'
FUNCTIONS = {
    'action_decoder': (0x2b817d0, 0x2b84365),
    'type_name_matcher': (0x2ba0a70, 0x2ba1aef),
    'payload_decoder': (0x20647f0, 0x2064ffc),
}


def va_to_offset(data, secs, va, size=1):
    hits = [s for s in secs if s['type'] != 8 and s['address'] <= va
            and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError(f'{va:#x}+{size:#x} lacks one file-backed section')
    s = hits[0]
    return s['offset'] + va - s['address']


def read_va(data, secs, va, size):
    off = va_to_offset(data, secs, va, size)
    return data[off:off + size]


def rela_dyn(data, secs):
    matches = [s for s in secs if s['name'] == '.rela.dyn']
    if len(matches) != 1:
        raise ValueError('Expected one .rela.dyn')
    sec = matches[0]
    if sec['type'] != 4 or sec['size'] % 24:
        raise ValueError('Unsupported .rela.dyn layout')
    off = sec['offset']
    return [struct.unpack_from('<QQq', data, p)
            for p in range(off, off + sec['size'], 24)]


def rel32_target(data, secs, call_va):
    raw = read_va(data, secs, call_va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'{call_va:#x} is not a direct call')
    return call_va + 5 + struct.unpack_from('<i', raw, 1)[0]


def extract(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != DIGEST:
        raise ValueError(f'Unexpected node #115 digest: {digest}')
    secs = sections(data)
    _, fdes, _ = fde_extents(data)
    fde_by_start = {row['start']: row for row in fdes}
    for name, (start, end) in FUNCTIONS.items():
        row = fde_by_start.get(start)
        if row is None or row['end'] != end:
            raise ValueError(f'{name} FDE boundary mismatch')

    # The outer Action decoder switches on the byte index returned by the
    # content name matcher. Its relative jump table is rooted at 0x607028.
    table_base, index = 0x607028, 19
    table_slot = table_base + index * 4
    rel = struct.unpack('<i', read_va(data, secs, table_slot, 4))[0]
    action_arm = table_base + rel
    if action_arm != 0x2b8367b:
        raise ValueError(f'Unexpected index-19 target: {action_arm:#x}')

    # Length 14 selects the arm that contains the overlapping name compares.
    matcher_table_base, matcher_length = 0x608540, 14
    matcher_table_slot = matcher_table_base + (matcher_length - 4) * 4
    matcher_rel = struct.unpack('<i', read_va(data, secs, matcher_table_slot, 4))[0]
    matcher_arm = matcher_table_base + matcher_rel
    if matcher_arm != 0x2ba0d30:
        raise ValueError(f'Unexpected length-14 matcher arm: {matcher_arm:#x}')
    # Exact compare is two overlapping 8-byte constants for the 14-byte name.
    compare_start = 0x2ba0d54
    cmp = read_va(data, secs, compare_start, 0x22)
    first = struct.unpack_from('<Q', cmp, 2)[0].to_bytes(8, 'little')
    second = struct.unpack_from('<Q', cmp, 0x0f)[0].to_bytes(8, 'little')
    recovered_name = first + second[2:]
    branch_va = compare_start + 0x1e
    branch_bytes = read_va(data, secs, branch_va, 6)
    if branch_bytes[:2] != b'\x0f\x84':
        raise ValueError('SetDisplayName compare does not end in expected JE')
    compare_target = branch_va + 6 + struct.unpack_from('<i', branch_bytes, 2)[0]
    if recovered_name != b'setDisplayName' or compare_target != 0x2ba19af:
        raise ValueError('SetDisplayName matcher arm mismatch')
    ordinal_store = read_va(data, secs, compare_target, 4)
    if ordinal_store != bytes.fromhex('c6400113'):
        raise ValueError('Matcher arm does not store variant index 19')

    # Read the selected Action decoder arm and its payload descriptor.
    arm_bytes = read_va(data, secs, action_arm, 0x4b)
    call_va = action_arm + 0x21
    call_target = rel32_target(data, secs, call_va)
    if call_target != 0x20647f0:
        raise ValueError(f'Unexpected payload decoder: {call_target:#x}')
    # Fixed RIP displacements in the arm identify the type name and field list.
    if arm_bytes[:7] != bytes.fromhex('488d153da9a6fd'):
        raise ValueError('SetDisplayNameAction literal LEA changed')
    if arm_bytes[7:14] != bytes.fromhex('4c8d0567bd8a03'):
        raise ValueError('SetDisplayName field-descriptor LEA changed')
    type_name_va = action_arm + 7 + struct.unpack_from('<i', arm_bytes, 3)[0]
    fields_va = action_arm + 14 + struct.unpack_from('<i', arm_bytes, 10)[0]
    if type_name_va != 0x5edfbf or fields_va != 0x642f3f0:
        raise ValueError('Action type/field descriptor target mismatch')
    type_name = read_va(data, secs, type_name_va, len(b'SetDisplayNameAction'))
    if type_name != b'SetDisplayNameAction':
        raise ValueError('Action type name literal mismatch')

    # The first 16-byte field descriptor contains a RELATIVE relocation to
    # "displayName" and its byte length. Relocations are kept as data; they
    # are not applied to or written into the captured ELF.
    relocations = rela_dyn(data, secs)
    descriptor_len = struct.unpack('<Q', read_va(data, secs, fields_va + 8, 8))[0]
    field_relocs = [(offset, info, addend) for offset, info, addend in relocations
                    if offset == fields_va and (info >> 32) == 0 and (info & 0xffffffff) == 8]
    if len(field_relocs) != 1 or descriptor_len != 11:
        raise ValueError('Expected one RELATIVE field-name relocation and length 11')
    field_name_va = field_relocs[0][2]
    field_name = read_va(data, secs, field_name_va, descriptor_len)
    if field_name != b'displayName':
        raise ValueError('Unexpected SetDisplayName field name')

    # The action decoder stores the established internal discriminant after
    # the payload helper returns on the selected normal path.
    tag_store_va = action_arm + 0x41
    tag_store = read_va(data, secs, tag_store_va, 6)
    if tag_store[:2] != b'\x41\xbe' or struct.unpack_from('<I', tag_store, 2)[0] != 0x99:
        raise ValueError('Selected arm no longer stores internal tag 0x99')
    output_tag_store = read_va(data, secs, 0x2b84278, 8)
    output_alloc_size = read_va(data, secs, 0x2b842f5, 5)
    output_copy_size = read_va(data, secs, 0x2b84310, 5)
    output_pointer_return = read_va(data, secs, 0x2b8431e, 5)
    output_ret = read_va(data, secs, 0x2b84334, 1)
    if output_tag_store != bytes.fromhex('4c89b424e8010000'):
        raise ValueError('Common output path no longer saves the selected tag')
    if output_alloc_size != bytes.fromhex('bff0000000') or output_copy_size != bytes.fromhex('baf0000000'):
        raise ValueError('Common output path no longer allocates/copies 0xf0 bytes')
    if output_pointer_return != bytes.fromhex('31c04889da') or output_ret != b'\xc3':
        raise ValueError('Common output path no longer returns the allocated object pointer')

    edges = [
        ('wire name', '0x2ba0d54', '0x2ba19af', '14-byte setDisplayName compare; writes index 19'),
        ('length switch', hex(matcher_table_slot), hex(matcher_arm), 'length 14 signed-relative table entry'),
        ('variant table', hex(table_slot), hex(action_arm), 'index 19 signed-relative table entry'),
        ('payload helper', hex(action_arm + 0x21), hex(call_target), 'direct call from selected Action arm'),
        ('field descriptor', hex(fields_va), hex(field_name_va), 'R_X86_64_RELATIVE addend; displayName length 11'),
        ('internal action tag', hex(tag_store_va), '0x99', 'normal path after payload helper'),
        ('allocated Action object', 'offset 0', '0x99 / size 0xf0', 'first qword is tag; returned pointer in rdx'),
    ]
    functions = []
    for name, (start, end) in FUNCTIONS.items():
        functions.append((name, hex(start), hex(end), end - start,
                          hashlib.sha256(read_va(data, secs, start, end-start)).hexdigest()))
    windows = [
        ('name_compare_and_ordinal', compare_start, compare_start + 0x22),
        ('matcher_length14_table_entry', matcher_table_slot, matcher_table_slot + 4),
        ('action_decoder_switch', 0x2b81870, 0x2b81880),
        ('action_index19_table_entry', table_slot, table_slot + 4),
        ('selected_action_arm', action_arm, action_arm + 0x4b),
        ('payload_map_sequence_head', 0x20647f0, 0x206481c),
        ('payload_sequence_key_setup', 0x2064889, 0x20648b4),
        ('action_output_tag_store', 0x2b84278, 0x2b84280),
        ('action_output_allocation', 0x2b842f5, 0x2b842fa),
        ('action_output_copy_size', 0x2b84310, 0x2b84315),
        ('action_output_pointer_return', 0x2b8431e, 0x2b84323),
        ('action_output_return', 0x2b84334, 0x2b84335),
    ]
    return {
        'binary_sha256': digest,
        'wire_name': recovered_name.decode(), 'variant_index': index,
        'matcher_length_arm': hex(matcher_arm),
        'action_arm': hex(action_arm), 'action_type': type_name.decode(),
        'field_name': field_name.decode(), 'field_name_length': descriptor_len,
        'payload_helper': hex(call_target), 'payload_helper_fde': [hex(FUNCTIONS['payload_decoder'][0]), hex(FUNCTIONS['payload_decoder'][1])],
        'internal_tag': '0x99', 'action_output_size': 0xf0, 'action_output_pointer_register': 'rdx',
        'limitations': 'Static edge evidence only; does not reconstruct every malformed-input branch or prove runtime reachability beyond the observed decoder/dispatch bytes.',
    }, edges, functions, windows, data, secs


def write_tsv(path, header, rows):
    with path.open('w', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(header)
        w.writerows(rows)


def generate(binary, out):
    data = binary.read_bytes()
    summary, edges, functions, windows, data, secs = extract(data)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    write_tsv(out / 'edges.tsv', ['edge', 'from', 'to', 'observation'], edges)
    write_tsv(out / 'functions.tsv', ['role', 'start_va', 'end_va', 'fde_extent_bytes', 'body_sha256'], functions)
    win_rows = []
    for name, start, end in windows:
        raw = read_va(data, secs, start, end-start)
        win_rows.append((name, hex(start), hex(end), len(raw), raw.hex()))
    write_tsv(out / 'windows.tsv', ['name', 'start_va', 'end_va', 'bytes', 'hex'], win_rows)
    manifest = []
    for path in sorted(p for p in out.iterdir() if p.is_file() and p.name != 'MANIFEST.sha256'):
        manifest.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}')
    (out / 'MANIFEST.sha256').write_text('\n'.join(manifest) + '\n')
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', type=Path, default=BINARY)
    ap.add_argument('--out', type=Path, default=ROOT / 'research/work-items/RE-010-display-name-wire-decode-115')
    args = ap.parse_args()
    print(json.dumps(generate(args.binary, args.out), indent=2))


if __name__ == '__main__':
    main()

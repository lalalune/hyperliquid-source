#!/usr/bin/env python3
"""Collect digest-bound static evidence for the node 94 client-ID index update."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = (
    ('user_entry', 0x3596b30, 0x3596d97, '5cf74a4033b4ff2459941305b382abfe8ac616f05cf0de808b9b485938c3583c'),
    ('user_probe', 0x3799e90, 0x3799fce, '7574d1ba789722311e751994cdabd28ac6b76e64e20efba0957bd43a711d84a6'),
    ('oid_to_client_put', 0x379f580, 0x379f72d, '5ca53b3f813d4d3d69e0bbdaaaa9110d064b0d65762c088d16d4a0412cbd06a9'),
    ('client_to_oid_put', 0x379d4f0, 0x379d685, 'abbd72e30d9a27250e7a71ebf9819589c258e770477b0d8c06e9e2eb443f49f1'),
    ('user_table_grow', 0x357c210, 0x357c859, '5b54a095a55bad2e8a80c9c31608782754b6405a3b532c2d16f6625a68a69a4c'),
    ('oid_table_grow', 0x357da80, 0x357df8c, '8c12319be72f9f6042f4a8e3363648ff6492e24f732ed8296dc958a7b553af2a'),
    ('client_table_grow', 0x35781f0, 0x35786fc, '9e5c1e429c2a53a8d1b6a949e2b9712be7207c43da5f4fd3f408c88c8c5d28c6'),
    ('table_allocate', 0x3577160, 0x3577309, '0a8613b741accfb2b65c10f18f2c68c347b985aeeb0094aedd72f267b8404f01'),
)
# Sites in the already documented insertion/cancellation host are contextual,
# not a claim to have recovered its full body.
DIRECT_CALLS = (
    ('insert_to_oid_slot_map', 0x4312fad, 0x488da60),
    ('entry_to_user', 0x342aa5f, 0x3596b30),
    ('entry_to_oid_put', 0x342aa73, 0x379f580),
    ('entry_to_client_put', 0x342abd9, 0x379d4f0),
    ('user_to_probe', 0x3596b49, 0x3799e90),
    ('probe_to_user_hash', 0x3799eab, 0x399c7a0),
    ('oid_put_to_hash', 0x379f5aa, 0x399c4a0),
    ('client_put_to_hash', 0x379d508, 0x399c650),
    ('user_grow_to_allocate', 0x357c27d, 0x3577160),
    ('oid_grow_to_allocate', 0x357daed, 0x3577160),
    ('client_grow_to_allocate', 0x357825d, 0x3577160),
    ('oid_rehash', 0x357db9f, 0x399c4a0),
    ('client_rehash', 0x357830f, 0x399c650),
)
INDIRECT_CALLS = (
    ('insert_to_bimap', 0x4312ff3, 0x5774810, 0x342aa50),
    ('probe_grow_user', 0x3799fc3, 0x5773670, 0x357c210),
    ('put_grow_oid', 0x379f70a, 0x5773748, 0x357da80),
    ('put_grow_client', 0x379d662, 0x5773778, 0x35781f0),
)
# Conditional branches selected at independently reviewed instruction boundaries.
BRANCHES = (
    ('insert_client_id_absent', 0x4312fb7, 0x4312ff9),
    ('previous_oid_absent', 0x342aa7c, 0x342abc7),
    ('same_client_early_return', 0x342aaa0, 0x342acfa),
    ('client_not_replaced', 0x342abe0, 0x342acfa),
    ('old_client_tombstone', 0x342abb4, 0x342abbc),
    ('displaced_oid_tombstone', 0x342ace7, 0x342acef),
    ('user_found', 0x3596b55, 0x3596ce9),
    ('user_probe_match', 0x3799f3a, 0x3799f6e),
    ('user_probe_empty', 0x3799f5c, 0x3799f82),
    ('user_probe_grow', 0x3799f87, 0x3799fb0),
    ('oid_no_growth_left', 0x379f5b5, 0x379f6f7),
    ('oid_existing', 0x379f618, 0x379f671),
    ('oid_empty_group', 0x379f654, 0x379f688),
    ('oid_no_vacant_lane_fallback', 0x379f68e, 0x379f718),
    ('client_no_growth_left', 0x379d512, 0x379d64f),
    ('client_existing', 0x379d588, 0x379d5e1),
    ('client_empty_group', 0x379d5c4, 0x379d5f4),
    ('client_no_vacant_lane_fallback', 0x379d5fa, 0x379d670),
    ('outer_count_overflow', 0x357c22a, 0x357c82e),
    ('outer_rehash_in_place', 0x357c25d, 0x357c429),
    ('oid_count_overflow', 0x357da9a, 0x357df61),
    ('oid_rehash_in_place', 0x357dacd, 0x357dc56),
    ('oid_allocation_error', 0x357db04, 0x357dc98),
    ('oid_empty_table', 0x357db0d, 0x357defe),
    ('oid_move_or_swap', 0x357ddd0, 0x357de95),
    ('client_count_overflow', 0x357820a, 0x35786d1),
    ('client_rehash_in_place', 0x357823d, 0x35783c6),
    ('client_allocation_error', 0x3578274, 0x3578408),
    ('client_empty_table', 0x357827d, 0x357866e),
    ('client_move_or_swap', 0x3578540, 0x3578605),
    ('allocate_small_class', 0x3577175, 0x3577190),
    ('allocate_count_overflow', 0x3577197, 0x35772d5),
    ('allocate_size_multiply_overflow', 0x35771dd, 0x357720e),
    ('allocate_size_round_overflow', 0x35771e3, 0x357720e),
    ('allocate_layout_ok', 0x357720c, 0x357722d),
    ('allocate_null', 0x3577252, 0x3577274),
)
WITNESSES = (
    ('insert_client_id_flag', 0x4312fb2, '807c2427007440'),
    ('insert_book_index_pointer', 0x4312fbe, '488d7848'),
    ('caller_old_oid_result', 0x342aa78, '803c24010f8545010000'),
    ('caller_same_client_test', 0x342aa8e, 'f3410f6f0f660f74c8660fd7c13dffff00000f8454020000'),
    ('caller_reverse_put', 0x342abc7, '488d7b30410f10070f2904244889e64c89f2e812293700a8010f8414010000'),
    ('caller_displaced_oid', 0x342abe6, '4989d6488914244889df4883c7204889e6'),
    ('caller_delete_old_client', 0x342abae, 'b2806683ff0f770648ff4340b2ff8814018854311048ff4b48'),
    ('caller_delete_displaced_oid', 0x342ace1, 'b2806683ff0f770648ff4310b2ff8814018854311048ff4b18'),
    ('outer_bucket_and_control', 0x3596c65, '468824064688640e1049f7d84080e701400fb6c749294610496bf878488d043e4c897c3e884c8b4424'),
    ('oid_previous_value', 0x379f671, '4a8d04d9660f1040f04883c0f066410f114601b101eb55'),
    ('oid_write', 0x379f6c7, '48f7df488d047f4c897cc1e8488d04c14883c0f031c90f10030f110041880e'),
    ('client_previous_value', 0x379d5e1, '4a8d04d9488b50f8488958f8b801000000eb52'),
    ('client_write', 0x379d62d, '48f7df488d047ff3410f6f06f30f7f44c1e848895cc1f831c0'),
    ('client_grow_threshold', 0x35781fe, '48895424104c8b77184c01f60f82c10400004989ff488b5f08488d53014889d748c1ef034889d04883e0f84829f84883fb08480f42c34889c748d1ef4839fe'),
    ('allocate_small_bucket_classes', 0x3577171, '4883fa0f731989d083e0084883c0084883fa0441bd040000004c0f43e8'),
    ('allocate_layout_checks', 0x35771d7, '4889f049f7e5702f4883f8f077294883c00f4883e0f04d8d75104989c74d01f70f92c148baf0ffffffffffff7f4939d70f97c208ca741f45'),
    ('client_growth_commit', 0x3578676, '48b801000000000000804c29f249892f4d89470849895710'),
)

# Offset of each four-byte PC-relative operand in the two 1292-byte grow bodies.
COPY_MASKS = (0x6e, 0x120, 0x23a, 0x289, 0x2ad, 0x2ce, 0x4d8, 0x4ec, 0x4f3, 0x4fe)
COPY_TARGETS = (
    (0x3577160, 0x3577160), (0x399c650, 0x399c4a0),
    (0x207980, 0x207980), (0x207980, 0x207980),
    (0x576e0e0, 0x576e0e0), (0x399c650, 0x399c4a0),
    (0x576e010, 0x576e010), (0x280866, 0x280866),
    (0x5685aa8, 0x5685aa8), (0x576e098, 0x576e098),
)
# Each value is read from an authenticated fixed instruction, not a disassembler.
CONSTANTS = (
    ('user_bucket_bytes', 0x357c275, 'be', 4),
    ('oid_bucket_bytes', 0x357dae5, 'be', 4),
    ('client_bucket_bytes', 0x3578255, 'be', 4),
    ('minimum_buckets', 0x3577184, '41bd', 4),
    ('small_bucket_cutoff', 0x3577171, '4883fa', 1),
    ('control_group_bytes', 0x3578490, 'ba', 4),
    ('fingerprint_shift', 0x379f5c7, '48c1ea', 1),
    ('allocation_layout_ceiling', 0x35771fa, '48ba', 8),
)

LITERALS = (
    ('growth_and_count_lanes', 0x203480, '0000000000000000ffffffffffffffff'),
    ('control_high_bit_mask', 0x207980, '80808080808080808080808080808080'),
    ('capacity_error', 0x280866, '48617368207461626c65206361706163697479206f766572666c6f77'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_data(data):
    if digest(data) != DIGEST:
        raise ValueError('node 94 SHA-256 mismatch')


def read_va(data, secs, va, size, executable=False):
    if size < 0 or va < 0 or va + size > 1 << 64:
        raise ValueError('invalid address range')
    found = [s for s in secs if s['type'] != 8 and
             (not executable or s['flags'] & 4) and
             s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('address range is not uniquely file-backed')
    off = found[0]['offset'] + va - found[0]['address']
    return off, data[off:off + size]


def direct(data, secs, site):
    _, raw = read_va(data, secs, site, 5, True)
    if raw[0] != 0xe8:
        raise ValueError('expected direct call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0], raw


def indirect(data, secs, site):
    _, raw = read_va(data, secs, site, 6, True)
    if raw[:2] != b'\xff\x15':
        raise ValueError('expected RIP-relative indirect call')
    return site + 6 + struct.unpack_from('<i', raw, 2)[0], raw


def branch(data, secs, site):
    _, raw = read_va(data, secs, site, 2, True)
    if 0x70 <= raw[0] <= 0x7f:
        size = 2
        delta = struct.unpack_from('<b', raw, 1)[0]
    elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        size = 6
        _, raw = read_va(data, secs, site, size, True)
        delta = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('expected conditional branch')
    return site + size + delta, site + size, raw


def relocations(data, secs):
    rel = {}
    for sec in secs:
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError('truncated RELA section')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if info == 8:
                if slot in rel:
                    raise ValueError('duplicate relative relocation')
                rel[slot] = addend
    return rel


def validate_witness(data, secs, va, expected):
    off, raw = read_va(data, secs, va, len(expected), True)
    if raw != expected:
        raise ValueError('instruction witness mismatch')
    return off, raw


def capacity(mask):
    if mask < 0 or mask > (1 << 63) - 1 or (mask & (mask + 1)):
        raise ValueError('mask is not a supported 2^n-1')
    n = mask + 1
    return mask if mask < 8 else n - n // 8


def allocation_layout(stride, request):
    """Synthetic projection of the witnessed bucket-class and layout checks."""
    if stride not in (0x18, 0x78) or not 0 <= request <= (1 << 64) - 1:
        raise ValueError('unsupported stride or request')
    if request < 4:
        buckets = 4
    elif request < 8:
        buckets = 8
    elif request < 15:
        buckets = 16
    elif request >= 1 << 61:
        return None
    else:
        buckets = 1 << ((request * 8 // 7 - 1).bit_length())
    payload = stride * buckets
    if payload > ((1 << 64) - 1) - 15:
        return None
    total = ((payload + 15) & ~15) + buckets + 16
    if total > 0x7ffffffffffffff0:
        return None
    return buckets, total


def growth_choice(mask, count, additional=1):
    cap = capacity(mask)
    if count < 0 or additional < 0 or count > cap:
        raise ValueError('invalid count')
    required = count + additional
    if required > (1 << 64) - 1:
        return ('overflow', None)
    if required <= cap // 2:
        return ('in_place', None)
    layout = allocation_layout(0x18, max(cap + 1, required))
    if layout is None:
        return ('layout_overflow', None)
    return ('allocate', layout[0])


def bind(mapping_oid, mapping_client, oid, client):
    """Synthetic logical projection, assuming normal returns and no aliasing."""
    oids, clients = dict(mapping_oid), dict(mapping_client)
    old = oids.get(oid)
    oids[oid] = client
    if old is not None and old == client:
        return oids, clients, 'same'
    if old is not None:
        clients.pop(old, None)
    displaced = clients.get(client)
    clients[client] = oid
    if displaced is not None:
        oids.pop(displaced, None)
    return oids, clients, 'updated'


def analyse(data, verify_digest=True):
    if verify_digest:
        checked_data(data)
    secs = sections(data)
    _, entries = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {}
    for f in fdes:
        if f['start'] in by_start:
            raise ValueError('duplicate FDE start')
        by_start[f['start']] = f
    index = {row['start']: row['fde'] for row in entries}
    fn_rows = []
    for label, start, end, expected in FUNCTIONS:
        f = by_start.get(start)
        if f is None or f['end'] != end or index.get(start) != f['fde']:
            raise ValueError('FDE extent or index mismatch')
        offset, raw = read_va(data, secs, start, end-start, True)
        if digest(raw) != expected:
            raise ValueError('function byte digest mismatch')
        fn_rows.append(dict(role=label, start=hex(start), end=hex(end), size=len(raw),
                            file_offset=hex(offset), fde=hex(f['fde']), cie=hex(f['cie']),
                            lsda=hex(f['lsda']) if f['lsda'] is not None else None,
                            sha256=digest(raw), bytes_hex=raw.hex()))
    rel = relocations(data, secs)
    call_rows = []
    for label, site, target in DIRECT_CALLS:
        actual, raw = direct(data, secs, site)
        if actual != target:
            raise ValueError('direct call target mismatch')
        call_rows.append((label, hex(site), raw.hex(), 'direct', '', hex(actual)))
    for label, site, slot, target in INDIRECT_CALLS:
        actual, raw = indirect(data, secs, site)
        if actual != slot or rel.get(slot) != target:
            raise ValueError('indirect call or relocation mismatch')
        read_va(data, secs, slot, 8)
        call_rows.append((label, hex(site), raw.hex(), 'relative relocation', hex(slot), hex(target)))
    branch_rows = []
    for label, site, target in BRANCHES:
        actual, fallthrough, raw = branch(data, secs, site)
        if actual != target:
            raise ValueError('branch target mismatch')
        branch_rows.append((label, hex(site), raw.hex(), hex(actual), hex(fallthrough)))
    witness_rows = []
    for label, va, expected in WITNESSES:
        off, raw = validate_witness(data, secs, va, bytes.fromhex(expected))
        witness_rows.append((label, hex(va), hex(off), raw.hex()))
    copy_rows = []
    masks = set()
    _, left = read_va(data, secs, 0x35781f0, 1292, True)
    _, right = read_va(data, secs, 0x357da80, 1292, True)
    for i, (offset, targets) in enumerate(zip(COPY_MASKS, COPY_TARGETS)):
        masks.update(range(offset, offset + 4))
        a = 0x35781f0 + offset + 4 + struct.unpack_from('<i', left, offset)[0]
        b = 0x357da80 + offset + 4 + struct.unpack_from('<i', right, offset)[0]
        if (a, b) != targets:
            raise ValueError('copy operand target mismatch')
        copy_rows.append((i, hex(offset), left[offset:offset+4].hex(), hex(a),
                          right[offset:offset+4].hex(), hex(b)))
    if any(a != b for i, (a, b) in enumerate(zip(left, right)) if i not in masks):
        raise ValueError('unmasked grow bodies differ')
    constant_rows = []
    for label, va, prefix, width in CONSTANTS:
        prefix = bytes.fromhex(prefix)
        off, raw = read_va(data, secs, va, len(prefix) + width, True)
        if not raw.startswith(prefix):
            raise ValueError('constant opcode mismatch')
        value = int.from_bytes(raw[len(prefix):], 'little')
        constant_rows.append((label, hex(va), hex(off), raw.hex(), hex(value), value))
    literal_rows = []
    for label, va, pattern in LITERALS:
        expected = bytes.fromhex(pattern)
        off, raw = read_va(data, secs, va, len(expected))
        if raw != expected:
            raise ValueError('literal mismatch')
        literal_rows.append((label, hex(va), hex(off), raw.hex()))
    location = 0x5685aa8
    path_va = rel.get(location)
    if path_va is None:
        raise ValueError('missing overflow-location relocation')
    _, loc = read_va(data, secs, location, 24)
    path_length, line, column = struct.unpack_from('<QII', loc, 8)
    if not 0 < path_length < 256:
        raise ValueError('invalid location path length')
    _, path = read_va(data, secs, path_va, path_length)
    suffix = '/'.join(path.decode('utf-8').split('/')[-3:])
    if suffix != 'src/raw/mod.rs' or (line, column) != (37, 40):
        raise ValueError('unexpected overflow location')
    location_rows = [(hex(location), hex(path_va), path_length, suffix, line, column)]
    return (fn_rows, call_rows, branch_rows, witness_rows, copy_rows,
            constant_rows, literal_rows, location_rows)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(map(str, r)) + '\n' for r in rows)


def generate(data, out):
    fn, calls, branches, witnesses, copies, constants, literals, locations = analyse(data)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'functions.json').write_text(json.dumps(fn, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (out / 'calls.tsv').write_text(tsv(('role','site_va','bytes','kind','slot_va','target_va'), calls), encoding='utf-8')
    (out / 'branches.tsv').write_text(tsv(('role','site_va','bytes','taken_va','fallthrough_va'), branches), encoding='utf-8')
    (out / 'witnesses.tsv').write_text(tsv(('role','va','file_offset','bytes'), witnesses), encoding='utf-8')
    (out / 'copy-operands.tsv').write_text(tsv(('index','offset','client_bytes','client_target','oid_bytes','oid_target'), copies), encoding='utf-8')
    (out / 'constants.tsv').write_text(tsv(('role','va','file_offset','bytes','value_hex','value_decimal'), constants), encoding='utf-8')
    (out / 'literals.tsv').write_text(tsv(('role','va','file_offset','bytes'), literals), encoding='utf-8')
    (out / 'locations.tsv').write_text(tsv(('slot_va','path_va','path_length','path_suffix','line','column'), locations), encoding='utf-8')
    summary = {'binary_sha256': DIGEST, 'coordinate_system': 'linked ELF virtual address',
               'selected_fdes': len(fn), 'selected_bytes': sum(x['size'] for x in fn),
               'direct_calls': len(DIRECT_CALLS), 'indirect_calls': len(INDIRECT_CALLS),
               'selected_branches': len(branches), 'instruction_witnesses': len(witnesses),
               'copy_operands': len(copies), 'copy_mask_bytes': len(COPY_MASKS) * 4,
               'immediate_constants': len(constants), 'data_literals': len(literals),
               'relocated_locations': len(locations),
               'limitations': 'Selected static evidence; no target execution or complete CFG.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    data = BINARY.read_bytes()
    checked_data(data)
    generate(data, args.out)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Reproduce node #94 question-settlement byte and arithmetic evidence.

Static ELF reads only; no external programs or execution of captured artifacts.
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
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    'collect_wrapper': 0x44845b0,
    'collect_and_order': 0x489edd0,
    'collect_rows': 0x4877ab0,
    'parse_row': 0x47bbba0,
    'tree_builder': 0x4298890,
    'build_settle_batch': 0x486a7c0,
    'question_body_a': 0x4d6abc0,
    'question_body_b': 0x4d6b5a0,
}
# Bytes selected by hand from instruction boundaries. These are checks, not a
# general x86 decoder or a claim that unlisted instructions are understood.
WINDOWS = {
    'row_length': (0x47bbca8, '498b52106641bf43014883fa640f86a0000000'),
    'unknown_outcome': (0x47bbc99, '6641bfec00'),
    'parse_slot_and_status': (0x47bbd5b, '498b7208488d7c2430ff156e74fb000fb74424303d860100000f85a0000000'),
    'convert_slot_and_status': (0x47bbd9f, '488dbc2490000000ff15bb7bfb0066c7442430ab00a8010f84cc000000f20f11442410'),
    'detail_length': (0x47bbdc2, '488d7c2430e84467fafe4c89e04d8b6424284981fcd10700000f83dafeffff'),
    'conversion_error': (0x47bbec4, '6641bfab00e9edfdffff'),
    'collector_start': (0x4877ac7, '49bd0000000000000080488b4e50488d7c2460e8c140f4ff4c8b642470498d450148894424284939c4740f0f104424600f294424304d39ec751c'),
    'collector_next': (0x4877c12, '488b8c24b0000000488d7c2430488d742460e8773ff4ff488b6c2440483b6c2428745e0f104424300f298424e00000004c39ed744c4c8b642448'),
    'collector_call': (0x489ee19, '488d7c2408488d742430e8888cfdff488b7424184885f60f84b3000000'),
    'sort_cutover': (0x489ef29, '4883fe150f83b6000000'),
    'small_sort_compare': (0x489ef77, '4889f2498b7028493b3073e0'),
    'small_sort_shift': (0x489efbb, '4983f92874884d8d41d84a3b740fb04d89c172cb'),
    'tree_next_row': (0x4298a33, '498d4d2848894c2460498b7510498d45184c89ef4989cd4839de7525e9bc000000'),
    'tree_row_key': (0x4298a74, '488b0f488b5708488b7f18488b40084d39f5'),
    'tree_equal_run': (0x4298ae1, '4839dd745a483b4c243075534885f60f842affffff31d2ff1512554d014c8d4c2448e918ffffff'),
    'tree_insert_row': (0x42989c0, '488b4c24788d500166418997c2010000488b542410498994c768010000c1e005488b54242049891407488b14244989540708488b542408498954071049894c0718488b44242848ff00'),
    'tree_insert_branch': (0x4298b74, '410fb787c20100004883f80b0f823afeffff'),
    'wrapper_status': (0x4484607, '4889e7488d742430e8bca741006681bc24880000008601751b488b442410488943180f1004240f11430866c7038601'),
    'question_lookup': (0x4d6abe4, '4883bea8010000000f84b7000000'),
    'membership_before_fraction': (0x4d6ae0d, '488b43d0bd230000004885c00f84a30100004c8bb4f168010000f20f100411'),
    'membership_tree_branch': (0x4d6ae73, '85f674394883e9017320'),
    'non_binary_text_pointer': (0x4d6ad85, '488d0598a69afb'),
    'foreign_text_pointer': (0x4d6afc2, '488d05b2a49afb4889442418'),
    'classify_a': (0x4d6aeb0, '660f2e0578f849fb75027b34660fefc9660f2ec10f859f0400000f8a99040000'),
    'classify_b': (0x4d6b890, '660f2e0598ee49fb75027b34660fefc9660f2ec10f859f0400000f8a99040000'),
    'second_winner': (0x4d6af00, '49bd00000000000000804c396c24080f847ffeffffbd24000000488d0536a59afb4889442418'),
    'no_winner': (0x4d6b0f8, '4c396c24087571488d05f8a29afb4889442418bd260000004c896c24084c8b642458'),
    'remaining_count': (0x4d6b170, '4c8b742450498d4601483b43e04c8b6424580f85f4010000'),
    'winner_literal_and_batch': (0x4d6b1f3, '48b8000000000000f03f48898424e8000000488dbc2448010000488db424e0000000e8a6f5afff'),
    'zero_batch_rows': (0x486a8f1, '4883c61066662e0f1f840000000000498b0c24498b5424184889542450410f104424080f294424404983c42048894ef048c746f8000000000f284424400f1106488b4c245048894e1049ffc54883c6284939ec75ba'),
    'append_winner': (0x486a9a7, '49ffc64c39f57c304a8d0cad000000004c01e90f10034883c3180f1104c848896cc8100f10030f1144c81849ffc5eb08'),
    'settle_call': (0x4d6b2b7, 'f30f7e45e0488b4dd84889842460010000f30f6f4df0f30f7f0b4c89ff488b742460488b9424d80000004d89e0e8f7e7ffff'),
    'settle_result': (0x4d6b343, '3d860100000f85540100004883c5284983c5d80f8544ffffff'),
    'bad_fraction': (0x4d6b369, 'bd330000004d85ff0f855cfcff'),
    'missing_outcomes_error': (0x4d6b3e7, '488d1dd99f9afbbd3700000066b87b01664189042441c644240208'),
    'success': (0x4d6b496, '6641c704248601'),
}
# Context edges outside the scope belong to the previously researched action
# handler. Remaining edges join the newly selected FDEs or an explicit boundary.
EDGES = [
    ('context_handler_to_collect', 0x4d68dd2, 0x44845b0),
    ('context_handler_to_question', 0x4d68e19, 0x4d6abc0),
    ('collect_to_order', 0x448460f, 0x489edd0),
    ('order_to_rows', 0x489ee23, 0x4877ab0),
    ('first_row', 0x4877ada, 0x47bbba0),
    ('next_row', 0x4877c24, 0x47bbba0),
    ('order_to_tree_builder', 0x489eed2, 0x4298890),
    ('question_to_batch_a', 0x4d6b215, 0x486a7c0),
    ('question_to_batch_b', 0x4d6bbf5, 0x486a7c0),
    ('settle_boundary_a', 0x4d6b2e4, 0x4d69ae0),
    ('settle_boundary_b', 0x4d6bcc4, 0x4d69820),
]
BRANCHES = [
    ('no_global_outcome_map', 0x47bbbea, 'eq', 0x47bbc99),
    ('fraction_length_accepted', 0x47bbcb5, 'below_or_equal', 0x47bbd5b),
    ('parser_error', 0x47bbd74, 'not_equal', 0x47bbe1a),
    ('conversion_error', 0x47bbdb6, 'eq', 0x47bbe88),
    ('details_too_long', 0x47bbddb, 'above_or_equal', 0x47bbcbb),
    ('large_sort', 0x489ef2d, 'above_or_equal', 0x489efe9),
    ('small_sort_pair_ordered', 0x489ef81, 'above_or_equal', 0x489ef63),
    ('distinct_adjacent_keys', 0x4298aeb, 'not_equal', 0x4298b40),
    ('room_in_tree_node', 0x4298b80, 'below', 0x42989c0),
    ('no_question_map', 0x4d6abec, 'eq', 0x4d6aca9),
    ('empty_membership', 0x4d6ae19, 'eq', 0x4d6afc2),
    ('member_found', 0x4d6ae75, 'eq', 0x4d6aeb0),
    ('membership_exhausted', 0x4d6ae97, 'below', 0x4d6afc2),
    ('first_winner', 0x4d6af0f, 'eq', 0x4d6ad94),
    ('has_winner', 0x4d6b0fd, 'not_equal', 0x4d6b170),
    ('remaining_count_mismatch', 0x4d6b182, 'not_equal', 0x4d6b37c),
    ('callee_error', 0x4d6b348, 'not_equal', 0x4d6b4a2),
    ('next_batch_row', 0x4d6b356, 'not_equal', 0x4d6b2a0),
]
# Manually identified rel32 displacement offsets within both same-sized FDEs.
# Each site is required to have one of the explicit instruction prefixes below.
COPY_DISPLACEMENTS = (
    0x45, 0x1c8, 0x21c, 0x2f4, 0x327, 0x35d, 0x398, 0x3b3, 0x3c7,
    0x405, 0x41d, 0x42c, 0x44c, 0x479, 0x4a1, 0x4db, 0x4f6, 0x52a,
    0x542, 0x57f, 0x5a7, 0x656, 0x725, 0x7cf, 0x7e9, 0x823, 0x82a,
    0x898, 0x8d2, 0x93d, 0x954, 0x95c, 0x969, 0x981, 0x990, 0x998,
    0x9a7, 0x9cb, 0x9d3,
)
TEXTS = [
    ('all_remaining', 0x7153c7, 55),
    ('no_winner', 0x7153fe, 38),
    ('non_binary_fraction', 0x715424, 51),
    ('second_winner', 0x715457, 36),
    ('invalid_outcome', 0x71547b, 35),
]


def check_hash(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET_SHA256:
        raise ValueError('node #94 SHA-256 mismatch')
    return digest


class Image:
    def __init__(self, data):
        check_hash(data)
        self.data = data
        self.sections = sections(data)

    def offset(self, va, size=1):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size < 0:
            raise ValueError('invalid VA range')
        matches = [s for s in self.sections if s['type'] != 8 and s['size']
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('VA range is absent, ambiguous, or not file-backed')
        sec = matches[0]
        pos = sec['offset'] + va - sec['address']
        if pos + size > len(self.data):
            raise ValueError('VA range is outside file')
        return pos

    def read(self, va, size):
        pos = self.offset(va, size)
        return self.data[pos:pos + size]

    def relocations(self, slots):
        # ELF64 Rela: r_offset, r_info, r_addend. R_X86_64_RELATIVE is 8,
        # with symbol index zero. Refuse duplicates and other relocation kinds.
        found = {}
        for s in self.sections:
            if s['type'] != 4:  # SHT_RELA
                continue
            if s['size'] % 24:
                raise ValueError('invalid RELA section size')
            for pos in range(s['offset'], s['offset'] + s['size'], 24):
                where, info, addend = struct.unpack_from('<QQq', self.data, pos)
                if where in slots:
                    if where in found or info != 8:
                        raise ValueError('ambiguous or unsupported slot relocation')
                    found[where] = addend
        if set(found) != set(slots):
            raise ValueError('missing slot relocation')
        return found


def validate_windows(image):
    for name, (va, expected) in WINDOWS.items():
        wanted = bytes.fromhex(expected)
        if image.read(va, len(wanted)) != wanted:
            raise ValueError('unexpected instruction bytes: ' + name)


def relative_call(image, site):
    raw = image.read(site, 5)
    if raw[0] != 0xe8:
        raise ValueError('expected a direct relative call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def indirect_slot(image, site):
    raw = image.read(site, 6)
    if raw[:2] != b'\xff\x15':
        raise ValueError('expected an indirect RIP-relative call')
    return site + 6 + struct.unpack_from('<i', raw, 2)[0]


def rip_lea_target(image, site):
    raw = image.read(site, 7)
    if raw[:3] not in (b'\x48\x8d\x05', b'\x48\x8d\x1d'):
        raise ValueError('expected a RIP-relative LEA')
    return site + 7 + struct.unpack_from('<i', raw, 3)[0]


def conditional_branch(image, site):
    raw = image.read(site, 6)
    names = {2: 'below', 3: 'above_or_equal', 4: 'eq', 5: 'not_equal',
             6: 'below_or_equal', 10: 'parity', 11: 'not_parity'}
    if raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        code, width = raw[1] & 15, 6
    elif 0x70 <= raw[0] <= 0x7f:
        code, width = raw[0] & 15, 2
    else:
        raise ValueError('expected a conditional branch')
    if code not in names:
        raise ValueError('unsupported conditional branch')
    return names[code], branch_target(site, raw, 0, width), raw[:width]


def compare_body_copies(image, end_a, end_b):
    """Compare entire FDE ranges with only identified rel32 operands masked."""
    start_a, start_b = FUNCTIONS['question_body_a'], FUNCTIONS['question_body_b']
    size = end_a - start_a
    if size <= 0 or end_b - start_b != size:
        raise ValueError('question body FDE sizes differ')
    a, b = image.read(start_a, size), image.read(start_b, size)
    differing = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    different_set = set(differing)
    starts = tuple(i for i in differing if i - 1 not in different_set)
    if starts != COPY_DISPLACEMENTS:
        raise ValueError('unexpected locations of body differences')
    mask, rows = set(), []
    prefixes = [(bytes.fromhex('660f2e05'), 'ucomisd_data'),
                (bytes.fromhex('488d05'), 'lea_data'),
                (bytes.fromhex('488d1d'), 'lea_data'),
                (bytes.fromhex('488b1d'), 'load_slot'),
                (bytes.fromhex('4c8b3d'), 'load_slot'),
                (bytes.fromhex('4c8b25'), 'load_slot'),
                (bytes.fromhex('ff15'), 'call_slot'),
                (bytes.fromhex('e8'), 'direct_call')]
    differences = 0
    for offset in starts:
        if offset < 4 or offset + 4 > size or mask.intersection(range(offset, offset + 4)):
            raise ValueError('invalid or overlapping copy displacement')
        matched = [(prefix, label) for prefix, label in prefixes
                   if a[offset-len(prefix):offset] == prefix
                   and b[offset-len(prefix):offset] == prefix]
        if not matched:
            raise ValueError('unrecognized displacement instruction')
        prefix, label = matched[0]
        da = struct.unpack_from('<i', a, offset)[0]
        db = struct.unpack_from('<i', b, offset)[0]
        target_a, target_b = start_a + offset + 4 + da, start_b + offset + 4 + db
        if target_a != target_b:
            if (offset, label, target_a, target_b) != (0x725, 'direct_call', 0x4d69ae0, 0x4d69820):
                raise ValueError('unexpected differing rel32 target')
            differences += 1
        if a[offset:offset+4] == b[offset:offset+4]:
            raise ValueError('unnecessary displacement mask')
        mask.update(range(offset, offset + 4))
        rows.append((hex(offset), label, prefix.hex(), hex(start_a + offset),
                     a[offset:offset+4].hex(), hex(target_a), hex(start_b + offset),
                     b[offset:offset+4].hex(), hex(target_b)))
    if differences != 1 or not set(differing) <= mask:
        raise ValueError('question bodies differ outside their documented operands')
    return rows, {'fde_bytes_each': size, 'masked_operand_bytes': len(mask),
                  'unmasked_equal_bytes': size - len(mask),
                  'raw_differing_bytes': len(differing),
                  'rel32_operands': len(rows), 'different_resolved_targets': differences}


def branch_target(base, code, offset, width):
    if width == 2:
        displacement = struct.unpack_from('<b', code, offset + 1)[0]
    elif width == 6:
        displacement = struct.unpack_from('<i', code, offset + 2)[0]
    else:
        raise ValueError('unsupported conditional branch width')
    return base + offset + width + displacement


def classify(bits, code, base):
    """Interpret with DAZ off and invalid/denormal FP exceptions masked.

    Only ZF and PF matter. Equality/unordered follow IEEE-754 binary64
    encodings; no host float or target execution is used.
    """
    if not 0 <= bits < 1 << 64:
        raise ValueError('binary64 payload out of range')
    if len(code) != 32 or code[:4] != b'\x66\x0f\x2e\x05' or code[12:21] != bytes.fromhex('660fefc9660f2ec10f'):
        raise ValueError('unsupported classifier instructions')
    if code[8:9] != b'\x75' or code[10:11] != b'\x7b' or code[21:22] != b'\x85' or code[26:28] != b'\x0f\x8a':
        raise ValueError('unsupported classifier branches')
    one_va = base + 8 + struct.unpack_from('<i', code, 4)[0]
    if one_va != 0x20a730:
        raise ValueError('unexpected comparison constant address')
    alternate = branch_target(base, code, 8, 2)
    winner = branch_target(base, code, 10, 2)
    bad_a = branch_target(base, code, 20, 6)
    bad_b = branch_target(base, code, 26, 6)
    if (alternate != base + 12 or winner != base + 0x40
            or bad_a != base + 0x4b9 or bad_a != bad_b):
        raise ValueError('unexpected classifier control flow')
    exp = (bits >> 52) & 0x7ff
    frac = bits & ((1 << 52) - 1)
    unordered = exp == 0x7ff and frac != 0
    equal_one = bits == 0x3ff0000000000000
    # ucomisd sets both ZF and PF on unordered. JNE then JNP.
    zf, pf = unordered or equal_one, unordered
    if zf and not pf:
        return 'winner', winner
    equal_zero = (bits & 0x7fffffffffffffff) == 0
    zf, pf = unordered or equal_zero, unordered
    if not zf or pf:
        return 'reject', bad_a
    return 'zero', base + 32


def partition(code, base):
    """Partition all payloads by sign, exponent and zero/nonzero fraction.

    Each partition is homogeneous for equality with zero/one and unordered;
    nonzero fraction classes have (2**52 - 1) members.
    """
    totals = {'zero': 0, 'winner': 0, 'reject': 0}
    paths = {}
    groups = 0
    for sign in range(2):
        for exp in range(2048):
            for fraction_nonzero in (0, 1):
                bits = (sign << 63) | (exp << 52) | fraction_nonzero
                result, pc = classify(bits, code, base)
                size = ((1 << 52) - 1) if fraction_nonzero else 1
                totals[result] += size
                paths[result] = pc
                groups += 1
    if sum(totals.values()) != 1 << 64:
        raise ValueError('incomplete binary64 partition')
    return {'partition_count': groups, 'payload_count': 1 << 64,
            'counts': totals, 'terminal_addresses': {k: hex(v) for k, v in sorted(paths.items())}}


def abstract_question(rows, existing, remaining, statuses=()):
    """Model the newly inspected validation path at the helper boundary.

    rows are ordered distinct (id, payload) pairs after input collection.
    statuses represent successive boundary return words. It is not a machine
    emulator and does not implement the parser or settlement callee.
    """
    code = bytes.fromhex(WINDOWS['classify_a'][1])
    base = WINDOWS['classify_a'][0]
    ids = [r[0] for r in rows]
    if len(ids) != len(set(ids)):
        raise ValueError('model expects distinct collected IDs')
    losers, winner = [], None
    for identifier, bits in rows:
        if identifier not in existing:
            return 'invalid_outcome', []
        kind, _ = classify(bits, code, base)
        if kind == 'reject':
            return 'non_binary_fraction', []
        if kind == 'winner':
            if winner is not None:
                return 'second_winner', []
            winner = identifier
        else:
            losers.append(identifier)
    if winner is None:
        return 'no_winner', []
    if len(losers) + 1 != remaining:
        return 'all_remaining', []
    calls = []
    for index, identifier in enumerate(losers + [winner]):
        price = 0 if identifier != winner else 0x3ff0000000000000
        calls.append((identifier, price))
        status = statuses[index] if index < len(statuses) else 0x186
        if status != 0x186:
            return 'callee_error', calls
    return 'success', calls


def coalesce_step(code, next_present, equal_key, allocated):
    """Interpret the fixed adjacent-key branch window at 0x4298ae1."""
    base = 0x4298ae1
    if (len(code) != 39 or code[:4] != bytes.fromhex('4839dd74')
            or code[5:11] != bytes.fromhex('483b4c243075')
            or code[12:17] != bytes.fromhex('4885f60f84')
            or code[21:25] != bytes.fromhex('31d2ff15')
            or code[29:35] != bytes.fromhex('4c8d4c2448e9')):
        raise ValueError('unexpected adjacent-key instructions')
    no_next = branch_target(base, code, 3, 2)
    different = branch_target(base, code, 10, 2)
    no_allocation = branch_target(base, code, 15, 6)
    after_cleanup = base + 39 + struct.unpack_from('<i', code, 35)[0]
    if (no_next != 0x4298b40 or different != no_next
            or no_allocation != 0x4298a20 or after_cleanup != no_allocation):
        raise ValueError('unexpected adjacent-key control flow')
    if not next_present or not equal_key:
        return 'keep_current'
    return 'drop_current_with_cleanup' if allocated else 'drop_current_without_cleanup'


def coalesce_sorted(rows):
    """Model the selected adjacent-key loop after an ordered row stream."""
    code = bytes.fromhex(WINDOWS['tree_equal_run'][1])
    result = []
    for index, row in enumerate(rows):
        if index and row[0] < rows[index - 1][0]:
            raise ValueError('coalescer expects nondecreasing keys')
        next_present = index + 1 < len(rows)
        equal_key = next_present and row[0] == rows[index + 1][0]
        if coalesce_step(code, next_present, equal_key, False) == 'keep_current':
            result.append(row)
    return result


def length_gate(value, kind, code):
    """Decode the specific unsigned cmp/jcc pair in the pinned row function."""
    if not isinstance(value, int) or not 0 <= value < 1 << 64:
        raise ValueError('length must be an unsigned 64-bit integer')
    if kind == 'fraction':
        if len(code) != 19 or code[9:12] != bytes.fromhex('4883fa') or code[13:15] != bytes.fromhex('0f86'):
            raise ValueError('unexpected fraction length comparison')
        limit = struct.unpack_from('<b', code, 12)[0]
        if limit < 0:
            raise ValueError('negative sign-extended fraction limit')
        return value <= limit
    if kind == 'detail':
        if len(code) != 31 or code[18:21] != bytes.fromhex('4981fc') or code[25:27] != bytes.fromhex('0f83'):
            raise ValueError('unexpected detail length comparison')
        cutoff = struct.unpack_from('<i', code, 21)[0]
        if cutoff < 0:
            raise ValueError('negative sign-extended detail cutoff')
        return value < cutoff
    raise ValueError('unknown length gate')


def abstract_input(outcome_exists, fraction_len, parser_ok, conversion_ok, detail_len):
    """Ordered row gates, assuming earlier collection and status preconditions."""
    if not outcome_exists:
        return 'unknown_outcome_0xec'
    fraction_code = bytes.fromhex(WINDOWS['row_length'][1])
    detail_code = bytes.fromhex(WINDOWS['detail_length'][1])
    if not length_gate(fraction_len, 'fraction', fraction_code):
        return 'fraction_length_0x143'
    if not parser_ok:
        return 'parser_error'
    if not conversion_ok:
        return 'conversion_error_0xab'
    if not length_gate(detail_len, 'detail', detail_code):
        return 'detail_length_0x143'
    return 'accepted'


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.writer(out, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(data, output):
    image = Image(data)
    validate_windows(image)
    _, fdes = eh_frame_records(data, image.sections)
    by_start = {}
    for row in fdes:
        if row['start'] in FUNCTIONS.values():
            if row['start'] in by_start:
                raise ValueError('duplicate selected FDE')
            by_start[row['start']] = row
    if set(by_start) != set(FUNCTIONS.values()):
        raise ValueError('missing selected FDE')
    function_rows = []
    for name, start in FUNCTIONS.items():
        fde = by_start[start]
        executable = [s for s in image.sections if s['type'] != 8 and s['flags'] & 4
                      and s['address'] <= start and fde['end'] <= s['address'] + s['size']]
        if len(executable) != 1:
            raise ValueError('FDE is not wholly within one file-backed executable section')
        raw = image.read(start, fde['end'] - start)
        function_rows.append((name, hex(start), hex(fde['end']), hex(fde['fde']),
                              hex(image.offset(start)), len(raw), hashlib.sha256(raw).hexdigest()))
    clone_rows, clone_summary = compare_body_copies(image,
        by_start[FUNCTIONS['question_body_a']]['end'], by_start[FUNCTIONS['question_body_b']]['end'])
    body_size = clone_summary['fde_bytes_each']
    a_body = image.read(FUNCTIONS['question_body_a'], body_size)
    b_body = image.read(FUNCTIONS['question_body_b'], body_size)
    raw_body_rows = [(hex(i), a_body[i:i+32].hex(), b_body[i:i+32].hex())
                     for i in range(0, body_size, 32)]
    edge_rows = []
    for name, site, expected in EDGES:
        target = relative_call(image, site)
        if target != expected:
            raise ValueError('unexpected direct call: ' + name)
        edge_rows.append((name, hex(site), image.read(site, 5).hex(), hex(target)))
    branch_rows = []
    for name, site, expected_cond, expected_target in BRANCHES:
        cond, target, raw = conditional_branch(image, site)
        if cond != expected_cond or target != expected_target:
            raise ValueError('unexpected conditional branch: ' + name)
        owner = [r for r in by_start.values() if r['start'] <= site < r['end']]
        if len(owner) != 1 or not owner[0]['start'] <= target < owner[0]['end']:
            raise ValueError('conditional branch leaves selected FDE')
        branch_rows.append((name, hex(site), raw.hex(), cond, hex(target)))
    slots = {'text_parse': (0x47bbd64, 0x57731d8, 0x3799510),
             'decimal_to_f64': (0x47bbda7, 0x5773968, 0x4ead680),
             'large_row_sort': (0x489efee, 0x5775038, 0x44861f0)}
    actual = image.relocations({v[1] for v in slots.values()})
    slot_rows = []
    for name, (site, want_slot, target) in slots.items():
        slot = indirect_slot(image, site)
        if slot != want_slot or actual[slot] != target:
            raise ValueError('unexpected slot: ' + name)
        slot_rows.append((name, hex(site), hex(slot), 'R_X86_64_RELATIVE', hex(target)))
    for name, start in FUNCTIONS.items():
        end = by_start[start]['end']
        if not all(start <= va and va + len(bytes.fromhex(h)) <= end
                   for n, (va, h) in WINDOWS.items()
                   if (name == 'parse_row' and n in ('unknown_outcome','row_length','parse_slot_and_status','convert_slot_and_status','detail_length','conversion_error'))
                   or (name == 'question_body_a' and n in ('question_lookup','membership_before_fraction','membership_tree_branch','non_binary_text_pointer','foreign_text_pointer','classify_a','second_winner','no_winner','remaining_count','winner_literal_and_batch','settle_call','settle_result','bad_fraction','missing_outcomes_error','success'))
                   or (name == 'question_body_b' and n == 'classify_b')
                   or (name == 'build_settle_batch' and n in ('zero_batch_rows','append_winner'))
                   or (name == 'collect_rows' and n in ('collector_start','collector_next'))
                   or (name == 'collect_and_order' and n in ('collector_call','sort_cutover','small_sort_compare','small_sort_shift'))
                   or (name == 'tree_builder' and n in ('tree_next_row','tree_row_key','tree_equal_run','tree_insert_row','tree_insert_branch'))
                   or (name == 'collect_wrapper' and n == 'wrapper_status')):
            raise ValueError('selected window outside FDE: ' + name)
    constant = image.read(0x20a730, 8)
    if constant != bytes.fromhex('000000000000f03f'):
        raise ValueError('unexpected binary64 constant')
    text_rows = []
    for name, va, size in TEXTS:
        text_rows.append((name, hex(va), hex(image.offset(va, size)), size,
                          image.read(va, size).decode('ascii')))
    for site, target in [(0x4d6ad85, 0x715424), (0x4d6af1a, 0x715457),
                         (0x4d6afc2, 0x71547b), (0x4d6b0ff, 0x7153fe),
                         (0x4d6b3e7, 0x7153c7)]:
        if rip_lea_target(image, site) != target:
            raise ValueError('unexpected text pointer')
    windows = [(name, hex(va), hex(image.offset(va, len(bytes.fromhex(h)))), h)
               for name, (va, h) in WINDOWS.items()]
    gate_a = image.read(WINDOWS['classify_a'][0], 32)
    gate_b = image.read(WINDOWS['classify_b'][0], 32)
    pa = partition(gate_a, WINDOWS['classify_a'][0])
    pb = partition(gate_b, WINDOWS['classify_b'][0])
    if pa['counts'] != pb['counts'] or pa['counts'] != {'zero': 2, 'winner': 1, 'reject': (1 << 64) - 3}:
        raise ValueError('classifier partition mismatch')
    cases = [
        ('positive_zero', 0x0000000000000000), ('negative_zero', 0x8000000000000000),
        ('positive_min_subnormal', 0x0000000000000001), ('negative_min_subnormal', 0x8000000000000001),
        ('below_one', 0x3fefffffffffffff), ('one', 0x3ff0000000000000),
        ('above_one', 0x3ff0000000000001), ('minus_one', 0xbff0000000000000),
        ('positive_inf', 0x7ff0000000000000), ('negative_inf', 0xfff0000000000000),
        ('quiet_nan', 0x7ff8000000000001), ('signaling_nan', 0x7ff0000000000001),
    ]
    case_rows = []
    for name, bits in cases:
        a, target_a = classify(bits, gate_a, WINDOWS['classify_a'][0])
        b, target_b = classify(bits, gate_b, WINDOWS['classify_b'][0])
        if a != b:
            raise ValueError('classifier copies disagree')
        case_rows.append((name, f'{bits:016x}', a, hex(target_a), b, hex(target_b)))
    z, o, h = 0, 0x3ff0000000000000, 0x3fe0000000000000
    scenarios = [
        ('one_winner', [(10,o)], {10}, 1, ()),
        ('winner_between_losers', [(10,z),(20,o),(30,1<<63)], {10,20,30}, 3, ()),
        ('no_rows', [], set(), 0, ()),
        ('no_winner', [(10,z),(20,z)], {10,20}, 2, ()),
        ('two_winners', [(10,o),(20,o)], {10,20}, 2, ()),
        ('fraction_half', [(10,h)], {10}, 1, ()),
        ('foreign_id_before_price', [(10,h)], set(), 1, ()),
        ('missing_remaining', [(10,o)], {10,20}, 2, ()),
        ('callee_rejects_second', [(10,z),(20,z),(30,o)], {10,20,30}, 3, (0x186,0x140)),
    ]
    scenario_rows = []
    for label, rows, existing, count, statuses in scenarios:
        result, calls = abstract_question(rows, existing, count, statuses)
        scenario_rows.append((label, ','.join(f'{i}:{bits:016x}' for i,bits in rows),
                              ','.join(str(i) for i in sorted(existing)), count,
                              ','.join(hex(s) for s in statuses), result,
                              ','.join(f'{i}:{bits:016x}' for i,bits in calls)))
    input_cases = [
        ('minimum', True, 0, True, True, 0),
        ('inclusive_limits', True, 100, True, True, 2000),
        ('unknown_before_length', False, 101, False, False, 2001),
        ('fraction_too_long', True, 101, False, False, 2001),
        ('parser_before_conversion', True, 100, False, False, 2001),
        ('conversion_before_details', True, 100, True, False, 2001),
        ('details_too_long', True, 100, True, True, 2001),
    ]
    input_rows = [(name, int(exists), length, int(parsed), int(converted), details,
                   abstract_input(exists, length, parsed, converted, details))
                  for name, exists, length, parsed, converted, details in input_cases]
    coalesce_cases = [
        ('empty', []), ('distinct', [(1,0),(2,o)]),
        ('duplicates', [(1,0),(1,o),(2,o)]),
        ('three_equal', [(5,0),(5,o),(5,h)]),
    ]
    coalesce_rows = []
    for label, rows in coalesce_cases:
        serialize = lambda items: ','.join(f'{i}:{v:016x}' for i,v in items)
        coalesce_rows.append((label, serialize(rows), serialize(coalesce_sorted(rows))))
    coal_code = image.read(WINDOWS['tree_equal_run'][0], len(bytes.fromhex(WINDOWS['tree_equal_run'][1])))
    coal_steps = [(int(n), int(e), int(a), coalesce_step(coal_code, n, e, a))
                  for n,e,a in [(False,False,False), (False,True,True), (True,False,False),
                                (True,False,True), (True,True,False), (True,True,True)]]
    length_rows = []
    for kind, values, name in [('fraction', (0, 99, 100, 101, (1 << 64)-1), 'row_length'),
                               ('detail', (0, 1999, 2000, 2001, (1 << 64)-1), 'detail_length')]:
        va, encoding = WINDOWS[name]
        raw = image.read(va, len(bytes.fromhex(encoding)))
        for value in values:
            length_rows.append((kind, hex(va), value, int(length_gate(value, kind, raw))))
    output.mkdir(parents=True, exist_ok=True)
    write_tsv(output / 'functions.tsv', ['role','start_va','end_va_exclusive','fde_va','file_offset','fde_bytes','sha256'], function_rows)
    write_tsv(output / 'windows.tsv', ['label','start_va','file_offset','bytes_hex'], windows)
    write_tsv(output / 'edges.tsv', ['label','call_va','bytes_hex','target_va'], edge_rows)
    write_tsv(output / 'branches.tsv', ['label','branch_va','bytes_hex','condition','taken_target_va'], branch_rows)
    write_tsv(output / 'body-rel32.tsv', ['offset','kind','instruction_prefix_hex','operand_a_va','operand_a_hex','target_a_va','operand_b_va','operand_b_hex','target_b_va'], clone_rows)
    write_tsv(output / 'body-raw.tsv', ['offset','body_a_hex','body_b_hex'], raw_body_rows)
    write_tsv(output / 'slots.tsv', ['label','call_va','slot_va','relocation','addend_va'], slot_rows)
    write_tsv(output / 'texts.tsv', ['label','va','file_offset','bytes','ascii'], text_rows)
    write_tsv(output / 'binary64-cases.tsv', ['case','payload_hex','body_a','target_a','body_b','target_b'], case_rows)
    write_tsv(output / 'model-cases.tsv', ['case','rows_id_payload','existing_ids','remaining_count','callee_statuses','abstract_result','abstract_calls_id_payload'], scenario_rows)
    write_tsv(output / 'input-model.tsv', ['case','outcome_exists','fraction_bytes','parser_ok','conversion_ok','detail_bytes','abstract_result'], input_rows)
    write_tsv(output / 'coalesce-model.tsv', ['case','ordered_input_id_payload','abstract_output_id_payload'], coalesce_rows)
    write_tsv(output / 'coalesce-steps.tsv', ['next_present','keys_equal','current_allocated','interpreted_result'], coal_steps)
    write_tsv(output / 'length-cases.tsv', ['kind','window_va','unsigned_length','admitted'], length_rows)
    summary = {'target_sha256': TARGET_SHA256, 'constant_va': hex(0x20a730),
               'constant_bytes': constant.hex(), 'selected_fdes': len(function_rows),
               'checked_windows': len(windows), 'checked_direct_calls': len(edge_rows),
               'checked_conditional_branches': len(branch_rows),
               'body_copy_comparison': clone_summary,
               'checked_indirect_slots': len(slot_rows), 'body_a': pa, 'body_b': pb,
               'binary64_boundary_cases': len(case_rows), 'abstract_scenarios': len(scenario_rows),
               'abstract_input_cases': len(input_rows), 'coalesce_model_cases': len(coalesce_rows),
               'coalesce_interpreted_steps': len(coal_steps),
               'length_boundary_cases': len(length_rows),
               'qualification': 'Classifier partition assumes DAZ disabled and masked SIMD invalid and denormal-operand exceptions. Other code and indirect callees are not executed.'}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    generate(TARGET.read_bytes(), args.out)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('question_settlement94: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)

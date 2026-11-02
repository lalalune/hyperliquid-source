#!/usr/bin/env python3
"""Static, digest-bound analysis of the long trigger-candidate sort in node 94."""
import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These labels are descriptions, not recovered symbol names. Ends are checked
# against .eh_frame and are half-open unwind extents, not a symbol census.
FUNCTIONS = (
    ('long_sort_a', 0x4486f50, 0x4487057),
    ('long_sort_b', 0x44898b0, 0x44899b7),
    ('run_merge_a', 0x4dc43b0, 0x4dc4a9b),
    ('run_merge_b', 0x4db8660, 0x4db8d4b),
    ('partition_a', 0x4496ec0, 0x4497436),
    ('partition_b', 0x4491c40, 0x44921b6),
    ('small_sort', 0x4919550, 0x4919b36),
    ('pivot_selector', 0x45c1360, 0x45c1426),
)

# Instruction boundaries were inspected separately. Each pin is a fixed exact
# byte sequence; this tool performs no general instruction decoding.
PINS = (
    ('small_second_network', 0x4919655, '488d14ed00000000488d14924c8d0c174c8b441728488b4417784531d24531db4c3b0417410f93c2410f92c34c8d04174983c0784c8d3c174983c750483b4417504f8d1c9b4f8d14924f8d34d14c89f8490f42c04d0f42c74d8b384f8b14d14d39d74d89f44c0f42e04c8b284f3b2cd94f8d0cd94d0f42e14c0f42c80f114b78490f42c64d39d74d0f43f0490f42c00f1183880000004c8b004d3b0424488b49204d89e04c0f42c048898b98000000490f42c4498b492048894c1320410f1001410f1049100f114c13100f110413410f1000410f1048100f11441328498b482048894c13480f114c13380f10000f1048100f114413500f114c1360488b482048894c1370410f1006410f104e100f114413780f118c1388000000498b4e2048898c1398000000'),
    ('small_second_insert', 0x4919945, '4e8b0c114e3b4c11d873b9'),
    ('small_merge_front_back', 0x4919a3d, '4c8b214531d24531db4889ce4c3b27400f93c5410f92c572034889fe4c8b66204d8960200f10060f104e10410f114810410f11004c8b32498b074939c641bc000000004983d4ff4c89fe4939c60f8250ffffff4889d6'),
    ('small_merge_odd', 0x4919aa7, '31c031f64c39ff0f93c0400f92c64989c94c0f42cf'),
    ('sort4_network', 0x4919588, '488b4f28488b57784531c04531d2483b0f410f93c0410f92c2488d47784c8d4f50483b57504f8d14924e8d34d74f8d04804c89ca480f42d04a8d0cc7490f42c14c8b0a4c8b184e8b04c74d39c34989cf4c0f42fa4e3b0cd74d0f42fe4c0f42f2480f42d14d39c3480f43c8480f42d0488b02493b074c89f8480f42c2490f42d74d8b46204c894320410f1006410f104e100f114b100f11034c8b40204c8943480f10000f1048100f114b380f114328488b4220488943700f10020f104a100f114b600f1143500f10090f104110488d14ed00000000488d14924c8d0c174c8b441728488b4417784531d24531db4c3b0417410f93c2410f92c34c8d04174983c0784c8d3c174983c750483b4417504f8d1c9b4f8d14924f8d34d14c89f8490f42c04d0f42c74d8b384f8b14d14d39d74d89f44c0f42e04c8b284f3b2cd94f8d0cd94d0f42e14c0f42c80f114b78490f42c64d39d74d0f43f0490f42c00f1183880000004c8b004d3b0424488b49204d89e04c0f42c048898b98000000490f42c4'),
    ('network_width', 0x491977b, 'ba04000000'),
    ('stack_frame', 0x4486f50, '4157415641554154534881ec001000004889d3'),
    ('caller_finish', 0x432217a, '488b442478488b8c2480000000488b942488000000488d1492488d14d148898c24e800000048898c24f000000048898424f80000004889942400010000488db424e80000004889dfe859ad2200'),
    ('candidate_row', 0x4321d86, '488b842480000000488d0cad000000004801e94c8934c80f284424600f1144c8088b5424708954c818488b542448488954c820'),
    ('caller_threshold', 0x4322159, '488bbc2480000000488d44241748894424204883fd02488b5c24500f838c000000'),
    ('caller_long', 0x4322206, '4883fd15736d488d4c2420ba010000004889eee832175f00'),
    ('caller_dispatch', 0x4322279, '488d5424204889eeff1571434501'),
    ('buffer_plan', 0x4486f63, '4889f148d1e94889f04829c84881fe400d030041bc400d03004c0f42e64939c44c0f46e04983fc67730a4989e6b966000000eb46'),
    ('buffer_heap', 0x4486f97, '4a8d0ce5000000004c8d3c8948b933333333333333034839c8760b31ff4c89feff15fb6f2e014989fe4c89ff4989f5ff150c702e014c89f74c89ee4989c64c89e14885c07440'),
    ('buffer_sort_release', 0x4486fdd, '4531c04883fe41410f92c04c89f24989d9e8bdd393004983fc66761349c1e4034b8d34a44c89f731d2ff1504702e01'),
    ('buffer_failure', 0x448701d, 'bf080000004c89feff158d6f2e014889c34983fc6773084889dfe8d4901d0149c1e4034b8d34a44c89f731d2ff15c16f2e014889dfe8b9901d01'),
    ('run_plan', 0x4dc43d0, '4883fe020f82af0600004889d74989c848b8000000000000004031d248f7f64883fa014883d8ff48898424800000004881fe0110000048897424384889f0731d48d1e84889f14829c14883f940b840000000480f42c14889442420eb274883c801480fbdc889c8d1e883e10101c1b80100000048d3e048d3ee4801c648d1ee4889742420'),
    ('descending_test', 0x4dc45a0, '4c8b174c8b5f284d39d30f83a9000000'),
    ('descending_extend', 0x4dc46b0, '4d89c14c8b064d39c8730f48ffc04883c6284939c775e9'),
    ('ascending_extend', 0x4dc4680, '4d89c14c8b064d39c8723f48ffc04883c6284939c775e9'),
    ('copy_shorter', 0x4dc4908, '4d39ef4c89e8490f42c74839c10f8298feffff4a8d0cad000000004c01e9488d2ccb4d39fd4889de480f47f548c1e0034c8d24804889d74c89e2ff1598969a004c8b4424184d01c44d39fd766f'),
    ('merge_backward', 0x4dc4960, '488d4dd8498b5424d831f631ff483b55d8498d5424d8400f92c6480f42d1400f93c7488b4a20488948200f10020f104a100f1148100f1100488d0cbf488d6ccdd8488d0cb64d8d24cc4983c4d8'),
    ('merge_forward', 0x4dc49d0, '488b4d0031c031d2483b0e0f92c10f93c24889f7480f42fd4c8b47204c8943200f10070f104f100f114b100f1103488d1492488d34d64883c328'),
    ('small_dispatch', 0x4496edf, '4883fe21731e4c89e74c89ee4c89fa4889e94c8b8424a0000000e852264800e9dd040000'),
    ('pivot_threshold', 0x4496f4b, '4883fb40732f498b0424498b0e4839c8400f92c6488b3a4839f80f92c04030f04839f90f92c14030f14c0f45f284c04d0f45f4eb164c89e74c89f64c8b8424a0000000e8cda312004989c6'),
    ('partition_less', 0x4497020, '488b384883c1d8493b3e4889cf490f42ff4f8d44ad004c8b48204e894cc7200f10000f104810420f114cc710420f1104c74983d5004883c028'),
    ('partition_equal', 0x4497220, '498b364883c1d8483b304889ce490f43f7488d7cad004c8b40204c8944fe200f10000f1048100f114cfe100f1104fe4883ddff4883c028'),
    ('fallback', 0x44973c1, '4c89e74889de4c89fa4889e941b8010000004c8b8c24a0000000e8d0cf9200'),
    ('small_guard', 0x491955e, '4883fe020f8291050000488d46104839c10f82990500004889d34889f548d1ed4883fe070f8608020000'),
    ('small_insert', 0x4919855, '4e8b040b4e3b440bd873b9'),
    ('small_shift', 0x49198a1, '4983fa280f8455ffffff4d8d4ad84e3b4413b04d89ca72c7'),
    ('median', 0x45c13eb, '498b06488b0b4839c80f92c2498b374839f00f92c030d04839f10f92c130d1490f45df84c0490f45de4889d8'),
)

# Each mask is exactly one four-byte PC-relative displacement. None removes an
# opcode, ModRM byte, conditional branch, or data/relocation value. The pairs
# are compared only as code bodies, not as proof of equivalent callees.
PAIRS = (
    ('long_sort', 0x4486f50, 0x44898b0, (0x69, 0x78, 0x9f, 0xb8, 0xd7, 0xe8, 0xfb, 0x103)),
    ('run_merge', 0x4dc43b0, 0x4db8660, (0x182, 0x3eb, 0x4b8, 0x52c, 0x594, 0x6d5)),
    ('partition', 0x4496ec0, 0x4491c40, (0x3a, 0xcf, 0x1f4, 0x314, 0x3f4, 0x51c, 0x54a, 0x551, 0x55c, 0x563, 0x572)),
)

# Calls in excluded callers are context, not subjects of this packet.
# The slot addend is read from R_X86_64_RELATIVE, not from a runtime process.
SLOT_CALLS = (
    ('selector_a_to_long', 0x4322281, 0x57765f8, 0x4486f50),
    ('selector_b_to_long', 0x43218d1, 0x57749b0, 0x44898b0),
    ('merge_a_to_partition', 0x4dc4530, 0x5776890, 0x4496ec0),
    ('merge_b_to_partition', 0x4db87e0, 0x5776828, 0x4491c40),
    ('partition_a_recursive', 0x44971d2, 0x5776890, 0x4496ec0),
    ('partition_b_recursive', 0x4491f52, 0x5776828, 0x4491c40),
)
DIRECT_CALLS = (
    ('context_host_a_select', 0x4cf5096, 0x4321930),
    ('context_host_a_wrapper', 0x4cf55f8, 0x4d44470),
    ('context_host_a_direct_fire', 0x4cf574d, 0x42ff010),
    ('context_wrapper_a_fire', 0x4d4459c, 0x42ff010),
    ('context_fire_a_insert', 0x42ffc35, 0x4311140),
    ('context_host_b_select', 0x4cfad36, 0x4320f80),
    ('context_host_b_wrapper', 0x4cfb298, 0x4d47070),
    ('context_wrapper_b_fire', 0x4d4719c, 0x4300950),
    ('context_fire_b_insert', 0x4301575, 0x4314da0),
    ('selector_to_short_excluded', 0x4322219, 0x4913950),
    ('selector_to_compact_excluded', 0x43221c2, 0x454cf20),
    ('long_a_to_merge', 0x4486fee, 0x4dc43b0),
    ('long_b_to_merge', 0x448994e, 0x4db8660),
    ('partition_a_to_small', 0x4496ef9, 0x4919550),
    ('partition_b_to_small', 0x4491c79, 0x4919550),
    ('partition_a_to_pivot', 0x4496f8e, 0x45c1360),
    ('partition_b_to_pivot', 0x4491d0e, 0x45c1360),
    ('partition_a_to_merge_fallback', 0x44973db, 0x4dc43b0),
    ('partition_b_to_merge_fallback', 0x449215b, 0x4db8660),
)
BRANCH_SITES = (
    ('selector_under_two', 0x4322174, 0x83),
    ('selector_long_at_21', 0x432220a, 0x73),
    ('wrapper_stack_below_103', 0x4486f8b, 0x73),
    ('wrapper_overflow_bound', 0x4486fb0, 0x76),
    ('wrapper_null_allocation', 0x4486fdb, 0x74),
    ('wrapper_release_heap', 0x4486ff7, 0x76),
    ('merge_under_two', 0x4dc43d4, 0x82),
    ('merge_large_run_plan', 0x4dc440e, 0x73),
    ('merge_remaining_at_threshold', 0x4dc4505, 0x73),
    ('merge_large_flag_clear', 0x4dc450c, 0x74),
    ('merge_under_two_remaining', 0x4dc4564, 0x73),
    ('merge_short_run', 0x4dc46d2, 0x82),
    ('merge_buffer_too_short', 0x4dc4915, 0x82),
    ('merge_copy_left_shorter', 0x4dc4953, 0x76),
    ('merge_final_run_ready', 0x4dc4a55, 0x75),
    ('partition_budget_exhausted', 0x4496f24, 0x82),
    ('partition_scratch_short', 0x4496fe6, 0x82),
    ('partition_left_at_least_33', 0x44971df, 0x83),
    ('partition_right_at_least_33', 0x44973b6, 0x83),
    ('merge_ascending', 0x4dc45aa, 0x83),
    ('ascending_break', 0x4dc4689, 0x72),
    ('descending_break', 0x4dc46b9, 0x73),
    ('partition_small_at_most_32', 0x4496ee3, 0x73),
    ('partition_pivot_at_least_64', 0x4496f4f, 0x73),
    ('small_guard_under_two', 0x4919562, 0x82),
    ('small_guard_buffer_short', 0x491956f, 0x82),
    ('small_sort_insertion_at_most_seven', 0x4919582, 0x86),
    ('small_insertion_equal_stays', 0x491985e, 0x73),
)


class EvidenceError(ValueError):
    pass


def authenticate(data):
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        raise EvidenceError('target SHA-256 mismatch')


def file_offset(data, va, length=1, executable=False):
    if not isinstance(va, int) or not isinstance(length, int) or va < 0 or length <= 0:
        raise EvidenceError('invalid address or length')
    matches = [s for s in sections(data) if s['type'] != 8
               and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise EvidenceError('address has no unique file-backed mapping')
    sec = matches[0]
    off = sec['offset'] + va - sec['address']
    if off + length > len(data):
        raise EvidenceError('mapped bytes exceed file')
    return off


def read_va(data, va, length, executable=False):
    off = file_offset(data, va, length, executable)
    return data[off:off + length]


def check_pin(actual, expected):
    if actual != expected:
        raise EvidenceError('pinned instruction bytes changed')


def fde_map(data):
    _, rows = eh_frame_records(data, sections(data))
    by_start = {}
    for row in rows:
        by_start.setdefault(row['start'], []).append(row)
    return by_start


def relative_relocations(data, slots):
    found = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise EvidenceError('partial relocation record')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if slot in slots:
                if info != 8 or slot in found:
                    raise EvidenceError('ambiguous or unsupported slot relocation')
                found[slot] = {'addend': addend, 'file_offset': off,
                               'slot_file_offset': file_offset(data, slot, 8)}
    if set(found) != set(slots):
        raise EvidenceError('missing slot relocation')
    return found


def direct_target(raw, site):
    if len(raw) != 5 or raw[0] != 0xe8:
        raise EvidenceError('expected call rel32')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def slot_target(raw, site, relocs):
    if len(raw) != 6 or raw[:2] != b'\xff\x15':
        raise EvidenceError('expected RIP-relative call through a slot')
    slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
    if slot not in relocs:
        raise EvidenceError('unknown slot')
    return slot, relocs[slot]['addend']


def decode_branch(data, site, expected_opcode):
    raw = read_va(data, site, 2, True)
    if raw[0] == 0x0f:
        raw = read_va(data, site, 6, True)
        if raw[1] != expected_opcode:
            raise EvidenceError('conditional opcode changed')
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        if raw[0] != expected_opcode:
            raise EvidenceError('conditional opcode changed')
        disp = struct.unpack_from('<b', raw, 1)[0]
    names = {0x72: 'below', 0x73: 'above-or-equal', 0x74: 'equal',
             0x75: 'not-equal', 0x76: 'below-or-equal', 0x82: 'below', 0x83: 'above-or-equal',
             0x86: 'below-or-equal'}
    if expected_opcode not in names:
        raise EvidenceError('unsupported branch condition')
    return {'site': hex(site), 'bytes': raw.hex(), 'condition': names[expected_opcode],
            'target': hex(site + len(raw) + disp)}


def compare_pair(data, fdes, a, b, masks):
    x = bytearray(read_va(data, a, fdes[a]['end'] - a, True))
    y = bytearray(read_va(data, b, fdes[b]['end'] - b, True))
    if len(x) != len(y):
        raise EvidenceError('paired extents have different sizes')
    differences = [i for i, (u, v) in enumerate(zip(x, y)) if u != v]
    if any(m < 0 or m + 4 > len(x) for m in masks):
        raise EvidenceError('mask outside extent')
    if any(not any(m <= i < m + 4 for m in masks) for i in differences):
        raise EvidenceError('unmasked paired code difference')
    for m in masks:
        for raw in (x, y):
            prefix = raw[max(0, m - 3):m]
            if not (prefix[-1:] == b'\xe8' or prefix[-2:] == b'\xff\x15' or
                    (len(prefix) == 3 and prefix[0] in (0x48, 0x4c) and
                     prefix[1] == 0x8d and prefix[2] & 0xc7 == 5)):
                raise EvidenceError('mask is not a recognised PC-relative displacement')
        x[m:m + 4] = b'\0' * 4
        y[m:m + 4] = b'\0' * 4
    if x != y:
        raise EvidenceError('normalised paired code mismatch')
    return differences


def constants(pins):
    plan = pins['buffer_plan']
    heap = pins['buffer_heap']
    dispatch = pins['caller_long']
    run = pins['run_plan']
    # Matched windows above include the surrounding opcodes; read immediates
    # only after the entire window has passed the exact-byte check.
    return {
        'selector_min': pins['caller_threshold'][21],
        'selector_long_min': dispatch[3],
        'stack_frame_bytes': struct.unpack_from('<I', pins['stack_frame'], 12)[0],
        'small_scratch_extra': pins['small_guard'][13],
        'network_width': struct.unpack_from('<I', pins['network_width'], 1)[0],
        'stack_max': plan[46],
        'heap_min': plan[39],
        'small_flag_below': pins['buffer_sort_release'][6],
        'capacity_cap': struct.unpack_from('<I', plan, 15)[0],
        'record_stride': pins['partition_less'][-1],
        'arithmetic_half_limit': struct.unpack_from('<Q', heap, 14)[0],
        'run_large_min': struct.unpack_from('<I', run, 50)[0],
        'run_small_cap': run[76],
        'small_partition_min': pins['small_dispatch'][3],
        'pivot_recursive_min': pins['pivot_threshold'][3],
        'small_insertion_max': pins['small_guard'][-7],
    }


def buffer_case(n, c):
    if n < 0 or n >= 1 << 64:
        raise EvidenceError('count outside unsigned 64-bit range')
    if n < c['selector_min']:
        return {'count': n, 'path': 'no_sort', 'scratch_entries': None,
                'scratch_bytes': None, 'small_flag': None}
    if n < c['selector_long_min']:
        return {'count': n, 'path': 'selector_short', 'scratch_entries': None,
                'scratch_bytes': None, 'small_flag': None}
    half = (n + 1) // 2
    required = max(min(n, c['capacity_cap']), half)
    if required < c['heap_min']:
        entries, path = c['stack_max'], 'stack'
    elif half > c['arithmetic_half_limit']:
        entries, path = required, 'capacity_error'
    else:
        entries, path = required, 'heap'
    return {'count': n, 'path': path, 'scratch_entries': entries,
            'scratch_bytes': entries * c['record_stride'] if path != 'capacity_error' else None,
            'small_flag': int(n < c['small_flag_below'])}


def run_threshold(n, c):
    if n < c['selector_min'] or n >= 1 << 64:
        raise EvidenceError('run threshold requires a nontrivial u64 count')
    if n < c['run_large_min']:
        return min((n + 1) // 2, c['run_small_cap'])
    power = (n | 1).bit_length() - 1
    shift = (power + 1) // 2
    return ((1 << shift) + (n >> shift)) // 2


def four_row_network(rows, *, mutant=False):
    """Transcribe the first four-row key-selection network, after byte pins pass.

    Elements are (unsigned key, original position) pairs. `mutant` changes the
    max-pair equality condition and exists only to exercise a negative control.
    This is a model of a selected window, not execution of captured code.
    """
    if len(rows) != 4:
        raise EvidenceError('four rows required')
    a, b, c, d = rows
    if any(not 0 <= x[0] < 1 << 64 for x in rows):
        raise EvidenceError('network key is not u64')
    low_ab, high_ab = (b, a) if b[0] < a[0] else (a, b)
    low_cd, high_cd = (d, c) if d[0] < c[0] else (c, d)
    middle = low_cd if high_cd[0] < high_ab[0] else high_ab
    first, other, last = low_ab, low_cd, high_ab
    if low_cd[0] < low_ab[0]:
        middle, first, other = low_ab, low_cd, high_ab
    later_max = high_cd[0] > high_ab[0] if mutant else high_cd[0] >= high_ab[0]
    if later_max:
        last = high_cd
    else:
        other = high_cd
    if other[0] < middle[0]:
        second, third = other, middle
    else:
        second, third = middle, other
    return [first, second, third, last]


def small_sort_model(rows, *, mutant=False):
    """Model the two sorted halves and front/back merge of a small partition.

    This records selected static semantics; it is not an instruction emulator.
    The result is independently checked against stable key sorting in tests.
    """
    n = len(rows)
    if not 2 <= n <= 32:
        raise EvidenceError('small partition model supports counts 2 through 32')
    midpoint = n // 2
    def half_sort(part):
        seed = 4 if n >= 8 else 1
        out = four_row_network(part[:seed], mutant=mutant) if seed == 4 else list(part[:seed])
        for item in part[seed:]:
            i = len(out)
            while i and item[0] < out[i - 1][0]:
                i -= 1
            out.insert(i, item)
        return out
    left, right = half_sort(rows[:midpoint]), half_sort(rows[midpoint:])
    left_start = right_start = 0
    left_end, right_end = len(left), len(right)
    front, back = [], []
    while left_start < left_end and right_start < right_end:
        if right[right_start][0] < left[left_start][0]:
            front.append(right[right_start])
            right_start += 1
        else:
            front.append(left[left_start])
            left_start += 1
        if left_start >= left_end or right_start >= right_end:
            break
        if right[right_end - 1][0] < left[left_end - 1][0]:
            left_end -= 1
            back.append(left[left_end])
        else:
            right_end -= 1
            back.append(right[right_end])
    front.extend(left[left_start:left_end])
    front.extend(right[right_start:right_end])
    return front + list(reversed(back))


def write_tsv(path, fields, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fields, delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def generate(data, out):
    authenticate(data)
    all_fdes = fde_map(data)
    _, index_rows = unwind_index(data)
    indexed = {row['start']: row for row in index_rows}
    fdes = {}
    function_rows = []
    for name, start, end in FUNCTIONS:
        rows = all_fdes.get(start, [])
        if len(rows) != 1 or rows[0]['end'] != end:
            raise EvidenceError('unexpected FDE extent')
        fde = rows[0]
        if start not in indexed or indexed[start]['fde'] != fde['fde']:
            raise EvidenceError('unwind index does not refer to the selected FDE')
        fdes[start] = fde
        raw = read_va(data, start, end - start, True)
        function_rows.append({'role': name, 'start_va': hex(start), 'end_va': hex(end),
                              'fde_va': hex(fde['fde']), 'unwind_index': indexed[start]['index'], 'file_offset': hex(file_offset(data, start, len(raw), True)),
                              'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    pin_data, window_rows = {}, []
    for label, site, encoded in PINS:
        expected = bytes.fromhex(encoded)
        actual = read_va(data, site, len(expected), True)
        check_pin(actual, expected)
        pin_data[label] = actual
        window_rows.append({'label': label, 'start_va': hex(site), 'end_va': hex(site + len(actual)),
                            'file_offset': hex(file_offset(data, site, len(actual), True)), 'bytes_hex': actual.hex()})
    c = constants(pin_data)
    if c != {'selector_min': 2, 'selector_long_min': 21, 'stack_frame_bytes': 4096, 'small_scratch_extra': 16, 'network_width': 4, 'stack_max': 102, 'heap_min': 103,
             'small_flag_below': 65, 'capacity_cap': 200000, 'record_stride': 40,
             'arithmetic_half_limit': 0x333333333333333, 'run_large_min': 4097,
             'run_small_cap': 64, 'small_partition_min': 33, 'pivot_recursive_min': 64,
             'small_insertion_max': 7}:
        raise EvidenceError('decoded immediate does not match the pinned instruction')
    relocations = relative_relocations(data, {slot for _, _, slot, _ in SLOT_CALLS})
    call_rows = []
    for name, site, slot, target in SLOT_CALLS:
        raw = read_va(data, site, 6, True)
        actual_slot, actual_target = slot_target(raw, site, relocations)
        if (actual_slot, actual_target) != (slot, target):
            raise EvidenceError('slot call differs')
        call_rows.append({'role': name, 'site_va': hex(site), 'bytes_hex': raw.hex(),
                          'kind': 'slot', 'slot_va': hex(slot), 'target_va': hex(target),
                          'relocation_file_offset': hex(relocations[slot]['file_offset']),
                          'slot_file_offset': hex(relocations[slot]['slot_file_offset'])})
    for name, site, target in DIRECT_CALLS:
        raw = read_va(data, site, 5, True)
        if direct_target(raw, site) != target:
            raise EvidenceError('direct call differs')
        call_rows.append({'role': name, 'site_va': hex(site), 'bytes_hex': raw.hex(),
                          'kind': 'rel32', 'slot_va': '', 'target_va': hex(target), 'relocation_file_offset': '', 'slot_file_offset': ''})
    branches = []
    for name, site, opcode in BRANCH_SITES:
        branches.append({'role': name, **decode_branch(data, site, opcode)})
    comparisons = []
    for name, a, b, masks in PAIRS:
        differences = compare_pair(data, fdes, a, b, masks)
        comparisons.append({'role': name, 'first_va': hex(a), 'second_va': hex(b),
                            'differing_bytes': len(differences),
                            'difference_offsets': [hex(x) for x in differences],
                            'masked_displacement_ranges': [[hex(x), hex(x + 4)] for x in masks]})
    bound_values = {0, 1, 2}
    for x in (c['selector_long_min'], c['small_partition_min'], c['small_flag_below'],
              c['heap_min'], c['run_large_min'], c['capacity_cap'],
              2 * c['capacity_cap'], 2 * c['arithmetic_half_limit']):
        bound_values.update((x - 1, x, x + 1))
    cases = [buffer_case(n, c) for n in sorted(bound_values)]
    run_counts = sorted({n for base in (c['selector_min'], 2 * c['run_small_cap'],
                       c['run_large_min'], 2 * (c['run_large_min'] - 1))
                       for n in (base - 1, base, base + 1) if n >= c['selector_min']})
    run_cases = [{'count': n, 'threshold': run_threshold(n, c)} for n in run_counts]
    network_rows = []
    network_mutant_mismatches = 0
    for keys in itertools.product(range(c['network_width']), repeat=c['network_width']):
        rows = list(zip(keys, range(c['network_width'])))
        got = four_row_network(rows)
        reference = sorted(rows, key=lambda row: row[0])
        if got != reference:
            raise EvidenceError('four-row model differs from stable key ordering')
        network_mutant_mismatches += four_row_network(rows, mutant=True) != reference
        network_rows.append({'keys': ','.join(str(key) for key in keys),
                             'output_positions': ','.join(str(row[1]) for row in got)})
    small_model_rows = []
    for n in range(c['selector_min'], c['small_partition_min']):
        if n <= 2 * c['network_width']:
            inputs = itertools.product(range(c['network_width'] - 1), repeat=n)
        else:
            inputs = (tuple(range(n)), tuple(reversed(range(n))), (0,) * n,
                      tuple((i * c['network_width'] + 1) % (c['network_width'] + 1) for i in range(n)))
        case_count = mismatches = mutant_mismatches = 0
        for keys in inputs:
            values = list(zip(keys, range(n)))
            reference = sorted(values, key=lambda row: row[0])
            mismatches += small_sort_model(values) != reference
            mutant_mismatches += small_sort_model(values, mutant=True) != reference
            case_count += 1
        if mismatches:
            raise EvidenceError('small-sort model differs from stable key ordering')
        small_model_rows.append({'count': n, 'cases': case_count,
                                 'mismatches': mismatches, 'tie_mutant_mismatches': mutant_mismatches})
    result = {'target_sha256': TARGET_SHA, 'coordinate_system': 'linked ELF virtual addresses',
              'constants': c, 'functions': function_rows, 'branches': branches,
              'calls': call_rows, 'paired_code': comparisons,
              'model_summary': {'four_row_cases': len(network_rows),
                                'four_row_mutant_mismatches': network_mutant_mismatches,
                                'small_sort_cases': sum(row['cases'] for row in small_model_rows),
                                'small_sort_mutant_mismatches': sum(row['tie_mutant_mismatches'] for row in small_model_rows)},
              'scope': 'Static selected windows and FDE ranges; helper, allocator, execution and full behavior remain unverified.'}
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_tsv(out / 'windows.tsv', ('label', 'start_va', 'end_va', 'file_offset', 'bytes_hex'), window_rows)
    write_tsv(out / 'calls.tsv', ('role', 'site_va', 'bytes_hex', 'kind', 'slot_va', 'target_va', 'relocation_file_offset', 'slot_file_offset'), call_rows)
    write_tsv(out / 'branches.tsv', ('role', 'site', 'bytes', 'condition', 'target'), branches)
    write_tsv(out / 'buffer-boundaries.tsv', ('count', 'path', 'scratch_entries', 'scratch_bytes', 'small_flag'), cases)
    write_tsv(out / 'run-boundaries.tsv', ('count', 'threshold'), run_cases)
    write_tsv(out / 'small-network-model.tsv', ('keys', 'output_positions'), network_rows)
    write_tsv(out / 'small-sort-model.tsv', ('count', 'cases', 'mismatches', 'tie_mutant_mismatches'), small_model_rows)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = generate(TARGET.read_bytes(), args.out)
    except (EvidenceError, ValueError, OSError, struct.error) as error:
        parser.exit(1, f'evidence: {error}\n')
    print(f"Verified {len(result['functions'])} FDEs, {len(result['calls'])} calls and {len(result['branches'])} branches.")


if __name__ == '__main__':
    main()

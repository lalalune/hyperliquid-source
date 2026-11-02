#!/usr/bin/env python3
"""Extract and model the node 94 TWAP sequence-to-size conversion boundary."""
import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK = (1 << 64) - 1
BODIES = {
    0x221eb40: (0x221ec9b, 'c4e88de3e700f4694059f297f1897daefbca2b8b38f84fefa5d5254c7409a296', 'outer_a'),
    0x336e970: (0x336eaac, 'cc9c7e8cf5e4c8516b08a6bccfbef018c75d1f29245826946760ae9c11f474dd', 'outer_b'),
    0x48fc490: (0x48fc5eb, '199a269e7aae170e6f99f9e482ebc2490fecc57b51da8e571bed791031b6bd0e', 'outer_c'),
    0x212e4a0: (0x212f8f0, 'e61cd59b7e6dcdb394856f7af0e4ea6d6626ff820dee3925ad49107653d31e93', 'reader_a'),
    0x3a66630: (0x3a67a80, '2f79ea9cc8fe3f2d04cc163a03ba3323ed4dceba5a8af00313651a9441154c0c', 'reader_b'),
    0x4bcfc70: (0x4bd10c0, '4b574c8a88ee8e4b921a8a1ec57955618eaab772d50b96c92a940f78de32dfff', 'reader_c'),
    0x1edd530: (0x1edd651, '8b54b981e83bdbd88407b8e327d63f22247666dbc48319b01891b58412ffbbf9', 'asset_step_a'),
    0x1eee530: (0x1eee67a, '73ee3e234299459b6df4938b2fe3789eef0b7a7a57f0d7df68025b876e6cb029', 'bool_step_a'),
    0x207faf0: (0x207fd52, 'e2dc10dbf596e42c26199be7c1bf983b9ab372a28b869dcb85c2b6501b8b38cf', 'unsigned_value_a'),
    0x1eb44b0: (0x1eb453e, '554b38e017866d991a3a82598638325d90bea3672dba87f79af5b5c45df3fe1a', 'finish_a'),
    0x34fe880: (0x34fe9a1, '8b0d05cbddefae339197f6ed36cf80e8b2e1997b97fed38824ff1cbe3185114f', 'asset_step_b'),
    0x44e13f0: (0x44e1511, '895fe7ffefa5f1e8d5d2b0085a01e98e0389fa77e2a43c6ca63b8ef80c4b9292', 'asset_step_c'),
    0x34ffa90: (0x34ffbda, '0dc39511057187832c27b360a1e91b1670590fb38c2a133fa695e3b1d345447f', 'bool_step_b'),
    0x44df210: (0x44df35a, '75a510c934a1974c6dd66228f9f4468ae57b02d0dd97ff3e6dc47b38a88b54d0', 'bool_step_c'),
    0x3a37f70: (0x3a381d2, 'cc2083c506031eff6d614949402e665104d9592c2cbc6e3757e80e8fae1d584b', 'unsigned_value_b'),
    0x4b84400: (0x4b84662, 'd7e3d22b87c76df3754f2b6a9bc668701f6019460ff805babe49a5340638aa5f', 'unsigned_value_c'),
    0x3444fb0: (0x344503e, '6560d9b7956c2dd0796aa0851e6a254d4d9ba749729934b0fa4cc3716d79727f', 'finish_b'),
    0x44c3010: (0x44c309e, '5efdea49c463b99544fb24de3cb55a85612735f2a46f709a9c74b30144601007', 'finish_c'),
}
READERS = (0x212e4a0, 0x3a66630, 0x4bcfc70)
OUTERS = (0x221eb40, 0x336e970, 0x48fc490)
DESCRIPTORS = (0x569dd70, 0x56e9c48, 0x5733df8)
NAMES = ('a', 'asset', 'b', 'isBuy', 's', 'sz', 'r', 'reduceOnly', 'm', 'minutes', 'randomize', 't')
# Branch addresses in reader A. The other selected readers use the same offsets.
BRANCHES = (
 (0x212e4c9, 'sequence_tag'), (0x212e4d2, 'other_tag'),
 (0x212ea80, 'asset_error'), (0x212ea8b, 'asset_absent'),
 (0x212eab3, 'buy_error'), (0x212eabd, 'buy_absent'),
 (0x212eacc, 'size_no_buffer'), (0x212eade, 'size_at_end'),
 (0x212eaf2, 'size_present'), (0x212eff8, 'size_counter_overflow'),
 (0x212f022, 'size_reader_error'), (0x212f033, 'size_reader_absent'),
 (0x212f071, 'reduce_error'), (0x212f080, 'minutes_no_buffer'),
 (0x212f092, 'minutes_at_end'), (0x212f0a6, 'minutes_present'),
 (0x212f2c6, 'minutes_counter_overflow'), (0x212f2f0, 'minutes_error'),
 (0x212f322, 'randomize_error'), (0x212f37b, 'finish_ok'),
)
CALLS = (
 (0x212ea74, 'asset_step'), (0x212eaa2, 'buy_step'),
 (0x212eb0f, 'missing_size'), (0x212f016, 'size_value_external'),
 (0x212f055, 'reduce_step'), (0x212f0c4, 'missing_minutes'),
 (0x212f2e4, 'unsigned_value'), (0x212f310, 'randomize_step'),
 (0x212f367, 'finish_step'),
)
# Complete basic blocks selected for the sequence path; offsets are in reader A.
WINDOWS = (
 (0x212e4b4, 0x212e4d8, 'input_dispatch'),
 (0x212ea28, 0x212eaf8, 'sequence_first_three'),
 (0x212eaf8, 0x212eb19, 'size_missing'),
 (0x212efcd, 0x212f0ac, 'size_and_reduce'),
 (0x212f0ac, 0x212f0ef, 'minutes_missing'),
 (0x212f29b, 0x212f3ac, 'minutes_randomize_finish'),
 (0x212f440, 0x212f447, 'asset_missing'),
 (0x212f6b5, 0x212f6d6, 'buy_missing'),
 (0x221eb93, 0x221ebfd, 'outer_a_success'),
 (0x1edd535, 0x1edd595, 'asset_cursor'),
 (0x1eee539, 0x1eee599, 'bool_cursor'),
 (0x1eee5d2, 0x1eee5f7, 'bool_value'),
 (0x1eb44bb, 0x1eb453e, 'finish'),
 (0x207faf7, 0x207fb21, 'unsigned_dispatch'),
 (0x207fc95, 0x207fcb8, 'unsigned_return'),
)


def digest(b):
    return hashlib.sha256(b).hexdigest()


def authenticate(data, expected=DIGEST):
    if digest(data) != expected:
        raise ValueError('target digest mismatch')


def resolver(data, secs, va, size, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid file range')
    found = [s for s in secs if s['type'] != 8 and (not executable or s['flags'] & 4)
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('range is not uniquely file backed')
    s = found[0]
    offset = s['offset'] + va - s['address']
    if offset + size > len(data):
        raise ValueError('truncated file range')
    return offset, data[offset:offset + size]


def branch(data, secs, va):
    _, code = resolver(data, secs, va, 2, True)
    if 0x70 <= code[0] <= 0x7f:
        n, condition = 2, code[0] - 0x70
        delta = struct.unpack('<b', code[1:2])[0]
    elif code[0] == 0x0f and 0x80 <= code[1] <= 0x8f:
        n, condition = 6, code[1] - 0x80
        _, c = resolver(data, secs, va, n, True)
        delta = struct.unpack('<i', c[2:])[0]
    else:
        raise ValueError('unsupported conditional branch')
    _, raw = resolver(data, secs, va, n, True)
    return {'va': hex(va), 'bytes': raw.hex(), 'condition': condition,
            'target_va': hex(va + n + delta), 'fallthrough_va': hex(va + n)}


def rip_lea(data, secs, va, opcode):
    _, raw = resolver(data, secs, va, 7, True)
    if raw[:3] != bytes.fromhex(opcode):
        raise ValueError('unexpected RIP-relative LEA')
    return va + 7 + struct.unpack('<i', raw[3:])[0]


def direct_call(data, secs, va):
    _, raw = resolver(data, secs, va, 5, True)
    if raw[0] != 0xe8:
        raise ValueError('expected direct call')
    return va + 5 + struct.unpack('<i', raw[1:])[0]


def slot_call(data, secs, va):
    _, raw = resolver(data, secs, va, 6, True)
    if raw[:2] != b'\xff\x15':
        raise ValueError('expected indirect call')
    return va + 6 + struct.unpack('<i', raw[2:])[0]


def relocations(data, secs):
    rows = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(rows) != 1 or rows[0]['size'] % 24:
        raise ValueError('bad relocation section')
    s = rows[0]
    out = {}
    for p in range(s['offset'], s['offset'] + s['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, p)
        if info == 8:
            if slot in out:
                raise ValueError('duplicate relative relocation')
            out[slot] = addend
    return out


def expect_bytes(data, secs, va, expected):
    raw = bytes.fromhex(expected)
    if resolver(data, secs, va, len(raw), True)[1] != raw:
        raise ValueError('unexpected cursor instruction')


def replay_bool_cursor(data, secs, present, at_end, marker, counter, value=0):
    """Follow the fixed bytes of bool-step A up to the type decoder boundary."""
    if type(present) is not bool or type(at_end) is not bool:
        raise ValueError('bad cursor state')
    bounded(marker, 0, 255, 'marker')
    bounded(value, 0, 255, 'value')
    bounded(counter, 0, MASK, 'counter')
    # Assert the actual test, movement, marker, counter and return encodings.
    for va, code in (
        (0x1eee539, '48833e00'), (0x1eee53f, '488b4608483b4618'),
        (0x1eee549, '488d482048894e080fb60880f916'),
        (0x1eee559, '66c7070902'),
        (0x1eee581, '488b46204883f8ff'),
        (0x1eee592, '48ffc048894620'),
        (0x1eee5d2, '807c243000'),
        (0x1eee5d9, '0fb66c2431'),
    ):
        expect_bytes(data, secs, va, code)
    jump = {site: branch(data, secs, site) for site in
            (0x1eee53d, 0x1eee547, 0x1eee557, 0x1eee589, 0x1eee5d7)}
    def taken(site, zero):
        condition = jump[site]['condition']
        if condition == 4:
            return zero
        if condition == 5:
            return not zero
        raise ValueError('unexpected cursor condition')
    if taken(0x1eee53d, not present) or taken(0x1eee547, at_end):
        return {'status': 'absent', 'advance': 0, 'counter': counter, 'tag': 9, 'value': 2}
    if not taken(0x1eee557, marker == 0x16):
        return {'status': 'absent', 'advance': 32, 'counter': counter, 'tag': 9, 'value': 2}
    if taken(0x1eee589, counter == MASK):
        return {'status': 'counter_overflow', 'advance': 32, 'counter': counter}
    if taken(0x1eee5d7, marker == 0):
        return {'status': 'external_decoder', 'advance': 32, 'counter': counter + 1}
    return {'status': 'direct_bool', 'advance': 32, 'counter': counter + 1, 'tag': 9, 'value': value}


def replay_inline_cursor(data, secs, which, present, at_end, marker, counter):
    """Follow the reader A size or minutes cursor and overflow guards."""
    if which not in ('size', 'minutes') or type(present) is not bool or type(at_end) is not bool:
        raise ValueError('bad inline cursor state')
    bounded(marker, 0, 255, 'marker')
    bounded(counter, 0, MASK, 'counter')
    start, end_cmp, advance, marker_cmp, over_cmp, incr, branches = (
        (0x212eac3, 0x212ead6, 0x212eae0, 0x212eaec, 0x212eff4, 0x212effe,
         (0x212eacc, 0x212eade, 0x212eaf2, 0x212eff8)) if which == 'size' else
        (0x212f077, 0x212f08a, 0x212f094, 0x212f0a0, 0x212f2c2, 0x212f2cc,
         (0x212f080, 0x212f092, 0x212f0a6, 0x212f2c6)))
    for va, code in ((start, '4883bc24b000000000'), (end_cmp, '483b8424c8000000'),
                     (advance, '488d482048898c24b8000000'), (marker_cmp, '0fb60880f916'),
                     (over_cmp, '4883f8ff'), (incr, '48ffc048898424d0000000')):
        expect_bytes(data, secs, va, code)
    decoded = [branch(data, secs, site) for site in branches]
    if [x['condition'] for x in decoded] != [4, 4, 5, 4]:
        raise ValueError('unexpected inline cursor condition')
    if not present or at_end:
        return {'status': 'absent', 'advance': 0, 'counter': counter}
    if marker == 0x16:
        return {'status': 'absent', 'advance': 32, 'counter': counter}
    if counter == MASK:
        return {'status': 'counter_overflow', 'advance': 32, 'counter': counter}
    return {'status': 'decode', 'advance': 32, 'counter': counter + 1}


def inline_fixture(data, secs):
    rows = []
    for which in ('size', 'minutes'):
        for state, present, end in (('empty', False, False), ('end', True, True), ('present', True, False)):
            for marker in range(256):
                for counter in (0, MASK):
                    got = replay_inline_cursor(data, secs, which, present, end, marker, counter)
                    if state != 'present':
                        expected = {'status': 'absent', 'advance': 0, 'counter': counter}
                    elif marker == 0x16:
                        expected = {'status': 'absent', 'advance': 32, 'counter': counter}
                    elif counter == MASK:
                        expected = {'status': 'counter_overflow', 'advance': 32, 'counter': counter}
                    else:
                        expected = {'status': 'decode', 'advance': 32, 'counter': counter + 1}
                    if got != expected:
                        raise ValueError('inline cursor replay differs from model')
                    rows.append({'field': which, 'state': state, 'marker': marker,
                                 'counter_in': counter, 'status': got['status'],
                                 'advance': got['advance'], 'counter_out': got['counter']})
    return rows


def cursor_fixture(data, secs):
    rows = []
    for state, present, end in (('empty', False, False), ('end', True, True), ('present', True, False)):
        for marker in range(256):
            for count in (0, MASK):
                got = replay_bool_cursor(data, secs, present, end, marker, count, 0xa5)
                # Independently express the control predicates; no native target run.
                if state != 'present':
                    expected = {'status': 'absent', 'advance': 0, 'counter': count, 'tag': 9, 'value': 2}
                elif marker == 0x16:
                    expected = {'status': 'absent', 'advance': 32, 'counter': count, 'tag': 9, 'value': 2}
                elif count == MASK:
                    expected = {'status': 'counter_overflow', 'advance': 32, 'counter': count}
                elif marker:
                    expected = {'status': 'external_decoder', 'advance': 32, 'counter': count + 1}
                else:
                    expected = {'status': 'direct_bool', 'advance': 32, 'counter': count + 1, 'tag': 9, 'value': 0xa5}
                if got != expected:
                    raise ValueError('cursor replay differs from model')
                rows.append({'state': state, 'marker': marker, 'counter_in': count,
                             'status': got['status'], 'advance': got['advance'],
                             'counter_out': got['counter'], 'tag': got.get('tag', ''),
                             'value': got.get('value', '')})
    return rows


def bounded(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('invalid ' + name)
    return value


def decode_unsigned(tag, word):
    """Model value reader A from its table: no native execution."""
    bounded(tag, 0, 255, 'tag')
    bounded(word, 0, MASK, 'word')
    if not 1 <= tag <= 8:
        return ('type_error', None)
    bits = (8, 16, 32, 64)[(tag - 1) % 4]
    value = word & ((1 << bits) - 1)
    if tag >= 5 and value & (1 << (bits - 1)):
        return ('negative_error', None)
    return ('ok', value)


# Each prefix is the observed x86 load and, for signed variants, sign test.
INTEGER_ARMS = (
 (0x207fb18, '0fb64601', 8, False, None),
 (0x207fc1d, '0fb74602', 16, False, None),
 (0x207fb97, '8b4604', 32, False, None),
 (0x207fb9f, '488b4608', 64, False, None),
 (0x207fb21, '480fbe46014885c0', 8, True, 0x207fb29),
 (0x207fc23, '480fbf46024885c0', 16, True, 0x207fc2b),
 (0x207fc95, '486346044885c0', 32, True, 0x207fc9c),
 (0x207fba8, '488b46084885c0', 64, True, 0x207fbaf),
)


def replay_unsigned(data, secs, tag, word):
    bounded(tag, 0, 255, 'tag')
    bounded(word, 0, MASK, 'word')
    expect_bytes(data, secs, 0x207fafa, '0fb606ffc883f807')
    guard = branch(data, secs, 0x207fb02)
    if guard['condition'] != 7:
        raise ValueError('unexpected unsigned dispatch condition')
    if not 1 <= tag <= 8:
        return 'type_error', None
    va, prefix, bits, signed, sign_branch = INTEGER_ARMS[tag - 1]
    _, entry = resolver(data, secs, 0x3c6d08 + 4 * (tag - 1), 4)
    if 0x3c6d08 + struct.unpack('<i', entry)[0] != va:
        raise ValueError('bad integer arm target')
    expect_bytes(data, secs, va, prefix)
    value = word & ((1 << bits) - 1)
    if signed:
        b = branch(data, secs, sign_branch)
        if b['condition'] not in (8, 9):
            raise ValueError('unexpected sign condition')
        is_negative = bool(value & (1 << (bits-1)))
        taken = is_negative if b['condition'] == 8 else not is_negative
        target = int(b['target_va'], 16)
        success = target == 0x207fc9e if taken else b['condition'] == 8
        if not success:
            return 'negative_error', None
    return 'ok', value


def integer_fixture(data, secs):
    values = sorted(set(range(256)) | {2**15-1, 2**15, 2**16-1, 2**31-1,
                                     2**31, 2**32-1, 2**63-1, 2**63, MASK})
    rows = []
    for tag in range(10):
        for word in values:
            actual = replay_unsigned(data, secs, tag, word)
            if actual != decode_unsigned(tag, word):
                raise ValueError('numeric replay differs from model')
            rows.append({'tag': tag, 'word': word, 'status': actual[0],
                         'value': '' if actual[1] is None else actual[1]})
    return rows


def model_sequence(items, *, convert_ok=True, counter=0, buffer_present=True):
    """Abstract only documented branch decisions; helper outcomes are explicit.

    Items are (kind, value); kind is marker, asset, bool, size, uint or error.
    A malformed internal array is outside this model. Type decoding of the asset
    and size is supplied by the caller; numeric conversion is also a stub.
    """
    bounded(counter, 0, MASK, 'counter')
    if type(convert_ok) is not bool or type(buffer_present) is not bool:
        raise ValueError('invalid model flag')
    cursor = 0
    events = []
    result = {}

    def take(index):
        nonlocal cursor, counter
        if not buffer_present or cursor == len(items):
            events.append(f'{index}:end')
            return 'absent', None
        if cursor > len(items):
            raise ValueError('cursor outside sequence')
        kind, value = items[cursor]
        cursor += 1
        if kind == 'marker':
            events.append(f'{index}:marker')
            return 'absent', None
        if counter == MASK:
            events.append(f'{index}:counter_overflow')
            return 'counter_overflow', None
        counter += 1
        events.append(f'{index}:{kind}')
        if kind == 'error':
            return 'reader_error', None
        return kind, value

    def done(status):
        return {'status': status, 'cursor': cursor, 'counter': counter,
                'events': events, 'fields': result}

    for index, name, expected in ((0, 'asset', 'asset'), (1, 'isBuy', 'bool'),
                                   (2, 'sz', 'size'), (3, 'reduceOnly', 'bool'),
                                   (4, 'minutes', 'uint'), (5, 'randomize', 'bool')):
        kind, val = take(index)
        if kind in ('counter_overflow', 'reader_error'):
            return done(kind + ':' + str(index))
        if kind == 'absent':
            if index in (0, 1, 2, 4):
                return done('missing:' + str(index))
            result[name] = 0
            continue
        if kind != expected:
            return done('type_error:' + str(index))
        if expected == 'bool':
            bounded(val, 0, 255, 'boolean payload')
            if index == 1 and val == 2:
                return done('missing:1')
            result[name] = val if index == 1 else val & 1
        elif expected == 'uint':
            if not isinstance(val, (tuple, list)) or len(val) != 2:
                raise ValueError('invalid unsigned input')
            status, numeric = decode_unsigned(*val)
            if status != 'ok':
                return done(status + ':4')
            result[name] = numeric
        elif expected == 'size':
            # 3-word input to the existing external converter; no unit assumed.
            if not isinstance(val, (tuple, list)) or len(val) != 3:
                raise ValueError('invalid size carrier')
            for v in val:
                bounded(v, 0, MASK, 'carrier word')
            if val[0] == 1 << 63:
                return done('missing:2')
            result[name] = list(val)
        else:
            bounded(val, 0, (1 << 32) - 1, 'asset')
            result[name] = val
    if buffer_present and cursor != len(items):
        remaining = len(items) - cursor
        if counter + remaining > MASK:
            events.append('finish:counter_overflow')
            return done('finish_counter_overflow')
        events.append('finish:remaining')
        return done('trailing')
    events.append('finish:ok')
    events.append('convert:ok' if convert_ok else 'convert:error')
    return done('ok' if convert_ok else 'conversion_error')


# All comparison masks are four-byte relative operands in the selected reader
# windows. They do not imply equivalence of the referenced callees or data.
COPY_CALL_MASKS = tuple(site for site, _ in CALLS) + (0x212f6cc,)
COPY_LEA_MASKS = (0x212eafc, 0x212eb03, 0x212f0ac, 0x212f0b3, 0x212f6be, 0x212f6c5)


def compare_selected_windows(data, secs):
    comparisons = []
    masks = []
    selected = [(a, e, name) for a, e, name in WINDOWS
                if READERS[0] <= a < e <= BODIES[READERS[0]][0]]
    for a, end, name in selected:
        modified = []
        mask_details = []
        for site in COPY_CALL_MASKS:
            if a <= site and site + 5 <= end:
                for reader in READERS:
                    actual = reader + site - READERS[0]
                    direct_call(data, secs, actual)
                mask_details.append((site+1, 'call_rel32', site))
        for site in COPY_LEA_MASKS:
            if a <= site and site + 7 <= end:
                for reader in READERS:
                    actual = reader + site - READERS[0]
                    _, prefix = resolver(data, secs, actual, 3, True)
                    if prefix[:2] != b'\x48\x8d' or prefix[2] & 0xc7 != 5:
                        raise ValueError('unexpected masked address operand')
                mask_details.append((site+3, 'rip_lea_disp32', site))
        for reader in READERS:
            _, raw = resolver(data, secs, reader + a - READERS[0], end-a, True)
            work = bytearray(raw)
            for off, kind, instruction in mask_details:
                work[off-a:off-a+4] = b'\0'*4
                masks.append({'window': name, 'owner': hex(reader), 'instruction_va': hex(reader + instruction - READERS[0]),
                              'operand_va': hex(reader + off - READERS[0]), 'length': 4, 'kind': kind})
            modified.append(bytes(work))
        if not all(item == modified[0] for item in modified[1:]):
            raise ValueError('selected reader windows differ after operand masks')
        comparisons.append({'role': name, 'reader_a_va': hex(a), 'bytes_per_copy': end-a,
                            'copies': len(READERS), 'masked_operands_per_copy': len(mask_details),
                            'normalized_sha256': digest(modified[0])})
    return comparisons, masks


HELPER_GROUPS = (
    ('asset_cursor', (0x1edd530, 0x34fe880, 0x44e13f0), 0x1edd535, 0x1edd595, ()),
    ('bool_cursor', (0x1eee530, 0x34ffa90, 0x44df210), 0x1eee539, 0x1eee599, ()),
    ('bool_value', (0x1eee530, 0x34ffa90, 0x44df210), 0x1eee5d2, 0x1eee5f7,
     ((0x1eee5e3, 'call'),)),
    ('integer_dispatch', (0x207faf0, 0x3a37f70, 0x4b84400), 0x207faf7, 0x207fb21,
     ((0x207fb08, 'lea'),)),
    ('finish', (0x1eb44b0, 0x3444fb0, 0x44c3010), 0x1eb44bb, 0x1eb453e,
     ((0x1eb44ea, 'call'), (0x1eb4518, 'lea'), (0x1eb452a, 'call'),
      (0x1eb4531, 'lea'), (0x1eb4538, 'indirect'))),
)


def compare_helper_windows(data, secs):
    rows = []
    masks = []
    for name, owners, start, end, operands in HELPER_GROUPS:
        variants = []
        for owner in owners:
            a = owner + start - owners[0]
            _, raw = resolver(data, secs, a, end-start, True)
            normalized = bytearray(raw)
            for site, kind in operands:
                at = owner + site - owners[0]
                if kind == 'call':
                    direct_call(data, secs, at)
                    offset = 1
                elif kind == 'lea':
                    _, p = resolver(data, secs, at, 3, True)
                    if p[:2] != b'\x48\x8d' or p[2] & 0xc7 != 5:
                        raise ValueError('bad helper LEA mask')
                    offset = 3
                else:
                    slot_call(data, secs, at)
                    offset = 2
                pos = site-start+offset
                normalized[pos:pos+4] = b'\0'*4
                masks.append({'window': name, 'owner': hex(owner), 'instruction_va': hex(at),
                              'operand_va': hex(at+offset), 'length': 4,
                              'kind': {'call':'call_rel32', 'lea':'rip_lea_disp32',
                                       'indirect':'rip_call_disp32'}[kind]})
            variants.append(bytes(normalized))
        if len(set(variants)) != 1:
            raise ValueError('selected helper windows differ after operand masks')
        rows.append({'role': name, 'reader_a_va': hex(start), 'bytes_per_copy': end-start,
                     'copies': len(owners), 'masked_operands_per_copy': len(operands),
                     'normalized_sha256': digest(variants[0])})
    return rows, masks


def integer_copy_dispatch(data, secs):
    rows = []
    for owner in (0x207faf0, 0x3a37f70, 0x4b84400):
        lea = owner + 0x207fb08 - 0x207faf0
        _, raw = resolver(data, secs, lea, 7, True)
        if raw[:3] != bytes.fromhex('488d0d'):
            raise ValueError('integer table LEA mismatch')
        table = lea + 7 + struct.unpack('<i', raw[3:])[0]
        for i, (va, prefix, bits, signed, sign_branch) in enumerate(INTEGER_ARMS):
            entry_va = table + 4*i
            _, entry = resolver(data, secs, entry_va, 4)
            target = table + struct.unpack('<i', entry)[0]
            expected = owner + va - 0x207faf0
            if target != expected:
                raise ValueError('integer copy table target mismatch')
            expect_bytes(data, secs, target, prefix)
            sign_target = ''
            if sign_branch is not None:
                cb = branch(data, secs, owner + sign_branch - 0x207faf0)
                baseline = branch(data, secs, sign_branch)
                if (cb['condition'] != baseline['condition'] or
                    int(cb['target_va'], 16) - owner != int(baseline['target_va'], 16) - 0x207faf0):
                    raise ValueError('integer copy sign branch mismatch')
                sign_target = cb['target_va']
            rows.append({'owner': hex(owner), 'table_va': hex(table), 'tag': i+1,
                         'entry_va': hex(entry_va), 'entry_bytes': entry.hex(),
                         'target_va': hex(target), 'bits': bits, 'signed': signed,
                         'sign_target_va': sign_target})
    return rows


def raw_copy_differences(data, secs, comparisons, masks):
    rows = []
    mask_map = {}
    for row in masks:
        for i in range(row['length']):
            mask_map[(row['window'], row['owner'], int(row['operand_va'], 16) + i)] = row['kind']
    helper_owners = {row[0]: row[1] for row in HELPER_GROUPS}
    for c in comparisons:
        name = c['role']
        owners = helper_owners.get(name, READERS)
        source_va = int(c['reader_a_va'], 16)
        n = c['bytes_per_copy']
        base = owners[0]
        ref = resolver(data, secs, source_va, n, True)[1]
        for owner in owners[1:]:
            start = owner + source_va - base
            other = resolver(data, secs, start, n, True)[1]
            for i, (left, right) in enumerate(zip(ref, other)):
                if left != right:
                    va = start + i
                    mask = mask_map.get((name, hex(owner), va))
                    if mask is None:
                        raise ValueError('unmasked raw copy difference')
                    rows.append({'window': name, 'baseline_va': hex(source_va+i),
                                 'variant_owner': hex(owner), 'variant_va': hex(va),
                                 'baseline_byte': f'{left:02x}', 'variant_byte': f'{right:02x}',
                                 'mask_kind': mask})
    return rows


def collect(data, verify=True):
    if verify:
        authenticate(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    starts = {}
    for row in fdes:
        starts.setdefault(row['start'], []).append(row)
    indexed = {row['start']: row['fde'] for row in index}
    bodies = []
    for va, (end, expected, name) in BODIES.items():
        fs = starts.get(va, [])
        if len(fs) != 1 or fs[0]['end'] != end or indexed.get(va) != fs[0]['fde']:
            raise ValueError('missing or ambiguous FDE')
        off, code = resolver(data, secs, va, end-va, True)
        if digest(code) != expected:
            raise ValueError('body digest mismatch')
        bodies.append({'name': name, 'start_va': hex(va), 'end_va': hex(end),
                       'fde_va': hex(fs[0]['fde']), 'file_offset': hex(off),
                       'sha256': expected, 'bytes': code.hex()})
    rels = relocations(data, secs)
    descriptors = []
    for base in DESCRIPTORS:
        for i, name in enumerate(NAMES):
            slot = base + i * 16
            ptr = rels.get(slot)
            _, length_raw = resolver(data, secs, slot + 8, 8)
            length = struct.unpack('<Q', length_raw)[0]
            if ptr is None or length != len(name) or resolver(data, secs, ptr, length)[1] != name.encode('ascii'):
                raise ValueError('descriptor mismatch')
            descriptors.append({'descriptor_va': hex(base), 'index': i, 'pointer_slot_va': hex(slot),
                                'text_va': hex(ptr), 'length': length, 'text': name})
    outer_anchors = []
    setups = ((0x221eb40, 0x221eb54, 0x221eb5b, 0x221eb67, 0x221eb6c),
              (0x336e970, 0x336e984, 0x336e98b, 0x336e995, 0x336e99a),
              (0x48fc490, 0x48fc4a4, 0x48fc4ab, 0x48fc4b7, 0x48fc4bc))
    for i, (owner, name_site, desc_site, len_site, count_site) in enumerate(setups):
        name_va = rip_lea(data, secs, name_site, '488d15')
        descriptor = rip_lea(data, secs, desc_site, '4c8d05')
        expect_bytes(data, secs, len_site, 'b90d000000')
        expect_bytes(data, secs, count_site, '41b90c000000')
        if descriptor != DESCRIPTORS[i] or resolver(data, secs, name_va, 13)[1] != b'TwapWireSerde':
            raise ValueError('outer descriptor setup mismatch')
        outer_anchors.append({'owner': hex(owner), 'name_site': hex(name_site), 'name_va': hex(name_va),
                              'name': 'TwapWireSerde', 'name_length': 13,
                              'descriptor_site': hex(desc_site), 'descriptor_va': hex(descriptor),
                              'descriptor_count': 12})
    asset_literal = rip_lea(data, secs, 0x1edd5cd, '488d15')
    if resolver(data, secs, asset_literal, 9)[1] != b'AssetWire':
        raise ValueError('asset label mismatch')
    # The outer functions contain an exact shared decimal-converter slot call.
    outer_sites = (0x221ebcc, 0x336e9e3, 0x48fc51c)
    outer_visitor_sites = (0x221eb72, 0x336e9a0, 0x48fc4c2)
    edges = []
    for owner, reader, at, vcall in zip(OUTERS, READERS, outer_sites, outer_visitor_sites):
        if direct_call(data, secs, vcall) != reader or slot_call(data, secs, at) != 0x5773898:
            raise ValueError('outer edge mismatch')
        target = rels.get(0x5773898)
        if target != 0x3330210:
            raise ValueError('converter relocation mismatch')
        edges.append({'owner': hex(owner), 'site': hex(vcall), 'kind': 'direct', 'target': hex(reader), 'role': 'visitor'})
        edges.append({'owner': hex(owner), 'site': hex(at), 'kind': 'indirect', 'slot': hex(0x5773898),
                      'target': hex(target), 'role': 'external_size_converter'})
    # Verify selected direct calls in each reader, retaining exact targets.
    expected_a = (0x1edd530, 0x1eee530, 0x1703e70, 0x209d0b0,
                  0x1eee530, 0x1703e70, 0x207faf0, 0x1eee530, 0x1eb44b0)
    for k, reader in enumerate(READERS):
        for j, (site, role) in enumerate(CALLS):
            va = reader + site - READERS[0]
            target = direct_call(data, secs, va)
            if k == 0 and target != expected_a[j]:
                raise ValueError('reader call mismatch')
            edges.append({'owner': hex(reader), 'site': hex(va), 'kind': 'direct',
                          'target': hex(target), 'role': role})
    branches = []
    for reader in READERS:
        for site, role in BRANCHES:
            row = branch(data, secs, reader + site - READERS[0])
            row.update(owner=hex(reader), role=role)
            branches.append(row)
    checks = (
        (0x212ea79, '0fb64424403c09'), (0x212ea86, '837c244401'),
        (0x212eaa7, '0fb64424400fb66c2441'), (0x212eab9, '4080fd02'),
        (0x212f01b, '0fb64424403c09'), (0x212f028, '4c8b7c24484c89f848f7d8'),
        (0x212f064, '0fb6442440440fb66424413c09'), (0x212f2e9, '0fb64424403c09'),
        (0x212f315, '0fb64c24400fb6442441'), (0x212f328, '4180e4012401'),
        (0x212f36c, '807c244009'))
    for reader in READERS:
        for site, expected in checks:
            expect_bytes(data, secs, reader + site - READERS[0], expected)
    for site, expected in ((0x221ebd2, '0fb74424483d86010000'),
                           (0x336e9e9, '0fb74424283d86010000'),
                           (0x48fc522, '0fb74424483d86010000')):
        expect_bytes(data, secs, site, expected)
    positions = []
    position_specs = (
       (0, 'asset', 0x212ea74, 0x212ea80, 0x212ea8b, 'returned asset presence'),
       (1, 'isBuy', 0x212eaa2, 0x212eab3, 0x212eabd, 'byte 2 is absent'),
       (2, 'sz', 0x212f016, 0x212f022, 0x212f033, 'first word equals 0x8000000000000000'),
       (3, 'reduceOnly', 0x212f055, 0x212f071, None, 'result byte masked with 1'),
       (4, 'minutes', 0x212f2e4, 0x212f2f0, 0x212f0a6, 'cursor missing edge'),
       (5, 'randomize', 0x212f310, 0x212f322, None, 'result byte masked with 1'))
    for owner in READERS:
        for index, field, call, failure, absence, note in position_specs:
            delta = owner - READERS[0]
            pos = {'owner': hex(owner), 'index': index, 'field_inference': field,
                   'value_call_va': hex(call+delta), 'value_target_va': hex(direct_call(data, secs, call+delta)),
                   'error_branch_va': hex(failure+delta), 'error_target_va': branch(data, secs, failure+delta)['target_va'],
                   'absence_branch_va': '' if absence is None else hex(absence+delta), 'interpretation': note}
            positions.append(pos)
    # All sequence control branches have the same condition and local target offset in three readers.
    for j in range(len(BRANCHES)):
        group = [branches[j + k * len(BRANCHES)] for k in range(3)]
        if len({(r['condition'], int(r['target_va'], 16) - READERS[k],
                 int(r['fallthrough_va'], 16) - READERS[k]) for k, r in enumerate(group)}) != 1:
            raise ValueError('reader branch shape mismatch')
    for site in (0x221eb7e, 0x221ebdc, 0x1edd539, 0x1edd543, 0x1edd553, 0x1edd585,
                 0x1eee53d, 0x1eee547, 0x1eee557, 0x1eee589, 0x1eee5d7,
                 0x1eb44c4, 0x1eb44f2, 0x1eb4511, 0x207fb02, 0x207fb29,
                 0x207fbaf, 0x207fc2b, 0x207fc9c):
        row = branch(data, secs, site)
        row.update(owner=hex(next(a for a, (end, _, _) in BODIES.items() if a <= site < end)),
                   role='finish_count_overflow' if site == 0x1eb4511 else 'helper_or_outer')
        branches.append(row)
    for owner in (0x3444fb0, 0x44c3010):
        row = branch(data, secs, owner + 0x61)
        if row['condition'] != 2 or int(row['target_va'], 16) != owner + 0x81:
            raise ValueError('finish carry branch mismatch')
        row.update(owner=hex(owner), role='finish_count_overflow')
        branches.append(row)
    table = []
    for i in range(8):
        va = 0x3c6d08 + i * 4
        off, raw = resolver(data, secs, va, 4)
        target = 0x3c6d08 + struct.unpack('<i', raw)[0]
        expected = (0x207fb18, 0x207fc1d, 0x207fb97, 0x207fb9f,
                    0x207fb21, 0x207fc23, 0x207fc95, 0x207fba8)[i]
        if target != expected:
            raise ValueError('numeric jump table mismatch')
        table.append({'tag': i+1, 'entry_va': hex(va), 'file_offset': hex(off),
                      'bytes': raw.hex(), 'target_va': hex(target), 'bits': (8,16,32,64)[i % 4],
                      'signed': i >= 4})
    windows = []
    for start, end, role in WINDOWS:
        owner = next(a for a, (limit, _, _) in BODIES.items() if a <= start < end <= limit)
        off, raw = resolver(data, secs, start, end-start, True)
        windows.append({'owner': hex(owner), 'start': hex(start), 'end': hex(end),
                        'file_offset': hex(off), 'role': role, 'bytes': raw.hex()})
    comparisons, masks = compare_selected_windows(data, secs)
    helper_comparisons, helper_masks = compare_helper_windows(data, secs)
    copies = integer_copy_dispatch(data, secs)
    comparisons += helper_comparisons
    masks += helper_masks
    raw_diff = raw_copy_differences(data, secs, comparisons, masks)
    return {'copy_comparisons': comparisons, 'copy_masks': masks, 'raw_copy_differences': raw_diff,
            'integer_copy_dispatch': copies,
            'positions': positions, 'outer_anchors': outer_anchors, 'asset_literal_va': hex(asset_literal),
            'target_sha256': DIGEST, 'address_space': 'ELF link-time VA; ends exclusive',
            'functions': bodies, 'descriptors': descriptors, 'edges': edges,
            'branches': branches, 'integer_dispatch': table, 'windows': windows}


def replay_finish(data, secs, counter, remaining):
    """Replay aligned-record end arithmetic, stopping at external calls."""
    bounded(counter, 0, MASK, 'counter')
    bounded(remaining, 0, MASK >> 5, 'remaining')
    for va, code in ((0x1eb44ef, '4d29e6'), (0x1eb4506, '49c1ee05'),
                     (0x1eb450a, '498b4720'), (0x1eb450e, '4901c6')):
        expect_bytes(data, secs, va, code)
    nonempty = branch(data, secs, 0x1eb44f2)
    overflow = branch(data, secs, 0x1eb4511)
    if (nonempty['condition'], nonempty['target_va'], overflow['condition'],
        overflow['target_va']) != (5, '0x1eb4506', 2, '0x1eb4531'):
        raise ValueError('unexpected finish branch')
    if remaining == 0:
        return ('ok', None)
    total = counter + remaining
    return ('counter_overflow', None) if total > MASK else ('remaining_constructor', total)


def finish_fixture(data, secs):
    rows = []
    for counter in (0, 1, MASK - 1, MASK):
        for remaining in (0, 1, 2, MASK >> 5):
            status, total = replay_finish(data, secs, counter, remaining)
            expected = ('ok', None) if remaining == 0 else (
                ('counter_overflow', None) if remaining > MASK - counter
                else ('remaining_constructor', counter + remaining))
            if (status, total) != expected:
                raise ValueError('finish replay differs from model')
            rows.append({'counter': counter, 'remaining': remaining, 'status': status,
                         'total': '' if total is None else total})
    return rows


def fixtures():
    base = [('asset', 7), ('bool', 1), ('size', (1, 22, 33)),
            ('bool', 1), ('uint', (4, 9)), ('bool', 1)]
    rows = []
    for n in range(8):
        seq = base[:n]
        if n == 7:
            seq = base + [('marker', 0)]
        for conv in (False, True):
            rows.append({'case': 'length_' + str(n), 'converter_ok': conv,
                         'items': seq, **model_sequence(seq, convert_ok=conv)})
    for i in range(6):
        for kind, value in (('marker', 0), ('error', 0)):
            seq = list(base); seq[i] = (kind, value)
            rows.append({'case': kind + '_' + str(i), 'converter_ok': True,
                         'items': seq, **model_sequence(seq)})
    for i in (1, 3, 5):
        for value in (0, 1, 2, 3, 254, 255):
            seq = list(base); seq[i] = ('bool', value)
            rows.append({'case': 'bool_' + str(i) + '_' + str(value), 'converter_ok': True,
                         'items': seq, **model_sequence(seq)})
    for tag in range(0, 10):
        for value in (0, 1, 127, 128, 255, 256, 32767, 32768, (1 << 31)-1,
                      1 << 31, (1 << 63)-1, 1 << 63, MASK):
            seq = list(base); seq[4] = ('uint', (tag, value))
            rows.append({'case': 'uint_' + str(tag) + '_' + str(value), 'converter_ok': True,
                         'items': seq, **model_sequence(seq)})
    for label, seq, counter, present in (
        ('size_sentinel', base[:2] + [('size', (1 << 63, 0, 0))] + base[3:], 0, True),
        ('counter_max', base, MASK, True), ('counter_near_max', base, MASK - 2, True),
        ('no_buffer', base, 0, False),
        ('finish_sum_max', base + [('marker', 0)], MASK - 7, True),
        ('finish_sum_overflow', base + [('marker', 0)], MASK - 6, True),
    ):
        rows.append({'case': label, 'converter_ok': True, 'items': seq,
                     'initial_counter': counter, 'buffer_present': present,
                     **model_sequence(seq, counter=counter, buffer_present=present)})
    return rows


def pattern_fixture():
    defaults = [('asset', 7), ('bool', 1), ('size', (1, 22, 33)),
                ('bool', 1), ('uint', (4, 9)), ('bool', 1)]
    rows = []
    for pattern in itertools.product('PME', repeat=6):
        values = [defaults[i] if t == 'P' else ('marker', 0) if t == 'M' else ('error', 0)
                  for i, t in enumerate(pattern)]
        outcome = model_sequence(values)
        first = next((i for i, t in enumerate(pattern)
                      if t == 'E' or (t == 'M' and i in (0, 1, 2, 4))), None)
        if first is None:
            expected, cursor = 'ok', 6
        else:
            expected = ('reader_error:' if pattern[first] == 'E' else 'missing:') + str(first)
            cursor = first + 1
        if outcome['status'] != expected or outcome['cursor'] != cursor:
            raise ValueError('sequence pattern disagrees with first-failure rule')
        rows.append({'pattern': ''.join(pattern), 'status': outcome['status'],
                     'cursor': outcome['cursor'], 'counter': outcome['counter'],
                     'converter_called': int('convert:ok' in outcome['events'])})
    return rows


def write_tsv(path, rows, keys):
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=keys, delimiter='\t', lineterminator='\n', extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)


def generate(data, out):
    evidence = collect(data)
    cases = fixtures()
    cursor_cases = cursor_fixture(data, sections(data))
    integer_cases = integer_fixture(data, sections(data))
    inline_cases = inline_fixture(data, sections(data))
    patterns = pattern_fixture()
    finish_cases = finish_fixture(data, sections(data))
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (out / 'cases.json').write_text(json.dumps(cases, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    write_tsv(out / 'finish-cases.tsv', finish_cases, ('counter','remaining','status','total'))
    write_tsv(out / 'positions.tsv', evidence['positions'], ('owner','index','field_inference','value_call_va','value_target_va','error_branch_va','error_target_va','absence_branch_va','interpretation'))
    write_tsv(out / 'outer-anchors.tsv', evidence['outer_anchors'], ('owner','name_site','name_va','name','name_length','descriptor_site','descriptor_va','descriptor_count'))
    write_tsv(out / 'raw-copy-differences.tsv', evidence['raw_copy_differences'], ('window','baseline_va','variant_owner','variant_va','baseline_byte','variant_byte','mask_kind'))
    write_tsv(out / 'integer-copy-dispatch.tsv', evidence['integer_copy_dispatch'], ('owner','table_va','tag','entry_va','entry_bytes','target_va','bits','signed','sign_target_va'))
    write_tsv(out / 'sequence-patterns.tsv', patterns, ('pattern','status','cursor','counter','converter_called'))
    write_tsv(out / 'copy-masks.tsv', evidence['copy_masks'], ('window','owner','instruction_va','operand_va','length','kind'))
    write_tsv(out / 'copy-comparisons.tsv', evidence['copy_comparisons'], ('role','reader_a_va','bytes_per_copy','copies','masked_operands_per_copy','normalized_sha256'))
    write_tsv(out / 'inline-cursor-cases.tsv', inline_cases, ('field','state','marker','counter_in','status','advance','counter_out'))
    write_tsv(out / 'integer-cases.tsv', integer_cases, ('tag','word','status','value'))
    write_tsv(out / 'cursor-cases.tsv', cursor_cases, ('state','marker','counter_in','status','advance','counter_out','tag','value'))
    write_tsv(out / 'branches.tsv', evidence['branches'], ('owner','role','va','bytes','condition','target_va','fallthrough_va'))
    write_tsv(out / 'calls.tsv', evidence['edges'], ('owner','role','site','kind','slot','target'))
    write_tsv(out / 'descriptors.tsv', evidence['descriptors'], ('descriptor_va','index','pointer_slot_va','text_va','length','text'))
    write_tsv(out / 'integer-dispatch.tsv', evidence['integer_dispatch'], ('tag','entry_va','file_offset','bytes','target_va','bits','signed'))
    status = {}
    for case in cases:
        status[case['status']] = status.get(case['status'], 0) + 1
    summary = {'functions': len(evidence['functions']), 'branches': len(evidence['branches']),
               'edges': len(evidence['edges']), 'descriptor_entries': len(evidence['descriptors']),
               'compared_windows': len(evidence['copy_comparisons']),
               'masked_operands': len(evidence['copy_masks']),
               'raw_differing_bytes': len(evidence['raw_copy_differences']),
               'position_records': len(evidence['positions']),
               'numeric_tag_cases': len(evidence['integer_dispatch']),
               'integer_copy_arms': len(evidence['integer_copy_dispatch']), 'cases': len(cases),
               'finish_replays': len(finish_cases), 'finish_mismatches': 0,
               'cursor_replays': len(cursor_cases), 'cursor_mismatches': 0,
               'inline_replays': len(inline_cases), 'inline_mismatches': 0,
               'integer_replays': len(integer_cases), 'integer_mismatches': 0,
               'sequence_patterns': len(patterns), 'sequence_model_mismatches': 0,
               'model_statuses': dict(sorted(status.items()))}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(generate(TARGET.read_bytes(), args.out), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('twap_sequence_size94: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)

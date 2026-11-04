#!/usr/bin/env python3
"""Extract the node 115 result-ring growth and cleanup boundary, without executing it."""

import argparse
from bisect import bisect_left
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OLD_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK64 = (1 << 64) - 1

# This is an explicit selection, not a scan or a function census. The hashes
# pin complete unwind-described ranges; FDEs are not source boundaries.
OWNED = (
    ('reposition_after_grow', 0x5800d70, 0x5800e08,
     'a9d698bb78710fe95a29371d52c95feb25390d4d703a40832c1198526b48214e'),
    ('capacity_grow', 0x5962d20, 0x5962d84,
     '4fe9418711a8c4f779dc1f0c4c25f256c94aed68f030924347b110da6f11ae00'),
)

# The selected complete instructions are byte pinned, not discovered by a
# disassembler or a pattern scan. Context is from previously proposed work.
WINDOWS = (
    ('reposition_entry', 'new', 0x5800d70, '41574156534889fb4c8b37ff15cfb1ce00'),
    ('no_wrap_test', 'new', 0x5800d81, '488b7310488b53184c89f04829d04839c67651'),
    ('wrapped_choice', 'new', 0x5800d94, '4c8b3b4c89f04829f04829c24839d00f96c14c89ff4c29f74839d7400f92c74008cf4080ff01752f'),
    ('move_tail', 'new', 0x5800dbc, '4929c7488b4b0848c1e6064801ce4c89ff48c1e7064801cf48c1e0064889c2ff1587e7cd004c897b10'),
    ('normal_return', 'new', 0x5800de5, '5b415e415fc3'),
    ('move_prefix', 'new', 0x5800deb, '488b730849c1e6064901f648c1e2064c89f75b415e415fff2500e7cd00'),
    ('capacity_setup', 'new', 0x5962d20, '4156534883ec184889fb488b37488d04364883f80541be040000004c0f43f0488b57084889e741b80800000041b9400000004c89f1'),
    ('capacity_result_test', 'new', 0x5962d55, 'e8f6080000833c24017414'),
    ('capacity_publish', 'new', 0x5962d60, '488b442408488943084c89334883c4185b415ec3'),
    ('capacity_failure', 'new', 0x5962d74, '488b7c2408488b742410ff1514c7b700'),
    ('after_failure_call', 'new_boundary', 0x5962d84, 'cc'),
    ('lookup_and_threshold', 'prior_context', 0x4dd0177, 'e8548ba2004885c00f95c1498b77184883fe40400f93c74084f90f8490000000'),
    ('insert_call', 'prior_context', 0x4dd0260, '488d4424104c89ff4889d64889d34889c2e80aa1a100'),
    ('full_ring_call', 'prior_context', 0x57ea38b, '4c8b47184c39c60f87e30000004989f64989ff488b3f4939f875104c89ffff15b1bacf00498b3f4d8b4718'),
    ('bad_index_exit', 'prior_context', 0x57ea47b, '488d3d39c014fb488d156768cc00be27000000ff152452cf000f0b'),
    ('insert_unwind_landing', 'prior_context', 0x57ea496, '4989c64889dfe83f00ffff4c89f7e8a765c000'),
    ('loader_location', 'prior_context', 0x3c1352f, '488d1572328602e8d5ae61004883f8017546'),
    ('begin_state_stores', 'prior_context', 0x5483fd3, '498b752848ffc648c7c2ffffffff480f45d64989552849c745000000000049894d3049898d7819000049898d981a0000'),
    ('collector_row_loads', 'prior_context', 0x5b78628, '48c1e206488b0c170f104417180f298424800000000f104417080f29442470488b4417280f10441730'),
)

# kind determines the exact opcode and displacement width. Only these selected
# aligned instructions are decoded; there is no whole-section caller census.
TRANSFERS = (
    ('reposition_calls_capacity', 'new', 0x5800d7b, 'call_slot', 0x64ebf50),
    ('already_contiguous', 'new', 0x5800d92, 'jbe8', 0x5800de5),
    ('choose_prefix', 'new', 0x5800dba, 'jne8', 0x5800deb),
    ('move_tail', 'new', 0x5800ddb, 'call_slot', 0x64df568),
    ('move_prefix', 'new', 0x5800e02, 'jmp_slot', 0x64df508),
    ('allocate_boundary', 'new', 0x5962d55, 'call', 0x5963650),
    ('tag_one_failure', 'new', 0x5962d5e, 'je8', 0x5962d74),
    ('failure_boundary', 'new', 0x5962d7e, 'call_slot', 0x64df498),
    ('previous_lookup', 'prior_context', 0x4dd0177, 'call', 0x57f8cd0),
    ('previous_insert', 'prior_context', 0x4dd0271, 'call', 0x57ea380),
    ('previous_bad_index', 'prior_context', 0x57ea392, 'ja32', 0x57ea47b),
    ('previous_not_full', 'prior_context', 0x57ea3a4, 'jne8', 0x57ea3b6),
    ('previous_growth', 'prior_context', 0x57ea3a9, 'call_slot', 0x64e5e60),
    ('previous_index_failure', 'prior_context', 0x57ea48e, 'call_slot', 0x64df6b8),
    ('previous_landing_drop', 'prior_context', 0x57ea49c, 'call', 0x57da4e0),
    ('previous_landing_resume', 'prior_context', 0x57ea4a4, 'call', 0x63f0a50),
    ('previous_location_ref', 'prior_context', 0x3c1352f, 'lea_rdx', 0x64767a8),
)

# The first slot is the prior insertion boundary; all other bindings are used
# by the new helpers. Shared external bindings and error targets remain helpers.
SLOTS = (
    ('prior_insertion_grow', 'prior_context', 0x64e5e60, 8, 0x5800d70, ''),
    ('capacity_grow', 'new_edge', 0x64ebf50, 8, 0x5962d20, ''),
    ('tail_memmove', 'shared_boundary', 0x64df568, 6, 0, 'memmove'),
    ('prefix_memcpy', 'shared_boundary', 0x64df508, 6, 0, 'memcpy'),
    ('failure_boundary', 'shared_boundary', 0x64df498, 8, 0x141e264, ''),
    ('location_path', 'prior_context', 0x64767a8, 8, None, ''),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data, expected):
    actual = sha(data)
    if actual != expected:
        raise ValueError('input SHA-256 mismatch')
    return actual


def unique_section(secs, name):
    matches = [s for s in secs if s['name'] == name and s['type'] != 8]
    if len(matches) != 1:
        raise ValueError('missing, duplicate, or fileless section: ' + name)
    return matches[0]


def file_offset(data, secs, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid address or size')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address is not in one allocated file-backed section')
    sec = matches[0]
    off = sec['offset'] + va - sec['address']
    if off < 0 or off + size > len(data):
        raise ValueError('mapped file range outside input')
    return off


def read_va(data, secs, va, size):
    off = file_offset(data, secs, va, size)
    return data[off:off + size]


def check_window(actual, expected):
    if bytes(actual) != bytes.fromhex(expected):
        raise ValueError('selected instruction bytes changed')


def check_window_partition(windows):
    """Require the new byte windows to partition both selected FDE intervals."""
    for _, scope, va, _ in windows:
        if scope == 'new' and sum(start <= va < end for _, start, end, _ in OWNED) != 1:
            raise ValueError('new window is outside the selected FDEs')
    for _, start, end, _ in OWNED:
        spans = sorted((va, va + len(expected) // 2)
                       for _, scope, va, expected in windows
                       if scope == 'new' and start <= va < end)
        cursor = start
        for first, last in spans:
            if first != cursor or last <= first or last > end:
                raise ValueError('new FDE windows overlap or leave a gap')
            cursor = last
        if cursor != end:
            raise ValueError('new FDE windows do not reach the end')


def decode_transfer(raw, va, kind):
    forms = {
        'call_slot': (b'\xff\x15', 4), 'jmp_slot': (b'\xff\x25', 4),
        'call': (b'\xe8', 4), 'jbe8': (b'\x76', 1),
        'jne8': (b'\x75', 1), 'je8': (b'\x74', 1),
        'ja32': (b'\x0f\x87', 4),
        'lea_rdx': (b'\x48\x8d\x15', 4),
    }
    if kind not in forms:
        raise ValueError('unsupported transfer form')
    prefix, width = forms[kind]
    if len(raw) != len(prefix) + width or not raw.startswith(prefix):
        raise ValueError('transfer opcode or size changed')
    disp = int.from_bytes(raw[len(prefix):], 'little', signed=True)
    return va + len(raw) + disp


def checked_transfer(raw, va, kind, expected):
    target = decode_transfer(raw, va, kind)
    if target != expected:
        raise ValueError('transfer destination changed')
    return target


def relocation_records(data, secs, slots):
    rela = unique_section(secs, '.rela.dyn')
    if rela['type'] != 4 or rela['size'] % 24:
        raise ValueError('malformed rela.dyn length')
    wanted = {item[2] for item in slots}
    if len(wanted) != len(slots):
        raise ValueError('duplicate requested relocation')
    hits = {}
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', data, off)
        if target in wanted:
            if target in hits:
                raise ValueError('duplicate target relocation')
            hits[target] = (off, info & 0xffffffff, info >> 32, addend)
    if set(hits) != wanted:
        raise ValueError('missing relocation')
    dynsym = unique_section(secs, '.dynsym')
    dynstr = unique_section(secs, '.dynstr')
    if dynsym['type'] != 11 or dynstr['type'] != 3 or dynsym['size'] % 24:
        raise ValueError('malformed dynamic symbol table')
    rows = []
    for label, scope, target, typ, expected_addend, expected_name in slots:
        off, found_type, symbol, addend = hits[target]
        if found_type != typ:
            raise ValueError('relocation type changed')
        if typ == 8:
            if symbol or (expected_addend is not None and addend != expected_addend):
                raise ValueError('relative relocation changed')
            name = ''
        else:
            if symbol <= 0 or 24 * (symbol + 1) > dynsym['size']:
                raise ValueError('dynamic symbol index outside table')
            name_offset = struct.unpack_from('<I', data, dynsym['offset'] + symbol * 24)[0]
            if name_offset >= dynstr['size']:
                raise ValueError('dynamic symbol name outside table')
            start = dynstr['offset'] + name_offset
            end = data.find(b'\0', start, dynstr['offset'] + dynstr['size'])
            if end < 0:
                raise ValueError('unterminated dynamic symbol')
            name = data[start:end].decode('ascii')
            if name != expected_name or addend != 0:
                raise ValueError('dynamic symbol or addend changed')
        rows.append((label, scope, target, off, found_type, symbol, addend, name))
    return rows


def select_fdes(data, secs):
    _, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {}
    for fde in fdes:
        if fde['start'] in by_start:
            raise ValueError('duplicate FDE start')
        by_start[fde['start']] = fde
    indexed = {row['start']: row for row in index}
    selected = {}
    for role, start, end, expected_hash in OWNED:
        frame = by_start.get(start)
        row = indexed.get(start)
        if frame is None or row is None or frame['fde'] != row['fde'] or frame['end'] != end:
            raise ValueError('selected FDE or header mismatch')
        body = read_va(data, secs, start, end - start)
        if sha(body) != expected_hash:
            raise ValueError('selected FDE body changed')
        selected[role] = (frame, row, body)
    # Context FDE is used only to locate the already recorded exception edge.
    frame = by_start.get(0x57ea380)
    row = indexed.get(0x57ea380)
    if frame is None or row is None or frame['fde'] != row['fde'] or frame['end'] != 0x57ea4af:
        raise ValueError('prior insertion FDE mismatch')
    return selected, frame


def read_exception_rows(data, secs, fde):
    if fde['lsda'] is None:
        raise ValueError('context FDE has no exception table')
    sec = unique_section(secs, '.gcc_except_table')
    if not sec['address'] <= fde['lsda'] < sec['address'] + sec['size']:
        raise ValueError('LSDA outside exception section')
    pos = file_offset(data, secs, fde['lsda'], 1)
    end = sec['offset'] + sec['size']
    if pos + 2 > end or data[pos] != 0xff or data[pos + 1] not in (0xff, 0x9b):
        raise ValueError('unsupported exception header')
    encoding = data[pos + 1]
    pos += 2
    if encoding == 0x9b:
        delta, pos = uleb(data, pos, end)
        table_limit = pos + delta
        if table_limit > end:
            raise ValueError('type table outside exception section')
    else:
        table_limit = end
    if pos >= end or data[pos] != 1:
        raise ValueError('unsupported call-site encoding')
    length, pos = uleb(data, pos + 1, end)
    stop = pos + length
    if stop > end or stop > table_limit:
        raise ValueError('truncated exception table')
    rows = []
    while pos < stop:
        record = pos
        relative, pos = uleb(data, pos, stop)
        span, pos = uleb(data, pos, stop)
        landing, pos = uleb(data, pos, stop)
        action, pos = uleb(data, pos, stop)
        extent = fde['end'] - fde['start']
        if relative + span > extent or (landing and landing >= extent):
            raise ValueError('exception entry outside unwind extent')
        rows.append((record, fde['start'] + relative, fde['start'] + relative + span,
                     fde['start'] + landing if landing else 0, action,
                     bytes(data[record:pos]).hex()))
    return rows


def checked_location(data, secs, reloc_rows, va, expected_line, expected_column):
    loc_rows = [r for r in reloc_rows if r[2] == va]
    if len(loc_rows) != 1:
        raise ValueError('location relocation missing')
    ptr = loc_rows[0][6]
    size, line, column = struct.unpack('<QII', read_va(data, secs, va + 8, 16))
    if not 0 < size <= 256 or line != expected_line or column != expected_column:
        raise ValueError('location fields changed')
    path = bytes(read_va(data, secs, ptr, size))
    suffix = b'l1/src/abci/state.rs'
    if not path.endswith(suffix):
        raise ValueError('location suffix changed')
    return ptr, size, line, column, suffix.decode('ascii')


def capacity_after_growth(capacity, minimum=4):
    if not 0 <= capacity <= MASK64 or minimum != 4:
        raise ValueError('invalid growth inputs')
    doubled = (capacity * 2) & MASK64
    return doubled if doubled >= minimum + 1 else minimum


def branch_plan(capacity, head, length, new_capacity):
    # This model specifies the valid-storage domain; it is not a binary check.
    if capacity == 0:
        if head != 0 or length != 0:
            raise ValueError('invalid empty descriptor')
    elif not (0 <= head < capacity and 0 <= length <= capacity):
        raise ValueError('invalid ring descriptor')
    if capacity < 0 or new_capacity < capacity or new_capacity > MASK64:
        raise ValueError('invalid new capacity')
    if head <= capacity - length:
        return ('contiguous', head, 0, 0, 0, 0, 0)
    tail = capacity - head
    prefix = length - tail
    extra = new_capacity - capacity
    if tail <= prefix or extra < prefix:
        destination = new_capacity - tail
        return ('tail', destination, head, destination, tail, tail, prefix)
    return ('prefix', head, 0, capacity, prefix, tail, prefix)


def model_growth(capacity, head, length, minimum=4):
    new_capacity = capacity_after_growth(capacity, minimum)
    if new_capacity < capacity:
        raise ValueError('wrapped capacity is outside the valid model domain')
    if new_capacity > 8192:
        raise ValueError('synthetic model allocation exceeds its bound')
    rows = [None] * new_capacity
    logical_before = [(i, (i * 0x9e3779b1) & 0xffffffff) for i in range(length)]
    for i, item in enumerate(logical_before):
        rows[(head + i) % capacity] = item
    kind, new_head, src, dst, count, tail, prefix = branch_plan(capacity, head, length, new_capacity)
    snapshot = rows[src:src + count]
    rows[dst:dst + count] = snapshot
    logical_after = [rows[(new_head + i) % new_capacity] for i in range(length)]
    if logical_after != logical_before:
        raise ValueError('model did not preserve logical rows')
    return {'old_capacity': capacity, 'head': head, 'length': length,
            'new_capacity': new_capacity, 'new_head': new_head, 'branch': kind,
            'source': src, 'destination': dst, 'moved_rows': count,
            'tail': tail, 'prefix': prefix, 'preserved': True}


def make_models(minimum, threshold):
    counts = {'contiguous': 0, 'tail': 0, 'prefix': 0}
    full = {'contiguous': 0, 'tail': 0, 'prefix': 0}
    count = 0
    for cap in range(threshold):
        heads = range(cap) if cap else (0,)
        for head in heads:
            for length in range(cap + 1):
                result = model_growth(cap, head, length, minimum)
                counts[result['branch']] += 1
                count += 1
                if length == cap:
                    full[result['branch']] += 1
    capacities = sorted(set((0, 1, 2, 3, 4, 8, 16, 31, 32, threshold - 1)))
    examples = []
    for cap in capacities:
        heads = sorted({0, cap // 2, cap - 1}) if cap else [0]
        for head in heads:
            if head >= 0 and (cap == 0 or head < cap):
                examples.append(model_growth(cap, head, cap, minimum))
    # The extra-space arm is observable in the code but cannot occur in the
    # bounded selected path. This row is an explicitly counterfactual input.
    forced = branch_plan(8, 3, 8, 10)
    if forced[0] != 'tail':
        raise ValueError('counterfactual extra-space branch changed')
    return ({'old_capacity_range': [0, threshold - 1], 'valid_descriptors': count,
             'all_branch_counts': counts, 'full_branch_counts': full,
             'full_descriptors': sum(full.values()), 'logical_mismatches': 0,
             'note': 'synthetic models, not captured execution'}, examples,
            {'old_capacity': 8, 'head': 3, 'length': 8, 'new_capacity': 10,
             'branch': forced[0], 'source': forced[2], 'destination': forced[3],
             'moved_rows': forced[4], 'tail': forced[5], 'prefix': forced[6]})


def model_history(keys, minimum, threshold):
    """Conditional synthetic ring lifecycle; prior lookup/move contracts are assumed."""
    capacity = head = length = 0
    physical = []
    trace = []
    for step, key in enumerate(keys):
        ordered = [physical[(head + i) % capacity] for i in range(length)]
        values = [item[0] for item in ordered]
        if values != sorted(set(values)):
            raise ValueError('synthetic input lost strict key order')
        position = bisect_left(values, key)
        before_capacity, before_head, before_length = capacity, head, length
        growth_kind = 'none'
        if position < length and values[position] == key:
            operation = 'replace'
            physical[(head + position) % capacity] = (key, step)
            expected = ordered[:position] + [(key, step)] + ordered[position + 1:]
        elif length >= threshold:
            operation = 'convert_boundary'
            expected = ordered
        else:
            operation = 'insert'
            expected = ordered[:position] + [(key, step)] + ordered[position:]
            if length == capacity:
                new_capacity = capacity_after_growth(capacity, minimum)
                plan = branch_plan(capacity, head, length, new_capacity)
                growth_kind, new_head, source, destination, moved, _, _ = plan
                physical.extend([None] * (new_capacity - capacity))
                physical[destination:destination + moved] = list(physical[source:source + moved])
                capacity, head = new_capacity, new_head
            # The already studied insertion helper is treated as an assumed
            # logical move contract, not claimed as proven by this packet.
            if length - position >= position:
                new_head = (head - 1) % capacity
                prefix = [physical[(head + i) % capacity] for i in range(position)]
                for i, row in enumerate(prefix):
                    physical[(new_head + i) % capacity] = row
                head = new_head
            else:
                suffix = [physical[(head + i) % capacity] for i in range(position, length)]
                for i, row in enumerate(suffix, start=position + 1):
                    physical[(head + i) % capacity] = row
            physical[(head + position) % capacity] = (key, step)
            length += 1
        actual = [physical[(head + i) % capacity] for i in range(length)]
        if actual != expected:
            raise ValueError('synthetic move lost or reordered a row')
        trace.append((step, key, before_length, before_capacity, before_head, position,
                      operation, growth_kind, length, capacity, head))
        if operation == 'convert_boundary':
            break
    return trace


def tsv(headers, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def json_bytes(obj):
    return (json.dumps(obj, indent=2, sort_keys=True) + '\n').encode('utf-8')


def verify_historical(data):
    authenticate(data, OLD_SHA)
    secs = sections(data)
    rows = relocation_records(data, secs, (
        ('old_location', 'historical', 0x56dfbf8, 8, 0x1dd8eb, ''),
        ('old_callee', 'historical', 0x57755a8, 8, 0x3273810, ''),
    ))
    checked_location(data, secs, rows, 0x56dfbf8, 107, 37)
    _, frames = eh_frame_records(data, secs)
    found = {(f['start'], f['end']) for f in frames}
    if not {(0x32725d0, 0x3272b3a), (0x3273810, 0x327396c)} <= found:
        raise ValueError('historical FDEs changed')
    for va, expected in ((0x3272785, 'ff151d2e5002'), (0x3273856, '488d0d9bc34602'),
                         (0x3273871, '4983fd02')):
        check_window(read_va(data, secs, va, len(expected) // 2), expected)
    if decode_transfer(read_va(data, secs, 0x3272785, 6), 0x3272785, 'call_slot') != 0x57755a8:
        raise ValueError('historical call target changed')


def collect(data):
    authenticate(data, TARGET_SHA)
    secs = sections(data)
    functions, context_fde = select_fdes(data, secs)
    check_window_partition(WINDOWS)
    function_rows = []
    for role, start, end, expected_hash in OWNED:
        fde, index, body = functions[role]
        function_rows.append((role, hex(start), hex(end), hex(file_offset(data, secs, start, end - start)),
                              len(body), hex(fde['fde']), hex(fde['cie']),
                              hex(fde['lsda']) if fde['lsda'] is not None else '-',
                              index['index'], expected_hash, body.hex()))
    windows = []
    for label, scope, va, expected in WINDOWS:
        actual = read_va(data, secs, va, len(expected) // 2)
        check_window(actual, expected)
        windows.append((label, scope, hex(va), hex(file_offset(data, secs, va, len(actual))),
                        len(actual), sha(actual), actual.hex()))
    edges = []
    prefixes = {'call_slot': 2, 'jmp_slot': 2, 'call': 1, 'jbe8': 1, 'jne8': 1,
                'je8': 1, 'ja32': 2, 'lea_rdx': 3}
    for label, scope, va, kind, expected in TRANSFERS:
        width = 1 if kind.endswith('8') else 4
        raw = read_va(data, secs, va, prefixes[kind] + width)
        target = checked_transfer(raw, va, kind, expected)
        edges.append((label, scope, hex(va), hex(file_offset(data, secs, va, len(raw))),
                      kind, raw.hex(), hex(target)))
    relocs = relocation_records(data, secs, SLOTS)
    pointer, size, line, column, suffix = checked_location(data, secs, relocs, 0x64767a8, 123, 37)
    minimum = struct.unpack('<I', read_va(data, secs, 0x5962d37, 4))[0]
    alignment = struct.unpack('<I', read_va(data, secs, 0x5962d48, 4))[0]
    stride = struct.unpack('<I', read_va(data, secs, 0x5962d4e, 4))[0]
    threshold = read_va(data, secs, 0x4dd0189, 1)[0]
    if (minimum, alignment, stride, threshold) != (4, 8, 64, 64):
        raise ValueError('selected operand changed')
    rows = read_exception_rows(data, secs, context_fde)
    matching = [r for r in rows if r[1] <= 0x57ea3a9 and 0x57ea3af <= r[2]]
    if len(matching) != 1 or matching[0][3:] != (0x57ea496, 0, '26ee01960200'):
        raise ValueError('prior call to landing relation changed')
    sweep, examples, forced = make_models(minimum, threshold)
    history = model_history(list(range(threshold - 1, -1, -1)) + [threshold // 2, threshold],
                            minimum, threshold)
    relocation_rows = [(a, b, hex(c), hex(d), e, f, hex(g), h)
                       for a, b, c, d, e, f, g, h in relocs]
    ex = matching[0]
    metadata = {
        'artifact': 'node-115', 'binary_sha256': sha(data),
        'scope': 'selected FDEs and contextual call-site evidence',
        'new_fdes': len(function_rows), 'windows': len(windows),
        'new_windows': sum(x[1] == 'new' for x in windows),
        'transfers': len(edges), 'new_transfers': sum(x[1] == 'new' for x in edges),
        'selected_relocations': len(relocation_rows),
        'prior_callsite_matches': len(matching),
        'minimum_capacity': minimum, 'element_alignment': alignment,
        'element_bytes': stride, 'prior_conversion_threshold': threshold,
        'synthetic_sweep': sweep,
        'synthetic_history_steps': len(history),
    }
    output = {
        'functions.tsv': tsv(('role', 'start_va', 'end_va_exclusive', 'file_offset', 'byte_count', 'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'sha256', 'raw_hex'), function_rows),
        'windows.tsv': tsv(('label', 'scope', 'va', 'file_offset', 'byte_count', 'sha256', 'raw_hex'), windows),
        'transfers.tsv': tsv(('label', 'scope', 'va', 'file_offset', 'form', 'raw_hex', 'destination_va'), edges),
        'relocations.tsv': tsv(('label', 'scope', 'slot_va', 'record_file_offset', 'type', 'symbol_index', 'addend', 'symbol'), relocation_rows),
        'location.tsv': tsv(('scope', 'location_va', 'location_file_offset', 'string_va', 'string_length', 'line', 'column', 'path_suffix'),
                            [('prior_context', hex(0x64767a8), hex(file_offset(data, secs, 0x64767a8, 24)), hex(pointer), size, line, column, suffix)]),
        'unwind-context.tsv': tsv(('scope', 'lsda_va', 'entry_file_offset', 'begin_va', 'end_va_exclusive', 'landing_va', 'action', 'raw_hex'),
                                  [('prior_context', hex(context_fde['lsda']), hex(ex[0]), hex(ex[1]), hex(ex[2]), hex(ex[3]), ex[4], ex[5])]),
        'synthetic-examples.tsv': tsv(('old_capacity', 'head', 'length', 'new_capacity', 'new_head', 'branch', 'source', 'destination', 'moved_rows', 'tail', 'prefix', 'preserved'),
                                      [tuple(x[k] for k in ('old_capacity', 'head', 'length', 'new_capacity', 'new_head', 'branch', 'source', 'destination', 'moved_rows', 'tail', 'prefix', 'preserved')) for x in examples]),
        'synthetic-counterfactual.json': json_bytes(forced),
        'synthetic-history.tsv': tsv(('step', 'key', 'old_count', 'old_capacity', 'old_head', 'position', 'operation', 'growth_branch', 'new_count', 'new_capacity', 'new_head'), history),
        'summary.json': json_bytes(metadata),
    }
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--historical-node', type=Path, help='optionally authenticate and cross-check a separate node 94 capture')
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    output = collect(data)
    if args.historical_node is not None:
        verify_historical(args.historical_node.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, contents in sorted(output.items()):
        (args.out / name).write_bytes(contents)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error, UnicodeError) as error:
        print('abci_ring_growth115: ' + str(error), file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Extract the node 115 precompile registry refresh path statically.

Only authenticated ELF bytes and the repository's shared ELF/FDE readers are
used. Selected x86 instruction shapes are deliberately narrow, not a general
instruction decoder. No target code or external program is executed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE_COMMIT = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'

# FDE and digest checks describe these selected bodies, not all functions.
FUNCTIONS = (
    (0x2668a20, 0x2668e7a, '25071c00839d39208bdd6aa60f7f67aace2471af788c0db85db9d0cdd53c87ba', 'context preparation'),
    (0x2a03a10, 0x2a03b0f, '6713ed3d3e532ee371e594d7e0afdedf933f61b17ad447994ac776d45e2c3b91', 'nested map cleanup'),
    (0x2a318d0, 0x2a31a25, 'f61bc2516efc260533147ff93c88bfef0d02bceb39371f817f3cc019c5a94300', 'nested map probe'),
    (0x2a32b00, 0x2a32c97, 'f0f2f22fc1761fec5cc642b965a43ebcf313e52e77046be7d5396af2efaf6c12', 'nested key insertion'),
    (0x2a6b7a0, 0x2a6b875, 'f89b5ad45e9ecfb6da66663eb70e601e5fd5781fe73837457f7e38bdf1062815', 'selector update'),
    (0x38be4a0, 0x38be7f6, '8d3626b95fe860556a7e6d824a891729e171d97f0210888afc083b105ae8623b', 'replacement address set builder'),
    (0x3ec3f40, 0x3ec3f7b, '791adb2678451687f3b797bf4c0b0c7670049efa1cef66b7f578fb33ed1a7d71', 'address set cleanup'),
    (0x5bdf390, 0x5bdf60e, 'd1277eb46a1f582afe78748abc9cadfbc08c75b9cbce50964603af81b00bd243', 'full address set replacement'),
    (0x5bdf610, 0x5bdf8d7, '004d33b42800683c2de8e1e0f3e3bbeb4e8906298f814138133c4f5425ec4bde', 'compact projection and set copy'),
    (0x5be4f10, 0x5be533a, '68d1ffa9a992caff410914631bf5c10c11bafb0f5b60fc77249469666701a24f', 'address set reserve'),
)

# The following windows and transfers are selected, not a complete CFG.
WINDOWS = (
    ('context_entry', 0x2668a37, 0x2668a8e),
    ('context_20byte_copy', 0x2668a8e, 0x2668ac2),
    ('optional_rows', 0x2668ac2, 0x2668b60),
    ('row_key', 0x2668b70, 0x2668bbd),
    ('map_insert', 0x2668c5c, 0x2668cfd),
    ('nested_reserve', 0x2668d05, 0x2668d40),
    ('nested_key_loop', 0x2668d40, 0x2668d82),
    ('map_publish', 0x2668ddd, 0x2668e36),
    ('context_return', 0x2668e36, 0x2668e52),
    ('context_exception', 0x2668e63, 0x2668e7a),
    ('selector_entry', 0x2a6b7aa, 0x2a6b7fa),
    ('selector_replacement', 0x2a6b7fa, 0x2a6b854),
    ('selector_return', 0x2a6b854, 0x2a6b875),
    ('builder_prepare', 0x38be4a0, 0x38be4d8),
    ('builder_finish', 0x38be7a2, 0x38be7f6),
    ('cleanup', 0x3ec3f40, 0x3ec3f7b),
    ('reserve_select', 0x5be4f32, 0x5be4fb6),
    ('reserve_size', 0x5be4fb6, 0x5be5034),
    ('reserve_alloc', 0x5be5056, 0x5be50b0),
    ('reserve_publish', 0x5be5296, 0x5be52fe),
    ('reserve_fail', 0x5be52fe, 0x5be533a),
    ('projection_header', 0x5bdf61e, 0x5bdf651),
    ('projection_prepare', 0x5bdf6d4, 0x5bdf747),
    ('projection_scan', 0x5bdf747, 0x5bdf7fe),
    ('projection_bit', 0x5bdf7fe, 0x5bdf830),
    ('projection_finish', 0x5bdf856, 0x5bdf883),
    ('projection_failure', 0x5bdf884, 0x5bdf8d7),
    ('setcopy_equal', 0x5bdf3a1, 0x5bdf404),
    ('setcopy_empty', 0x5bdf404, 0x5bdf470),
    ('setcopy_allocate', 0x5bdf470, 0x5bdf515),
    ('setcopy_publish', 0x5bdf515, 0x5bdf596),
    ('setcopy_failure', 0x5bdf5a0, 0x5bdf60e),
    ('map_lookup', 0x2a318de, 0x2a319be),
    ('map_hit_miss', 0x2a319be, 0x2a31a25),
    ('nested_insert_start', 0x2a32b0b, 0x2a32b22),
    ('nested_insert_compare', 0x2a32b4c, 0x2a32bc0),
    ('nested_insert_write', 0x2a32c01, 0x2a32c61),
    ('nested_insert_reserve', 0x2a32c61, 0x2a32c97),
    ('nested_cleanup', 0x2a03a1b, 0x2a03b0f),
)

EDGES = (
    ('context_update', 0x2668a4e), ('context_changed', 0x2668a55),
    ('context_word_zero', 0x2668a5f), ('context_extra_address', 0x2668a64),
    ('context_optional_feature', 0x2668a6e), ('context_rebuild', 0x2668a83), ('optional_state', 0x2668abc),
    ('rows_complete', 0x2668b4a), ('map_probe', 0x2668bab),
    ('nested_reserve_needed', 0x2668d27), ('nested_insert', 0x2668d74),
    ('nested_reserve_call', 0x2668d93), ('old_map_cleanup', 0x2668e09),
    ('temporary_map_cleanup', 0x2668e6d), ('unchanged_selector', 0x2a6b7b3),
    ('registry_init_guard', 0x2a6b7e5), ('set_builder', 0x2a6b7f4),
    ('previous_set_guard', 0x2a6b805), ('old_set_drop', 0x2a6b833),
    ('registry_once_adapter', 0x2a6b86b), ('set_clone', 0x38be4b4),
    ('hint_guard', 0x38be4d2), ('hint_reserve', 0x38be7d4),
    ('builder_cleanup', 0x38be7e9), ('reserve_overflow', 0x5be4f36),
    ('reserve_rehash', 0x5be4f63), ('reserve_capacity', 0x5be4fac),
    ('reserve_size_guard', 0x5be5001), ('reserve_size_limit', 0x5be5036),
    ('reserve_alloc', 0x5be505e), ('reserve_alloc_guard', 0x5be5067),
    ('reserve_old_drop', 0x5be52f3), ('reserve_unwind', 0x5be5335),
    ('compact_limit', 0x5bdf7f8), ('compact_bound', 0x5bdf814),
    ('copy_full_set', 0x5bdf868), ('setcopy_size', 0x5bdf484),
    ('setcopy_alloc', 0x5bdf50f), ('setcopy_old_drop', 0x5bdf585),
    ('map_duplicate', 0x2a31991), ('map_empty', 0x2a319ac),
    ('map_miss_growth', 0x2a319d4), ('map_reserve', 0x2a31a17), ('nested_growth', 0x2a32b1c),
    ('nested_duplicate', 0x2a32ba8), ('nested_empty', 0x2a32be4),
    ('nested_reserve', 0x2a32c74),
)

SLOTS = {
    0x64e7158: 0x38be4a0,
    0x64e5ff0: 0x5bdf610,
    0x64e94e8: 0x5be4f10,
    0x64e7030: 0x3eda870,
    0x64dfab8: 0x143d5f0,
    0x64dfa78: 0x64ffe90,
    0x64df480: 0x6355830,
    0x64df490: 0x141e251,
    0x64df4a0: 0x635de30,
}

def fail(message):
    raise ValueError(message)


def check_digest(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail('node 115 SHA-256 mismatch')


class Image:
    def __init__(self, data, *, authenticate=True):
        if authenticate:
            check_digest(data)
        self.data = data
        self.sections = sections(data)
        _, index = unwind_index(data)
        self.index = {e['start']: e for e in index}
        _, fdes = eh_frame_records(data, self.sections)
        self.fdes = {}
        for fde in fdes:
            self.fdes.setdefault(fde['start'], []).append(fde)
        self._relocations = None

    def locate(self, va, size):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            fail('invalid file-backed range')
        hits = [s for s in self.sections if s['type'] != 8 and s['address'] <= va
                and va + size <= s['address'] + s['size']]
        if len(hits) != 1:
            fail('range is not uniquely file-backed')
        s = hits[0]
        off = s['offset'] + va - s['address']
        if off < 0 or off + size > len(self.data):
            fail('range exceeds ELF file')
        return s, off

    def read(self, va, size):
        _, off = self.locate(va, size)
        return bytes(self.data[off:off + size])

    def record(self, va):
        n = struct.unpack('<I', self.read(va, 4))[0]
        if n == 0 or n == 0xffffffff:
            fail('unsupported unwind record')
        return self.read(va, n + 4)

    def relocations(self):
        if self._relocations is None:
            found = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
            if len(found) != 1 or found[0]['size'] % 24:
                fail('bad relocation section')
            sec = found[0]
            result = {}
            for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
                raw = bytes(self.data[off:off + 24])
                slot, info, addend = struct.unpack('<QQq', raw)
                result.setdefault(slot, []).append((info, addend, off, raw))
            self._relocations = result
        return self._relocations

    def relative_relocation(self, slot):
        rows = self.relocations().get(slot, [])
        if len(rows) != 1:
            fail('missing or duplicate relocation')
        info, addend, off, raw = rows[0]
        if info != 8 or addend < 0:
            fail('expected symbol-free R_X86_64_RELATIVE')
        return {'slot_va': hx(slot), 'entry_file_offset': hx(off),
                'type': 'R_X86_64_RELATIVE', 'addend_va': hx(addend), 'raw': raw.hex()}

    def functions(self):
        result = []
        for start, end, expected, role in FUNCTIONS:
            found = self.fdes.get(start, [])
            if len(found) != 1 or start not in self.index:
                fail('selected FDE missing, duplicated, or absent from index')
            fde = found[0]
            if fde['end'] != end or self.index[start]['fde'] != fde['fde']:
                fail('selected FDE/index mismatch')
            sec, off = self.locate(start, end - start)
            if not sec['flags'] & 4:
                fail('selected FDE is not executable file data')
            body = self.read(start, end - start)
            got = hashlib.sha256(body).hexdigest()
            if got != expected:
                fail('selected FDE body digest mismatch')
            result.append({'start_va': hx(start), 'end_va_exclusive': hx(end),
                           'file_offset': hx(off), 'section': sec['name'],
                           'size': len(body), 'sha256': got, 'fde_va': hx(fde['fde']),
                           'cie_va': hx(fde['cie']),
                           'lsda_va': hx(fde['lsda']) if fde['lsda'] is not None else None,
                           'fde_bytes': self.record(fde['fde']).hex(),
                           'cie_bytes': self.record(fde['cie']).hex(),
                           'body_bytes': body.hex(), 'role_inferred': role})
        return result


def hx(n):
    return hex(n)


def signed_byte(n):
    return n - 256 if n >= 128 else n


def transfer(image, va):
    b = image.read(va, 2)
    if b[0] in (0xe8, 0xe9):
        raw = image.read(va, 5)
        target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        kind = 'call' if b[0] == 0xe8 else 'jump'
    elif b[0] in range(0x70, 0x80) or b[0] == 0xeb:
        raw = b
        target = va + 2 + signed_byte(b[1])
        kind = 'short-branch'
    elif b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
        raw = image.read(va, 6)
        target = va + 6 + struct.unpack_from('<i', raw, 2)[0]
        kind = 'near-branch'
    elif b == b'\xff\x15':
        raw = image.read(va, 6)
        target = va + 6 + struct.unpack_from('<i', raw, 2)[0]
        kind = 'indirect-slot'
    else:
        fail('unsupported selected transfer')
    return kind, target, raw


def rip_target(image, va, prefix):
    raw = image.read(va, len(prefix) + 4)
    if raw[:len(prefix)] != prefix:
        fail('unexpected RIP-relative instruction')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def set_calls(image):
    result = []
    for owner, start, stack in ((0x38be4a0, 0x38be4d8, 0x18),):
        for index in range(21):
            va = start + index * 34
            raw = image.read(va, 34)
            if (raw[:2] != bytes.fromhex('8b05') or raw[6:10] != bytes.fromhex('89442410')
                    or raw[10:13] != bytes.fromhex('0f1005')
                    or raw[17:25] != bytes.fromhex('0f290424488d7c24')
                    or raw[25] != stack or raw[26:29] != bytes.fromhex('4889e6')
                    or raw[29] != 0xe8):
                fail('unexpected set insertion preparation')
            tail_source = va + 6 + struct.unpack_from('<i', raw, 2)[0]
            prefix_source = va + 17 + struct.unpack_from('<i', raw, 13)[0]
            target = va + 34 + struct.unpack_from('<i', raw, 30)[0]
            if tail_source != prefix_source + 16 or target != 0x3ed7620:
                fail('set insertion source or callee changed')
            key = image.read(prefix_source, 20)
            result.append({'owner_va': hx(owner), 'index': index, 'window_va': hx(va),
                           'window_bytes': raw.hex(), 'source_va': hx(prefix_source),
                           'source_file_offset': hx(image.locate(prefix_source, 20)[1]),
                           'key_hex': key.hex(), 'stack_set_offset': hx(stack),
                           'callee_va': hx(target)})
    return result


def exception_tables(image):
    """Decode selected LSDA call-site tables, not action/type semantics."""
    headers = []
    rows = []
    for start, end, _, _ in FUNCTIONS:
        fde = image.fdes[start][0]
        va = fde['lsda']
        if va is None:
            continue
        section, _ = image.locate(va, 1)
        if section['name'] != '.gcc_except_table':
            fail('LSDA is outside the exception section')
        available = section['address'] + section['size'] - va
        head = image.read(va, min(available, 32))
        if len(head) < 4 or head[0] != 0xff or head[1] not in (0xff, 0x9b):
            fail('unsupported LSDA header')
        pos = 2
        type_offset = None
        if head[1] != 0xff:
            type_offset, pos = uleb(head, pos, len(head))
        if pos >= len(head) or head[pos] != 1:
            fail('unsupported LSDA call-site encoding')
        pos += 1
        length, pos = uleb(head, pos, len(head))
        if length > available - pos:
            fail('truncated LSDA call-site table')
        raw = image.read(va, pos + length)
        table_start, table_end = pos, pos + length
        count = 0
        while pos < table_end:
            row_start = pos
            values = []
            for _ in range(4):
                value, pos = uleb(raw, pos, table_end)
                values.append(value)
            offset, size, landing, action = values
            if offset + size > end - start or (landing and landing >= end - start):
                fail('LSDA call-site or landing outside selected FDE')
            rows.append({'fde_start_va': hx(start), 'lsda_va': hx(va),
                         'entry_va': hx(va + row_start), 'entry_bytes': raw[row_start:pos].hex(),
                         'start_va': hx(start + offset), 'end_va_exclusive': hx(start + offset + size),
                         'landing_va': hx(start + landing) if landing else '', 'action_offset': action})
            count += 1
        if pos != table_end:
            fail('LSDA call-site length mismatch')
        headers.append({'fde_start_va': hx(start), 'lsda_va': hx(va),
                        'file_offset': hx(image.locate(va, len(raw))[1]),
                        'lpstart_encoding': raw[0], 'type_encoding': raw[1],
                        'type_table_offset': type_offset, 'callsite_encoding': 1,
                        'callsite_table_offset': table_start, 'callsite_table_length': length,
                        'callsite_count': count, 'header_and_callsite_bytes': raw.hex()})
    return headers, rows


def correlate_calls(edges, copies, rows):
    """Join a selected call address to LSDA intervals without executing it."""
    sites = [(x['name'], int(x['site_va'], 16)) for x in edges
             if x['kind'] in ('call', 'indirect-slot')]
    sites += [('set_insert_' + x['owner_va'] + '_' + str(x['index']),
               int(x['window_va'], 16) + 29) for x in copies]
    output = []
    for name, site in sorted(sites, key=lambda item: (item[1], item[0])):
        owners = [(start, end) for start, end, _, _ in FUNCTIONS if start <= site < end]
        if len(owners) != 1:
            fail('selected call has no unique FDE')
        owner = owners[0][0]
        matches = [row for row in rows if int(row['fde_start_va'], 16) == owner
                   and int(row['start_va'], 16) <= site < int(row['end_va_exclusive'], 16)]
        if len(matches) > 1:
            fail('overlapping LSDA call-site intervals')
        row = matches[0] if matches else None
        output.append({'name': name, 'site_va': hx(site), 'fde_start_va': hx(owner),
                       'lsda_entry_va': row['entry_va'] if row else '',
                       'landing_va': row['landing_va'] if row else '',
                       'action_offset': row['action_offset'] if row else '',
                       'coverage': 'covered' if row else 'no selected table entry'})
    return output


def small_key(key, limit):
    """Model only the selected 20-byte zero-prefix and unsigned limit test."""
    if len(key) != 20 or not 0 <= limit <= 65536:
        fail('invalid projection input')
    if key[:18] != bytes(18):
        return None
    value = int.from_bytes(key[18:], 'big')
    return value if value < limit else None


def fold64(a, b):
    if not (0 <= a < 1 << 64 and 0 <= b < 1 << 64):
        fail('hash word out of range')
    product = a * b
    return (product & ((1 << 64) - 1)) ^ (product >> 64)


def hash20(key, seed, secret):
    if len(key) != 20:
        fail('key is not 20 bytes')
    a, b, c = struct.unpack('<QQI', key)
    return fold64(fold64(a ^ seed, b ^ secret) ^ c, secret)


def probe20(controls, keys, value, key):
    """A bounded model of the observed 16-control candidate/empty scan."""
    count = len(controls)
    if (count < 16 or count & (count - 1) or len(keys) != count or len(key) != 20
            or not 0 <= value < 1 << 64
            or any(not isinstance(c, int) or not 0 <= c <= 255 for c in controls)):
        fail('invalid synthetic table')
    if any(k is not None and len(k) != 20 for k in keys):
        fail('invalid synthetic key')
    mask = count - 1
    pos = value & mask
    tag = value >> 57
    step = 0
    for _ in range(count // 16):
        group = [(pos + i) & mask for i in range(16)]
        for index in group:
            if controls[index] == tag and keys[index] == key:
                return index
        if any(controls[index] == 0xff for index in group):
            return None
        step += 16
        pos = (pos + step) & mask
    fail('synthetic table has no reachable empty control')


def nested_key32(key):
    """Model the selected four-word byte swap and reverse-word stores."""
    if len(key) != 32:
        fail('nested key is not 32 bytes')
    words = [int.from_bytes(key[i:i + 8], 'little') for i in range(0, 32, 8)]
    return b''.join(word.to_bytes(8, 'big') for word in reversed(words))


def model_reserve(mask, count, additional):
    """Model the selected reserve arithmetic for valid synthetic table masks."""
    maximum = (1 << 64) - 1
    if (not 0 <= mask < maximum or not 0 <= count <= maximum
            or not 0 <= additional <= maximum):
        fail('invalid synthetic reserve inputs')
    buckets = mask + 1
    if buckets & (buckets - 1):
        fail('synthetic mask is not one less than a power of two')
    needed = count + additional
    if needed > maximum:
        fail('synthetic count overflow')
    capacity = mask if mask < 8 else buckets - buckets // 8
    if needed <= capacity // 2:
        return {'action': 'in_place'}
    request = max(capacity + 1, needed)
    if request < 4:
        replacement = 4
    elif request < 8:
        replacement = 8
    elif request < 15:
        replacement = 16
    else:
        if request >= 1 << 61:
            fail('synthetic reserve request overflow')
        adjusted = (request * 8) // 7
        replacement = 1 << (adjusted - 1).bit_length()
    payload = 20 * replacement
    if payload > maximum:
        fail('synthetic allocation multiplication overflow')
    size = ((payload + 15) & ~15) + replacement + 16
    if size > (1 << 63) - 16:
        fail('synthetic allocation size overflow')
    return {'action': 'allocate', 'buckets': replacement, 'bytes': size}


def refresh_decision(old, new, occupied):
    if not (0 <= old <= 255 and 0 <= new <= 255 and occupied >= 0):
        fail('invalid synthetic selector input')
    return {'old': old, 'new': new, 'context_word': occupied,
            'selector_changed': int(old != new),
            'rebuild_projection': int(old != new or occupied == 0),
            'copy_extra_address': int(new > 9)}


def project(image):
    functions = image.functions()
    edges = []
    for name, va in EDGES:
        if sum(start <= va < end for start, end, _, _ in FUNCTIONS) != 1:
            fail('selected transfer is outside the selected FDEs')
        kind, target, raw = transfer(image, va)
        edges.append({'name': name, 'site_va': hx(va),
                      'file_offset': hx(image.locate(va, len(raw))[1]),
                      'bytes': raw.hex(), 'kind': kind, 'target_va': hx(target)})
    relocations = []
    for slot, expected in sorted(SLOTS.items()):
        rel = image.relative_relocation(slot)
        if int(rel['addend_va'], 16) != expected:
            fail('unexpected selected relocation addend')
        relocations.append(rel)
    secret_relocation = image.relative_relocation(0x64dfa78)
    secret_va = int(secret_relocation['addend_va'], 16)
    secret_sections = [sec for sec in image.sections if sec['type'] == 8
                       and sec['address'] <= secret_va < sec['address'] + sec['size']]
    if len(secret_sections) != 1:
        fail('runtime hash secret target is not in one NOBITS section')
    secret_section = secret_sections[0]
    runtime_boundary = {'secret_slot_relocation': secret_relocation,
                        'target_section': secret_section['name'],
                        'section_type': secret_section['type'],
                        'section_start_va': hx(secret_section['address']),
                        'section_end_va_exclusive': hx(secret_section['address'] + secret_section['size']),
                        'runtime_secret_value': None,
                        'limitation': 'NOBITS supplies no file bytes for the relocated runtime target.'}
    copies = set_calls(image)
    expected_keys = [0x800, 0x813] + list(range(0x801, 0x813)) + [0x814]
    if [bytes.fromhex(row['key_hex']) for row in copies] != [n.to_bytes(20, 'big') for n in expected_keys]:
        fail('selected builder key sequence changed')
    anchor_va = 0x64c0730
    anchor_bytes = image.read(anchor_va, 56)
    address09 = (9).to_bytes(20, 'big')
    rel = image.relative_relocation(anchor_va + 24)
    tag = struct.unpack_from('<Q', anchor_bytes)[0]
    if (anchor_bytes[32:52] != address09 or tag != 0x8000000000000009
            or rel['addend_va'] != hx(0x5c165b0)):
        fail('prior standard address-09 record changed')
    anchor = {'record_va': hx(anchor_va), 'record_file_offset': hx(image.locate(anchor_va, 56)[1]),
              'record_bytes': anchor_bytes.hex(), 'tag_le_u64': hx(tag),
              'key_offset': 32, 'key_hex': address09.hex(),
              'callback_relocation': rel,
              'limitation': 'Data-only anchor. Its construction and runtime use depend on separate prior evidence.'}
    table = rip_target(image, 0x2a6b7bf, bytes.fromhex('488d0d'))
    mode_bytes = image.read(table, 15)
    if mode_bytes != bytes((0, 0, 0, 0, 1, 1, 2, 3, 3, 3, 3, 4, 5, 6, 6)):
        fail('selected selector-table bytes changed')
    modes = [{'raw_selector': i, 'entry_va': hx(table + i), 'entry_byte': b}
             for i, b in enumerate(mode_bytes)]
    instruction = image.read(0x5bdf7f2, 6)
    if instruction[:2] != bytes.fromhex('81f9'):
        fail('unexpected compact-key bound instruction')
    limit = struct.unpack_from('<I', instruction, 2)[0]
    if limit != 300:
        fail('unexpected compact-key bound')
    if small_key(address09, limit) != 9 or any(small_key(bytes.fromhex(x['key_hex']), limit) is not None for x in copies):
        fail('compact-key classification changed')
    projections = []
    candidates = [('prior_record', anchor_va + 32, anchor_bytes[32:52])]
    candidates += [('replacement_builder', int(row['source_va'], 16), bytes.fromhex(row['key_hex']))
                   for row in copies]
    for origin, key_va, key in candidates:
        index = small_key(key, limit)
        projections.append({'origin': origin, 'key_va': hx(key_va), 'key_hex': key.hex(),
                            'limit_exclusive': limit, 'passes_key_test': int(index is not None),
                            'index_if_passes': index if index is not None else ''})
    windows = []
    for name, start, end in WINDOWS:
        if sum(owner <= start < end <= limit for owner, limit, _, _ in FUNCTIONS) != 1:
            fail('selected window is outside the selected FDEs')
        raw = image.read(start, end - start)
        windows.append({'name': name, 'start_va': hx(start), 'end_va_exclusive': hx(end),
                        'file_offset': hx(image.locate(start, len(raw))[1]), 'bytes': raw.hex()})
    headers, rows = exception_tables(image)
    calls = correlate_calls(edges, copies, rows)
    summary = {'target': 'Linux x86-64 node 115', 'sha256': DIGEST, 'source_commit': BASE_COMMIT,
               'coordinate_system': 'linked ELF VA before load bias',
               'selected_fde_count': len(functions), 'selected_fde_bytes': sum(x['size'] for x in functions),
               'selected_window_count': len(windows), 'selected_transfer_count': len(edges),
               'relative_relocation_count': len(relocations), 'replacement_insert_call_count': len(copies),
               'mode_table_va': hx(table), 'mode_sample_count': len(modes),
               'small_key_bound_instruction_va': hx(0x5bdf7f2), 'small_key_bound_exclusive': limit,
               'lsda_table_count': len(headers), 'lsda_callsite_count': len(rows),
               'selected_callsite_count': len(calls),
               'limitations': 'Selected code and static bytes only; no target execution, complete CFG, runtime state, source build or component gate.'}
    return {'summary.json': summary, 'functions.json': functions, 'dependency-anchor.json': anchor,
            'runtime-boundary.json': runtime_boundary,
            'lsda-headers.json': headers, 'lsda-call-sites.tsv': rows,
            'selected-call-sites.tsv': calls, 'windows.tsv': windows, 'edges.tsv': edges,
            'relocations.tsv': relocations, 'set-copies.tsv': copies, 'mode-cases.tsv': modes,
            'key-projection.tsv': projections}


def write_outputs(output, records):
    output.mkdir(parents=True, exist_ok=True)
    for name, value in records.items():
        if name.endswith('.json'):
            (output / name).write_text(json.dumps(value, indent=2, ensure_ascii=True) + '\n', encoding='ascii')
        else:
            if not value:
                fail('empty evidence table')
            with (output / name).open('w', encoding='ascii', newline='') as handle:
                writer = csv.DictWriter(handle, fieldnames=list(value[0]), delimiter='\t', lineterminator='\n')
                writer.writeheader()
                writer.writerows(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    image = Image(data)
    write_outputs(args.out, project(image))


if __name__ == '__main__':
    main()

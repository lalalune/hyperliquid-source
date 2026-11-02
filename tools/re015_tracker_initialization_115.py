"""Reproduce selected node-115 alert-tracker initialization evidence by static reads.

This is a digest-specific collector, not an x86 decoder or a runtime emulator.
All instruction witnesses were selected after independent disassembly; only
explicit opcodes and operands are decoded here.  The shared ELF and DWARF
parsers supply sections and unwind ranges.
"""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records, uleb  # noqa: E402

TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OLD_TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/115/hl-node'

# role, FDE start, exclusive FDE end, hash of all file-backed FDE bytes
FUNCTIONS = [
    ('owner_initializer', 0x150c020, 0x150c1de, '3b11878a8b8ae8e9b44714ee33c0a077b2729a079f32ee2424e2d4622a66d53a'),
    ('ack_initializer', 0x1549e20, 0x154a35d, '1eeb455e34d37a6eccf6a4e0241bd6ed39b4e3ebe6e82769b501bb660a3eef7b'),
    ('ignore_initializer', 0x154a360, 0x154a89d, 'abf9a8f403b777a5133d99c21a66d37bf656767247f68a1e27038042bc55faba'),
    ('ack_reader', 0x1503670, 0x15039d5, 'c43ebffe3cbcae7b4fe049decb6d1b80f4c2477850af60a9bc9a315052236de4'),
    ('ignore_reader', 0x15039e0, 0x1503d45, '19d4f39210f234234f272b8165e3e0f19de944fb86fd6e38d2b9f4297b09bb9a'),
    ('ack_writer', 0x1504330, 0x1504797, '0270e9243aa1beedc4e3ae9bd48db2cff1133092ed69674ff5c87ddcd50f6024'),
    ('ignore_writer', 0x1504c10, 0x1505077, '00c990b760a1b41714e48acb5128bcbe13d95f361330b5c3f2c6dfc4fe0184da'),
]

# Only these selected conditional edges are claimed.  The paired instances
# have the same local control-flow geometry but distinct FDEs.
CONSTRUCTOR_BRANCHES = [
    ('config_guard', 0x1549e44, '0f85', 0x154a1d6),
    ('not_regular', 0x1549ec8, '74', 0x1549efc),
    ('empty_path', 0x1549ecd, '0f84', 0x1549fa5),
    ('alloc_failed', 0x1549edf, '0f84', 0x154a2ba),
    ('secondary_guard', 0x1549f1f, '0f85', 0x154a212),
    ('initial_write_failed', 0x1549f45, '0f85', 0x154a252),
    ('timestamp_ok', 0x1549fc9, '75', 0x1549fd2),
    ('read_not_error_sentinel', 0x154a00a, '71', 0x154a021),
    ('no_path_allocation', 0x154a00f, '74', 0x154a077),
    ('secondary_guard_loaded', 0x154a03d, '0f85', 0x154a27a),
    ('original_path_not_sentinel', 0x154a06e, '0f85', 0x154a16b),
    ('no_temp_allocation', 0x154a1c4, '74', 0x154a156),
]
READER_BRANCHES = [
    ('expanded_not_regular', 0x15036a7, '74', 0x15036be),
    ('component_not_tag_9', 0x1503772, '0f85', 0x1503819),
    ('suffix_compare_false', 0x15037d3, '74', 0x1503819),
    ('binary_input_not_error', 0x1503804, '0f81', 0x1503903),
    ('text_input_not_error', 0x1503848, '71', 0x1503860),
    ('text_decode_not_error', 0x150389d, '75', 0x15038b7),
    ('binary_decode_not_tag_9', 0x150394d, '75', 0x1503971),
]
WRITER_BRANCHES = [
    ('device_length_ne_9', 0x1504361, '0f85', 0x150440e),
    ('device_bytes_equal', 0x1504380, '0f84', 0x150441c),
    ('suffix_compare_false', 0x15044bb, '0f84', 0x1504545),
    ('binary_encode_error', 0x1504530, '0f85', 0x150470f),
    ('text_allocation_failed', 0x1504553, '0f84', 0x1504753),
    ('text_encode_nonzero', 0x15045ad, '0f85', 0x15046e6),
    ('text_buffer_sentinel', 0x15045c3, '0f80', 0x15046fd),
    ('component_outside_range', 0x150461b, '73', 0x1504641),
    ('component_conversion_other', 0x150463b, '0f85', 0x15046d7),
    ('directory_predicate_true', 0x150465e, '75', 0x1504690),
    ('create_ok', 0x1504681, '74', 0x1504690),
]

# name, instruction VA, form, expected destination or RELATIVE slot.
# Indirect destinations are independently resolved via .rela.dyn, not guessed.
TRANSFERS = [
    ('make_ignore', 0x150c035, 'direct', 0x154a360),
    ('make_ack', 0x150c046, 'direct', 0x1549e20),
    ('owner_allocate', 0x150c050, 'slot', 0x64df480),
    ('owner_alloc_failure', 0x150c1a0, 'slot', 0x64df498),
    ('owner_drop_ack', 0x150c1b0, 'direct', 0x150c320),
    ('owner_drop_ignore', 0x150c1b8, 'direct', 0x150c3c0),
    ('owner_drop_ignore_after_ack_unwind', 0x150c1cb, 'direct', 0x150c3c0),
    ('owner_resume_unwind', 0x150c1d3, 'direct', 0x63f0a50),
]
INIT_TRANSFERS = [
    ('format_path', 0x1549e9c, 'slot', 0x64df6e8),
    ('regular_predicate', 0x1549ec0, 'slot', 0x64e0950),
    ('make_default', 0x1549f3d, 'direct', 0x1504330),
    ('read_timestamp', 0x1549fbe, 'slot', 0x64e0a10),
    ('load_value', 0x1549ff5, 'direct', 0x1503670),
    ('record_load_error', 0x154a100, 'slot', 0x64e0b18),
    ('write_failure', 0x154a272, 'slot', 0x64df6a0),
    ('allocation_failure', 0x154a2c2, 'slot', 0x64df498),
]
READER_TRANSFERS = [
    ('expand_path', 0x1503689, 'slot', 0x64e0948),
    ('regular_predicate', 0x150369f, 'slot', 0x64e0950),
    ('extension_compare', 0x15037cc, 'direct', 0x159fca0),
    ('binary_read', 0x15037e4, 'slot', 0x64e09b8),
    ('text_read', 0x1503828, 'slot', 0x64e09c0),
    ('binary_read_error', 0x1503812, 'direct', 0x1504130),
    ('text_read_error', 0x1503852, 'direct', 0x15040b0),
    ('text_decode_error', 0x15038a4, 'direct', 0x15041b0),
    ('binary_decode_error', 0x150398f, 'direct', 0x1504280),
]
WRITER_TRANSFERS = [
    ('extension_compare', 0x15044b4, 'direct', 0x159fca0),
    ('directory_predicate', 0x1504656, 'slot', 0x64e0928),
    ('directory_create', 0x1504678, 'slot', 0x64e0940),
    ('create_error', 0x1504689, 'direct', 0x1500b90),
    ('publish_bytes', 0x15046a6, 'slot', 0x64e09e8),
    ('allocation_failure', 0x150475d, 'slot', 0x64df498),
    ('text_encode_error', 0x1504708, 'direct', 0x1505980),
    ('binary_encode_error', 0x1504749, 'direct', 0x15058c0),
]

# role, VA, exact bytes.  These pin data flow and immediate operands that a
# branch-target table alone would miss.  No bytes are copied into executable code.
WITNESSES = [
    ('owner_marker_size', 0x150c04b, 'bf14000000'),
    ('owner_marker_tail', 0x150c069, 'c74010696f6e29'),
    ('copy_ignore_first', 0x150c083, '0f114330'),
    ('copy_ignore_last', 0x150c0a1, '0f118380000000'),
    ('copy_ack_first', 0x150c0c2, '0f118390000000'),
    ('copy_ack_last', 0x150c0f5, '0f1183e0000000'),
    ('owner_sentinel_first', 0x150c122, '488983f0000000'),
    ('owner_sentinel_second', 0x150c129, '48898308010000'),
    ('ack_interval_bits', 0x1549f83, '48b80000000000001440'),
    ('ack_directory_field', 0x1549e4a, '4983c618'),
    ('ack_interval_store', 0x1549f8d, '48894330'),
    ('ack_default_metadata', 0x1549f74, '48c743501a40f600'),
    ('ack_error_pointer_store', 0x154a152, '48894348'),
    ('ack_loaded_value_first', 0x154a17b, '48894318'),
    ('ack_loaded_timestamp_first', 0x154a1b2, '894350'),
    ('ignore_interval_bits', 0x154a4c3, '48b80000000000001440'),
    ('ignore_directory_field', 0x154a38a, '4983c618'),
    ('ignore_interval_store', 0x154a4cd, '48894330'),
    ('ignore_default_metadata', 0x154a4b4, '48c743501a40f600'),
    ('ignore_error_pointer_store', 0x154a692, '48894348'),
    ('ignore_loaded_value_first', 0x154a6bb, '48894318'),
    ('ignore_loaded_timestamp_first', 0x154a6f2, '894350'),
    ('ack_device_length', 0x150435d, '4883fa09'),
    ('ack_device_first_8', 0x1504367, '48b82f6465762f6e756c'),
    ('ack_device_prefix_xor', 0x1504371, '48334500'),
    ('ack_device_tail_compare', 0x1504375, '0fb64d084883f16c4809c1'),
    ('ignore_device_length', 0x1504c3d, '4883fa09'),
    ('ignore_device_first_8', 0x1504c47, '48b82f6465762f6e756c'),
    ('ignore_device_prefix_xor', 0x1504c51, '48334500'),
    ('ignore_device_tail_compare', 0x1504c55, '0fb64d084883f16c4809c1'),
    ('ack_reader_error_sentinel', 0x15037ea, '49bc0000000000000080'),
    ('ack_reader_error_store', 0x1503857, '488943084c8923'),
    ('ignore_reader_error_sentinel', 0x1503b5a, '49bc0000000000000080'),
    ('ignore_reader_error_store', 0x1503bc7, '488943084c8923'),
    ('ack_writer_null_return', 0x150441c, '31c0e9a2020000'),
    ('ignore_writer_null_return', 0x1504cfc, '31c0e9a2020000'),
]

# Selected RIP-relative references are checked at the instruction start.  The
# target is a linked ELF VA, not an instruction's file offset or a runtime VA.
REFERENCES = [
    ('owner_ignore_location', 0x150c02b, '488d35', 0x63fc1b8),
    ('owner_ack_location', 0x150c03a, '488d35', 0x63fc1d0),
    ('owner_marker_bytes', 0x150c05f, '0f1005', 0x465b7c),
    ('ack_config_cell_slot', 0x1549e37, '4c8b35', 0x64e0918),
    ('ignore_config_cell_slot', 0x154a377, '4c8b35', 0x64e0918),
    ('ack_empty_argument', 0x1549e5f, '488d05', 0x453aa0),
    ('ignore_empty_argument', 0x154a39f, '488d05', 0x453aa0),
    ('ack_string_adapter', 0x1549e6b, '488d05', 0x15ebba0),
    ('ignore_string_adapter', 0x154a3ab, '488d05', 0x15ebba0),
    ('ack_label_descriptor', 0x1549e77, '488d0d', 0x63fbf70),
    ('ignore_label_descriptor', 0x154a3b7, '488d0d', 0x63fbf80),
    ('ack_full_template', 0x1549e88, '488d35', 0x43ec01),
    ('ignore_full_template', 0x154a3c8, '488d35', 0x43ec01),
    ('ack_read_extension', 0x15037c0, '488d15', 0x4659e5),
    ('ignore_read_extension', 0x1503b30, '488d15', 0x4659e5),
    ('ack_missing_diagnostic', 0x15036cf, '488d05', 0x446b15),
    ('ignore_missing_diagnostic', 0x1503a3f, '488d05', 0x446b15),
    ('ack_write_extension', 0x15044a8, '488d15', 0x4659e5),
    ('ignore_write_extension', 0x1504d88, '488d15', 0x4659e5),
    ('ack_read_type_label', 0x150392d, '488d15', 0x4659cb),
    ('ignore_read_type_label', 0x1503c9d, '488d15', 0x4659d7),
    ('ack_write_type_label', 0x15044fc, '488d15', 0x4659cb),
    ('ignore_write_type_label', 0x1504ddc, '488d15', 0x4659d7),
    ('ack_unwrap_diagnostic', 0x154a257, '488d3d', 0x467008),
    ('ignore_unwrap_diagnostic', 0x154a797, '488d3d', 0x467008),
]

# Larger windows provide context for reviewer inspection.  The machine code
# remains evidence only; each containing full FDE is hashed independently.
WINDOWS = [
    ('owner_calls', 0x150c02b, 0x25), ('owner_copies', 0x150c070, 0x8c),
    ('owner_defaults', 0x150c0fc, 0x8e), ('owner_failure', 0x150c196, 0x48),
    ('ack_format', 0x1549e37, 0x6b), ('ignore_format', 0x154a377, 0x6b),
    ('ack_missing', 0x1549efc, 0xa9), ('ignore_missing', 0x154a43c, 0xa9),
    ('ack_existing', 0x1549fab, 0x107), ('ignore_existing', 0x154a4eb, 0x107),
    ('ack_fallback', 0x154a077, 0xf4), ('ignore_fallback', 0x154a5b7, 0xf4),
    ('ack_read_dispatch', 0x150376d, 0xf3), ('ignore_read_dispatch', 0x1503add, 0xf3),
    ('ack_device', 0x150435d, 0x29), ('ignore_device', 0x1504c3d, 0x29),
    ('ack_write_dispatch', 0x1504499, 0xd0), ('ignore_write_dispatch', 0x1504d79, 0xd0),
    ('ack_write_handoff', 0x1504641, 0x84), ('ignore_write_handoff', 0x1504f21, 0x84),
]

SLOT_EXPECTED = {
    0x64df480: 0x6355830, 0x64df498: 0x141e264,
    0x64df6e8: 0x141e3a0, 0x64df6a0: 0x1680c30,
    0x64e0918: 0x64f06c0, 0x64efeb8: 0x150c020,
    0x64e0948: 0x1500c10, 0x64e0950: 0x1500d20,
    0x64e0a10: 0x15027d0, 0x64e0b18: 0x150b310,
    0x64e09b8: 0x5ca4d50, 0x64e09c0: 0x5ca4940,
    0x64e0928: 0x1500a60, 0x64e0940: 0x5c8f4c0,
    0x64e09e8: 0x15024a0,
    0x63fbf70: 0x465872, 0x63fbf80: 0x46587f,
    0x63fc1b8: 0x43fea4, 0x63fc1d0: 0x43fea4,
    0x63f8998: 0x464716, 0x6410ef8: 0x481e30,
}


def digest_check(data, expected):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('input SHA-256 mismatch')
    return actual


def locate(secs, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid file-backed span')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('span is not uniquely file-backed')
    s = matches[0]
    return s, s['offset'] + va - s['address']


class Image:
    def __init__(self, data, expected=TARGET):
        digest_check(data, expected)
        self.data = data
        self.secs = sections(data)
        _, index = unwind_index(data)
        self.index = {row['start']: row for row in index}
        _, records = eh_frame_records(data, self.secs)
        self.fdes = {}
        for row in records:
            self.fdes.setdefault(row['start'], []).append(row)
        rela = [s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4]
        if len(rela) != 1 or rela[0]['size'] % 24:
            raise ValueError('invalid dynamic relocation section')
        self.rela = {}
        for p in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
            off = struct.unpack_from('<Q', data, p)[0]
            self.rela.setdefault(off, []).append(p)

    def read(self, va, size):
        section, offset = locate(self.secs, va, size)
        if offset + size > len(self.data):
            raise ValueError('span outside file')
        return bytes(self.data[offset:offset + size])

    def relative(self, slot, expected=None):
        ps = self.rela.get(slot, [])
        if len(ps) != 1:
            raise ValueError('missing or duplicate relocation')
        p = ps[0]
        actual_slot, info, addend = struct.unpack_from('<QQq', self.data, p)
        if actual_slot != slot or info != 8 or addend < 0:
            raise ValueError('relocation is not the expected RELATIVE entry')
        if expected is not None and addend != expected:
            raise ValueError('relocation addend mismatch')
        self.read(slot, 8)
        return p, addend

    def function(self, spec):
        role, start, end, expected_hash = spec
        fs = self.fdes.get(start, [])
        if len(fs) != 1 or fs[0]['end'] != end:
            raise ValueError('FDE range mismatch')
        f = fs[0]
        row = self.index.get(start)
        if row is None or row['fde'] != f['fde']:
            raise ValueError('unwind index and FDE disagree')
        sec, off = locate(self.secs, start, end - start)
        if not sec['flags'] & 4:
            raise ValueError('FDE body is not executable')
        body_hash = hashlib.sha256(self.read(start, end - start)).hexdigest()
        if body_hash != expected_hash:
            raise ValueError('selected FDE body hash mismatch')
        return [role, hex(start), hex(end), end - start, hex(off), sec['name'],
                hex(f['fde']), hex(f['cie']), '' if f['lsda'] is None else hex(f['lsda']),
                row['index'], body_hash]

    def containing_function(self, site, length=1):
        hits = [spec for spec in FUNCTIONS if spec[1] <= site and site + length <= spec[2]]
        if len(hits) != 1:
            raise ValueError('instruction outside selected FDEs')
        return hits[0][0]

    def branch(self, role, site, opcode, expected_target):
        prefix = bytes.fromhex(opcode)
        if len(prefix) not in (1, 2) or (len(prefix) == 1 and not 0x70 <= prefix[0] <= 0x7f) or (len(prefix) == 2 and not (prefix[0] == 0x0f and 0x80 <= prefix[1] <= 0x8f)):
            raise ValueError('unsupported conditional branch')
        n = len(prefix) + (1 if len(prefix) == 1 else 4)
        raw = self.read(site, n)
        if not raw.startswith(prefix):
            raise ValueError('branch opcode mismatch')
        disp = struct.unpack('<b' if len(prefix) == 1 else '<i', raw[len(prefix):])[0]
        target = site + n + disp
        owner = self.containing_function(site, n)
        if target != expected_target or self.containing_function(target) != owner:
            raise ValueError('branch target mismatch or outside FDE')
        _, off = locate(self.secs, site, n)
        return [owner, role, hex(site), hex(off), raw.hex(), hex(site + n), hex(target)]

    def transfer(self, role, site, form, expected):
        n = 5 if form == 'direct' else 6 if form == 'slot' else 0
        if not n:
            raise ValueError('unsupported transfer form')
        raw = self.read(site, n)
        if form == 'direct':
            if raw[0] != 0xe8:
                raise ValueError('direct call opcode mismatch')
            dest = site + n + struct.unpack('<i', raw[1:])[0]
            if dest != expected:
                raise ValueError('direct call target mismatch')
            slot = relocation = ''
        else:
            if raw[:2] != b'\xff\x15':
                raise ValueError('indirect call opcode mismatch')
            slot_va = site + n + struct.unpack('<i', raw[2:])[0]
            if slot_va != expected or slot_va not in SLOT_EXPECTED:
                raise ValueError('indirect call slot mismatch')
            rp, dest = self.relative(slot_va, SLOT_EXPECTED[slot_va])
            slot, relocation = hex(slot_va), hex(rp)
        owner = self.containing_function(site, n)
        _, off = locate(self.secs, site, n)
        return [owner, role, hex(site), hex(off), raw.hex(), form, slot, relocation, hex(dest)]

    def witness(self, label, site, expected_hex):
        expected = bytes.fromhex(expected_hex)
        actual = self.read(site, len(expected))
        if actual != expected:
            raise ValueError('selected instruction bytes mismatch')
        owner = self.containing_function(site, len(expected))
        _, off = locate(self.secs, site, len(expected))
        return [owner, label, hex(site), hex(off), actual.hex()]

    def reference(self, label, site, prefix_hex, expected_target):
        prefix = bytes.fromhex(prefix_hex)
        normal = len(prefix) == 3 and prefix[0] in range(0x48, 0x50) and prefix[1] in (0x8b, 0x8d) and prefix[2] & 0xc7 == 5
        xmm_load = prefix == bytes.fromhex('0f1005')
        if not (normal or xmm_load):
            raise ValueError('unsupported RIP-relative reference')
        raw = self.read(site, 7)
        if raw[:3] != prefix:
            raise ValueError('reference opcode mismatch')
        target = site + 7 + struct.unpack('<i', raw[3:])[0]
        if target != expected_target:
            raise ValueError('reference target mismatch')
        self.read(target, 1)
        owner = self.containing_function(site, 7)
        _, off = locate(self.secs, site, 7)
        return [owner, label, hex(site), hex(off), raw.hex(), hex(target)]

    def exception_sites(self, spec):
        """Decode only the selected LSDA call-site tables, leaving actions opaque."""
        role, start, end, _ = spec
        fs = self.fdes.get(start, [])
        if len(fs) != 1 or fs[0]['end'] != end or fs[0]['lsda'] is None:
            raise ValueError('missing selected LSDA')
        lsda = fs[0]['lsda']
        sec, offset = locate(self.secs, lsda, 3)
        if sec['name'] != '.gcc_except_table':
            raise ValueError('LSDA outside exception table')
        limit = sec['offset'] + sec['size']
        pos = offset
        lp_encoding = self.data[pos]
        type_encoding = self.data[pos + 1]
        pos += 2
        if lp_encoding != 0xff or type_encoding not in (0xff, 0x9b):
            raise ValueError('unsupported LSDA encodings')
        type_base = None
        if type_encoding != 0xff:
            type_delta, pos = uleb(self.data, pos, limit)
            type_base = pos + type_delta
            if type_base > limit:
                raise ValueError('LSDA type table outside section')
        if pos >= limit or self.data[pos] != 1:
            raise ValueError('unsupported LSDA call-site encoding')
        pos += 1
        length, pos = uleb(self.data, pos, limit)
        table_start, table_end = pos, pos + length
        if table_end > limit or (type_base is not None and table_end > type_base):
            raise ValueError('LSDA call-site table outside bounds')
        rows, previous_end = [], start
        while pos < table_end:
            row_off = pos
            a, pos = uleb(self.data, pos, table_end)
            n, pos = uleb(self.data, pos, table_end)
            landing, pos = uleb(self.data, pos, table_end)
            action, pos = uleb(self.data, pos, table_end)
            begin, finish = start + a, start + a + n
            landing_va = start + landing if landing else None
            if not n or begin < previous_end or begin < start or finish > end:
                raise ValueError('invalid LSDA call-site range')
            if landing_va is not None and not start <= landing_va < end:
                raise ValueError('LSDA landing outside FDE')
            previous_end = finish
            rows.append([role, hex(lsda), hex(sec['address'] + row_off - sec['offset']),
                         bytes(self.data[row_off:pos]).hex(), hex(begin), hex(finish),
                         '' if landing_va is None else hex(landing_va), action])
        if pos != table_end:
            raise ValueError('LSDA call-site table length mismatch')
        header = [role, hex(lsda), hex(offset), hex(lp_encoding), hex(type_encoding),
                  hex(sec['address'] + table_start - sec['offset']), length,
                  '' if type_base is None else hex(sec['address'] + type_base - sec['offset']), len(rows)]
        return header, rows


def pair_branches():
    out = [('owner_allocation_failed', 0x150c059, '0f84', 0x150c196)]
    for base, delta in ((CONSTRUCTOR_BRANCHES, 0x540), (READER_BRANCHES, 0x370), (WRITER_BRANCHES, 0x8e0)):
        for role, site, opcode, target in base:
            out.append(('ack_' + role, site, opcode, target))
            out.append(('ignore_' + role, site + delta, opcode, target + delta))
    return out


def pair_transfers():
    out = list(TRANSFERS)
    for source, delta in ((INIT_TRANSFERS, 0x540), (READER_TRANSFERS, 0x370), (WRITER_TRANSFERS, 0x8e0)):
        for role, site, form, dest in source:
            out.append(('ack_' + role, site, form, dest))
            # Calls to type-specialized functions have different targets.
            paired = {0x1504330: 0x1504c10, 0x1503670: 0x15039e0}.get(dest, dest) if form == 'direct' else dest
            out.append(('ignore_' + role, site + delta, form, paired))
    out += [
        ('ack_text_decode', 0x150388b, 'direct', 0x1574d70),
        ('ignore_text_decode', 0x1503bfb, 'direct', 0x1574840),
        ('ack_binary_decode', 0x1503943, 'direct', 0x14a02d0),
        ('ignore_binary_decode', 0x1503cb3, 'direct', 0x149ede0),
        ('ack_binary_encode', 0x1504516, 'direct', 0x159a170),
        ('ignore_binary_encode', 0x1504df6, 'direct', 0x1599dc0),
        ('ack_text_encode', 0x15045a2, 'direct', 0x159b130),
        ('ignore_text_encode', 0x1504e82, 'direct', 0x159acd0),
    ]
    return out


def slices(image):
    # Literal bytes are rendered as hex to preserve exact boundaries and avoid
    # treating path templates as actual runtime paths.
    selected = [
        ('tracker_template', 0x43ec01, bytes.fromhex('c0c0172f66696c655f6d6f645f74696d655f747261636b65722fc0052e6a736f6e00')),
        ('cham_template_115', 0x44ab69, bytes.fromhex('c0052f6368616d00')),
        ('static_config_template_115', 0x4401ef, bytes.fromhex('c00e2f7374617469635f636f6e66696700')),
        ('format_empty_slice', 0x453aa0, bytes.fromhex('01000000000000000000000000000000')),
        ('ack_label', 0x465872, b'bug_alert_ack'),
        ('ignore_label', 0x46587f, b'crit_msg_ignore'),
        ('ack_type_label', 0x4659cb, b'BugAlertAcks'),
        ('ignore_type_label', 0x4659d7, b'CritMsgIgnores'),
        ('extension', 0x4659e5, b'rmp'),
        ('failure_diagnostic', 0x467008, b'called `Result::unwrap()` on an `Err` value'),
        ('missing_file_template', 0x446b15, b'\x0emissing file: \xc0\x00'),
        ('source_location', 0x43fea4, b'base/src/crit_msg.rs'),
        ('owner_marker', 0x465b7c, b'N/A (non-production)'),
    ]
    rows = []
    for name, va, expected in selected:
        raw = image.read(va, len(expected))
        if raw != expected:
            raise ValueError('literal bytes mismatch')
        sec, off = locate(image.secs, va, len(raw))
        rows.append([name, hex(va), hex(off), sec['name'], len(raw), raw.hex()])
    return rows


def name_descriptor(image, slot, table_base, expected_target):
    rp, text_va = image.relative(slot, expected_target)
    length = struct.unpack('<Q', image.read(slot + 8, 8))[0]
    if image.read(slot, 8) != bytes(8) or length != 9 or image.read(text_va, length) != b'NvTestnet':
        raise ValueError('name descriptor mismatch')
    if slot < table_base or (slot - table_base) % 16:
        raise ValueError('invalid name index')
    return [hex(table_base), hex(slot), hex(rp), hex(text_va), length, (slot - table_base) // 16, image.read(text_va, length).hex()]


def slice_descriptor(image, label, slot, expected):
    relocation, text_va = image.relative(slot, SLOT_EXPECTED[slot])
    pointer_bytes = image.read(slot, 8)
    length = struct.unpack('<Q', image.read(slot + 8, 8))[0]
    raw = image.read(text_va, length)
    if pointer_bytes != bytes(8) or raw != expected:
        raise ValueError('slice descriptor mismatch')
    return [label, hex(slot), hex(relocation), hex(text_va), length, raw.hex()]


def location_descriptor(image, label, slot):
    row = slice_descriptor(image, label, slot, b'base/src/crit_msg.rs')
    line, column = struct.unpack('<II', image.read(slot + 16, 8))
    if not line or not column:
        raise ValueError('invalid source location')
    return row + [line, column]


def tracker_template(image):
    """Parse this one verified compact template, not arbitrary format data."""
    start = 0x43ec01
    end = start + 34
    raw = image.read(start, end - start)
    rows = []
    pos = 0
    while pos < len(raw):
        at = pos
        token = raw[pos]
        pos += 1
        if token == 0:
            rows.append(['terminator', hex(start + at), 0, ''])
            break
        if token == 0xc0:
            rows.append(['argument', hex(start + at), 0, ''])
        elif 0 < token < 0x80 and pos + token <= len(raw):
            rows.append(['literal', hex(start + at), token, raw[pos:pos + token].hex()])
            pos += token
        else:
            raise ValueError('unsupported or truncated template token')
    if pos != len(raw) or [r[0] for r in rows] != ['argument', 'argument', 'literal', 'argument', 'literal', 'terminator']:
        raise ValueError('template structure mismatch')
    return rows


def device_match(image, data):
    if not isinstance(data, bytes):
        raise TypeError('candidate must be bytes')
    for witness in WITNESSES:
        if witness[0] in ('ack_device_length', 'ack_device_first_8', 'ack_device_prefix_xor', 'ack_device_tail_compare', 'ignore_device_length', 'ignore_device_first_8', 'ignore_device_prefix_xor', 'ignore_device_tail_compare'):
            image.witness(*witness)
    image.branch('device_length_ne_9', 0x1504361, '0f85', 0x150440e)
    image.branch('device_bytes_equal', 0x1504380, '0f84', 0x150441c)
    image.branch('device_length_ne_9', 0x1504c41, '0f85', 0x1504cee)
    image.branch('device_bytes_equal', 0x1504c60, '0f84', 0x1504cfc)
    immediate = image.read(0x1504369, 8)
    tail = image.read(0x150437c, 1)
    return len(data) == 9 and data[:8] == immediate and data[8:] == tail


def tracker_route(image, regular, timestamp_tag, read_word, path_word, write_result):
    """Finite model of selected local branches, with external outcomes supplied.

    This is not execution and does not establish that every combination occurs.
    """
    if type(regular) is not bool or type(timestamp_tag) is not int or not 0 <= timestamp_tag < (1 << 32):
        raise ValueError('invalid predicate or timestamp tag')
    if any(type(x) is not int or not 0 <= x < (1 << 64) for x in (read_word, path_word, write_result)):
        raise ValueError('invalid machine word')
    image.branch('not_regular', 0x1549ec8, '74', 0x1549efc)
    image.branch('write_failed', 0x1549f45, '0f85', 0x154a252)
    image.branch('timestamp_ok', 0x1549fc9, '75', 0x1549fd2)
    image.branch('read_ok', 0x154a00a, '71', 0x154a021)
    image.branch('path_ok', 0x154a06e, '0f85', 0x154a16b)
    if image.read(0x1549fc4, 5) != bytes.fromhex('837c240801'):
        raise ValueError('timestamp tag comparison changed')
    if image.read(0x154a043, 10) != bytes.fromhex('48b80000000000000080'):
        raise ValueError('sentinel immediate changed')
    sentinel = int.from_bytes(image.read(0x154a045, 8), 'little')
    if not regular:
        return 'write_failure_boundary' if write_result else 'default_after_write'
    if timestamp_tag == 1:
        return 'fallback_timestamp_error'
    if read_word == sentinel:
        return 'fallback_read_sentinel'
    if path_word == sentinel:
        return 'fallback_path_sentinel'
    return 'loaded_value_and_timestamp'


def csv_bytes(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def collect(image):
    funcs = [image.function(spec) for spec in FUNCTIONS]
    branches = [image.branch(*spec) for spec in pair_branches()]
    transfers = [image.transfer(*spec) for spec in pair_transfers()]
    witnesses = [image.witness(*spec) for spec in WITNESSES]
    references = [image.reference(*spec) for spec in REFERENCES]
    literals = slices(image)
    exception_headers, exceptions = [], []
    for spec in FUNCTIONS:
        header, rows = image.exception_sites(spec)
        exception_headers.append(header)
        exceptions.extend(rows)
    relocs = []
    for slot in sorted(SLOT_EXPECTED):
        p, target = image.relative(slot, SLOT_EXPECTED[slot])
        sec, off = locate(image.secs, slot, 8)
        relocs.append([hex(slot), sec['name'], hex(off), hex(p), hex(target)])
    names = [name_descriptor(image, 0x63f8998, 0x63f8788, 0x464716),
             name_descriptor(image, 0x6410ef8, 0x6410ce8, 0x481e30)]
    labels = [slice_descriptor(image, 'ack', 0x63fbf70, b'bug_alert_ack'),
              slice_descriptor(image, 'ignore', 0x63fbf80, b'crit_msg_ignore')]
    locations = [location_descriptor(image, 'ignore', 0x63fc1b8),
                 location_descriptor(image, 'ack', 0x63fc1d0)]
    template = tracker_template(image)
    windows = []
    for label, site, size in WINDOWS:
        owner = image.containing_function(site, size)
        _, off = locate(image.secs, site, size)
        windows.append([owner, label, hex(site), hex(off), size, image.read(site, size).hex()])
    # Values are finite probes of the exact comparison, not node executions.
    target = image.read(0x1504369, 8) + image.read(0x150437c, 1)
    probes = [('exact', target), ('shorter', target[:-1]), ('longer', target + bytes([0]))]
    for i in range(len(target)):
        candidate = bytearray(target)
        candidate[i] ^= 1
        probes.append(('flip_' + str(i), bytes(candidate)))
    cases = [[label, raw.hex(), len(raw), int(device_match(image, raw))] for label, raw in probes]
    sentinel = int.from_bytes(image.read(0x154a045, 8), 'little')
    route_inputs = [
        ('not_regular_write_ok', False, 0, 0, 0, 0),
        ('not_regular_write_error', False, 0, 0, 0, 1),
        ('write_error_precedes_unused_inputs', False, 1, sentinel, sentinel, 1),
        ('timestamp_error', True, 1, 0, 0, 0),
        ('timestamp_error_precedes_read', True, 1, sentinel, sentinel, 0),
        ('read_sentinel', True, 0, sentinel, 0, 0),
        ('read_sentinel_precedes_path', True, 0, sentinel, sentinel, 0),
        ('path_sentinel', True, 0, 0, sentinel, 0),
        ('loaded_zero', True, 0, 0, 0, 0),
        ('loaded_neighbor', True, 2, sentinel + 1, sentinel - 1, 0),
        ('write_result_unused_for_regular', True, 0, 0, 0, 1),
    ]
    routes = [[label, int(regular), tag, hex(word), hex(path), hex(wr),
               tracker_route(image, regular, tag, word, path, wr)]
              for label, regular, tag, word, path, wr in route_inputs]
    return {
        'functions.tsv': csv_bytes(['role', 'start_va', 'end_va_exclusive', 'size', 'file_offset', 'section', 'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'sha256'], funcs),
        'branches.tsv': csv_bytes(['owner', 'condition', 'site_va', 'file_offset', 'bytes', 'fallthrough_va', 'taken_va'], branches),
        'transfers.tsv': csv_bytes(['owner', 'role', 'site_va', 'file_offset', 'bytes', 'form', 'slot_va', 'rela_file_offset', 'target_va'], transfers),
        'witnesses.tsv': csv_bytes(['owner', 'role', 'site_va', 'file_offset', 'bytes'], witnesses),
        'references.tsv': csv_bytes(['owner', 'role', 'site_va', 'file_offset', 'bytes', 'target_va'], references),
        'relocations.tsv': csv_bytes(['slot_va', 'section', 'slot_file_offset', 'rela_file_offset', 'relative_addend_va'], relocs),
        'literals.tsv': csv_bytes(['role', 'va', 'file_offset', 'section', 'length', 'bytes'], literals),
        'name-descriptor.tsv': csv_bytes(['table_base_va', 'slot_va', 'rela_file_offset', 'text_va', 'length', 'index', 'name_bytes'], names),
        'label-descriptors.tsv': csv_bytes(['role', 'slot_va', 'rela_file_offset', 'text_va', 'length', 'bytes'], labels),
        'locations.tsv': csv_bytes(['role', 'slot_va', 'rela_file_offset', 'text_va', 'length', 'bytes', 'line', 'column'], locations),
        'template.tsv': csv_bytes(['kind', 'va', 'length', 'literal_bytes'], template),
        'exception-headers.tsv': csv_bytes(['owner', 'lsda_va', 'file_offset', 'lp_encoding', 'type_encoding', 'call_table_va', 'call_table_bytes', 'type_table_va', 'rows'], exception_headers),
        'exception-edges.tsv': csv_bytes(['owner', 'lsda_va', 'entry_va', 'bytes', 'start_va', 'end_va_exclusive', 'landing_va', 'action'], exceptions),
        'windows.tsv': csv_bytes(['owner', 'role', 'va', 'file_offset', 'length', 'bytes'], windows),
        'device-probes.tsv': csv_bytes(['case', 'candidate_bytes', 'length', 'matches'], cases),
        'route-probes.tsv': csv_bytes(['case', 'regular', 'timestamp_tag', 'read_word', 'path_word', 'write_result', 'abstract_route'], routes),
        'summary.json': (json.dumps({'target_sha256': TARGET, 'function_count': len(funcs), 'fde_bytes': sum(row[3] for row in funcs), 'selected_conditional_branches': len(branches), 'selected_transfers': len(transfers), 'instruction_witnesses': len(witnesses), 'rip_references': len(references), 'relocations': len(relocs), 'literal_slices': len(literals), 'name_descriptors': len(names), 'label_descriptors': len(labels), 'source_locations': len(locations), 'template_tokens': len(template), 'lsda_tables': len(exception_headers), 'lsda_call_sites': len(exceptions), 'windows': len(windows), 'device_probes': len(cases), 'route_probes': len(routes), 'limitations': 'Selected static observations; not complete CFG, runtime execution, implementation, or component equivalence.'}, indent=2, sort_keys=True) + '\n').encode(),
    }


def compare_historical(image, data):
    digest_check(data, OLD_TARGET)
    old_sections = sections(data)
    def old_read(va, n):
        _, off = locate(old_sections, va, n)
        return bytes(data[off:off + n])
    anchors = []
    for label, old_va, new_va, raw in [
        ('cham', 0x1fc0ec, 0x44ab69, bytes.fromhex('c0052f6368616d00')),
        ('static_config', 0x1ef5f5, 0x4401ef, bytes.fromhex('c00e2f7374617469635f636f6e66696700')),
    ]:
        if old_read(old_va, len(raw)) != raw or image.read(new_va, len(raw)) != raw:
            raise ValueError('cross-release template mismatch')
        anchors.append({'label': label, 'old_va': hex(old_va), 'new_va': hex(new_va), 'bytes': raw.hex()})
    for site, target in ((0x164f840, 0x1fc0ec), (0x164fbae, 0x1ef5f5)):
        raw = old_read(site, 7)
        if raw[:3] != b'\x48\x8d\x35' or site + 7 + struct.unpack('<i', raw[3:])[0] != target:
            raise ValueError('historical RIP-relative reference mismatch')
    for site, target in ((0x17780f3, 0x44ab69), (0x177840e, 0x4401ef)):
        raw = image.read(site, 7)
        if raw[:3] != b'\x48\x8d\x35' or site + 7 + struct.unpack('<i', raw[3:])[0] != target:
            raise ValueError('target RIP-relative reference mismatch')
    old_slot = 0x5668488
    old_rela = [s for s in old_sections if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(old_rela) != 1 or old_rela[0]['size'] % 24:
        raise ValueError('historical relocation section mismatch')
    found = []
    for p in range(old_rela[0]['offset'], old_rela[0]['offset'] + old_rela[0]['size'], 24):
        off, info, addend = struct.unpack_from('<QQq', data, p)
        if off == old_slot:
            found.append((info, addend))
    if found != [(8, 0x2180ff)] or struct.unpack('<Q', old_read(old_slot + 8, 8))[0] != 9 or old_read(0x2180ff, 9) != b'NvTestnet':
        raise ValueError('historical name descriptor mismatch')
    if old_read(0x164fc56, 3) != bytes.fromhex('40b520') or image.read(0x177845c, 3) != bytes.fromhex('40b521'):
        raise ValueError('historical and target default bytes mismatch')
    return {'old_sha256': OLD_TARGET, 'target_sha256': TARGET, 'templates': anchors,
            'historical_refs': ['0x164f840', '0x164fbae'],
            'target_refs': ['0x17780f3', '0x177840e'],
            'name': {'old_table_base': '0x5668288', 'old_slot': hex(old_slot),
                     'old_index': (old_slot - 0x5668288) // 16,
                     'old_text_va': '0x2180ff', 'new_index': name_descriptor(image, 0x6410ef8, 0x6410ce8, 0x481e30)[5]},
            'default_bytes_old': old_read(0x164fc56, 3).hex(), 'default_bytes_new': image.read(0x177845c, 3).hex()}


def generate(image, out):
    results = collect(image)  # validate everything before creating output files
    out.mkdir(parents=True, exist_ok=True)
    for name in sorted(results):
        (out / name).write_bytes(results[name])
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--compare-94', type=Path)
    args = parser.parse_args()
    image = Image(BINARY.read_bytes())
    if args.compare_94:
        comparison = compare_historical(image, args.compare_94.read_bytes())
        print(json.dumps(comparison, sort_keys=True))
    generate(image, args.out)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        print('tracker evidence:', str(exc), file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Extract a #115 configuration-name factor into a scheduled observer cell.

Static ELF reads only.  All selected instruction claims are guarded by exact
byte windows.  Unknown instructions are not decoded or counted here.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE115 = 105896032
SIZE94 = 91774280

# FDE ranges are unwind-described, not a census or proof of function ownership.
FUNCTIONS = (
    ('poll_wrapper', 0x15fe340, 0x15fe45c),
    ('scheduled_poll', 0x15ed290, 0x15ed954),
    ('publish_a', 0x15edb90, 0x15edbe9),
    ('publish_b', 0x15ea1e0, 0x15ea239),
    ('cell_initializer', 0x15d86b0, 0x15d8722),
    ('observer_constructor', 0x1548bb0, 0x1548f3d),
    ('keyed_lookup', 0x15543f0, 0x155474d),
    ('name_factor_selector', 0x15474d0, 0x1547529),
    ('constructor_cleanup', 0x154f790, 0x154f846),
)

# Address, expected x86 condition and taken target.  Fallthrough is decoded.
BRANCHES = (
    ('parent_state', 0x15fe355, 'jne', 0x15fe38a),
    ('parent_tls_ready', 0x15fe37e, 'je', 0x15fe3c8),
    ('parent_tls_other', 0x15fe3ea, 'jne', 0x15fe41b),
    ('parent_pending', 0x15fe3ee, 'jne', 0x15fe409),
    ('parent_ready', 0x15fe43c, 'je', 0x15fe3f0),
    ('poll_refcount_nonpositive', 0x15ed2cb, 'jle', 0x15ed853),
    ('poll_terminal_marker', 0x15ed31a, 'je', 0x15ed6dd),
    ('prefix_too_short', 0x15ed3c3, 'jb', 0x15ed5fe),
    ('prefix_mismatch', 0x15ed3f3, 'jne', 0x15ed5fe),
    ('map_lazy', 0x15ed405, 'jne', 0x15ed7a7),
    ('map_lock_contended', 0x15ed414, 'jne', 0x15ed7e3),
    ('empty_key', 0x15ed427, 'je', 0x15ed458),
    ('map_alloc_failed', 0x15ed439, 'je', 0x15ed845),
    ('lookup_sentinel', 0x15ed496, 'jo', 0x15ed5cf),
    ('map_scan_next_group', 0x15ed51e, 'je', 0x15ed80e),
    ('map_scan_wrap', 0x15ed535, 'jns', 0x15ed830),
    ('map_unlock_contended', 0x15ed5f8, 'jne', 0x15ed7fa),
    ('global_lazy', 0x15ed60f, 'jne', 0x15ed73c),
    ('global_lock_contended', 0x15ed61f, 'jne', 0x15ed77c),
    ('global_unlock_contended', 0x15ed64a, 'jne', 0x15ed793),
    ('child_pending', 0x15ed67c, 'jne', 0x15ed71e),
    ('child_state_a', 0x15ed689, 'jne', 0x15ed2fb),
    ('child_state_b', 0x15ed696, 'jne', 0x15ed2fb),
    ('child_variant', 0x15ed6aa, 'je', 0x15ed6bd),
    ('child_release_a', 0x15ed6b3, 'jne', 0x15ed6cc),
    ('child_release_b', 0x15ed6c4, 'jne', 0x15ed6cc),
    ('poll_terminal_release_a', 0x15ed6e4, 'jne', 0x15ed6ef),
    ('poll_terminal_release_b', 0x15ed6f7, 'jne', 0x15ed703),
    ('poll_terminal_empty', 0x15ed70c, 'je', 0x15ed71a),
    ('global_unwind_unlock', 0x15ed8e0, 'je', 0x15ed903),
    ('publish_a_null', 0x15edbaa, 'je', 0x15edbd6),
    ('publish_a_state', 0x15edbb0, 'je', 0x15edbe3),
    ('publish_b_null', 0x15ea1fa, 'je', 0x15ea226),
    ('publish_b_state', 0x15ea200, 'je', 0x15ea233),
    ('factor_lazy', 0x15474e1, 'jne', 0x15474f9),
    ('length_nonnegative', 0x1548bf7, 'jns', 0x1548c09),
    ('length_zero', 0x1548c18, 'je', 0x1548c40),
    ('allocation_null', 0x1548c26, 'je', 0x1548eca),
    ('time_conversion_failed', 0x1548c7c, 'je', 0x1548eaf),
    ('product_nonnegative', 0x1548cf0, 'jns', 0x1548e6f),
    ('product_special_negative', 0x1548cff, 'jae', 0x1548e82),
    ('product_candidate_negative', 0x1548d16, 'jae', 0x1548e9d),
    ('product_zero', 0x1548d1f, 'je', 0x1548d25),
    ('product_normal_positive', 0x1548e7c, 'jb', 0x1548d05),
    ('product_small_positive', 0x1548e97, 'jb', 0x1548d1c),
    ('product_nonzero', 0x1548ea4, 'jne', 0x1548d21),
    ('lookup_len_at_least_17', 0x1554414, 'jae', 0x155443c),
    ('lookup_len_at_most_7', 0x155441a, 'jbe', 0x15544c3),
    ('lookup_len_at_most_3', 0x15544c7, 'jbe', 0x15546c7),
    ('lookup_no_candidates', 0x155458d, 'je', 0x1554640),
    ('lookup_length_mismatch', 0x15545d4, 'jne', 0x1554607),
    ('lookup_equal_bytes', 0x1554605, 'je', 0x155465c),
    ('lookup_another_candidate', 0x1554636, 'jne', 0x15545b3),
    ('lookup_empty_control', 0x155464a, 'jne', 0x1554692),
    ('lookup_key_no_free', 0x1554683, 'je', 0x15546b5),
    ('lookup_grow_required', 0x1554697, 'je', 0x155470a),
    ('lookup_empty_key', 0x15546de, 'je', 0x1554516),
    ('lookup_unwind_no_free', 0x1554738, 'je', 0x1554745),
    ('cleanup_sentinel', 0x154f79e, 'jo', 0x154f7f6),
    ('cleanup_inner_missing', 0x154f7b1, 'je', 0x154f7bf),
    ('cleanup_empty', 0x154f7c2, 'je', 0x154f7d0),
)

# The labels are interpretive; addresses and byte strings are checked against
# the authenticated ELF, then reproduced verbatim in windows.tsv.
WINDOWS = (
('entry_state_dispatch', '0x15ed2a7', '0fb68780020000488d0dafcde7fe486304814801c84889742410ffe0'),
('prefix_length', '0x15ed3be', '48837b10180f8235020000'),
('prefix_compare', '0x15ed3c9', '488b4308f30f6f00f30f7e4810660f740d8241e6fe660f7405fa8be6fe660fdbc1660fd7c03dffff00000f8505020000'),
('global_load_guard', '0x15ed5fe', '4c8b254b42ef04418b84246802000085c00f8527010000'),
('global_lock_acquire', '0x15ed615', 'b10131c0f0410fb00c240f8557010000'),
('global_record_call', '0x15ed625', '498d7c2408488d15f747e104f30f7e4424084c89feff15d039ef04'),
('global_lock_release', '0x15ed640', '31c9b001f0410fb00c240f8543010000'),
('poll_pending', '0x15ed668', '4c8dbbe80100004c89ff4c89f6e866e5ffff84c00f859c00000080bb78020000030f856cfcffff80bb70020000030f855ffcffff'),
('poll_complete', '0x15ed703', '488b3340b5014885f6740c488b7b0831d2ff15861def0431c0eb05b00140b5034088ab80020000'),
('poll_unwind_state', '0x15ed93f', 'c68380020000024c89f7e80231e004'),
('global_init_setup', '0x15ed73c', '4c89a42488020000488d8424880200004889442428498dbc2468020000488d0d9845e1044c8d057945e104488d542428be01000000ff157922ef04'),
('global_lock_contention', '0x15ed77c', '488b3dcd40ef04ba00ca9a3bff156a2aef04e992feffff'),
('global_unlock_contention', '0x15ed793', '488b3db640ef0431f6ff159637ef04'),
('cell_initial_length', '0x15d86bd', '488d15f014e9fe4c8d742408f20f10050f0de8feb91d0000004c89f7be01000000'),
('cell_wrapper_result', '0x15d86e4', '48c74424080100000048b800000000000008404889442410c603004889df4883c708ba600200004c89f6ff15f46df004'),
('callback_a_take', '0x15edb9a', '488b07488b1848c700000000004885db742a807e040174314989e64c89f7ff13'),
('callback_a_copy', '0x15edbba', 'ba680200004889df4c89f6ff153d19ef04'),
('callback_a_fail', '0x15edbd6', '488d3d4341e104ff154d1cef04ff15e723ef04'),
('callback_b_take', '0x15ea1ea', '488b07488b1848c700000000004885db742a807e040174314989e64c89f7ff13'),
('callback_b_copy', '0x15ea20a', 'ba680200004889df4c89f6ff15ed52ef04'),
('callback_b_fail', '0x15ea226', '488d3df37ae104ff15fd55ef04ff15975def04'),
('factor_selector', '0x15474d5', '488b1d3c94f9048b435085c075160fb64348488d0de2fcf1fef20f1004c14883c4105bc3'),
('factor_lazy', '0x15474f9', '48891c244889e04889442408488d7b50488d0d109dec044c8d05319dec04488d542408be01000000ff15c984f904ebba'),
('constructor_input', '0x1548bc1', '4889cb4989d4f20f1144241089f54989fe'),
('constructor_length', '0x1548bf4', '4885db791031ff4889deff159468f904e9bf020000448b6c2404488b442408488944242074264889dfff155d68f904'),
('constructor_time_error', '0x1548c71', '448bac24880100004585ed0f842d020000'),
('factor_call', '0x1548cb6', 'ff154c83f904f20f10542410f20f59d0'),
('normalizer_first', '0x1548cc6', '66480f7ed148b8ffffffffffffff7f4821c848ba000000000000f0ff4801c248c1ea35660f57c04885c90f897901000048ffc981faff0300000f837d01000048baffffffffffff0f00660f28ca4839d10f83810100004885c07404660f28d1'),
('constructor_fields_a', '0x1548d2b', '49895e284d897e3049895e384589ae40020000660f57c066410f11860002000049c786100200000000000049c786f8010000d0070000'),
('constructor_field_factor', '0x1548dcc', 'f20f10442410f2410f1186180200004188ae5d02000048b80000000000003e4049898620020000'),
('normalizer_tail', '0x1548e6f', '660f28c248ffc981faff0300000f8283feffff660f57c048baffffffffffff0f00660f28ca4839d10f827ffeffff660f28c84885c00f8577feffffe976feffff'),
('constructor_failure', '0x1548eaf', '488d3d01ccf1fe488d15a332eb04be2b000000ff15a868f9040f0bbf01000000e927fdffff'),
('constructor_cleanup', '0x1548ed4', '4989c6488dbc2438020000e8ac680000488dbc2488010000e89f68000040b501eb054989c631ed4885db740e4c89ff4889de31d2ff159265f9044084ed7405eb1a4989c6488dbc24d8000000e86b680000488d7c2428e8616800004c89f7e8197bea04ff158365f904'),
('cleanup_helper', '0x154f790', '4157415653488b374889f048f7d870564889fb48b8000000000000008048394748740c488d7b48e8e4faffff488b334885f6740c488b7b0831d2ff15d0fcf8044c8d7b18'),
('parent_call', '0x15fe3c8', '644d8b6730644d896f304c89642408e8b4eefeff'),
('parent_failure', '0x15fe38a', '488d3de6c1e6fe488d15d849e004be75000000ff151513ee04'),
('global_second_initializer', '0x15ed4b0', '488b5308488b4b10488d7c2428f30f7e051bbfe6febe01000000ff15503bef04'),
('prefix_hit_object_copy', '0x15ed4d0', '48c74424280100000048b8000000000000f03f4889442430488dbc2488020000488d742428ba60020000ff150820ef04'),
('prefix_hit_object_store', '0x15ed54f', '48f7de4869ce780200004c8d34084080e5014c89ac0888fdffff4c89a40890fdffff488b5424204889940898fdffff488d3c084881c7a0fdffff488db42488020000ba60020000ff156c1fef04'),
('poll_fail_cleanup', '0x15ed8d3', '4989c631c9b001f0410fb00c247421488b3d673fef0431f6ff154736ef04eb10'),
)

# Selected pointer relocations. Existing helper bodies remain external boundaries.
RELOCS = (
    ('config_cell_slot', 0x64e0918, 0x64f06c0),
    ('factor_selector_slot', 0x64e1008, 0x15474d0),
    ('observer_update_slot', 0x64e1010, 0x1547530),
    ('observer_constructor_slot', 0x64e1020, 0x1548bb0),
    ('scheduled_cell_slot', 0x64e1850, 0x64f0428),
    ('scheduled_initializer', 0x64f0428, 0x15d86b0),
    ('scheduled_callback_a', 0x6401d10, 0x15edb90),
    ('scheduled_callback_b', 0x6401d18, 0x15ea1e0),
    ('once_helper', 0x64df9f0, 0x5c87d50),
    ('lookup_grow_helper', 0x64e1120, 0x1559270),
)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def file_offset(blob, secs, va, size):
    need(type(va) is int and type(size) is int and va >= 0 and size > 0 and
         va + size <= 1 << 64, 'invalid address or size')
    found = [s for s in secs if s['type'] != 8 and s['flags'] & 2 and s['size'] and
             s['address'] <= va and va + size <= s['address'] + s['size']]
    need(len(found) == 1, 'address is unmapped, non-file-backed, or ambiguous')
    sec = found[0]
    offset = sec['offset'] + va - sec['address']
    need(0 <= offset and offset + size <= len(blob), 'file span outside input')
    return offset


class Image:
    def __init__(self, blob, digest, length):
        need(len(blob) == length and hashlib.sha256(blob).hexdigest() == digest,
             'input size or SHA-256 mismatch')
        self.blob = blob
        self.secs = sections(blob)
        _, frames = eh_frame_records(blob, self.secs)
        self.fdes = {row['start']: row for row in frames}
        need(len(self.fdes) == len(frames), 'ambiguous FDE start')
        _, index = unwind_index(blob)
        self.index = {row['start']: row for row in index}
        need(len(self.index) == len(index), 'ambiguous unwind index')
        relsections = [s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] != 8]
        need(len(relsections) == 1 and relsections[0]['size'] % 24 == 0,
             'missing or malformed .rela.dyn')
        sec = relsections[0]
        self.rels = {}
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', blob, off)
            if info == 8:
                need(slot not in self.rels, 'duplicate RELATIVE relocation')
                self.rels[slot] = (off, addend)

    def offset(self, va, size):
        return file_offset(self.blob, self.secs, va, size)

    def read(self, va, size):
        off = self.offset(va, size)
        return self.blob[off:off + size]

    def u64(self, va):
        return struct.unpack('<Q', self.read(va, 8))[0]

    def rel(self, slot, expected=None):
        need(slot in self.rels, 'missing RELATIVE relocation')
        off, addend = self.rels[slot]
        if expected is not None:
            need(addend == expected, 'unexpected RELATIVE addend')
        return off, addend

    def fde(self, start, end):
        need(start in self.fdes and start in self.index, 'missing FDE or index entry')
        fde, index = self.fdes[start], self.index[start]
        need(fde['end'] == end and fde['fde'] == index['fde'], 'FDE or index mismatch')
        self.offset(start, end - start)
        return fde, index


def check_windows(image):
    rows = []
    for name, addr_text, expected_hex in WINDOWS:
        addr = int(addr_text, 16)
        expected = bytes.fromhex(expected_hex)
        actual = image.read(addr, len(expected))
        need(actual == expected, 'selected instruction bytes changed: ' + name)
        rows.append((name, hex(addr), hex(image.offset(addr, len(actual))), actual.hex()))
    return rows


CONDITIONS = {0x0: 'jo', 0x2: 'jb', 0x3: 'jae', 0x4: 'je', 0x5: 'jne', 0x6: 'jbe',
              0x9: 'jns', 0xe: 'jle'}


def branch(image, site, expected_condition, expected_target):
    head = image.read(site, 2)
    if 0x70 <= head[0] <= 0x7f:
        raw = image.read(site, 2)
        condition, disp = head[0] & 15, struct.unpack('<b', raw[1:])[0]
    else:
        need(head[0] == 0x0f and 0x80 <= head[1] <= 0x8f,
             'unsupported conditional branch')
        raw = image.read(site, 6)
        condition, disp = head[1] & 15, struct.unpack('<i', raw[2:])[0]
    name = CONDITIONS.get(condition)
    fallthrough = site + len(raw)
    target = fallthrough + disp
    need(name == expected_condition and target == expected_target, 'branch predicate or target changed')
    return name, fallthrough, target, raw


def rip_target(image, site, prefix):
    raw = image.read(site, len(prefix) + 4)
    need(raw.startswith(prefix), 'unexpected RIP-relative instruction')
    return site + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0], raw


def direct_call(image, site):
    raw = image.read(site, 5)
    need(raw[0] == 0xe8, 'expected direct call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0], raw


def u32_immediate(image, va, prefix):
    raw = image.read(va, len(prefix) + 4)
    need(raw.startswith(prefix), 'unexpected immediate instruction')
    return struct.unpack_from('<I', raw, len(prefix))[0]


def names(image, base, count):
    result = []
    for i in range(count):
        slot = base + 16 * i
        _, string_va = image.rel(slot)
        length = image.u64(slot + 8)
        need(0 < length <= 64, 'invalid descriptor length')
        raw = image.read(string_va, length)
        try:
            text = raw.decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('non-ASCII selected name') from error
        result.append((text, string_va, length))
    need(len(set(x[0] for x in result)) == len(result), 'duplicate selected names')
    return result


def factors(image, base, count):
    raw = image.read(base, count * 8)
    values = struct.unpack('<' + 'Q' * count, raw)
    need(set(values) <= {0x3ff0000000000000, 0x4014000000000000},
         'unexpected binary64 factor')
    return values


def dynamic_symbol(image, slot, expected_name):
    """Resolve one selected R_X86_64_GLOB_DAT symbol through ELF bytes."""
    rs = [s for s in image.secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    syms = [s for s in image.secs if s['name'] == '.dynsym' and s['type'] == 11]
    strings = [s for s in image.secs if s['name'] == '.dynstr' and s['type'] == 3]
    need(len(rs) == len(syms) == len(strings) == 1, 'missing dynamic symbol inputs')
    rela, symtab, strtab = rs[0], syms[0], strings[0]
    need(rela['size'] % 24 == 0 and symtab['size'] % 24 == 0, 'invalid dynamic table size')
    found = []
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', image.blob, pos)
        if address == slot:
            found.append((pos, info, addend))
    need(len(found) == 1, 'missing or duplicate selected dynamic relocation')
    pos, info, addend = found[0]
    index, kind = info >> 32, info & 0xffffffff
    need(kind == 6 and index > 0 and index * 24 + 24 <= symtab['size'],
         'invalid dynamic relocation type or symbol index')
    symbol_offset = symtab['offset'] + index * 24
    name_offset = struct.unpack_from('<I', image.blob, symbol_offset)[0]
    need(name_offset < strtab['size'], 'dynamic symbol name outside string table')
    begin, end = strtab['offset'] + name_offset, strtab['offset'] + strtab['size']
    terminator = image.blob.find(b'\0', begin, end)
    need(terminator >= begin, 'unterminated dynamic symbol name')
    try:
        symbol = bytes(image.blob[begin:terminator]).decode('ascii')
    except UnicodeDecodeError as error:
        raise ValueError('non-ASCII dynamic symbol') from error
    need(symbol == expected_name and addend == 0, 'unexpected dynamic symbol or addend')
    return pos, index, symbol_offset, symbol


def lookup_thresholds(image):
    values = []
    for address in (0x155440c, 0x1554416, 0x15544c3):
        raw = image.read(address, 4)
        need(raw[:3] == bytes.fromhex('4983ff'), 'lookup length comparison changed')
        values.append(raw[3])
    need(tuple(values) == (17, 7, 3), 'lookup length boundaries changed')
    return tuple(values)


def lookup_length_bucket(length, thresholds):
    need(type(length) is int and 0 <= length < 1 << 64, 'invalid key length')
    upper, middle, lower = thresholds
    if length >= upper:
        return 'at_least_17'
    if length > middle:
        return '8_to_16'
    if length > lower:
        return '4_to_7'
    return '0_to_3'


def template(image, va, expected):
    header = image.read(va, 2)
    need(header[0] == 0xc0, 'template does not start with argument marker')
    size = header[1]
    raw = image.read(va, size + 3)
    need(raw[-1] == 0 and raw[2:-1] == expected, 'template suffix or terminator changed')
    return raw


def matches_prefix(value, prefix):
    """The selected length/SIMD gate admits the prefix and any following bytes."""
    need(isinstance(value, bytes) and isinstance(prefix, bytes), 'prefix inputs must be bytes')
    return len(value) >= len(prefix) and value[:len(prefix)] == prefix


def factor_at(values, index):
    # This is a research-domain check; the target selector has no local bound.
    need(type(index) is int and 0 <= index < len(values), 'factor index outside research domain')
    return values[index]


def product_bits(value_bits, factor_bits):
    x = struct.unpack('<d', struct.pack('<Q', value_bits))[0]
    factor = struct.unpack('<d', struct.pack('<Q', factor_bits))[0]
    return struct.unpack('<Q', struct.pack('<d', x * factor))[0]


def normalizer_constants(image):
    # These are operands in the checked constructor instruction windows.
    a = image.read(0x1548ccb, 10)
    b = image.read(0x1548cd8, 10)
    c = image.read(0x1548ce5, 4)
    d = image.read(0x1548cf9, 6)
    e = image.read(0x1548d05, 10)
    need(a[:2] == b'\x48\xb8' and b[:2] == b'\x48\xba' and
         c[:3] == b'\x48\xc1\xea' and d[:2] == b'\x81\xfa' and
         e[:2] == b'\x48\xba', 'normalizer operand encoding changed')
    values = (struct.unpack('<Q', a[2:])[0], struct.unpack('<Q', b[2:])[0],
              c[3], struct.unpack('<I', d[2:])[0], struct.unpack('<Q', e[2:])[0])
    need(values == (0x7fffffffffffffff, 0xfff0000000000000, 53, 1023,
                    0xfffffffffffff), 'normalizer operands changed')
    return values


def normalize_product(bits, constants):
    """Model the selected integer/SSE bit branches after MULSD, not the MULSD itself."""
    need(type(bits) is int and 0 <= bits < 1 << 64, 'invalid binary64 bits')
    magnitude_mask, bias, shift, special_cutoff, fraction_mask = constants
    modulus = (1 << 64) - 1
    magnitude = bits & magnitude_mask
    exponent_test = ((magnitude + bias) & modulus) >> shift
    primary = bits if bits >> 63 == 0 else 0
    if exponent_test >= special_cutoff:
        primary = 0
    compared = (bits - 1) & modulus
    alternative = primary if compared >= fraction_mask else bits
    return bits if magnitude == 0 else alternative

BODY_SHA256 = {
    'poll_wrapper': 'a93dda6cc5d49a7eac16400a73fe5ca5a88f19734f4753b26621d0c68bf5f75c',
    'scheduled_poll': 'c9976fea5bd8762f786cbc13bab6d02db8f966b77fe5242f5d0fb22955a48e6a',
    'publish_a': 'a1e61ca64377a8fa06f46ffbd9d75df981369cec2cde67ad688730dc0ed48198',
    'publish_b': '8bc73ca897de0a44bcb7658b92694ee20d154cbcf3d436e452ce2b51a9dddaf2',
    'cell_initializer': '047f764eb7936f2e7b3dc7d2b390ac9346bf3fae11ac96f859e934813a3df394',
    'observer_constructor': 'c3170fc950213862ae36e96ef5708fdde181ae700d2059620f390a0e12f3eb8b',
    'keyed_lookup': '018afcb8b3ed72dc856773451dfd3d6510064a95eec01e1747acaa685ed8db48',
    'name_factor_selector': '7120b01c5567ba4ffd0d74880d5c54374b5e72d35753e82fb0bdf31af127514a',
    'constructor_cleanup': '94fe09b52cf88a1df7ef7483b569666d1d80adfd6795f136ec3061451202c08a',
}

CALLS = (
    ('wrapper_failure_helper', 0x15fe39d, 'indirect', 0x64df6b8),
    ('wrapper_to_poll', 0x15fe3d7, 'direct', 0x15ed290),
    ('poll_projection_helper', 0x15ed3aa, 'indirect', 0x64e1888),
    ('poll_map_lookup', 0x15ed481, 'direct', 0x15543f0),
    ('poll_to_constructor', 0x15ed4ca, 'indirect', 0x64e1020),
    ('poll_map_value_copy', 0x15ed596, 'indirect', 0x64df508),
    ('poll_map_observer_update', 0x15ed5e9, 'indirect', 0x64e1010),
    ('poll_to_observer_update', 0x15ed63a, 'indirect', 0x64e1010),
    ('poll_child', 0x15ed675, 'direct', 0x15ebbe0),
    ('poll_to_once', 0x15ed771, 'indirect', 0x64df9f0),
    ('poll_lock_contended', 0x15ed788, 'indirect', 0x64e01f8),
    ('poll_unlock_contended', 0x15ed79c, 'indirect', 0x64e0f38),
    ('poll_map_lock_contended', 0x15ed7ef, 'indirect', 0x64e01f8),
    ('poll_map_unlock_contended', 0x15ed803, 'indirect', 0x64e0f38),
    ('initializer_to_constructor', 0x15d86de, 'indirect', 0x64e1020),
    ('initializer_copy', 0x15d870e, 'indirect', 0x64df508),
    ('callback_a_copy', 0x15edbc5, 'indirect', 0x64df508),
    ('callback_b_copy', 0x15ea215, 'indirect', 0x64df508),
    ('callback_a_null_failure', 0x15edbdd, 'indirect', 0x64df830),
    ('callback_a_state_failure', 0x15edbe3, 'indirect', 0x64dffd0),
    ('callback_b_null_failure', 0x15ea22d, 'indirect', 0x64df830),
    ('callback_b_state_failure', 0x15ea233, 'indirect', 0x64dffd0),
    ('lookup_grow_helper', 0x155471d, 'indirect', 0x64e1120),
    ('constructor_allocation_failure', 0x1548bfe, 'indirect', 0x64df498),
    ('constructor_time_conversion', 0x1548c6b, 'indirect', 0x64e0ab8),
    ('constructor_to_selector', 0x1548cb6, 'indirect', 0x64e1008),
    ('constructor_time_failure', 0x1548ec2, 'indirect', 0x64df770),
    ('constructor_cleanup_a', 0x1548edf, 'direct', 0x154f790),
    ('constructor_cleanup_b', 0x1548eec, 'direct', 0x154f790),
    ('constructor_cleanup_c', 0x1548f20, 'direct', 0x154f790),
    ('constructor_cleanup_d', 0x1548f2a, 'direct', 0x154f790),
    ('selector_to_once', 0x1547521, 'indirect', 0x64df9f0),
)


def call_record(image, label, site, kind, expected):
    if kind == 'direct':
        target, raw = direct_call(image, site)
    elif kind == 'indirect':
        target, raw = rip_target(image, site, b'\xff\x15')
    else:
        raise ValueError('unsupported call kind')
    need(target == expected, 'unexpected call target')
    relocation = image.rels.get(target) if kind == 'indirect' else None
    return (label, hex(site), hex(image.offset(site, len(raw))), raw.hex(), kind,
            hex(target), '' if relocation is None else hex(relocation[0]),
            '' if relocation is None else hex(relocation[1]))


def lsda_rows(image, name, fde):
    """Read selected LSDA call-site table; action chains are left unresolved."""
    address = fde['lsda']
    if address is None:
        return []
    secs = [s for s in image.secs if s['name'] == '.gcc_except_table' and
            s['type'] != 8 and s['address'] <= address < s['address'] + s['size']]
    need(len(secs) == 1, 'LSDA not in one file-backed exception section')
    section = secs[0]
    origin = image.offset(address, 2)
    end = section['offset'] + section['size']
    pos = origin
    lp_encoding, type_encoding = image.blob[pos:pos + 2]
    pos += 2
    need(lp_encoding == 0xff and type_encoding in (0xff, 0x9b), 'unsupported LSDA encoding')
    type_base = None
    if type_encoding != 0xff:
        delta, pos = uleb(image.blob, pos, end)
        type_base = pos + delta
        need(type_base <= end, 'LSDA type table outside section')
    need(pos < end and image.blob[pos] == 1, 'unsupported LSDA call-site encoding')
    length, pos = uleb(image.blob, pos + 1, end)
    stop = pos + length
    need(stop <= end and (type_base is None or stop <= type_base), 'LSDA entries outside section')
    rows = []
    last_end = 0
    while pos < stop:
        entry_start = pos
        vals = []
        for _ in range(4):
            value, pos = uleb(image.blob, pos, stop)
            vals.append(value)
        begin, length, landing, action = vals
        need(length > 0 and begin >= last_end and
             begin + length <= fde['end'] - fde['start'], 'invalid LSDA call-site range')
        need(landing == 0 or landing < fde['end'] - fde['start'], 'LSDA landing outside FDE')
        last_end = begin + length
        rows.append((name, hex(address), hex(entry_start),
                     hex(fde['start'] + begin), hex(fde['start'] + begin + length),
                     '' if landing == 0 else hex(fde['start'] + landing), action,
                     image.blob[entry_start:pos].hex()))
    return rows


def tsv(headers, rows):
    buffer = io.StringIO(newline='')
    writer = csv.writer(buffer, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return buffer.getvalue().encode('utf-8')


def selected_tables(image):
    # The decimal bound is read from the selected target diagnostic, not from a
    # copied release-94 name list. The table count is conditional on this binding.
    marker = b'variant index 0 <= i < '
    text = image.read(0x464893, len(marker) + 2)
    need(text.startswith(marker) and text[-2:].isdigit(), 'name-bound literal changed')
    count = int(text[-2:])
    need(count == 79, 'unexpected selected name domain')
    left = names(image, 0x63f8788, count)
    right = names(image, 0x6410ce8, count)
    need([x[0] for x in left] == [x[0] for x in right], 'name arrays disagree')
    table_va, raw = rip_target(image, 0x15474e7, b'\x48\x8d\x0d')
    need(table_va == 0x4671d0 and image.read(0x15474ee, 5) == bytes.fromhex('f20f1004c1'),
         'factor-indexed load changed')
    values = factors(image, table_va, count)
    return count, left, right, table_va, values, raw


def compare_94(image115, historical):
    """Optional identity-checked historical comparison, excluded from --out files."""
    historical_templates = []
    for name, va, literal in (('cham', 0x1fc0ec, b'/cham'),
                              ('static_config', 0x1ef5f5, b'/static_config')):
        raw = template(historical, va, literal)
        historical_templates.append({'name': name, 'entry_va': hex(va),
                                     'file_offset': hex(historical.offset(va, len(raw))),
                                     'bytes_hex': raw.hex()})
    table94, _ = rip_target(historical, 0x1402767, b'\x48\x8d\x0d')
    need(table94 == 0x218640 and historical.read(0x140276e, 5) == bytes.fromhex('f20f1004c1'),
         'historical indexed factor load changed')
    old_names = names(historical, 0x5668288, 76)
    old_values = factors(historical, table94, len(old_names))
    count, current_names, current_names_second, table115, current_values, _ = selected_tables(image115)
    old = {name: (idx, old_values[idx]) for idx, (name, _, _) in enumerate(old_names)}
    new = {name: (idx, current_values[idx]) for idx, (name, _, _) in enumerate(current_names)}
    shared = sorted(old.keys() & new.keys())
    added = sorted(new.keys() - old.keys())
    removed = sorted(old.keys() - new.keys())
    changed_names = [key for key in shared if old[key][1] != new[key][1]]
    ordinal = [i for i in range(min(len(old_values), count)) if old_values[i] != current_values[i]]
    return {
        'historical_sha256': SHA94,
        'historical_templates': historical_templates,
        'name_context': [
            {'name': name, 'historical_index': old[name][0],
             'historical_descriptor_va': hex(0x5668288 + 16 * old[name][0]),
             'historical_relocation_file_offset': hex(historical.rel(0x5668288 + 16 * old[name][0])[0]),
             'historical_text_va': hex(old_names[old[name][0]][1]),
             'current_index': new[name][0],
             'current_descriptor_va': hex(0x6410ce8 + 16 * new[name][0]),
             'current_relocation_file_offset': hex(image115.rel(0x6410ce8 + 16 * new[name][0])[0]),
             'current_text_va': hex(current_names_second[new[name][0]][1])}
            for name in ('NvTestnet', 'NvTestnet2', 'NvMainnet', 'JoinMainnet')
        ],
        'historical_name_table_va': hex(0x5668288),
        'historical_factor_load_va': hex(0x1402767),
        'historical_factor_table_va': hex(table94),
        'current_sha256': SHA115,
        'current_factor_load_va': hex(0x15474e7),
        'current_factor_table_va': hex(table115),
        'shared_names': len(shared),
        'moved_name_indices': sum(old[k][0] != new[k][0] for k in shared),
        'changed_factors_by_name': len(changed_names),
        'removed_names': removed,
        'added_names': [{'name': k, 'index': new[k][0], 'factor_bits': hex(new[k][1])} for k in added],
        'differing_ordinal_positions': ordinal,
        'ordinal_examples': [
            {'index': i, 'historical_name': old_names[i][0],
             'historical_factor_bits': hex(old_values[i]),
             'current_name': current_names[i][0], 'current_factor_bits': hex(current_values[i])}
            for i in ordinal
        ],
    }

WINDOWS += (
    ('lookup_lengths', '0x1554404', '4c8b72084c8b7a104983ff114889142473264983ff070f86a300000048b9d308a385886a3f2449330e48be447370032e8a1913e9d5000000'),
    ('lookup_match_compare', '0x15545c2', '48f7d84869d8780200004d39bc1d98fdffff75314c01eb488bbb90fdffff4c89f64c89fa4c897c24384c895424304d89cf41ffd14d89f94c8b5424304c8b7c243885c07455'),
    ('lookup_hit_return', '0x155465c', '488b442408488958084889c34c89501048b80000000000000080488903488b0424488b304885f674304c89f731d2ff1510aef804eb23'),
    ('lookup_miss_return', '0x1554692', '49837a10007471488b0c24488b411048894310f30f6f01f30f7f034c89531848896b204889d84883c4685b415c415d415e415f5dc3'),
    ('lookup_short_boundary', '0x15544c3', '4983ff030f86fa010000'),
    ('lookup_grow', '0x155470a', 'be010000004c89d74c89c2b9010000004d89d7ff15fdc9f8044d89fae96effffff'),
)

WINDOWS += (
    ('callback_a_after_fde', '0x15edbe9', 'cc'),
    ('callback_b_after_fde', '0x15ea239', 'cc'),
    ('poll_measure_projection', '0x15ed33a', '4c8bbb2801000031c9b8000000004d85ff745248698b8801000000ca9a3b8b83900100004801c84889c14c09f948c1e920740a31d249f7f74889c1eb0731d241f7f789c14889c848c1e80948ba535a9ba02fb8440048f7e248c1ea0b4869c200ca9a3b29c189cf31f64801c7400f92c6ff15d844ef04f20f590550c1e6fef20f11442408'),
)


def collect(image):
    window_rows = check_windows(image)
    function_rows, body_rows, exceptions = [], [], []
    for name, start, end in FUNCTIONS:
        fde, index = image.fde(start, end)
        code = image.read(start, end - start)
        digest = hashlib.sha256(code).hexdigest()
        need(digest == BODY_SHA256[name], 'selected FDE bytes changed: ' + name)
        function_rows.append((name, hex(start), hex(end), len(code), hex(image.offset(start, len(code))),
                              hex(fde['fde']), hex(fde['cie']),
                              '' if fde['lsda'] is None else hex(fde['lsda']), index['index'], digest))
        body_rows.append((name, hex(start), code.hex()))
        exceptions.extend(lsda_rows(image, name, fde))

    branch_rows = []
    for label, site, cond, target in BRANCHES:
        name, fallthrough, destination, raw = branch(image, site, cond, target)
        branch_rows.append((label, hex(site), hex(image.offset(site, len(raw))), raw.hex(), name,
                            hex(fallthrough), hex(destination)))
    call_rows = [call_record(image, *args) for args in CALLS]

    relocation_rows = []
    for label, slot, expected in RELOCS:
        off, addend = image.rel(slot, expected)
        relocation_rows.append((label, hex(slot), hex(image.offset(slot, 8)), image.read(slot, 8).hex(),
                                hex(off), hex(addend)))

    jump_base, _ = rip_target(image, 0x15ed2ae, b'\x48\x8d\x0d')
    need(jump_base == 0x46a064, 'poll state table changed')
    destinations = (0x15ed2c3, 0x15ed2ee, 0x15ed2e1, 0x15ed668)
    state_rows = []
    for index, expected in enumerate(destinations):
        slot = jump_base + index * 4
        raw = image.read(slot, 4)
        actual = jump_base + struct.unpack('<i', raw)[0]
        need(actual == expected, 'poll state destination changed')
        state_rows.append((index, hex(slot), hex(image.offset(slot, 4)), raw.hex(), hex(actual)))

    last_va, _ = rip_target(image, 0x15ed3d6, bytes.fromhex('660f740d'))
    first_va, _ = rip_target(image, 0x15ed3de, bytes.fromhex('660f7405'))
    first, last = image.read(first_va, 16), image.read(last_va, 16)
    prefix = first + last[:8]
    need(last[8:] == b'\0' * 8 and prefix == b'tokio_scheduled_observer',
         'selected SIMD prefix operands changed')
    length_check = image.read(0x15ed3be, 5)
    need(length_check[:4] == bytes.fromhex('48837b10') and length_check[4] == len(prefix),
         'prefix length check changed')

    name_va, _ = rip_target(image, 0x15d86bd, b'\x48\x8d\x15')
    name_length = u32_immediate(image, 0x15d86d1, b'\xb9')
    label = image.read(name_va, name_length)
    need(label == b'tokio_spawn_forever_scheduled', 'initializer name changed')
    value_va, _ = rip_target(image, 0x15d86c9, bytes.fromhex('f20f1005'))
    input_bits = image.u64(value_va)
    need(input_bits == 0x3fb999999999999a, 'initializer input changed')
    duration_va, _ = rip_target(image, 0x15ed3b0, bytes.fromhex('f20f5905'))
    duration_bits = image.u64(duration_va)
    diagnostic_va, _ = rip_target(image, 0x1548eaf, b'\x48\x8d\x3d')
    diagnostic_length = u32_immediate(image, 0x1548ebd, b'\xbe')
    diagnostic = image.read(diagnostic_va, diagnostic_length)
    need(diagnostic == b'Local time out of range for `NaiveDateTime`', 'constructor diagnostic changed')

    guard = u32_immediate(image, 0x15ed605, bytes.fromhex('418b8424'))
    need(guard == 0x268, 'scheduled cell guard offset changed')
    constructor_store = u32_immediate(image, 0x1548dd2, bytes.fromhex('f2410f1186'))
    need(constructor_store == 0x218, 'constructor factor store changed')
    need(image.read(0x15d8702, 4) == bytes.fromhex('4883c708'), 'wrapper destination offset changed')
    wrapper_offset = image.read(0x15d8705, 1)[0]
    payload = u32_immediate(image, 0x15d8706, b'\xba')
    callback_a = u32_immediate(image, 0x15edbba, b'\xba')
    callback_b = u32_immediate(image, 0x15ea20a, b'\xba')
    need(payload + wrapper_offset == callback_a == callback_b == guard,
         'wrapper, publication and guard sizes disagree')
    cell = image.rel(0x64e1850, 0x64f0428)[1]
    need(image.read(cell + guard, 4) == struct.pack('<I', 3), 'initial file guard changed')
    vtable = image.read(0x6401cf8, 24)
    need(struct.unpack('<QQQ', vtable) == (0, 8, 8), 'vtable header changed')

    comparison_slot, comparison_load = rip_target(image, 0x155456b, bytes.fromhex('4c8b0d'))
    need(comparison_slot == 0x64df9f8 and image.read(0x15545f3, 3) == bytes.fromhex('41ffd1'),
         'lookup comparison dispatch changed')
    symbol_offset, symbol_index, symbol_record, symbol_name = dynamic_symbol(image, comparison_slot, 'bcmp')
    thresholds = lookup_thresholds(image)
    upper, middle, lower = thresholds
    lengths = sorted({0, 1, lower, lower + 1, middle, middle + 1, upper - 1, upper,
                      upper + 14, upper + 15, upper + 16})
    lookup_rows = [(n, lookup_length_bucket(n, thresholds)) for n in lengths]
    symbol_rows = [('lookup_byte_compare', hex(0x155456b), comparison_load.hex(),
                    hex(comparison_slot), hex(image.offset(comparison_slot, 8)),
                    hex(symbol_offset), symbol_index, hex(symbol_record), symbol_name)]

    count, left, right, table_va, values, factor_lea = selected_tables(image)
    by_name = {name: i for i, (name, _, _) in enumerate(left)}
    contextual_names = ('EaMm', 'EaTx', 'HeavyTestnet', 'NvTestnet', 'NvTestnet2',
                        'NvMainnet', 'NvMainnet2', 'NvMainnet3', 'JoinMainnet', 'DummyNv', 'FBinSpot')
    name_rows = []
    for name in contextual_names:
        need(name in by_name, 'missing contextual selected name')
        i = by_name[name]
        left_slot, right_slot = 0x63f8788 + 16*i, 0x6410ce8 + 16*i
        name_rows.append((name, i, hex(left_slot), hex(image.rel(left_slot)[0]), hex(left[i][1]),
                          hex(right_slot), hex(image.rel(right_slot)[0]), hex(right[i][1]),
                          left[i][2], hex(factor_at(values, i))))

    factor_runs = []
    begin = 0
    for i in range(1, len(values) + 1):
        if i == len(values) or values[i] != values[begin]:
            factor_runs.append((begin, i - 1, hex(table_va + 8*begin), i - begin, hex(values[begin])))
            begin = i

    template_rows = []
    for name, va, literal in (('cham', 0x44ab69, b'/cham'),
                               ('static_config', 0x4401ef, b'/static_config')):
        raw = template(image, va, literal)
        template_rows.append((name, hex(va), hex(image.offset(va, len(raw))), len(raw), raw.hex()))
    data_rows = [
        ('initializer_label', hex(name_va), hex(image.offset(name_va, name_length)),
         name_length, label.hex()),
        ('observer_prefix_first', hex(first_va), hex(image.offset(first_va, 16)), 16, first.hex()),
        ('observer_prefix_last', hex(last_va), hex(image.offset(last_va, 16)), 16, last.hex()),
        ('constructor_time_diagnostic', hex(diagnostic_va), hex(image.offset(diagnostic_va, diagnostic_length)),
         diagnostic_length, diagnostic.hex()),
        ('initializer_input_binary64', hex(value_va), hex(image.offset(value_va, 8)), 8,
         image.read(value_va, 8).hex()),
        ('poll_scale_binary64', hex(duration_va), hex(image.offset(duration_va, 8)), 8,
         image.read(duration_va, 8).hex()),
        ('factor_table', hex(table_va), hex(image.offset(table_va, count*8)), count*8,
         image.read(table_va, count*8).hex()),
        ('scheduled_vtable_header', hex(0x6401cf8), hex(image.offset(0x6401cf8, 24)), 24, vtable.hex()),
        ('scheduled_initial_guard', hex(cell + guard), hex(image.offset(cell + guard, 4)), 4,
         image.read(cell + guard, 4).hex()),
    ]
    data_rows.extend(template_rows)

    constants = normalizer_constants(image)
    cases = (
        ('positive_zero', 0x0000000000000000), ('negative_zero', 0x8000000000000000),
        ('positive_subnormal', 0x0000000000000001), ('negative_subnormal', 0x8000000000000001),
        ('largest_positive_subnormal', 0x000fffffffffffff), ('smallest_positive_normal', 0x0010000000000000),
        ('positive_one', 0x3ff0000000000000), ('negative_one', 0xbff0000000000000),
        ('largest_finite', 0x7fefffffffffffff), ('positive_infinity', 0x7ff0000000000000),
        ('negative_infinity', 0xfff0000000000000), ('positive_quiet_nan', 0x7ff8000000000001),
        ('negative_quiet_nan', 0xfff8000000000001),
    )
    case_rows = [(name, f'{bits:016x}', f'{normalize_product(bits, constants):016x}')
                 for name, bits in cases]
    prefix_cases = (('empty', b''), ('one_byte_short', prefix[:-1]),
                    ('exact', prefix), ('exact_with_suffix', prefix + b'_x'),
                    ('first_byte_changed', bytes([prefix[0] ^ 1]) + prefix[1:]),
                    ('last_byte_changed', prefix[:-1] + bytes([prefix[-1] ^ 1])))
    prefix_rows = [(name, len(value), value.hex(), str(matches_prefix(value, prefix)).lower())
                   for name, value in prefix_cases]
    samples = []
    for name in ('NvTestnet', 'NvMainnet', 'EaTx', 'DummyNv'):
        index = by_name[name]
        factor = factor_at(values, index)
        product = product_bits(input_bits, factor)
        samples.append({'name': name, 'index': index, 'factor_bits': f'{factor:016x}',
                        'input_bits': f'{input_bits:016x}', 'product_bits': f'{product:016x}',
                        'stored_bits_after_normalizer': f'{normalize_product(product, constants):016x}'})

    results = {
        'functions.tsv': tsv(('role', 'start_va', 'end_va_exclusive', 'size', 'file_offset',
                              'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'sha256'), function_rows),
        'bodies.tsv': tsv(('role', 'start_va', 'complete_fde_bytes_hex'), body_rows),
        'windows.tsv': tsv(('label', 'site_va', 'file_offset', 'bytes_hex'), window_rows),
        'branches.tsv': tsv(('label', 'site_va', 'file_offset', 'bytes_hex', 'condition',
                             'fallthrough_va', 'taken_va'), branch_rows),
        'calls.tsv': tsv(('label', 'site_va', 'file_offset', 'bytes_hex', 'kind',
                          'target_or_slot_va', 'relative_relocation_offset', 'relative_addend_va'), call_rows),
        'relocations.tsv': tsv(('label', 'slot_va', 'slot_file_offset', 'initial_slot_bytes_hex',
                                'relocation_file_offset', 'relative_addend_va'), relocation_rows),
        'state-table.tsv': tsv(('state_byte', 'slot_va', 'file_offset', 'signed_delta_bytes_hex',
                                'destination_va'), state_rows),
        'exceptions.tsv': tsv(('function', 'lsda_va', 'entry_file_offset', 'start_va', 'end_va_exclusive',
                               'landing_va', 'action_index', 'encoded_bytes_hex'), exceptions),
        'data.tsv': tsv(('label', 'va', 'file_offset', 'size', 'bytes_hex'), data_rows),
        'factor-runs.tsv': tsv(('first_index', 'last_index_inclusive', 'first_factor_va', 'count',
                                'binary64_bits'), factor_runs),
        'name-context.tsv': tsv(('name', 'index', 'first_descriptor_va', 'first_relocation_file_offset',
                                 'first_text_va', 'second_descriptor_va', 'second_relocation_file_offset',
                                 'second_text_va', 'text_length', 'factor_bits'), name_rows),
        'product-model.tsv': tsv(('synthetic_product', 'input_bits_hex', 'stored_bits_hex'), case_rows),
        'prefix-model.tsv': tsv(('synthetic_input', 'input_length', 'input_bytes_hex',
                                 'selected_prefix_branch'), prefix_rows),
        'lookup-lengths.tsv': tsv(('synthetic_key_length', 'entry_bucket'), lookup_rows),
        'dynamic-symbol.tsv': tsv(('label', 'load_va', 'load_bytes_hex', 'slot_va', 'slot_file_offset',
                                   'relocation_file_offset', 'symbol_index', 'symbol_record_file_offset',
                                   'symbol_name'), symbol_rows),
    }
    summary = {
        'target_sha256': SHA115,
        'coordinate_system': 'linked ELF virtual addresses and source file offsets',
        'function_count': len(function_rows),
        'fde_bytes': sum(end - start for _, start, end in FUNCTIONS),
        'checked_windows': len(window_rows),
        'conditional_branches': len(branch_rows),
        'selected_calls': len(call_rows),
        'selected_relative_relocations': len(relocation_rows),
        'lsda_callsite_rows': len(exceptions),
        'poll_state_table_va': hex(jump_base),
        'poll_selected_state_slots': len(state_rows),
        'lookup_bcmp_symbol': symbol_name,
        'lookup_length_cases': len(lookup_rows),
        'poll_prefix': prefix.decode('ascii'),
        'poll_prefix_length': length_check[4],
        'poll_scale_bits': f'{duration_bits:016x}',
        'name_descriptor_count': count,
        'name_array_agreements': sum(a[0] == b[0] for a, b in zip(left, right)),
        'factor_table_va': hex(table_va),
        'factor_lea_bytes': factor_lea.hex(),
        'factor_one_count': values.count(0x3ff0000000000000),
        'factor_five_count': values.count(0x4014000000000000),
        'factor_runs': len(factor_runs),
        'initializer_label': label.decode('ascii'),
        'initializer_label_va': hex(name_va),
        'initializer_input_bits': f'{input_bits:016x}',
        'scheduled_cell_va': hex(cell),
        'scheduled_cell_guard_offset': hex(guard),
        'initial_guard_file_value': struct.unpack('<I', image.read(cell + guard, 4))[0],
        'wrapper_payload_bytes': payload,
        'wrapper_result_offset': wrapper_offset,
        'callback_copy_bytes': callback_a,
        'constructor_factor_store_offset': hex(constructor_store),
        'outer_cell_factor_offset': hex(wrapper_offset + constructor_store),
        'outer_cell_factor_va': hex(cell + wrapper_offset + constructor_store),
        'synthetic_product_model_cases': len(case_rows),
        'synthetic_prefix_model_cases': len(prefix_rows),
        'initializer_scenarios': samples,
        'limitations': ('Selected byte patterns and LSDA entries, not a complete x86 CFG, '
                        'concurrency proof, target execution, Rust implementation or equivalence.'),
    }
    results['summary.json'] = (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode()
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--compare-94', type=Path,
                        help='optional authenticated historical capture; comparison goes to stdout')
    args = parser.parse_args(argv)
    image = Image(TARGET.read_bytes(), SHA115, SIZE115)
    historical = None
    if args.compare_94 is not None:
        historical = Image(args.compare_94.read_bytes(), SHA94, SIZE94)
    result = collect(image)
    comparison = None if historical is None else compare_94(image, historical)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in result.items():
        (args.out / name).write_bytes(content)
    if comparison is not None:
        print(json.dumps(comparison, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print('node115_scheduled_factor:', error, file=sys.stderr)
        raise SystemExit(1)

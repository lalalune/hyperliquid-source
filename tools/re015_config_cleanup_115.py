#!/usr/bin/env python3
"""Recover a bounded #115 configuration-gated cleanup path from ELF bytes.

This is a static collector, not an x86 emulator or a filesystem operation.
The few instruction forms decoded below are selected after manual inspection;
unknown encodings, ambiguous addresses and changed witnesses fail closed.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb


ROOT = Path(__file__).resolve().parents[1]
DIGEST_115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
DIGEST_94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE_115 = 105896032
SIZE_94 = 91774280
NAME_TABLE_115 = 0x63f8788
NAME_TABLE_94 = 0x5668288

# These are selected unwind extents, not an inventory of all node functions.
# Hashes are independent corruption guards for the restricted witnesses below.
FUNCTIONS = [
    ('periodic_caller', 0x5a07ec0, 0x5a0871c, '25f84ed2821128021473629dafd092fe1058087d196097c36ebfe83d9cae466b'),
    ('hour_selector', 0x1567ad0, 0x1567b94, '1c40eb321e4ae81144d7199392e3294281f22a618155a9cba1e5b211f53fca87'),
    ('name_gate', 0x1563fc0, 0x1564116, '5193f1e3da627b3552b3786341928a2148a5fe078ce66e783cf591add851f6a5'),
    ('directory_predicate', 0x1500a60, 0x1500b83, '5dd7ac6a1971eab295f33940c9734fc7cdccf64be747f53e92ca31a746d463b4'),
    ('remove_retry', 0x1561530, 0x1561968, '1ff30827beb2d28c9d4f22864ce2cf8e99cac55a9e18f97e0a171dd6c1fc737e'),
    ('short_zero_check', 0x167e030, 0x167e141, '7de8a3aa83214dab2fefa596dbc71d36a5ea2a5772d21607a85dcc32c19e6412'),
    ('long_path_callback', 0x5cad7a0, 0x5cad7a8, '4efc85e5c631d11f0283c81b323a61f964c2b6ff659853ea87a6d5ef57155865'),
    ('remove_root', 0x5ca0ef0, 0x5ca0fee, '814d6b664b37df0322913a2cf7f192f1c447e85b89ba84f5e99e0ef18cdd3f89'),
    ('remove_tree', 0x5ca0ff0, 0x5ca147c, 'ed4fe4e6fe4f75ee557c0d3b40fd6f3c89862f580b01f4cf0a0dba3184540a75'),
    ('release_directory_stream', 0x5c98ca0, 0x5c98d2c, 'f0d45a5810f3955b4531b11859a96730332c64f685251598cd48d2ef03690338'),
    ('close_directory_stream', 0x5caaaa0, 0x5caab4b, '58564aea5c34570317c8d9285b92d182d95dde0fc23b3ed20578f05fd20e1875'),
    ('format_root', 0x37be6f0, 0x37be704, '05fbed50293a7bd568025a7ed1fca81965f8f2edbc7667e1e8750918c9b9bb99'),
    ('format_name', 0x46dd7f0, 0x46dd803, 'e12271b09f9af630f929ebc27510230390c1ce74c8a675e7deecdc1466e85ee7'),
    ('format_prefix', 0x59dbfb0, 0x59dbfc4, 'cae420b426669c6b15824475dc01b0408d5ae2a22b2fd3225a09591b716043aa'),
]

# Label, instruction start, expected taken target and x86 condition code.
# This is a curated edge set, not a complete disassembly or CFG census.
BRANCHES = [
    ('caller_past_guard_1', 0x5a07f13, 0x5a08563, 'b'),
    ('caller_mode_2_early', 0x5a07f21, 0x5a07f2e, 'e'),
    ('caller_mode_2_other', 0x5a07f2c, 0x5a07f48, 'ne'),
    ('caller_past_guard_2', 0x5a07f58, 0x5a0857c, 'b'),
    ('caller_snapshot_selector', 0x5a07f83, 0x5a07fbb, 'ne'),
    ('caller_remainder_64', 0x5a07fa3, 0x5a08351, 'ne'),
    ('caller_remainder_32', 0x5a07fb5, 0x5a08351, 'ne'),
    ('caller_snapshot_absent', 0x5a07fed, 0x5a08351, 'e'),
    ('caller_hour_below_two', 0x5a080d2, 0x5a081e0, 'b'),
    ('caller_global_cold', 0x5a080e5, 0x5a08595, 'ne'),
    ('caller_date_first_error', 0x5a08154, 0x5a085c6, 'e'),
    ('caller_date_second_error', 0x5a08167, 0x5a085db, 'e'),
    ('hour_overflow_guard', 0x1567ade, 0x1567b01, 'ae'),
    ('hour_invalid_range', 0x1567af9, 0x1567b26, 'ae'),
    ('mode_not_two', 0x1563fcd, 0x1563ff7, 'ne'),
    ('name_global_cold', 0x1563fdb, 0x1564018, 'ne'),
    ('name_above_mask', 0x1563fe5, 0x1564059, 'a'),
    ('name_bit_clear', 0x1563ff5, 0x1564059, 'ae'),
    ('release_empty', 0x1563ffd, 0x156400e, 'e'),
    ('cold_name_within_mask', 0x1564057, 0x1563fe7, 'be'),
    ('directory_false', 0x1564072, 0x15640a3, 'e'),
    ('retry_success', 0x1564099, 0x15640a3, 'e'),
    ('second_global_ready', 0x15640ae, 0x1563ff7, 'e'),
    ('unwind_empty', 0x1564100, 0x156410e, 'e'),
    ('metadata_first_ok', 0x1500a88, 0x1500aa5, 'ne'),
    ('metadata_first_nonerror', 0x1500ac9, 0x1500ae7, 'ne'),
    ('metadata_second_ok', 0x1500afd, 0x1500b1a, 'ne'),
    ('metadata_second_global_cold', 0x1500b11, 0x1500b2d, 'ne'),
    ('path_over_short_limit', 0x156155f, 0x15615cb, 'a'),
    ('short_no_interior_zero', 0x1561598, 0x15615a8, 'e'),
    ('first_remove_failed', 0x15615b5, 0x15615e7, 'ne'),
    ('first_long_succeeded', 0x15615e5, 0x15615b7, 'e'),
    ('default_delays', 0x1561604, 0x1561629, 'e'),
    ('custom_delays_empty', 0x1561613, 0x156179e, 'e'),
    ('retry_long_path', 0x1561651, 0x156182f, 'a'),
    ('short_sleep_error', 0x15616f3, 0x156191c, 'ne'),
    ('short_retry_zero_ok', 0x1561749, 0x1561760, 'ne'),
    ('short_retry_succeeded', 0x156176d, 0x156181b, 'e'),
    ('short_next_delay', 0x1561798, 0x1561690, 'ne'),
    ('long_sleep_error', 0x15618b2, 0x156191c, 'ne'),
    ('long_retry_succeeded', 0x15618e8, 0x156181b, 'e'),
    ('long_next_delay', 0x1561911, 0x1561858, 'ne'),
    ('zero_short_scan', 0x167e038, 0x167e067, 'a'),
    ('zero_empty', 0x167e03d, 0x167e0fe, 'e'),
    ('zero_found_short', 0x167e054, 0x167e113, 'e'),
    ('zero_loop_short', 0x167e060, 0x167e050, 'ne'),
    ('zero_word_fallback', 0x167e0b4, 0x167e0f9, 'ne'),
    ('zero_terminal', 0x167e11a, 0x167e12b, 'ne'),
    ('root_metadata_not_three', 0x5ca0f23, 0x5ca0f99, 'ne'),
    ('root_lstat_error', 0x5ca0f6b, 0x5ca0faf, 'e'),
    ('root_not_symlink', 0x5ca0f7d, 0x5ca0fdb, 'ne'),
    ('root_unlink_error', 0x5ca0f8b, 0x5ca0faf, 'e'),
    ('root_metadata_not_two', 0x5ca0f9c, 0x5ca0fc9, 'ne'),
    ('root_metadata_symlink', 0x5ca0fd9, 0x5ca0f7f, 'e'),
    ('tree_open_success', 0x5ca102e, 0x5ca1090, 'ne'),
    ('tree_open_not_interrupted', 0x5ca106c, 0x5ca1309, 'ne'),
    ('tree_open_repeat', 0x5ca108e, 0x5ca1050, 'e'),
    ('tree_fdopendir_error', 0x5ca109e, 0x5ca12eb, 'e'),
    ('tree_allocation_error', 0x5ca10de, 0x5ca13f4, 'e'),
    ('tree_readdir_end', 0x5ca1129, 0x5ca12d2, 'e'),
    ('tree_two_byte_name', 0x5ca1178, 0x5ca1140, 'e'),
    ('tree_single_dot', 0x5ca1183, 0x5ca1147, 'e'),
    ('tree_unknown_type', 0x5ca120e, 0x5ca122b, 'e'),
    ('tree_non_directory_type', 0x5ca1217, 0x5ca1245, 'ne'),
    ('tree_child_error', 0x5ca1241, 0x5ca1265, 'ne'),
    ('tree_unlink_child_ok', 0x5ca1258, 0x5ca12a0, 'ne'),
    ('tree_child_err_tag_low', 0x5ca1275, 0x5ca1380, 'b'),
    ('tree_child_err_tag_other', 0x5ca127e, 0x5ca1380, 'ne'),
    ('tree_child_err_not_two', 0x5ca128e, 0x5ca1380, 'ne'),
    ('tree_enumeration_success', 0x5ca12dc, 0x5ca1352, 'e'),
    ('tree_child_link_error_40', 0x5ca130c, 0x5ca1317, 'e'),
    ('tree_child_other_open_error', 0x5ca1311, 0x5ca13bc, 'ne'),
    ('tree_root_open_error', 0x5ca131f, 0x5ca13bc, 'e'),
    ('tree_child_fallback_ok', 0x5ca1339, 0x5ca1347, 'ne'),
    ('tree_final_unlink_error', 0x5ca137a, 0x5ca13ce, 'e'),
    ('tree_external_error_kind', 0x5ca13e3, 0x5ca13bc, 'ne'),
    ('stream_no_buffer', 0x5c98cbb, 0x5c98cc9, 'e'),
    ('stream_sentinel', 0x5c98ccd, 0x5c98cea, 'e'),
    ('stream_ref_still_owned', 0x5c98cd4, 0x5c98cea, 'ne'),
    ('stream_unwind_no_buffer', 0x5c98cf9, 0x5c98d07, 'e'),
    ('stream_unwind_sentinel', 0x5c98d0b, 0x5c98d24, 'e'),
    ('stream_unwind_still_owned', 0x5c98d12, 0x5c98d24, 'ne'),
    ('close_succeeded', 0x5caaac2, 0x5caaaed, 'e'),
    ('close_error_not_interrupted', 0x5caaaeb, 0x5caaaf6, 'ne'),
]

# Label, site, transfer form, expected direct target or relocation slot.
CALLS = [
    ('caller_clock', 0x5a080c1, 'rip_call', 0x64e0990),
    ('caller_hour', 0x5a080ca, 'rip_call', 0x64e0f58),
    ('caller_format_root', 0x5a0812c, 'rip_call', 0x64df6e8),
    ('caller_clock_again', 0x5a08135, 'rip_call', 0x64e0990),
    ('caller_date_convert', 0x5a08148, 'rip_call', 0x64e0ab8),
    ('caller_date_adjust', 0x5a0815f, 'rip_call', 0x64e0aa0),
    ('caller_format_separator', 0x5a081a4, 'rip_call', 0x64df6e8),
    ('caller_name_gate', 0x5a081da, 'rip_call', 0x64e1220),
    ('caller_continuation', 0x5a08267, 'call', 0x5a046f0),
    ('gate_directory', 0x156406a, 'rip_call', 0x64e0928),
    ('gate_remove_retry', 0x1564091, 'call', 0x1561530),
    ('gate_cold', 0x1564046, 'rip_call', 0x64df9f0),
    ('metadata_first', 0x1500a7d, 'rip_call', 0x64e0930),
    ('metadata_second', 0x1500af2, 'rip_call', 0x64e0930),
    ('retry_memcpy', 0x1561572, 'rip_call', 0x64df508),
    ('retry_zero_check', 0x156158d, 'rip_call', 0x64e0a30),
    ('retry_short_first', 0x15615ad, 'call', 0x5ca0ef0),
    ('retry_long_first', 0x15615dd, 'call', 0x5c78ed0),
    ('retry_zero_again', 0x156173e, 'rip_call', 0x64e0a30),
    ('retry_short_again', 0x1561765, 'call', 0x5ca0ef0),
    ('retry_long_again', 0x15618e0, 'call', 0x5c78ed0),
    ('long_path_callback', 0x5cad7a3, 'jump', 0x5ca0ef0),
    ('root_metadata', 0x5ca0f13, 'call', 0x5c9f780),
    ('root_lstat', 0x5ca0f62, 'rip_call', 0x64e1b88),
    ('root_unlink', 0x5ca0f82, 'rip_call', 0x64e0a38),
    ('root_tree', 0x5ca0fe9, 'jump', 0x5ca0ff0),
    ('tree_open', 0x5ca1025, 'rip_call', 0x64ec9d0),
    ('tree_open_error_number', 0x5ca103b, 'rip_call', 0x64dffc8),
    ('tree_fdopendir', 0x5ca1095, 'rip_call', 0x64ec9d8),
    ('tree_read', 0x5ca1120, 'rip_call', 0x64ec9e0),
    ('tree_child_a', 0x5ca1224, 'call', 0x5ca0ff0),
    ('tree_child_b', 0x5ca1236, 'call', 0x5ca0ff0),
    ('tree_unlink_child', 0x5ca124f, 'rip_call', 0x64ec9e8),
    ('tree_close_on_error', 0x5ca12fe, 'rip_call', 0x64dfe78),
    ('tree_fallback_unlink', 0x5ca1330, 'rip_call', 0x64ec9e8),
    ('tree_unlink_directory', 0x5ca1371, 'rip_call', 0x64ec9e8),
    ('tree_release_entry', 0x5ca12aa, 'rip_call', 0x64e0b60),
    ('tree_release_stream', 0x5ca135f, 'rip_call', 0x64e0b60),
    ('release_stream_close', 0x5c98cae, 'rip_call', 0x64ec598),
    ('close_directory_fd', 0x5caaab1, 'rip_call', 0x64eca48),
    ('close_directory', 0x5caaaba, 'rip_call', 0x64eca50),
    ('close_error_number', 0x5caaac4, 'rip_call', 0x64dffc8),
    ('root_format_tail', 0x37be6fe, 'rip_jump', 0x64df720),
    ('name_format_tail', 0x46dd7fd, 'rip_jump', 0x64df720),
    ('prefix_format_tail', 0x59dbfbe, 'rip_jump', 0x64df720),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(blob, expected=DIGEST_115, size=SIZE_115):
    require(len(blob) == size and hashlib.sha256(blob).hexdigest() == expected,
            'capture size or SHA-256 mismatch')


def file_offset(secs, va, size=1, executable=False):
    require(isinstance(va, int) and va >= 0 and isinstance(size, int) and size > 0,
            'invalid address or length')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'unmapped, ambiguous, NOBITS or crossing range')
    s = matches[0]
    return s['offset'] + va - s['address'], s['name']


def relocation_index(blob, offset, size):
    require(offset >= 0 and size >= 0 and size % 24 == 0 and offset + size <= len(blob),
            'truncated dynamic records')
    found = {}
    for p in range(offset, offset + size, 24):
        slot, info, addend = struct.unpack_from('<QQq', blob, p)
        require(slot not in found, 'duplicate relocation slot')
        found[slot] = (info & 0xffffffff, info >> 32, addend, p)
    return found


class Image:
    def __init__(self, blob, digest=DIGEST_115, size=SIZE_115):
        verify_digest(blob, digest, size)
        self.blob = blob
        self.sections = sections(blob)
        rs = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
        syms = [s for s in self.sections if s['name'] == '.dynsym' and s['type'] == 11]
        names = [s for s in self.sections if s['name'] == '.dynstr' and s['type'] == 3]
        require(len(rs) == len(syms) == len(names) == 1, 'missing or duplicate dynamic sections')
        r, self.sym, self.strings = rs[0], syms[0], names[0]
        require(r['size'] % 24 == 0 and self.sym['size'] % 24 == 0, 'truncated dynamic records')
        self.relocs = relocation_index(blob, r['offset'], r['size'])

    def read(self, va, size, executable=False):
        off, _ = file_offset(self.sections, va, size, executable)
        require(off + size <= len(self.blob), 'range outside file')
        return self.blob[off:off + size]

    def offset(self, va, size=1, executable=False):
        return file_offset(self.sections, va, size, executable)[0]

    def relocation(self, slot):
        require(slot in self.relocs, 'missing relocation slot')
        kind, symbol, addend, offset = self.relocs[slot]
        if kind == 8:
            require(symbol == 0, 'RELATIVE relocation has a symbol')
            return {'kind': kind, 'symbol': '', 'addend': addend, 'offset': offset}
        require(kind == 6 and addend == 0 and 0 < symbol < self.sym['size'] // 24,
                'unsupported dynamic relocation')
        pos = self.sym['offset'] + symbol * 24
        name = struct.unpack_from('<I', self.blob, pos)[0]
        require(name < self.strings['size'], 'dynamic symbol name out of bounds')
        begin = self.strings['offset'] + name
        end = self.blob.find(b'\0', begin, self.strings['offset'] + self.strings['size'])
        require(end >= 0, 'unterminated dynamic symbol')
        return {'kind': kind, 'symbol': self.blob[begin:end].decode('ascii'),
                'addend': addend, 'offset': offset}

    def relative(self, slot):
        r = self.relocation(slot)
        require(r['kind'] == 8, 'expected RELATIVE relocation')
        return r['addend']


def verify_body(body, expected_hash):
    require(hashlib.sha256(body).hexdigest() == expected_hash, 'selected body changed')


def check_extent(fde, index, start, end):
    require(fde['start'] == start and fde['end'] == end and
            index['start'] == start and index['fde'] == fde['fde'], 'FDE/index mismatch')


def selected_fdes(image, specs=FUNCTIONS):
    _, fdes = eh_frame_records(image.blob, image.sections)
    _, index = unwind_index(image.blob)
    wanted = {s for _, s, _, _ in specs}
    found, indexed = {}, {}
    for f in fdes:
        if f['start'] in wanted:
            require(f['start'] not in found, 'duplicate selected FDE start')
            found[f['start']] = f
    for row in index:
        if row['start'] in wanted:
            require(row['start'] not in indexed, 'duplicate selected unwind start')
            indexed[row['start']] = row
    require(set(found) == set(indexed) == wanted, 'selected FDE or unwind start missing')
    rows = []
    for label, start, end, digest in specs:
        f = found[start]
        check_extent(f, indexed[start], start, end)
        body = image.read(start, end - start, executable=True)
        verify_body(body, digest)
        rows.append({'role': label, 'start': start, 'end': end, 'fde': f['fde'],
                     'cie': f['cie'], 'lsda': f['lsda'], 'index': indexed[start]['index'],
                     'offset': image.offset(start, len(body), True), 'body': body})
    return rows


CONDITIONS = {0x2: 'b', 0x3: 'ae', 0x4: 'e', 0x5: 'ne',
              0x6: 'be', 0x7: 'a', 0xe: 'le'}


def branch_instruction(raw, site):
    require(len(raw) >= 2, 'truncated branch')
    if 0x70 <= raw[0] <= 0x7f:
        code, n = raw[0] & 15, 2
        displacement = struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        code, n = raw[1] & 15, 6
        displacement = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported or truncated branch')
    require(code in CONDITIONS, 'unsupported condition code')
    return n, CONDITIONS[code], site + n + displacement


def checked_branch(raw, site, expected_target, expected_condition):
    n, condition, target = branch_instruction(raw, site)
    require(target == expected_target and condition == expected_condition, 'branch witness changed')
    return n, condition, target


def exception_sites(blob, pos, end, start_va, end_va):
    """Read the selected ULEB call-site tables; action/type semantics remain opaque."""
    require(0 <= pos < end <= len(blob) and start_va < end_va, 'invalid LSDA range')
    begin = pos
    require(pos + 2 <= end and blob[pos] == 0xff and blob[pos + 1] in (0xff, 0x9b),
            'unsupported LSDA header')
    type_encoding = blob[pos + 1]
    pos += 2
    type_base = None
    if type_encoding != 0xff:
        type_delta, pos = uleb(blob, pos, end)
        type_base = pos + type_delta
        require(type_base <= end, 'LSDA type table outside section')
    require(pos < end and blob[pos] == 1, 'unsupported call-site encoding')
    pos += 1
    table_size, pos = uleb(blob, pos, end)
    table_end = pos + table_size
    require(table_end <= end, 'LSDA call-site table outside section')
    rows = []
    while pos < table_end:
        entry_offset = pos
        relative_start, pos = uleb(blob, pos, table_end)
        length, pos = uleb(blob, pos, table_end)
        relative_landing, pos = uleb(blob, pos, table_end)
        action, pos = uleb(blob, pos, table_end)
        first, last = start_va + relative_start, start_va + relative_start + length
        landing = start_va + relative_landing if relative_landing else None
        require(start_va <= first <= last <= end_va and
                (landing is None or start_va <= landing < end_va), 'LSDA site outside FDE')
        rows.append({'offset': entry_offset, 'start': first, 'end': last, 'landing': landing,
                     'action': action, 'bytes': bytes(blob[entry_offset:pos])})
    require(pos == table_end, 'LSDA call-site table length mismatch')
    return {'offset': begin, 'type_encoding': type_encoding, 'type_base': type_base,
            'table_size': table_size, 'rows': rows}


def decode_lea(raw, site, expected_target):
    require(len(raw) == 7 and raw[0] in (0x48, 0x4c) and raw[1] == 0x8d and
            raw[2] & 0xc7 == 0x05, 'unsupported RIP-relative LEA')
    target = site + 7 + struct.unpack_from('<i', raw, 3)[0]
    require(target == expected_target, 'LEA target changed')
    return target


def decode_rip_load(raw, site, expected_target):
    require(len(raw) == 7 and raw[0] in (0x48, 0x4c) and raw[1] == 0x8b and
            raw[2] & 0xc7 == 0x05, 'unsupported RIP-relative load')
    target = site + 7 + struct.unpack_from('<i', raw, 3)[0]
    require(target == expected_target, 'load target changed')
    return target


def transfer(raw, site, kind, expected):
    if kind in ('call', 'jump'):
        require(len(raw) >= 5 and raw[0] == (0xe8 if kind == 'call' else 0xe9),
                'bad direct transfer')
        n, target = 5, site + 5 + struct.unpack_from('<i', raw, 1)[0]
    else:
        require(kind in ('rip_call', 'rip_jump') and len(raw) >= 6 and
                raw[:2] == (b'\xff\x15' if kind == 'rip_call' else b'\xff\x25'),
                'bad indirect transfer')
        n, target = 6, site + 6 + struct.unpack_from('<i', raw, 2)[0]
    require(target == expected, 'transfer target changed')
    return n, target


def policy_operands(raw):
    # Slice starts at 0x1563fc9 and ends immediately after the BT branch.
    require(len(raw) == 46, 'policy witness truncated')
    require(raw[:4] == bytes.fromhex('4080ff02') and
            raw[6:10] == bytes.fromhex('488b1d42') and
            raw[20:24] == bytes.fromhex('0fb64348') and
            raw[24:27] == bytes.fromhex('4883f8') and
            raw[30:32] == bytes.fromhex('48b9') and
            raw[40:44] == bytes.fromhex('480fa3c1'), 'policy opcode changed')
    mode, bound = raw[3], raw[27]
    mask = struct.unpack_from('<Q', raw, 32)[0]
    require(mode == 2 and bound == 33 and mask == 0x2000800a1, 'policy immediate changed')
    checked_branch(raw[4:], 0x1563fcd, 0x1563ff7, 'ne')
    checked_branch(raw[28:], 0x1563fe5, 0x1564059, 'a')
    checked_branch(raw[44:], 0x1563ff5, 0x1564059, 'ae')
    return mode, bound, mask


def wants_directory(mode, tag, required_mode, bound, mask):
    require(0 <= mode <= 255 and 0 <= tag <= 255, 'mode or tag outside byte domain')
    return mode == required_mode and (tag > bound or not ((mask >> tag) & 1))


def c_string_case(raw):
    i = raw.find(b'\0')
    if i < 0:
        return 'no_zero', 1, 1, ''
    if i == len(raw) - 1:
        return 'terminal_zero', 0, '', i
    return 'interior_zero', 1, 0, i


def retry_case(success_attempt, count):
    require(count >= 0 and (success_attempt is None or success_attempt >= 1), 'invalid retry case')
    attempts = count + 1 if success_attempt is None else min(success_attempt, count + 1)
    success = success_attempt is not None and success_attempt <= count + 1
    return attempts, attempts - 1, 'success' if success else 'error_object'


def root_case(tag, mode_bits, lstat_failure=False):
    """Selected root branches, with external metadata results supplied by the caller."""
    if tag == 2:
        return 'metadata_error'
    if tag == 3 and lstat_failure:
        return 'lstat_error'
    return 'unlink' if mode_bits & 0xf000 == 0xa000 else 'tree'


def directory_case(first_tag, second_tag, mode_bits):
    if first_tag == 2 or second_tag == 2:
        return 'false'
    return 'true' if mode_bits & 0xf000 == 0x4000 else 'false'


def open_failure_case(child, errno):
    """Selected branches after openat64 returns -1; no OS call is made."""
    if errno == 4:
        return 'retry_open'
    if child and errno in (20, 40):
        return 'unlink_child'
    return 'return_error'


def entry_case(name, entry_type):
    require(0 <= entry_type <= 255, 'directory entry type outside byte domain')
    if name in (b'.', b'..'):
        return 'skip'
    return 'recurse' if entry_type in (0, 4) else 'unlink_child'


def child_result_case(raw_result):
    require(0 <= raw_result < 1 << 64, 'child result outside u64')
    if raw_result == 0 or (raw_result & 3 == 2 and raw_result >> 32 == 2):
        return 'continue'
    return 'return_error'


def close_case(result, errno):
    if result == 0 or errno == 4:
        return 'return'
    return 'diagnostic_boundary'


def template(raw, literal, second_argument=False):
    tail = b'\xc0\x00' if second_argument else b'\x00'
    expected = b'\xc0' + bytes([len(literal)]) + literal + tail
    require(raw == expected, 'format template bytes changed')
    return literal.decode('ascii')


def name_entry(image, base, index):
    require(index >= 0, 'negative name index')
    slot = base + index * 16
    ptr = image.relative(slot)
    length = struct.unpack('<Q', image.read(slot + 8, 8))[0]
    require(0 < length <= 64, 'name length out of bounds')
    text = image.read(ptr, length).decode('ascii')
    return {'index': index, 'slot': slot, 'reloc_offset': image.relocation(slot)['offset'],
            'text_va': ptr, 'length': length, 'text': text}


def time_operands(image):
    first = image.read(0x1567ad8, 6, True)
    mul = image.read(0x1567ae2, 5, True)
    shift = image.read(0x1567aeb, 4, True)
    second = image.read(0x1567af3, 6, True)
    require(first[:2] == b'\x81\xf9' and mul[0] == 0xb8 and
            shift[:3] == b'\x48\xc1\xe8' and second[:2] == b'\x81\xf9',
            'hour operand opcode changed')
    top, factor, bits, limit = (struct.unpack_from('<I', first, 2)[0],
                                struct.unpack_from('<I', mul, 1)[0], shift[3],
                                struct.unpack_from('<I', second, 2)[0])
    require((top, factor, bits, limit) == (921600, 0x91a2b3c5, 43, 90000),
            'hour operands changed')
    require(all((n * factor) >> bits == n // 3600 for n in range(limit)),
            'finite quotient check failed')
    return top, factor, bits, limit


def hour_case(n, top, factor, bits, limit):
    require(0 <= n < (1 << 32), 'hour input outside u32')
    if n >= top:
        return 'overflow_diagnostic', '', ''
    if n >= limit:
        return 'range_diagnostic', '', ''
    q = (n * factor) >> bits
    return 'normal', q, 'skip' if q < 2 else 'consider_cleanup'


def write_tsv(out, name, fields, rows):
    with (out / name).open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(fields)
        writer.writerows(rows)


def hx(x):
    return '' if x is None else hex(x)


def produce(image, out):
    selected = selected_fdes(image)
    mode, bound, mask = policy_operands(image.read(0x1563fc9, 46, True))
    top, factor, shift, limit = time_operands(image)
    require(image.relative(0x64e0918) == 0x64f06c0, 'configuration cell binding changed')

    exception_rows = []
    except_sections = [s for s in image.sections if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(except_sections) == 1, 'missing or duplicate exception table')
    except_section = except_sections[0]
    for f in selected:
        if f['lsda'] is None:
            continue
        off = image.offset(f['lsda'])
        require(except_section['offset'] <= off < except_section['offset'] + except_section['size'],
                'LSDA is outside exception table')
        parsed = exception_sites(image.blob, off, except_section['offset'] + except_section['size'],
                                 f['start'], f['end'])
        for row in parsed['rows']:
            exception_rows.append((f['role'], hx(f['lsda']), hx(row['offset']), hx(row['start']),
                                   hx(row['end']), hx(row['landing']), row['action'], row['bytes'].hex()))

    # The data table supplies names for only the relevant selected tags.
    expected = {0: 'Ec', 5: 'NodeTestnet', 7: 'NodeTestnet3',
                18: 'Ee', 19: 'SoloTestnet', 20: 'SoloMainnet',
                32: 'SoloSandbox', 33: 'NvTestnet', 34: 'NvTestnet2', 78: 'EbHlPerp'}
    names = [name_entry(image, NAME_TABLE_115, i) for i in sorted(expected)]
    require(all(row['text'] == expected[row['index']] for row in names), 'name mapping changed')
    protected = [n['index'] for n in names if n['index'] <= bound and mask & (1 << n['index'])]
    require(protected == [0, 5, 7, 19, 33] and mask.bit_count() == len(protected),
            'name policy and selected descriptors disagree')

    # Pool entries have two different shapes: one or two argument placeholders.
    pools = [
        ('historical_cham', 0x44ab69, b'/cham', False),
        ('historical_static_config', 0x4401ef, b'/static_config', False),
        ('periodic_data', 0x448b77, b'/data/', True),
        ('periodic_separator', 0x43aa84, b'/', True),
    ]
    pool_rows = []
    for label, va, literal, second_argument in pools:
        length = len(literal) + (4 if second_argument else 3)
        raw = image.read(va, length)
        text = template(raw, literal, second_argument)
        pool_rows.append((label, hx(va), hx(image.offset(va, length)), raw.hex(),
                          len(literal), text, int(second_argument)))

    leas = [
        ('data_template', 0x5a08117, 0x448b77),
        ('path_separator_template', 0x5a08192, 0x43aa84),
        ('periodic_descriptor', 0x5a080ff, 0x646e9f0),
        ('root_display_callback', 0x5a080f3, 0x37be6f0),
        ('name_display_callback', 0x5a0810b, 0x46dd7f0),
        ('prefix_display_callback', 0x5a08175, 0x59dbfb0),
        ('default_delay_start', 0x1561629, 0x467738),
        ('default_delay_end', 0x156163e, 0x467750),
        ('remove_operation', 0x156407e, 0x4659e8),
    ]
    lea_rows = []
    for label, site, target in leas:
        data = image.read(site, 7, True)
        decode_lea(data, site, target)
        lea_rows.append((label, hx(site), hx(image.offset(site, 7, True)), data.hex(), hx(target)))

    global_loads = []
    for label, site in (('caller_config_cell', 0x5a080d8), ('gate_config_cell', 0x1563fcf)):
        data = image.read(site, 7, True)
        slot = decode_rip_load(data, site, 0x64e0918)
        rel = image.relocation(slot)
        require(rel['kind'] == 8 and rel['addend'] == 0x64f06c0, 'configuration load binding changed')
        global_loads.append((label, hx(site), hx(image.offset(site, 7, True)), data.hex(),
                             hx(slot), hx(rel['offset']), hx(rel['addend'])))

    periodic_ptr = image.relative(0x646e9f0)
    periodic_len = struct.unpack('<Q', image.read(0x646e9f8, 8))[0]
    periodic = image.read(periodic_ptr, periodic_len)
    require(periodic == b'periodic_abci_states', 'periodic path descriptor changed')
    require(image.read(0x4659e8, 10) == b'remove_dir', 'operation literal changed')
    require(image.read(0x37be6f0, 14, True) == bytes.fromhex('4889f0488b7708488b57104889c7') and
            image.read(0x46dd7f0, 13, True) == bytes.fromhex('4889f0488b37488b57084889c7') and
            image.read(0x59dbfb0, 14, True) == bytes.fromhex('4889f0488b7708488b57104889c7'),
            'format argument callback changed')

    # The default count is an immediate in the selected wrapper, not an assumption.
    count_bytes = image.read(0x1561635, 9, True)
    require(count_bytes[:5] == bytes.fromhex('48c7442450') and
            struct.unpack_from('<I', count_bytes, 5)[0] == 3, 'retry count changed')
    count = struct.unpack_from('<I', count_bytes, 5)[0]
    delay_bytes = image.read(0x467738, count * 8)
    delays = struct.unpack('<' + 'd' * count, delay_bytes)
    require(delays == (0.001, 0.05, 1.0), 'default delays changed')
    short_compare = image.read(0x1561558, 7, True)
    require(short_compare[:3] == bytes.fromhex('4981ff'), 'short limit opcode changed')
    short_limit = struct.unpack_from('<I', short_compare, 3)[0]
    require(short_limit == 383, 'short length limit changed')

    # Fixed-form witnesses connect the synthetic filesystem cases below to
    # the selected branches and protect all their input constants.
    witnesses = [
        ('caller_hour_threshold', 0x5a080d0, '3c02'),
        ('caller_configuration_field', 0x5a080eb, '4983c518'),
        ('caller_first_argument', 0x5a080ef, '4c892c24'),
        ('caller_first_callback', 0x5a080fa, '4889442408'),
        ('caller_second_argument', 0x5a08106, '4889442410'),
        ('caller_second_callback', 0x5a08112, '4889442418'),
        ('caller_state_pointer', 0x5a081c7, '498b0424'),
        ('caller_mode_byte', 0x5a081cb, '0fb6b89a0b0000'),
        ('caller_gate_argument', 0x5a081d2, '488db424a0010000'),
        ('directory_mask', 0x1500b1a, 'b800f00000'),
        ('directory_mode', 0x1500b23, '3d00400000'),
        ('root_mode_mask', 0x5ca0f73, '2500f00000'),
        ('root_symlink_mode', 0x5ca0f78, '3d00a00000'),
        ('root_at_fdcwd', 0x5ca100a, '41bf9cffffff'),
        ('tree_open_flags', 0x5ca101e, 'ba00000b00'),
        ('open_errno_interrupted', 0x5ca1069, '83f804'),
        ('open_errno_loop', 0x5ca1309, '83f828'),
        ('open_errno_not_directory', 0x5ca130e, '83f814'),
        ('open_child_flag', 0x5ca131b, 'f645d001'),
        ('directory_remove_flags', 0x5ca136c, 'ba00020000'),
        ('dotdot_comparison', 0x5ca1140, '66813b2e2e'),
        ('dot_comparison', 0x5ca1180, '803b2e'),
        ('directory_type', 0x5ca1214, '83f804'),
        ('child_errno_missing', 0x5ca128b, '83f802'),
        ('closedir_errno_interrupted', 0x5caaae7, '4183fe04'),
    ]
    for label, va, expected_bytes in witnesses:
        raw = bytes.fromhex(expected_bytes)
        require(image.read(va, len(raw), True) == raw, 'filesystem witness changed: ' + label)
    stores = [
        ('caller_empty_result', 0x5a07f38, '488903', 'output_word', 'high_bit_sentinel'),
        ('entry_ref_increment', 0x5ca11e3, 'f049ff06', 'shared_word', 'atomic_increment'),
        ('entry_ref_decrement', 0x5ca12a0, 'f049ff0e', 'shared_word', 'atomic_decrement'),
        ('entry_name_clear', 0x5ca12b0, '41c6450000', 'entry_buffer_first_byte', 'zero'),
        ('error_ref_decrement', 0x5ca1380, 'f049ff0e', 'shared_word', 'atomic_decrement'),
        ('error_name_clear', 0x5ca1390, '41c6450000', 'entry_buffer_first_byte', 'zero'),
        ('stream_ref_decrement', 0x5ca13a9, 'f049ff0e', 'shared_word', 'atomic_decrement'),
        ('release_weak_decrement', 0x5c98ccf, 'f048ff4b08', 'shared_word_8', 'atomic_decrement'),
        ('release_unwind_decrement', 0x5c98d0d, 'f048ff4b08', 'shared_word_8', 'atomic_decrement'),
    ]
    for label, va, expected_bytes, _, _ in stores:
        raw = bytes.fromhex(expected_bytes)
        require(image.read(va, len(raw), True) == raw, 'store witness changed: ' + label)

    edges = []
    for label, site, target, condition in BRANCHES:
        owners = [row for row in selected if row['start'] <= site < row['end']]
        require(len(owners) == 1, 'branch has no unique selected extent')
        n, cc, dest = checked_branch(image.read(site, 6, True), site, target, condition)
        require(site + n <= owners[0]['end'] and owners[0]['start'] <= dest < owners[0]['end'],
                'branch leaves its selected FDE')
        edges.append((label, owners[0]['role'], hx(site), hx(image.offset(site, n, True)),
                      image.read(site, n, True).hex(), cc, hx(site + n), hx(dest)))

    bindings = {
        0x64e0990: (8, 0x1629690), 0x64e0f58: (8, 0x1567ad0),
        0x64e0ab8: (8, 0x1629fb0), 0x64e0aa0: (8, 0x16290d0),
        0x64df6e8: (8, 0x141e3a0), 0x64e1220: (8, 0x1563fc0),
        0x64e0928: (8, 0x1500a60), 0x64df9f0: (8, 0x5c87d50),
        0x64e0930: (8, 0x5c9c810), 0x64e0a30: (8, 0x167e030),
        0x64df720: (8, 0x167fa70), 0x64df508: (6, 'memcpy'),
        0x64e1b88: (6, 'lstat64'), 0x64e0a38: (6, 'unlink'),
        0x64ec9d0: (6, 'openat64'), 0x64dffc8: (6, '__errno_location'),
        0x64ec9d8: (6, 'fdopendir'), 0x64ec9e0: (6, 'readdir64'),
        0x64ec9e8: (6, 'unlinkat'), 0x64dfe78: (6, 'close'),
        0x64e11e8: (6, 'clock_nanosleep'),
        0x64e0b60: (8, 0x5c98ca0), 0x64ec598: (8, 0x5caaaa0),
        0x64eca48: (6, 'dirfd'), 0x64eca50: (6, 'closedir'),
    }
    for slot, (kind, value) in bindings.items():
        rel = image.relocation(slot)
        require(rel['kind'] == kind and (rel['addend'] if kind == 8 else rel['symbol']) == value,
                'relocation binding changed')
    call_rows = []
    for label, site, kind, expected_target in CALLS:
        n, target = transfer(image.read(site, 6 if kind.startswith('rip_') else 5, True),
                             site, kind, expected_target)
        rel = image.relocation(target) if kind.startswith('rip_') else None
        call_rows.append((label, hx(site), hx(image.offset(site, n, True)),
                          image.read(site, n, True).hex(), kind, hx(target),
                          '' if rel is None else rel['kind'],
                          '' if rel is None else hx(rel['offset']),
                          '' if rel is None else (hx(rel['addend']) if rel['kind'] == 8 else rel['symbol'])))

    # These two calls use a register loaded from the same dynamic slot.
    register_calls = []
    for label, load, opcode, call, call_opcode in (
        ('short_retry_sleep', 0x156167b, bytes.fromhex('4c8b3d'), 0x15616da, bytes.fromhex('41ffd7')),
        ('long_retry_sleep', 0x156184a, bytes.fromhex('4c8b35'), 0x15618a0, bytes.fromhex('41ffd6')),
    ):
        raw = image.read(load, 7, True)
        require(raw[:3] == opcode, 'sleep slot load changed')
        slot = load + 7 + struct.unpack_from('<i', raw, 3)[0]
        require(slot == 0x64e11e8 and image.read(call, len(call_opcode), True) == call_opcode,
                'sleep indirect call changed')
        rel = image.relocation(slot)
        require(rel['kind'] == 6 and rel['symbol'] == 'clock_nanosleep', 'sleep symbol changed')
        register_calls.append((label, hx(load), hx(image.offset(load, 7, True)), raw.hex(),
                               hx(call), hx(image.offset(call, len(call_opcode), True)), call_opcode.hex(),
                               hx(slot), hx(rel['offset']), rel['symbol']))

    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out, 'functions.tsv', ('role', 'start_va', 'end_va', 'size', 'file_offset',
                                     'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'sha256'),
              ((r['role'], hx(r['start']), hx(r['end']), len(r['body']), hx(r['offset']),
                hx(r['fde']), hx(r['cie']), hx(r['lsda']), r['index'],
                hashlib.sha256(r['body']).hexdigest()) for r in selected))
    write_tsv(out, 'body-bytes.tsv', ('role', 'start_va', 'file_offset', 'bytes_hex'),
              ((r['role'], hx(r['start']), hx(r['offset']), r['body'].hex()) for r in selected))
    write_tsv(out, 'branches.tsv', ('label', 'role', 'site_va', 'file_offset', 'bytes_hex',
                                    'condition', 'fallthrough_va', 'taken_va'), edges)
    write_tsv(out, 'exception-sites.tsv', ('role', 'lsda_va', 'entry_file_offset', 'start_va',
                                           'end_va', 'landing_va', 'action_offset', 'entry_bytes_hex'), exception_rows)
    write_tsv(out, 'calls.tsv', ('label', 'site_va', 'file_offset', 'bytes_hex', 'form',
                                 'direct_target_or_slot_va', 'relocation_type',
                                 'relocation_file_offset', 'resolved_target_or_symbol'), call_rows)
    write_tsv(out, 'register-calls.tsv', ('label', 'load_va', 'load_file_offset', 'load_bytes_hex', 'call_va',
                                          'call_file_offset', 'call_bytes_hex', 'slot_va',
                                          'relocation_file_offset', 'symbol'), register_calls)
    write_tsv(out, 'pool-entries.tsv', ('label', 'entry_va', 'file_offset', 'bytes_hex',
                                        'literal_length', 'literal', 'second_argument'), pool_rows)
    write_tsv(out, 'pool-references.tsv', ('label', 'site_va', 'file_offset', 'bytes_hex', 'target_va'), lea_rows)
    write_tsv(out, 'global-loads.tsv', ('label', 'site_va', 'file_offset', 'bytes_hex', 'slot_va',
                                        'relocation_file_offset', 'cell_va'), global_loads)
    write_tsv(out, 'operands.tsv', ('label', 'instruction_va', 'file_offset', 'bytes_hex'),
              ((label, hx(va), hx(image.offset(va, len(bytes.fromhex(raw)), True)),
                image.read(va, len(bytes.fromhex(raw)), True).hex())
               for label, va, raw in witnesses))
    write_tsv(out, 'state-writes.tsv', ('label', 'instruction_va', 'file_offset', 'bytes_hex', 'destination', 'effect'),
              ((label, hx(va), hx(image.offset(va, len(bytes.fromhex(raw)), True)),
                image.read(va, len(bytes.fromhex(raw)), True).hex(), destination, effect)
               for label, va, raw, destination, effect in stores))
    write_tsv(out, 'selected-names.tsv', ('index', 'slot_va', 'relocation_file_offset',
                                          'text_va', 'length', 'name', 'protected'),
              ((r['index'], hx(r['slot']), hx(r['reloc_offset']), hx(r['text_va']),
                r['length'], r['text'], int(r['index'] in protected)) for r in names))
    write_tsv(out, 'name-cases.tsv', ('mode', 'name_byte', 'selected_route'),
              ((m, tag, 'directory_predicate' if wants_directory(m, tag, mode, bound, mask) else 'release')
               for m in (1, mode) for tag in range(256)))
    write_tsv(out, 'clock-cases.tsv', ('input_word', 'outcome', 'quotient', 'caller_route'),
              ((n, *hour_case(n, top, factor, shift, limit)) for n in
               (0, 3599, 3600, 7199, 7200, 86399, 86400, 89999, 90000, 921599, 921600, 4294967295)))
    write_tsv(out, 'retry-cases.tsv', ('success_attempt_or_never', 'attempts', 'delay_count', 'result'),
              ((('never' if success is None else success), *retry_case(success, count))
               for success in (1, 2, 3, 4, None)))
    samples = (b'', b'\0', b'a', b'a\0', b'a\0b', b'a\0\0', b'a' * 15 + b'\0',
               b'a' * 16 + b'\0', b'a' * 383 + b'\0', b'a' * 384 + b'\0')
    write_tsv(out, 'zero-cases.tsv', ('input_hex', 'input_length', 'case', 'tag', 'word_8', 'first_zero'),
              ((sample.hex(), len(sample), *c_string_case(sample)) for sample in samples))
    write_tsv(out, 'root-cases.tsv', ('metadata_tag', 'mode_bits', 'lstat_failure', 'selected_route'),
              ((tag, hx(bits), int(failed), root_case(tag, bits, failed))
               for tag in (1, 2, 3) for bits in (0, 0x4000, 0x8000, 0xa000)
               for failed in (False, True)))
    write_tsv(out, 'directory-cases.tsv', ('first_tag', 'second_tag', 'mode_bits', 'predicate_result'),
              ((first, second, hx(bits), directory_case(first, second, bits))
               for first in (1, 2, 3) for second in (1, 2, 3)
               for bits in (0, 0x4000, 0x8000, 0xa000)))
    write_tsv(out, 'open-error-cases.tsv', ('child_flag', 'errno', 'selected_route'),
              ((child, errno, open_failure_case(child, errno))
               for child in (0, 1) for errno in (2, 4, 13, 20, 40, 255)))
    write_tsv(out, 'entry-cases.tsv', ('name_hex', 'type_byte', 'selected_route'),
              ((name.hex(), typ, entry_case(name, typ)) for name in (b'.', b'..', b'x') for typ in range(256)))
    child_results = (0, (2 << 32) | 2, (3 << 32) | 2, 2, 3, 0xffffffffffffffff)
    write_tsv(out, 'child-result-cases.tsv', ('raw_result', 'selected_route'),
              ((hx(value), child_result_case(value)) for value in child_results))
    write_tsv(out, 'close-cases.tsv', ('closedir_result', 'errno', 'selected_route'),
              ((result, errno, close_case(result, errno))
               for result in (0, -1) for errno in (0, 2, 4, 13)))

    summary = {
        'target': 'node115', 'binary_sha256': DIGEST_115,
        'coordinate_system': 'linked ELF virtual addresses and section-derived file offsets',
        'selected_fde_count': len(selected), 'selected_fde_bytes': sum(len(r['body']) for r in selected),
        'selected_branch_count': len(edges), 'selected_transfer_count': len(call_rows),
        'selected_lsda_call_site_count': len(exception_rows),
        'selected_register_call_count': len(register_calls),
        'selected_global_load_count': len(global_loads),
        'selected_pool_entry_count': len(pool_rows), 'selected_pool_reference_count': len(lea_rows),
        'selected_name_count': len(names), 'mode_immediate': mode, 'name_bound': bound,
        'selected_operand_count': len(witnesses), 'selected_store_count': len(stores),
        'name_mask': hx(mask), 'protected_name_indices': protected,
        'config_relocation_slot_va': hx(0x64e0918), 'config_cell_va': hx(0x64f06c0),
        'periodic_name_slot_va': hx(0x646e9f0), 'periodic_name_relocation_file_offset': hx(image.relocation(0x646e9f0)['offset']),
        'periodic_name_va': hx(periodic_ptr), 'periodic_name_length': periodic_len,
        'periodic_name': periodic.decode('ascii'), 'retry_count': count,
        'retry_delay_bits': [delay_bytes[i:i + 8].hex() for i in range(0, len(delay_bytes), 8)],
        'retry_delay_binary64_values': list(delays), 'short_path_limit': short_limit,
        'hour_comparison_limit': limit, 'hour_overflow_limit': top,
        'hour_factor': hx(factor), 'hour_shift': shift,
        'hour_exhaustive_quotient_domain_size': limit,
        'limitations': 'Selected static witnesses only; external helper behavior, runtime values, concurrent initialization, complete xrefs and Rust equivalence remain unresolved.',
    }
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def compare_historical(current, historical):
    """Optional independently authenticated comparison; no old capture is required by default."""
    old = Image(historical, DIGEST_94, SIZE_94)
    old_spec = [('old_gate', 0x13cbb80, 0x13cbcdf,
                 '1a84e63b8ff15c4e9e57d11a637328cae161f93b9730311eae24b6ce9399b49e')]
    selected_fdes(old, old_spec)
    require(old.read(0x13cbb89, 4, True) == bytes.fromhex('4080ff02') and
            old.read(0x13cbb9d, 4, True) == bytes.fromhex('0fb64348') and
            old.read(0x13cbba1, 3, True) == bytes.fromhex('4883f8') and
            old.read(0x13cbba7, 2, True) == bytes.fromhex('48b9') and
            old.read(0x13cbbb1, 4, True) == bytes.fromhex('480fa3c1'),
            'historical gate opcode changed')
    old_bound = old.read(0x13cbba4, 1, True)[0]
    old_mask = struct.unpack('<Q', old.read(0x13cbba9, 8, True))[0]
    require(old_bound == 32 and old_mask == 0x1000400a1, 'historical policy changed')
    new_mode, new_bound, new_mask = policy_operands(current.read(0x1563fc9, 46, True))
    old_indices = [i for i in range(old_bound + 1) if old_mask & (1 << i)]
    new_indices = [i for i in range(new_bound + 1) if new_mask & (1 << i)]
    old_names = [name_entry(old, NAME_TABLE_94, i) for i in old_indices]
    new_names = [name_entry(current, NAME_TABLE_115, i) for i in new_indices]
    require([r['text'] for r in old_names] == [r['text'] for r in new_names],
            'selected historical and current names disagree')
    old_neighbor = name_entry(old, NAME_TABLE_94, 33)
    new_neighbor = name_entry(current, NAME_TABLE_115, 34)
    require(old_neighbor['text'] == new_neighbor['text'] == 'NvTestnet2',
            'selected historical and current neighbor disagrees')
    for site, target, raw in ((0x164f840, 0x1fc0ec, b'/cham'),
                              (0x164fbae, 0x1ef5f5, b'/static_config')):
        decode_lea(old.read(site, 7, True), site, target)
        template(old.read(target, len(raw) + 3), raw)
    template(current.read(0x44ab69, 8), b'/cham')
    template(current.read(0x4401ef, 17), b'/static_config')
    return {
        'historical_sha256': DIGEST_94, 'current_sha256': DIGEST_115,
        'historical_gate_start_va': hx(0x13cbb80), 'current_gate_start_va': hx(0x1563fc0),
        'historical_gate_bound': old_bound, 'current_gate_bound': new_bound,
        'historical_mask': hx(old_mask), 'current_mask': hx(new_mask),
        'required_mode': new_mode,
        'protected_name_comparison': [
            {'name': x['text'], 'old_tag': x['index'], 'old_slot_va': hx(x['slot']),
             'current_tag': y['index'], 'current_slot_va': hx(y['slot'])}
            for x, y in zip(old_names, new_names)],
        'unprotected_neighbor': {'name': old_neighbor['text'],
                                 'old_tag': old_neighbor['index'], 'old_slot_va': hx(old_neighbor['slot']),
                                 'current_tag': new_neighbor['index'], 'current_slot_va': hx(new_neighbor['slot'])},
        'historical_template_refs': [
            {'literal': '/cham', 'entry_va': hx(0x1fc0ec), 'site_va': hx(0x164f840)},
            {'literal': '/static_config', 'entry_va': hx(0x1ef5f5), 'site_va': hx(0x164fbae)}],
        'current_template_entries': [
            {'literal': '/cham', 'entry_va': hx(0x44ab69)},
            {'literal': '/static_config', 'entry_va': hx(0x4401ef)}],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path, help='directory for deterministic generated evidence')
    parser.add_argument('--compare-94', type=Path, help='optional separately authenticated historical capture')
    args = parser.parse_args(argv)
    image = Image((ROOT / 'artifacts/node/115/hl-node').read_bytes())
    comparison = None
    if args.compare_94 is not None:
        comparison = compare_historical(image, args.compare_94.read_bytes())
    summary = produce(image, args.out)
    if comparison is not None:
        print(json.dumps(comparison, indent=2, sort_keys=True))
    else:
        print(json.dumps({'binary_sha256': summary['binary_sha256'],
                          'selected_fde_count': summary['selected_fde_count'],
                          'selected_branch_count': summary['selected_branch_count']}, sort_keys=True))


if __name__ == '__main__':
    main()

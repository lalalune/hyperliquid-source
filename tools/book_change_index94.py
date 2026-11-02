#!/usr/bin/env python3
"""Static, digest-bound evidence for the cancellation change-index path.

Only the selected byte patterns are decoded. This is not an x86 disassembler,
a target emulator, or a complete control-flow inventory.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# The hashes protect the entire selected FDEs. Names describe a role, not a
# recovered symbol. Half-open endpoints and hashes are checked independently.
FUNCTIONS = (
    ('outer_vacant_counterpart', 0x4959950, 0x4959abe, '6d8dab7df11f3f999ca0d81264ff52f636d963c8c7ca4e06378c58ac2fe189b5'),
    ('outer_insert_split', 0x4205930, 0x42067a7, '0cdc164ad7c140526e852c59c1d51053b7cf6a71cf4069d0926e16d35f0712c7'),
    ('inner_insert_split', 0x4223660, 0x4223f8c, '1a323ac0f945367f47d36d3489d5de386f9699b3b212c1f7bb28bbc54b7ce848'),
    ('inner_entry_counterpart', 0x33a0780, 0x33a094d, '1e8ec01b218c393d9297e26ffef41bc3a4e12b26fe860ef1e03d03369f73e510'),
    ('change_map_text_field', 0x47abcf0, 0x47abdb9, '2db04ce8abfce523d5bb4c240a249c789b1741a81dff55bbf8cb3794038827ae'),
)

# Windows in previously documented callers are context only, never additional
# selected functions. Each hash also protects context against accidental drift.
WINDOWS = (
    ('hash_miss_gate', 0x42f7a41, 0x42f7a53, '52a53a9b6de5ee5078805c1dc46970fc168dd23fa78db144e49f2d72de8db5dc'),
    ('text_field_caller', 0x46f6341, 0x46f637d, '3aa70ef0f310d57ee9883297daa252a17647b01aea5434e49f56fee8593daad6'),
    ('nested_equal', 0x33a0820, 0x33a0831, '59cc2e3f74cc599ae028960268c44749ee65b206347de2a1fc81437a9d7c5753'),
    ('nested_return', 0x33a090f, 0x33a0924, '51049045253b32cad13cf01eb9a931dab5bd61ce18b27edfafb302ec25ffd2e5'),
    ('cancel_registers', 0x42f78a1, 0x42f78bd, '4e002fccee1e0803d690e7febfac0566acb37675a99275b3e3d08e0f81f0c93d'),
    ('compare_loader', 0x42f82f3, 0x42f8316, 'b7decd2faa77c9628e30fd696c34adf2dcfe667a6ad73e4dfab7b3d12d3d971e'),
    ('nested_compare', 0x33a07e4, 0x33a0820, 'ca343191dc05b5e1fd224a676b298f9817ca31f19611237dc983508dacebb3bf'),
    ('nested_insert_counterpart', 0x33a0861, 0x33a0915, '96c265fe6a14048df1471f0989c44a5d435a63fc0e301b667919110fee906274'),
    ('untriggered_gate', 0x42f7962, 0x42f79bc, '4e4df4956c14d18ae299ce38cc305f1e031d08dc2266e3395ef802ee40f29318'),
    ('first_tracker_count', 0x42f7bf4, 0x42f7c66, '9230d0b7b19ce99b843238dbff375c489c24cfe96b2da29c571f7c8782001542'),
    ('first_tracker_vacant', 0x42f8084, 0x42f8155, 'e3d42255ecb9a6bc390dec44d47ebc0e4588576c4a15aa039285287bff909503'),
    ('tracker_search', 0x42f8316, 0x42f83c2, '0f1b7e41080d6e1bb7a546425bc3af912114d96dcdda265accdc50aac474a859'),
    ('saved_key', 0x42f7d84, 0x42f7d94, 'b89bfead728046f04c18b9d2962cb67e88f6590ecb82c4d1e8a05a5dfcec9b25'),
    ('slab_call', 0x42f7dc2, 0x42f7df4, 'b23f2168b3b3018b77b59d096540d10eb8227baa513ff0a9bcafd365dfe90d4a'),
    ('set_gate', 0x42f826a, 0x42f82aa, '3a37b1666f8c791805a3493da95114dba084e17c498f50b241dd8d669b46c65d'),
    ('tracker_count', 0x42f82aa, 0x42f8316, 'dd73a402ed96b5e4fa925867caa6be4738b47503a83e5cc7f85081a8b5246b48'),
    ('tracker_hit', 0x42f83c2, 0x42f83e3, 'fbab77259b7788820e3812ec4624a5a264df6dcc55de5c109d01a107e4b5e668'),
    ('tracker_vacant', 0x42f83e3, 0x42f84b9, '7ba03cf08622f7b2a82e8edf3deee391d95cfb127d41b0754479cdee947c7ada'),
    ('outer_entry_counterpart', 0x4959964, 0x4959a65, '000f80bc84412d016b3ea536f1cbcf515bca6cad8f6bdf4974b6de690445d884'),
    ('outer_leaf_select', 0x4205944, 0x4205b0c, 'd9ebdcfb9499a522c61f83ead2e0669a84b1114e65014c7806e7bb862656a625'),
    ('outer_copy_pivot', 0x4205b3c, 0x4205c00, '3fdfa55ce1a1d25686ae7767771d17e1d6f22354e40b57590b75f1c9c1e56e16'),
    ('outer_parent_select', 0x4205df2, 0x4205ea4, '3d1edbc8a8f0caf61aa5e911a02494f3468969665a934070b31aeccbff579053'),
    ('outer_root', 0x42062af, 0x4206340, 'c604f8c9b7dac8fb030c73f75c492a5f8a310554ed891e38524d2f6bdbaa7ba9'),
    ('inner_leaf_select', 0x4223674, 0x422375d, '14207b2ee8032c78d1a1095a2576d54754207e3e246704ce4cec0d0f8192cafb'),
    ('inner_copy_pivot', 0x422378c, 0x42237e6, '8eaecf6caf0ac10df0a6432d3e2b104f369a24f0736cda089afea85c31031aee'),
    ('inner_parent_select', 0x422388d, 0x4223944, 'f261c6f8b157ae72f815132e72b0b73f20a0424a135a69ae81dd078dd212229c'),
    ('inner_root', 0x4223bc2, 0x4223c8a, '63662b40462d4a7935b7a82968e68192d2bcac9747d83c143717daf49b2afa47'),
    ('inner_caller', 0x4935cfb, 0x4935d10, 'fa46df427ddf646a2f7c2a0cf600e3057f7ab10dbd4335cb2bbe206b955d24c7'),
    ('outer_failures', 0x42065b6, 0x42066ca, '10cab7a063801ae5db7cf307d3046f64a3a20ed31c9d967a4d3017a67028291d'),
    ('inner_failures', 0x4223e4c, 0x4223f51, 'bb7f9dd6bfab8ddbdd1ebeecbe1aa3175c6517c2e9eac6943f6facacbbc93c57'),
)

# Curated instruction starts, checked as short/near Jcc. This list is not
# inferred from searching for opcodes and is not an exhaustive x86 decoder.
BRANCH_SITES = tuple(int(s, 16) for s in '''
4959969 49599d5 4959a03
47abcfc 47abd19 47abd30 47abd52
33a0796 33a07e2 33a07e7 33a07f7 33a07fd 33a0829 33a0847 33a087c 33a08c8 33a08f4
4205958 4205972 42059a8 42059d8 42059e2 4205b1e 4205b96 4205c71
4205d99 4205dec 4205df5 4205e22 4205e32 4205e54 4205e5a 4205e9e
4205f1f 4205fe6 4205ff6 420603f 4206044 42060a5 42061ab 42061bb
42061e8 42061f1 420625f 42062c0 42062d8 42062fe 4206322 4206334
42063cc 42064d4 42064e8 4206519 4206528 420658f
4223682 422368f 4223717 4223728 422372e 422376f 42237a8 422380e
4223862 4223887 422389a 42238cb 42238da 42238f4 42238f9 422393e
422397e 42239d0 42239dc 4223a33 4223a38 4223a64 4223b02 4223b0f
4223b3b 4223b44 4223bb8 4223bd3 4223beb 4223c15 4223c38 4223c4a
4223cd4 4223d6b 4223d81 4223dad 4223dbb 4223e38
42f79b6 42f7a4d 42f7c39 42f7dee 42f82a4 42f82ea 42f82fd 42f838e 42f83aa
'''.split())
DIRECT_CALLS = (
    ('text_caller_to_field', 0x46f636f, 0x47abcf0),
    ('text_field_to_key_writer', 0x47abd10, 0x4ab04c0),
    ('text_field_to_value_writer', 0x47abd4a, 0x460e280),
    ('inner_counterpart_to_split', 0x33a08ab, 0x2f61640),
    ('outer_counterpart_to_split', 0x49599ab, 0x41fe620),
    ('outer_entry_to_split', 0x495a1cb, 0x4205930),
    ('inner_caller_to_split', 0x4935d0b, 0x4223660),
    ('cancel_to_untriggered_remove', 0x42f79a4, 0x49454a0),
    ('earlier_cancel_to_tracker_lookup', 0x42f7c28, 0x47d7ca0),
    ('cancel_to_slab_remove', 0x42f7de1, 0x42e8bf0),
    ('cancel_to_slot_set_remove', 0x42f828e, 0x4943a10),
    ('cancel_to_tracker_lookup', 0x42f82de, 0x47d7ca0),
    ('cancel_to_outer_vacant', 0x42f8486, 0x495a170),
    ('cancel_to_inner_set', 0x42f84b4, 0x4935be0),
    ('earlier_cancel_to_outer_vacant', 0x42f8122, 0x495a170),
    ('earlier_cancel_to_inner_set', 0x42f8150, 0x4935be0),
)
INDIRECT_CALLS = (
    ('inner_counterpart_allocate', 0x33a08bf), ('inner_counterpart_alloc_failure', 0x33a092e),
    ('outer_counterpart_allocate', 0x49599cc), ('outer_counterpart_alloc_failure', 0x4959a6f),
    ('outer_leaf_move', 0x4205a3b), ('outer_leaf_allocate', 0x4205b15), ('outer_leaf_copy', 0x4205bcc),
    ('outer_parent_allocate', 0x4205e95), ('outer_root_allocate', 0x42062cf),
    ('outer_bounds_failure', 0x4206650), ('outer_assertion', 0x4206601),
    ('inner_leaf_move', 0x42236c3), ('inner_leaf_allocate', 0x4223766), ('inner_leaf_copy', 0x42237d8),
    ('inner_parent_allocate', 0x4223935), ('inner_root_allocate', 0x4223be2),
    ('inner_bounds_failure', 0x4223ed9), ('inner_assertion', 0x4223e97),
)


# A subset of BRANCH_SITES whose taken edges enter structural or allocation
# failure handling. The labels describe the directly preceding machine test.
FAILURE_BRANCHES = (
    (0x47abcfc, 'nonzero formatter flag bypasses key write'),
    (0x47abd19, 'text key writer leaves assertion byte set'),
    (0x33a08c8, 'inner counterpart initial leaf allocation returned null'),
    (0x33a08f4, 'inner counterpart initial leaf count is not below capacity'),
    (0x49599d5, 'outer initial leaf allocation returned null'),
    (0x4959a03, 'outer initial leaf count is not below capacity'),
    (0x4205b1e, 'outer split leaf allocation returned null'),
    (0x4205b96, 'outer split sibling count is at least twelve'),
    (0x4205df5, 'outer split height values disagree'),
    (0x4205e9e, 'outer split internal allocation returned null'),
    (0x4205f1f, 'outer parent sibling count is at least twelve'),
    (0x4205fe6, 'outer parent edge count is out of bounds'),
    (0x4205ff6, 'outer parent edge count assertion failed'),
    (0x42062c0, 'outer old root pointer is null'),
    (0x42062d8, 'outer new root allocation returned null'),
    (0x42062fe, 'outer height increment wrapped'),
    (0x4206322, 'outer root heights disagree'),
    (0x4206334, 'outer new root count is not below capacity'),
    (0x422376f, 'inner split leaf allocation returned null'),
    (0x42237a8, 'inner split sibling count is at least twelve'),
    (0x422389a, 'inner split height values disagree'),
    (0x422393e, 'inner split internal allocation returned null'),
    (0x422397e, 'inner parent sibling count is at least twelve'),
    (0x42239d0, 'inner parent edge count is out of bounds'),
    (0x42239dc, 'inner parent edge count assertion failed'),
    (0x4223bd3, 'inner old root pointer is null'),
    (0x4223beb, 'inner new root allocation returned null'),
    (0x4223c15, 'inner height increment wrapped'),
    (0x4223c38, 'inner root heights disagree'),
    (0x4223c4a, 'inner new root count is not below capacity'),
)


class EvidenceError(ValueError):
    pass


# Each immediate is decoded only after matching its specific instruction prefix.
CONSTANT_SITES = (
    ('outer_node_key_count_offset', 0x4205947, '450fb7b5', 4, 0x1ee),
    ('outer_node_key_offset', 0x420599e, '4881c3', 4, 0x110),
    ('outer_parent_index_offset', 0x4205e01, '440fb7aa', 4, 0x1ec),
    ('outer_edges_offset', 0x42062f1, '4c89a0', 4, 0x1f0),
    ('inner_node_key_count_offset', 0x4223677, '0fb79d', 4, 0xba),
    ('inner_key_stride_shift', 0x4223694, '48c1e0', 1, 4),
    ('inner_parent_offset', 0x4223a22, '4c89b2', 4, 0xb0),
    ('inner_parent_index_offset', 0x4223a29, '66898a', 4, 0xb8),
    ('inner_edges_offset', 0x4223a1a, '498b94ce', 4, 0xc0),
    ('book_asset_offset', 0x42f82aa, '488b83', 4, 0xb0),
    ('user_slot_set_offset', 0x42f827f, '4983c5', 1, 0x20),
    ('counter_offset', 0x42f82e3, '488b48', 1, 0x20),
    ('change_map_root_offset', 0x42f82f3, '498baf', 4, 0x1320),
    ('change_map_height_offset', 0x42f8303, '498b87', 4, 0x1328),
    ('user_result_absent_tag', 0x42f79a9, '83bc24d0040000', 1, 2),
    ('slab_result_absent_tag', 0x42f7de6, '83bc24c0000000', 1, 2),
    ('formatter_map_offset', 0x46f6365, '488db3', 4, 0x1320),
    ('formatter_key_length', 0x47abd0b, 'ba', 4, 3),
    ('outer_capacity', 0x420594f, '4983fe', 1, 11),
    ('outer_position_five', 0x4205961, '4983fc', 1, 5),
    ('outer_pivot_four', 0x4205979, '41bc', 4, 4),
    ('outer_position_six', 0x42059de, '4983fc', 1, 6),
    ('outer_pivot_five', 0x42059e8, '41bc', 4, 5),
    ('outer_pivot_six', 0x4205b01, '41bc', 4, 6),
    ('outer_leaf_bytes', 0x4205b10, 'bf', 4, 0x1f0),
    ('outer_internal_bytes', 0x4205e90, 'bf', 4, 0x250),
    ('inner_capacity', 0x422367e, '4883fb', 1, 11),
    ('inner_position_five', 0x4223704, '4983ff', 1, 5),
    ('inner_pivot_four', 0x422371e, '41bf', 4, 4),
    ('inner_position_six', 0x422372a, '4983ff', 1, 6),
    ('inner_pivot_five', 0x4223730, '41bf', 4, 5),
    ('inner_pivot_six', 0x4223755, '41bf', 4, 6),
    ('inner_leaf_bytes', 0x4223761, 'bf', 4, 0xc0),
    ('inner_internal_bytes', 0x4223930, 'bf', 4, 0x120),
    ('cancel_change_tag', 0x42f84a7, 'be', 4, 1),
    ('user_compare_bytes', 0x42f8360, 'ba', 4, 20),
    ('user_key_stride', 0x42f8381, '4983c6', 1, 20),
)


def decode_immediate(raw, prefix, length, expected):
    prefix = bytes.fromhex(prefix)
    if len(raw) != len(prefix) + length or not raw.startswith(prefix) or length not in (1, 4):
        raise EvidenceError('immediate opcode mismatch')
    value = int.from_bytes(raw[len(prefix):], 'little')
    if value != expected:
        raise EvidenceError('immediate value mismatch')
    return value


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data, expected=TARGET_SHA256):
    if sha256(data) != expected:
        raise EvidenceError('target SHA-256 mismatch')


def map_va(secs, va, size, executable=False):
    if va < 0 or size <= 0:
        raise EvidenceError('invalid VA range')
    hits = [s for s in secs if s['type'] != 8 and s['size'] > 0
            and (not executable or s['flags'] & 4)
            and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise EvidenceError('VA range is not uniquely file-backed')
    s = hits[0]
    return s['offset'] + va - s['address']


def read_va(data, secs, va, size, executable=False):
    off = map_va(secs, va, size, executable)
    result = data[off:off + size]
    if len(result) != size:
        raise EvidenceError('truncated file-backed range')
    return result


def verify_window(raw, expected):
    if sha256(raw) != expected:
        raise EvidenceError('window digest mismatch')


def decode_branch(raw, site):
    if len(raw) < 2:
        raise EvidenceError('truncated branch')
    if 0x70 <= raw[0] <= 0x7f:
        size, cc = 2, raw[0] & 15
        disp = struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        size, cc = 6, raw[1] & 15
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise EvidenceError('expected x86 conditional branch')
    return {'site_va': hex(site), 'size': size, 'condition_code': cc,
            'target_va': hex(site + size + disp), 'fallthrough_va': hex(site + size),
            'raw_hex': raw[:size].hex()}


def decode_rel32(raw, site, expected):
    if len(raw) != 5 or raw[0] != 0xe8:
        raise EvidenceError('expected E8 relative call')
    target = site + 5 + struct.unpack_from('<i', raw, 1)[0]
    if target != expected:
        raise EvidenceError('relative call target mismatch')
    return target


def decode_indirect(raw, site):
    if len(raw) != 6 or raw[:2] != b'\xff\x15':
        raise EvidenceError('expected RIP-relative indirect call')
    return site + 6 + struct.unpack_from('<i', raw, 2)[0]


def decode_rip_load(raw, site):
    if len(raw) != 7 or raw[:3] != bytes.fromhex('4c8b25'):
        raise EvidenceError('expected selected RIP-relative pointer load')
    return site + 7 + struct.unpack_from('<i', raw, 3)[0]


def dynamic_symbol(data, secs, symbol_index):
    symbols = [s for s in secs if s['name'] == '.dynsym' and s['type'] == 11]
    strings = [s for s in secs if s['name'] == '.dynstr' and s['type'] == 3]
    if len(symbols) != 1 or len(strings) != 1 or symbol_index <= 0:
        raise EvidenceError('missing dynamic symbol tables')
    sym, st = symbols[0], strings[0]
    relative = symbol_index * 24
    if relative + 24 > sym['size']:
        raise EvidenceError('dynamic symbol index outside table')
    name_offset = struct.unpack_from('<I', data, sym['offset'] + relative)[0]
    if name_offset >= st['size']:
        raise EvidenceError('dynamic symbol name outside table')
    start = st['offset'] + name_offset
    end = data.find(b'\0', start, st['offset'] + st['size'])
    if end < 0:
        raise EvidenceError('unterminated dynamic symbol')
    try:
        return data[start:end].decode('ascii')
    except UnicodeDecodeError as exc:
        raise EvidenceError('invalid dynamic symbol name') from exc


LITERALS = (
    ('change_map_text_key', 0x6fa783, b'uaR'),
    ('height_assertion', 0x6ee281, b'assertion failed: edge.height == self.node.height - 1'),
    ('edge_length_assertion', 0x6ee259, b'assertion failed: src.len() == dst.len()'),
    ('capacity_assertion', 0x20ca60, b'assertion failed: idx < CAPACITY'),
)


def check_literal(raw, expected):
    if raw != expected:
        raise EvidenceError('diagnostic literal mismatch')


def decode_jump_table(raw, base, expected):
    if len(raw) != len(expected) * 4:
        raise EvidenceError('invalid jump table length')
    result = []
    for index, target in enumerate(expected):
        displacement = struct.unpack_from('<i', raw, index * 4)[0]
        actual = base + displacement
        if actual != target:
            raise EvidenceError('unexpected jump table target')
        result.append({'index': index, 'entry_va': hex(base + index * 4),
                       'raw_hex': raw[index * 4:index * 4 + 4].hex(),
                       'target_va': hex(actual)})
    return result


def parse_lsda(raw, start, end, lsda_va):
    """Decode only the omitted-LPStart, ULEB call-site format observed here.

    The returned raw span ends with the call-site table; type/action tables
    and unwind runtime effects are deliberately not interpreted.
    """
    if len(raw) < 4 or start >= end or raw[0] != 0xff or raw[1] not in (0xff, 0x9b):
        raise EvidenceError('unsupported LSDA header')
    pos = 2
    try:
        type_offset = None
        if raw[1] != 0xff:
            type_offset, pos = uleb(raw, pos, len(raw))
            if pos + type_offset > len(raw):
                raise EvidenceError('LSDA type table outside section')
        if pos >= len(raw) or raw[pos] != 1:
            raise EvidenceError('unsupported LSDA call-site encoding')
        pos += 1
        length, pos = uleb(raw, pos, len(raw))
        table_start = pos
        limit = pos + length
        if limit > len(raw):
            raise EvidenceError('truncated LSDA call-site table')
        entries = []
        previous_end = 0
        while pos < limit:
            begin = pos
            offset, pos = uleb(raw, pos, limit)
            size, pos = uleb(raw, pos, limit)
            landing, pos = uleb(raw, pos, limit)
            action, pos = uleb(raw, pos, limit)
            if offset < previous_end or offset + size > end - start:
                raise EvidenceError('LSDA range outside function or unordered')
            if landing and landing >= end - start:
                raise EvidenceError('LSDA landing pad outside function')
            previous_end = offset + size
            entries.append({'function_start_va': hex(start), 'lsda_va': hex(lsda_va),
                            'range_start_va': hex(start + offset),
                            'range_end_va': hex(start + offset + size),
                            'landing_va': hex(start + landing) if landing else None,
                            'action': action, 'record_va': hex(lsda_va + begin),
                            'raw_hex': raw[begin:pos].hex()})
        if pos != limit:
            raise EvidenceError('LSDA table did not end at its declared length')
    except EvidenceError:
        raise
    except ValueError as exc:
        raise EvidenceError('invalid LSDA ULEB') from exc
    header = {'function_start_va': hex(start), 'lsda_va': hex(lsda_va),
              'lpstart_encoding': raw[0], 'type_encoding': raw[1],
              'type_offset': type_offset, 'callsite_encoding': 1,
              'callsite_bytes': length, 'table_offset': table_start,
              'span_size': limit, 'raw_hex': raw[:limit].hex()}
    return header, entries



# The cancellation-context entry was already named by prior research; the
# independently selected counterpart is checked against it only as context.
COPY_OPERANDS = (
    (0x20, 3, 7, 0x70046c, 0x58a480),
    (0x12b, 1, 5, 0x4223660, 0x2f61640),
    (0x13f, 2, 6, 0x576dfd8, 0x576dfd8),
    (0x1ae, 2, 6, 0x576e020, 0x576e020),
    (0x1b4, 3, 7, 0x20ca60, 0x20ca60),
    (0x1bb, 3, 7, 0x571c420, 0x56d8f80),
    (0x1c7, 2, 6, 0x576e108, 0x576e108),
)


def checked_copy_target(raw, base, offset, displacement, size, expected):
    if offset < 0 or displacement < 0 or displacement + 4 > size or offset + size > len(raw):
        raise EvidenceError('invalid counterpart operand range')
    value = base + offset + size + struct.unpack_from('<i', raw, offset + displacement)[0]
    if value != expected:
        raise EvidenceError('counterpart operand target mismatch')
    return value


def compare_counterpart(original, twin):
    if len(original) != 0x1cd or len(twin) != len(original):
        raise EvidenceError('counterpart size mismatch')
    verify_window(original, '5a13feb2b8d000e853f527fb7a8d358151ec8cf601de0c12f72c8705846485d4')
    verify_window(twin, '1e8ec01b218c393d9297e26ffef41bc3a4e12b26fe860ef1e03d03369f73e510')
    masked_a, masked_b = bytearray(original), bytearray(twin)
    operands = []
    for offset, displacement, size, target_a, target_b in COPY_OPERANDS:
        actual_a = checked_copy_target(original, 0x4935be0, offset, displacement, size, target_a)
        actual_b = checked_copy_target(twin, 0x33a0780, offset, displacement, size, target_b)
        operands.append({'instruction_offset': hex(offset), 'context_target_va': hex(actual_a),
                         'counterpart_target_va': hex(actual_b),
                         'context_raw_hex': original[offset:offset + size].hex(),
                         'counterpart_raw_hex': twin[offset:offset + size].hex()})
        mask_start = offset + displacement
        masked_a[mask_start:mask_start + 4] = bytes(4)
        masked_b[mask_start:mask_start + 4] = bytes(4)
    if masked_a != masked_b:
        raise EvidenceError('counterpart differs outside selected operands')
    return {'context_start_va': '0x4935be0', 'counterpart_start_va': '0x33a0780',
            'size': len(original), 'raw_different_bytes': sum(a != b for a, b in zip(original, twin)),
            'masked_sha256': sha256(masked_a), 'mask_bytes': 4 * len(COPY_OPERANDS),
            'operands': operands}



OUTER_COPY_OPERANDS = (
    (0x5b, 1, 5, 0x4205930, 0x41fe620),
    (0x7c, 2, 6, 0x576dfd8, 0x576dfd8),
    (0x11f, 2, 6, 0x576e020, 0x576e020),
    (0x127, 3, 7, 0x20ca60, 0x20ca60),
    (0x12e, 3, 7, 0x571c420, 0x571c420),
    (0x13a, 2, 6, 0x576e108, 0x576e108),
    (0x148, 1, 5, 0x49b2bb0, 0x49b3680),
    (0x14f, 2, 6, 0x576e128, 0x576e128),
    (0x15b, 1, 5, 0x4900720, 0x4900e00),
    (0x163, 1, 5, 0x5660110, 0x5660110),
    (0x168, 2, 6, 0x576e128, 0x576e128),
)


def compare_outer_counterpart(original, twin):
    if len(original) != 0x16e or len(twin) != len(original):
        raise EvidenceError('outer counterpart size mismatch')
    verify_window(original, '93aace6a038a1419180ac99dbcbe3a07ac196c4bc15a461455b4f95a3e90f842')
    verify_window(twin, '6d8dab7df11f3f999ca0d81264ff52f636d963c8c7ca4e06378c58ac2fe189b5')
    a, b = bytearray(original), bytearray(twin)
    operands = []
    for off, displacement, size, target_a, target_b in OUTER_COPY_OPERANDS:
        ca = checked_copy_target(original, 0x495a170, off, displacement, size, target_a)
        cb = checked_copy_target(twin, 0x4959950, off, displacement, size, target_b)
        operands.append({'instruction_offset': hex(off), 'context_target_va': hex(ca),
                         'counterpart_target_va': hex(cb),
                         'context_raw_hex': original[off:off + size].hex(),
                         'counterpart_raw_hex': twin[off:off + size].hex()})
        a[off + displacement:off + displacement + 4] = bytes(4)
        b[off + displacement:off + displacement + 4] = bytes(4)
    if a != b:
        raise EvidenceError('outer counterpart differs outside selected operands')
    return {'context_start_va': '0x495a170', 'counterpart_start_va': '0x4959950',
            'size': len(original), 'raw_different_bytes': sum(x != y for x, y in zip(original, twin)),
            'masked_sha256': sha256(a), 'mask_bytes': 4 * len(OUTER_COPY_OPERANDS),
            'operands': operands}


def relocation_rows(data, secs, slots):
    result = {}
    for s in secs:
        if s['type'] != 4:
            continue
        if s['size'] % 24:
            raise EvidenceError('partial ELF64 Rela record')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            va, info, addend = struct.unpack_from('<QQq', data, off)
            if va in slots:
                if va in result:
                    raise EvidenceError('duplicate relocation slot')
                result[va] = {'slot_va': hex(va), 'section': s['name'],
                              'entry_file_offset': hex(off), 'type': info & 0xffffffff,
                              'symbol_index': info >> 32, 'addend': addend,
                              'symbol_name': dynamic_symbol(data, secs, info >> 32) if info >> 32 else '',
                              'raw_hex': data[off:off + 24].hex()}
    if set(result) != set(slots):
        raise EvidenceError('missing relocation for selected indirect call')
    return [result[x] for x in sorted(result)]


EXPECTED_RELOCATIONS = {
    0x576dfd8: (8, 0, 0x54c06b0),
    0x576dfe0: (6, 6, 0),
    0x576e020: (8, 0, 0x1345e2a),
    0x576e0e0: (6, 9, 0),
    0x576e108: (8, 0, 0x157b7f0),
    0x576e2e0: (8, 0, 0x157a6f0),
    0x576e488: (6, 12, 0),
}


def check_relocations(rows):
    found = {}
    for r in rows:
        va = int(r['slot_va'], 16)
        if va in found:
            raise EvidenceError('duplicate selected relocation')
        found[va] = (r['type'], r['symbol_index'], r['addend'])
    if found != EXPECTED_RELOCATIONS:
        raise EvidenceError('selected relocation mismatch')


def split_projection(position):
    """A synthetic full-node split under the selected static branch rules."""
    if not isinstance(position, int) or isinstance(position, bool) or not 0 <= position <= 11:
        raise ValueError('position must be an integer in 0..11')
    old = list(range(1, 23, 2))
    inserted = position * 2
    if position < 5:
        pivot, right = 4, False
    elif position == 5:
        pivot, right = 5, False
    elif position == 6:
        pivot, right = 5, True
    else:
        pivot, right = 6, True
    left, promoted, tail = old[:pivot], old[pivot], old[pivot + 1:]
    if right:
        tail.insert(position - pivot - 1, inserted)
    else:
        left.insert(position, inserted)
    return {'position': position, 'old_pivot_index': pivot,
            'insert_side': 'right' if right else 'left', 'inserted': inserted,
            'promoted': promoted, 'left': left, 'right': tail}


def route_projection(user_tag, hash_present, slab_tag, set_hit):
    """Project only the three pinned low-dword and boolean branch decisions."""
    for word in (user_tag, slab_tag):
        if type(word) is not int or not 0 <= word < 1 << 64:
            raise ValueError('tags must be unsigned 64-bit integers')
    if type(hash_present) is not bool or type(set_hit) is not bool:
        raise ValueError('presence inputs must be booleans')
    if user_tag & 0xffffffff != 2:
        return {'exit': 'user_value', 'change_mark': True, 'continues_to_unlink': False}
    if not hash_present:
        return {'exit': 'hash_absent', 'change_mark': False, 'continues_to_unlink': False}
    if slab_tag & 0xffffffff == 2:
        return {'exit': 'slab_absent', 'change_mark': False, 'continues_to_unlink': False}
    return {'exit': 'set_hit' if set_hit else 'set_miss',
            'change_mark': set_hit, 'continues_to_unlink': True}


def csv_bytes(rows, fields):
    stream = io.StringIO(newline='')
    w = csv.DictWriter(stream, fieldnames=fields, delimiter='\t', lineterminator='\n', extrasaction='raise')
    w.writeheader()
    w.writerows(rows)
    return stream.getvalue().encode('utf-8')


def checked_fde(by_start, indexed, start, end):
    candidates = by_start.get(start, [])
    if len(candidates) != 1 or candidates[0]['end'] != end:
        raise EvidenceError('unexpected FDE extent')
    f = candidates[0]
    if indexed.get(start) != f['fde']:
        raise EvidenceError('unwind header does not index selected FDE')
    return f


def collect(data):
    authenticate(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {}
    for f in fdes:
        by_start.setdefault(f['start'], []).append(f)
    indexed = {row['start']: row['fde'] for row in index}
    funcs = []
    for name, start, end, digest in FUNCTIONS:
        f = checked_fde(by_start, indexed, start, end)
        raw = read_va(data, secs, start, end-start, executable=True)
        verify_window(raw, digest)
        funcs.append({'role': name, 'start_va': hex(start), 'end_va': hex(end),
                      'file_offset': hex(map_va(secs, start, end-start, True)),
                      'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']),
                      'lsda_va': hex(f['lsda']) if f['lsda'] is not None else None,
                      'size': len(raw), 'sha256': sha256(raw), 'raw_hex': raw.hex()})
    except_sections = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(except_sections) != 1:
        raise EvidenceError('missing or ambiguous exception table')
    exception_sec = except_sections[0]
    lsda_headers, lsda_entries = [], []
    for f in funcs:
        if f['lsda_va'] is None:
            continue
        lsda_va = int(f['lsda_va'], 16)
        section_end = exception_sec['address'] + exception_sec['size']
        if not exception_sec['address'] <= lsda_va < section_end:
            raise EvidenceError('LSDA outside exception table')
        offset = map_va(secs, lsda_va, 1)
        raw = data[offset:exception_sec['offset'] + exception_sec['size']]
        header, entries = parse_lsda(raw, int(f['start_va'], 16), int(f['end_va'], 16), lsda_va)
        header['file_offset'] = hex(offset)
        for row in entries:
            row['record_file_offset'] = hex(map_va(secs, int(row['record_va'], 16), len(bytes.fromhex(row['raw_hex']))))
        lsda_headers.append(header)
        lsda_entries.extend(entries)
    windows = []
    for name, start, end, digest in WINDOWS:
        raw = read_va(data, secs, start, end-start, executable=True)
        verify_window(raw, digest)
        windows.append({'label': name, 'start_va': hex(start), 'end_va': hex(end),
                        'file_offset': hex(map_va(secs, start, end-start, True)),
                        'size': len(raw), 'sha256': sha256(raw), 'raw_hex': raw.hex()})
    branches = []
    for site in BRANCH_SITES:
        row = decode_branch(read_va(data, secs, site, 6, executable=True), site)
        row['file_offset'] = hex(map_va(secs, site, row['size'], True))
        branches.append(row)
    branches_by_site = {int(r['site_va'], 16): r for r in branches}
    failures = []
    for site, predicate in FAILURE_BRANCHES:
        row = branches_by_site[site]
        failures.append({'site_va': row['site_va'], 'target_va': row['target_va'],
                         'raw_hex': row['raw_hex'], 'predicate': predicate})
    calls = []
    for label, site, expected in DIRECT_CALLS:
        raw = read_va(data, secs, site, 5, executable=True)
        target = decode_rel32(raw, site, expected)
        calls.append({'label': label, 'site_va': hex(site),
                      'file_offset': hex(map_va(secs, site, 5, True)),
                      'target_va': hex(target), 'raw_hex': raw.hex()})
    indirect = []
    for label, site in INDIRECT_CALLS:
        raw = read_va(data, secs, site, 6, executable=True)
        slot = decode_indirect(raw, site)
        indirect.append({'label': label, 'site_va': hex(site),
                         'file_offset': hex(map_va(secs, site, 6, True)),
                         'slot_va': hex(slot), 'raw_hex': raw.hex()})
    constants = []
    for label, site, prefix, size, expected in CONSTANT_SITES:
        raw = read_va(data, secs, site, len(bytes.fromhex(prefix)) + size, executable=True)
        value = decode_immediate(raw, prefix, size, expected)
        constants.append({'label': label, 'site_va': hex(site),
                          'file_offset': hex(map_va(secs, site, len(raw), True)),
                          'value': value, 'raw_hex': raw.hex()})
    literals = []
    for label, site, expected in LITERALS:
        raw = read_va(data, secs, site, len(expected))
        check_literal(raw, expected)
        literals.append({'label': label, 'site_va': hex(site),
                         'file_offset': hex(map_va(secs, site, len(raw))),
                         'size': len(raw), 'text': raw.decode('ascii'), 'raw_hex': raw.hex()})
    jump_table = []
    for owner, table_base, target in (('cancel_context', 0x70046c, 0x4935c71),
                                       ('counterpart', 0x58a480, 0x33a0811)):
        table_raw = read_va(data, secs, table_base, 16)
        rows = decode_jump_table(table_raw, table_base, (target,) * 4)
        for row in rows:
            row['owner'] = owner
            row['file_offset'] = hex(map_va(secs, int(row['entry_va'], 16), 4))
        jump_table.extend(rows)
    original = read_va(data, secs, 0x4935be0, 0x1cd, executable=True)
    counterpart = read_va(data, secs, 0x33a0780, 0x1cd, executable=True)
    comparison = compare_counterpart(original, counterpart)
    outer_original = read_va(data, secs, 0x495a170, 0x16e, executable=True)
    outer_twin = read_va(data, secs, 0x4959950, 0x16e, executable=True)
    outer_comparison = compare_outer_counterpart(outer_original, outer_twin)
    load_site = 0x42f830f
    load_raw = read_va(data, secs, load_site, 7, executable=True)
    load_slot = decode_rip_load(load_raw, load_site)
    rip_loads = [{'label': 'user_key_compare_load', 'site_va': hex(load_site),
                  'file_offset': hex(map_va(secs, load_site, 7, True)),
                  'slot_va': hex(load_slot), 'raw_hex': load_raw.hex()}]
    slots = {int(r['slot_va'], 16) for r in indirect + rip_loads}
    relocs = relocation_rows(data, secs, slots)
    check_relocations(relocs)
    route_inputs = (
        ('user_value', 0, False, 2, False),
        ('user_value_ignores_hash', 1, True, 2, False),
        ('user_high_bits_are_ignored', 0x100000002, False, 0, True),
        ('hash_absent', 2, False, 0, True),
        ('slab_absent', 2, True, 2, True),
        ('slab_high_bits_are_ignored', 2, True, 0x100000002, True),
        ('slot_set_miss', 2, True, 0, False),
        ('slot_set_hit', 2, True, 0, True),
        ('slot_non_two_tag', 2, True, 0xffffffff, True),
    )
    routes = []
    for label, user_tag, present, slab_tag, hit in route_inputs:
        routes.append({'case': label, 'user_tag': hex(user_tag), 'hash_present': present,
                       'slab_tag': hex(slab_tag), 'set_hit': hit,
                       **route_projection(user_tag, present, slab_tag, hit)})
    projections = []
    for structure in ('outer_user_map', 'inner_tagged_set'):
        for position in range(12):
            row = split_projection(position)
            projections.append({'structure': structure, **row})
    return {'target_sha256': TARGET_SHA256, 'coordinate_system': 'linked ELF virtual address',
            'functions': funcs, 'lsda_headers': lsda_headers, 'lsda_entries': lsda_entries, 'windows': windows, 'branches': branches, 'failure_branches': failures,
            'direct_calls': calls, 'indirect_calls': indirect, 'rip_loads': rip_loads, 'jump_table': jump_table, 'counterpart_comparison': comparison, 'outer_counterpart_comparison': outer_comparison, 'literals': literals, 'relocations': relocs, 'constants': constants,
            'synthetic_split_cases': projections, 'synthetic_route_cases': routes}


def emit(out, evidence):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    outputs = (
        ('lsda-headers.tsv', evidence['lsda_headers'], ('function_start_va','lsda_va','file_offset','lpstart_encoding','type_encoding','type_offset','callsite_encoding','callsite_bytes','table_offset','span_size','raw_hex')),
        ('lsda-call-sites.tsv', evidence['lsda_entries'], ('function_start_va','lsda_va','record_va','record_file_offset','range_start_va','range_end_va','landing_va','action','raw_hex')),
        ('constants.tsv', evidence['constants'], ('label','site_va','file_offset','value','raw_hex')),
        ('functions.tsv', evidence['functions'], ('role','start_va','end_va','file_offset','fde_va','cie_va','lsda_va','size','sha256','raw_hex')),
        ('windows.tsv', evidence['windows'], ('label','start_va','end_va','file_offset','size','sha256','raw_hex')),
        ('failure-edges.tsv', evidence['failure_branches'], ('site_va','target_va','raw_hex','predicate')),
        ('branches.tsv', evidence['branches'], ('site_va','file_offset','size','condition_code','target_va','fallthrough_va','raw_hex')),
        ('calls.tsv', evidence['direct_calls'], ('label','site_va','file_offset','target_va','raw_hex')),
        ('indirect-calls.tsv', evidence['indirect_calls'], ('label','site_va','file_offset','slot_va','raw_hex')),
        ('literals.tsv', evidence['literals'], ('label','site_va','file_offset','size','text','raw_hex')),
        ('synthetic-routes.tsv', evidence['synthetic_route_cases'], ('case','user_tag','hash_present','slab_tag','set_hit','exit','change_mark','continues_to_unlink')),
        ('outer-copy-operands.tsv', evidence['outer_counterpart_comparison']['operands'], ('instruction_offset','context_target_va','counterpart_target_va','context_raw_hex','counterpart_raw_hex')),
        ('copy-operands.tsv', evidence['counterpart_comparison']['operands'], ('instruction_offset','context_target_va','counterpart_target_va','context_raw_hex','counterpart_raw_hex')),
        ('jump-table.tsv', evidence['jump_table'], ('owner','index','entry_va','file_offset','raw_hex','target_va')),
        ('rip-loads.tsv', evidence['rip_loads'], ('label','site_va','file_offset','slot_va','raw_hex')),
        ('relocations.tsv', evidence['relocations'], ('slot_va','section','entry_file_offset','type','symbol_index','symbol_name','addend','raw_hex')),
    )
    for name, rows, fields in outputs:
        (out / name).write_bytes(csv_bytes(rows, fields))
    split_rows = [{**r, 'left': ','.join(map(str, r['left'])),
                   'right': ','.join(map(str, r['right']))}
                  for r in evidence['synthetic_split_cases']]
    fields = ('structure','position','old_pivot_index','insert_side','inserted','promoted','left','right')
    (out / 'synthetic-splits.tsv').write_bytes(csv_bytes(split_rows, fields))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    emit(args.out, collect(TARGET.read_bytes()))


if __name__ == '__main__':
    main()

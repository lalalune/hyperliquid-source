#!/usr/bin/env python3
"""Extract selected node-115 return-data and output-action evidence offline."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
LEGACY = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = [
    ('shared_output_drop', 0x161bc50, 0x161bcda, '2689355908f9c2ec878dcbd04ab756146fc32574d2d76c1f5de2b668722e4f18'),
    ('shared_output_clone', 0x161bcf0, 0x161bd1b, '73fe82a1f116c2d385d2029b24be6960bbaa4c814f1db6325407ad84736d6998'),
    ('output_promote_shared', 0x161bec0, 0x161bfe8, 'cfe55f7607a296086dabdf9600f48e0e658a3224aafc229a231bfb105eb7ea7c'),
    ('odd_output_drop', 0x161c3f0, 0x161c4ba, '7afa043f7f6df0d121355d05a6836f8ad73c120160a5baa7dd6e64b81e960490'),
    ('even_output_drop', 0x161c4c0, 0x161c5a1, '19a7ab5d2abd44645f031695058d825c262b16466a8b01501b73d99bbbae2ec1'),
    ('odd_output_clone', 0x161c5d0, 0x161c617, '186f16eb4186072d0a7c8115793e243da6313996bb57b93ee158cb8d6c5f048c'),
    ('even_output_clone', 0x161c620, 0x161c66b, '534272f52eae036f83600ff72bee8ecf53451764f7db765bab92c3a1a44aaf4a'),
    ('memory_load', 0x2997410, 0x2997548, 'bcebd39dea45e4a3cd733cbdbc6401e147c6207e5c2e2cd2827c17330b1e0528'),
    ('memory_store', 0x29975b0, 0x29976dc, '734e45d02b0902e1eb008fa3fe9b5b6b8d4573a28359f9b127d75887dc4d1737'),
    ('memory_store_byte', 0x29976e0, 0x29977d4, '657699eb74c043b2fcbc39f68018bc86334d02f381e8d08b558d81ac4a14ada6'),
    ('return_data_copy', 0x2997bd0, 0x2997e58, '32ac0172ddfdd14c81ed7e37cf57a5cc41cf154a6aeaea0c4b8ddf2a192b8bdf'),
    ('return_data_size', 0x2997e60, 0x2997eac, '82c793a0d6c25f9db5ba0f70c5182abbbf8541af9d20947a86cb3ca23dbf78df'),
    ('output_action_builder', 0x29990c0, 0x29994e1, '2ae361d030a8740f8bfabb0a8a88d3581db802953356aa4975216faea5bbfdf9'),
    ('return_opcode', 0x2999560, 0x2999571, '2a16cb877925973e8c649aec5be5c748cbd3a45023660dfb651f321d4d13dd55'),
    ('revert_opcode', 0x29996d0, 0x29996ed, '4542518b5c47936ca91b756fd6c0d2880fad1f717d5564caabb110a9e06bbb26'),
    ('old_action_type1_drop', 0x29e15d0, 0x29e1654, '7b648652b39f299b18185db51b9f03f8f223f7ff2ef26ff2cf2ca2c79c62906d'),
]
# The table is a dependency established by earlier node-115 research. These
# entries are resolved independently from the file's RELA records.
OPCODES = [(0x3d, 'return_data_size', 0x2997e60),
           (0x3e, 'return_data_copy', 0x2997bd0),
           (0x51, 'memory_load', 0x2997410),
           (0x52, 'memory_store', 0x29975b0),
           (0x53, 'memory_store_byte', 0x29976e0),
           (0xf3, 'return_opcode', 0x2999560),
           (0xfd, 'revert_opcode', 0x29996d0)]
TABLE = 0x6441f00
WINDOWS = [
    ('shared_output_drop_normal',0x161bc50,0x161bc98),
    ('shared_output_drop_failure',0x161bc98,0x161bcda),
    ('shared_output_clone',0x161bcf0,0x161bd1b),
    ('output_promotion_allocate_and_cas',0x161bec0,0x161bf4f),
    ('output_promotion_cas_loser_and_failure',0x161bf4f,0x161bfa4),
    ('output_promotion_unwind',0x161bfa4,0x161bfe8),
    ('odd_output_drop_normal',0x161c3f0,0x161c446),
    ('odd_output_drop_failure',0x161c446,0x161c4ba),
    ('even_output_drop_normal',0x161c4c0,0x161c52d),
    ('even_output_drop_failure',0x161c52d,0x161c5a1),
    ('odd_output_clone',0x161c5d0,0x161c617),
    ('even_output_clone',0x161c620,0x161c66b),
    ('load_stack_and_width', 0x2997419, 0x2997448),
    ('load_big_endian_word', 0x2997475, 0x29974d9),
    ('store_stack_and_width', 0x29975bb, 0x2997611),
    ('store_big_endian_word', 0x299763e, 0x299767f),
    ('store_byte_stack_and_width', 0x29976e4, 0x299772c),
    ('store_byte_write', 0x2997758, 0x299777e),
    ('copy_revision_and_stack_gate', 0x2997bdb, 0x2997bf8),
    ('copy_stack_words_and_wide_size', 0x2997bf8, 0x2997c55),
    ('copy_source_clamp_and_bound', 0x2997c55, 0x2997c82),
    ('copy_word_charge', 0x2997c82, 0x2997cbe),
    ('copy_zero_and_destination_gate', 0x2997cbe, 0x2997cd5),
    ('copy_expansion_decision', 0x2997cd5, 0x2997d05),
    ('copy_memory_and_cleanup', 0x2997d05, 0x2997da6),
    ('copy_errors_and_expansion', 0x2997db5, 0x2997e07),
    ('copy_range_failures_and_unwind', 0x2997e07, 0x2997e58),
    ('size_revision_and_capacity', 0x2997e60, 0x2997e75),
    ('size_length_and_stack_push', 0x2997e75, 0x2997eac),
    ('action_stack_and_size_gate', 0x29990d1, 0x2999130),
    ('action_zero_and_offset_gate', 0x2999145, 0x2999162),
    ('action_memory_expansion_decision', 0x2999162, 0x299919e),
    ('action_allocation_and_copy', 0x299919e, 0x2999256),
    ('action_replace_and_status', 0x2999256, 0x299934b),
    ('action_old_tag_zero_dispatch', 0x299935d, 0x29993aa),
    ('action_errors_and_expansion', 0x29993aa, 0x29993f0),
    ('action_landing_publication', 0x2999439, 0x299948b),
    ('return_tag_and_tailcall', 0x2999560, 0x2999571),
    ('revert_revision_tag_and_tailcall', 0x29996d0, 0x29996ed),
    ('old_action_drop_normal', 0x29e15d0, 0x29e161a),
    ('old_action_drop_unwind', 0x29e161a, 0x29e1654),
]
# This is a curated edge set, not a linear disassembler or complete CFG.
EDGES = [
    ('shared_drop_nonfinal',0x161bc5c,0x161bc90), ('shared_drop_bad_length',0x161bc69,0x161bc98),
    ('shared_drop_resume',0x161bcd5,0x63f0a50), ('shared_clone_overflow',0x161bcf8,0x161bd14),
    ('promote_span_overflow',0x161bee1,0x161bfa4), ('promote_alloc_null',0x161bf01,0x161bf8a),
    ('promote_compare_exchange_lost',0x161bf28,0x161bf4f), ('promote_ref_overflow',0x161bf54,0x161bf9c),
    ('promote_cleanup_resume',0x161bfc7,0x63f0a50), ('promote_original_resume',0x161bfdd,0x63f0a50),
    ('odd_drop_tag',0x161c3fa,0x161c422), ('odd_drop_nonfinal',0x161c401,0x161c43e),
    ('odd_drop_bad_length',0x161c40e,0x161c478), ('odd_drop_size_carry',0x161c428,0x161c446),
    ('odd_drop_size_sign',0x161c42a,0x161c453), ('odd_drop_resume',0x161c4b5,0x63f0a50),
    ('even_drop_tag',0x161c4ca,0x161c505), ('even_drop_nonfinal',0x161c4d1,0x161c525),
    ('even_drop_bad_length',0x161c4de,0x161c55f), ('even_drop_size_carry',0x161c50f,0x161c52d),
    ('even_drop_size_sign',0x161c511,0x161c53a), ('even_drop_resume',0x161c59c,0x63f0a50),
    ('odd_clone_tag',0x161c5dd,0x161c601), ('odd_clone_overflow',0x161c5e4,0x161c611),
    ('odd_clone_promote',0x161c607,0x161bec0), ('even_clone_tag',0x161c62d,0x161c651),
    ('even_clone_overflow',0x161c634,0x161c665), ('even_clone_promote',0x161c65b,0x161bec0),
    ('load_empty_stack',0x2997420,0x29974e3), ('load_wide_offset',0x299743d,0x29974e7),
    ('load_expand',0x2997473,0x29974eb), ('load_memory_carry',0x2997479,0x2997517),
    ('load_grow_error',0x2997510,0x29974d9),
    ('store_stack',0x29975c5,0x299767f), ('store_wide_offset',0x299760f,0x299768e),
    ('store_expand',0x299763c,0x2997692), ('store_grow_error',0x29976b4,0x299767f),
    ('byte_stack',0x29976ee,0x299777e), ('byte_wide_offset',0x299772a,0x2997783),
    ('byte_expand',0x2997756,0x299778a), ('byte_grow_error',0x29977ac,0x299777e),
    ('copy_revision',0x2997be2,0x2997db5), ('copy_stack',0x2997bf2,0x2997da6),
    ('copy_wide_size',0x2997c4f,0x2997da6), ('copy_source_bound',0x2997c7c,0x2997da6),
    ('copy_charge_product_overflow',0x2997ca1,0x2997db9), ('copy_gas_underflow',0x2997cb1,0x2997dd0),
    ('copy_zero_size',0x2997cc1,0x2997d73), ('copy_wide_destination',0x2997ccf,0x2997da6),
    ('copy_expand',0x2997cff,0x2997dd4), ('copy_zero_fill_path',0x2997d26,0x2997d77),
    ('copy_source_end_carry',0x2997d32,0x2997e1a), ('copy_prefix_end_carry',0x2997d48,0x2997e30),
    ('copy_destination_end_carry',0x2997d61,0x2997e39), ('copy_dest_bound',0x2997d8d,0x2997e07),
    ('copy_overflow_charge_can_pass',0x2997dca,0x2997cb7), ('copy_grow_error',0x2997df6,0x2997da6),
    ('copy_grow_success',0x2997e02,0x2997d05), ('copy_unwind',0x2997e53,0x63f0a50),
    ('size_revision',0x2997e67,0x2997ea6), ('size_stack_full',0x2997e73,0x2997ea9),
    ('action_stack',0x29990db,0x299934b), ('action_wide_size',0x299912a,0x29993aa),
    ('action_zero_size',0x2999150,0x2999256), ('action_wide_offset',0x299915c,0x29993ae),
    ('action_expand',0x299918c,0x29993ba), ('action_end_carry',0x2999198,0x29993f0),
    ('action_start_base_carry',0x29991ad,0x29993ff), ('action_end_base_carry',0x29991b6,0x2999408),
    ('action_size_sign',0x29991bf,0x29991d6), ('action_alloc_failure',0x29991ea,0x2999417),
    ('action_old_tag_empty',0x29992cd,0x29992f6), ('action_old_tag_zero',0x29992d1,0x299935d),
    ('action_grow_success',0x29993cc,0x2999192), ('action_unwind',0x2999486,0x63f0a50),
    ('action_old_value_zero',0x2999367,0x29992f6), ('action_old_type_other',0x2999373,0x2999382),
    ('action_old_type1_drop',0x2999378,0x29e15d0),
    ('action_old_type1_complete',0x299937d,0x29992f6), ('action_old_other_complete',0x29993a5,0x29992f6),
    ('return_tail',0x299956c,0x29990c0), ('revert_revision',0x29996d7,0x29996ea),
    ('revert_tail',0x29996e5,0x29990c0),
    ('drop_no_inner_callback',0x29e15de,0x29e15ef), ('drop_reference_nonzero',0x29e15f7,0x29e1603),
    ('drop_unwind_reference_nonzero',0x29e162a,0x29e1636), ('drop_unwind_resume',0x29e1649,0x63f0a50),
]
CHECKS = [
    (0x2997bdb, '80bfa901000004'), (0x2997bec, 'b02c'),
    (0x2997c4d, 'b024'), (0x2997c70, '4c8b8760010000b02e'),
    (0x2997c96, '488b965002000048f76228'), (0x2997cbe, '4885db0f84ac000000'),
    (0x2997dd0, 'b020'), (0x2997e60, '80bfa901000004'),
    (0x2997e6d, '483d00040000'), (0x2997ea6, 'b02bc3b02dc3'),
    (0x2999567, 'ba02000000'), (0x29996e0, 'ba10000000'),
    (0x2999208, '4883cb0140f6c501480f45dd'),
    (0x299923a, '4c896c240848896c24104c8964241848895c2420'),
    (0x161bf11, '48c7401002000000'), (0x161bf23, 'f0480fb119'),
    (0x299771c, '420fb62c08'), (0x2997774, '42882c30'),
    (0x29990d5, 'b02c'), (0x29993aa, 'b024'), (0x29993ae, '40b524'),
    (0x2999370, '83f801'),
    (0x29992bb, '41c6864901000000'), (0x2999342, '4188ae10010000'),
]
RIP_SITES = [
    ('copy_memcpy',0x2997d58,0x64df508), ('copy_memset',0x2997d9a,0x64df750),
    ('copy_expand',0x2997dee,0x64e6de0), ('copy_panic',0x2997e40,0x64df520),
    ('load_expand',0x2997505,0x64e6de0), ('store_expand',0x29976a9,0x64e6de0),
    ('store_byte_expand',0x29977a1,0x64e6de0), ('action_expand',0x29993c4,0x64e6de0),
    ('action_allocate',0x29991e1,0x64df480), ('action_memcpy',0x29991ff,0x64df508),
    ('action_free',0x299939f,0x64df4a0),
    ('drop_last_reference',0x29e15fd,0x64e4fa8), ('drop_free_tail',0x29e1614,0x64df4a0),
    ('drop_unwind_last_reference',0x29e1630,0x64e4fa8), ('drop_unwind_free',0x29e1640,0x64df4a0),
    ('promotion_allocate',0x161bef8,0x64df480), ('promotion_free_tail',0x161bf84,0x64df4a0),
    ('promotion_allocation_error',0x161bf94,0x64df490), ('promotion_ref_error',0x161bf9c,0x64e1ac0),
    ('promotion_span_error',0x161bfab,0x64df520), ('promotion_unwind_free',0x161bfbe,0x64df4a0),
    ('odd_output_free',0x161c415,0x64df4a0), ('odd_output_free_tail',0x161c438,0x64df4a0),
    ('even_output_free_tail',0x161c51f,0x64df4a0), ('shared_output_unwind_free',0x161bccc,0x64df4a0),
]
SOURCE_SITES = [('action_end_carry',0x29993f0,0x643e110),
                ('action_start_base_carry',0x29993ff,0x64bfc68),
                ('action_end_base_carry',0x2999408,0x64bfc80)]


def digest(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('input SHA-256 mismatch')


U64_MAX = (1 << 64) - 1
U256_MAX = (1 << 256) - 1


def copy_gate(constants, revision, stack_count, destination, source, size, buffer_length, gas, word_price):
    """Synthetic projection through the copy's pre-expansion gates only.

    The dispatcher charge precedes this function. This does not simulate the
    memory growth helper, buffer ownership, machine instructions or the node.
    """
    fields = (destination, source, size)
    if (any(type(x) is not int or not 0 <= x <= U256_MAX for x in fields)
            or any(type(x) is not int or not 0 <= x <= U64_MAX
                   for x in (buffer_length, gas, word_price))
            or type(revision) is not int or not 0 <= revision <= 255
            or type(stack_count) is not int or not 0 <= stack_count <= 1024):
        raise ValueError('model input outside bounded domain')
    if revision < constants['revision_minimum']:
        return constants['copy_error_revision'], stack_count, gas, 'revision'
    if stack_count < 3:
        return constants['copy_error_stack'], stack_count, gas, 'stack'
    stack_count -= 3
    if size > U64_MAX:
        return constants['copy_error_wide'], stack_count, gas, 'size'
    source64 = min(source, U64_MAX)
    source_end = min(source64 + size, U64_MAX)
    if source_end > buffer_length:
        return constants['copy_error_source_bounds'], stack_count, gas, 'source'
    words = (size >> 5) + bool(size & 31)
    charge = min(words * word_price, U64_MAX)
    if gas < charge:
        return constants['copy_error_insufficient_gas'], stack_count, gas, 'charge'
    gas -= charge
    if not size:
        return 0, stack_count, gas, 'empty'
    if destination > U64_MAX:
        return constants['copy_error_wide'], stack_count, gas, 'destination'
    return 0, stack_count, gas, 'memory-boundary'


def action_gate(constants, stack_count, offset, size, status, growth_status=0):
    """Synthetic pre-allocation projection for RETURN and REVERT."""
    if (type(stack_count) is not int or not 0 <= stack_count <= 1024
            or any(type(x) is not int or not 0 <= x <= U256_MAX for x in (offset,size))
            or type(growth_status) is not int or not 0 <= growth_status <= 255
            or type(status) is not int
            or status not in (constants['return_status'],constants['revert_status'])):
        raise ValueError('model input outside bounded domain')
    if stack_count < 2:
        return constants['copy_error_stack'], stack_count, 'stack'
    stack_count -= 2
    if size > U64_MAX:
        return constants['copy_error_wide'], stack_count, 'size'
    if size == 0:
        return status, stack_count, 'empty-action'
    if offset > U64_MAX:
        return constants['copy_error_wide'], stack_count, 'offset'
    if growth_status:
        return growth_status, stack_count, 'growth-boundary'
    return status, stack_count, 'allocation-boundary'


def section_named(sec, name):
    rows = [s for s in sec if s['name'] == name and s['type'] != 8]
    if len(rows) != 1:
        raise ValueError('missing, ambiguous or NOBITS section: ' + name)
    return rows[0]


def file_offset(sec, va, length, executable=False):
    if type(va) is not int or type(length) is not int or va < 0 or length <= 0:
        raise ValueError('invalid address or length')
    matches = [s for s in sec if s['type'] != 8 and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address is unmapped, ambiguous or not file-backed')
    s = matches[0]
    return s, s['offset'] + va - s['address']


def read_va(data, sec, va, length, executable=False):
    _, off = file_offset(sec, va, length, executable)
    if off < 0 or off + length > len(data):
        raise ValueError('file-backed range is truncated')
    return data[off:off + length]


def checked_bytes(data, sec, va, expected, executable=True):
    raw = read_va(data, sec, va, len(expected), executable)
    if raw != expected:
        raise ValueError('instruction shape mismatch at ' + hex(va))
    return raw


def read_record(data, sec, va):
    frame = section_named(sec, '.eh_frame')
    if not frame['address'] <= va < frame['address'] + frame['size']:
        raise ValueError('unwind record outside section')
    length = struct.unpack('<I', read_va(data, sec, va, 4))[0]
    if length in (0, 0xffffffff) or length + 4 > frame['size']:
        raise ValueError('invalid unwind record length')
    return read_va(data, sec, va, length + 4)


def selected_fdes(data, sec):
    _, index = unwind_index(data)
    cies, fdes = eh_frame_records(data, sec)
    starts = {item[1] for item in FUNCTIONS}
    found = [f for f in fdes if f['start'] in starts]
    table = {x['start']: x for x in index if x['start'] in starts}
    if len(found) != len(starts) or len(table) != len(starts):
        raise ValueError('missing or duplicate selected FDE')
    bystart = {f['start']: f for f in found}
    if len(bystart) != len(starts):
        raise ValueError('duplicate selected FDE start')
    rows = []
    for label, start, end, expected_hash in FUNCTIONS:
        f = bystart[start]
        if f['end'] != end or table[start]['fde'] != f['fde']:
            raise ValueError('selected FDE extent or header differs')
        body = read_va(data, sec, start, end-start, True)
        if hashlib.sha256(body).hexdigest() != expected_hash:
            raise ValueError('selected body SHA-256 mismatch')
        section, offset = file_offset(sec, start, len(body), True)
        cie = cies[f['cie']]
        rows.append({'label':label, 'start_va':hex(start), 'end_va_exclusive':hex(end),
                     'size':len(body), 'file_offset':hex(offset), 'section':section['name'],
                     'sha256':hashlib.sha256(body).hexdigest(), 'raw_bytes':body.hex(),
                     'fde_va':hex(f['fde']), 'fde_raw':read_record(data,sec,f['fde']).hex(),
                     'cie_va':hex(f['cie']), 'cie_raw':read_record(data,sec,f['cie']).hex(),
                     'cie_augmentation':cie['augmentation'],
                     'lsda_va':None if f['lsda'] is None else hex(f['lsda']),
                     'unwind_index':table[start]['index']})
    return rows, bystart


def relocations(data, sec, wanted):
    rela = section_named(sec, '.rela.dyn')
    if rela['size'] % 24:
        raise ValueError('malformed RELA section')
    found = {}
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', data, off)
        if address in wanted:
            if address in found:
                raise ValueError('duplicate selected relocation')
            found[address] = {'offset':address, 'info':info, 'addend':addend,
                              'file_offset':off, 'raw':data[off:off+24].hex()}
    if set(found) != set(wanted):
        raise ValueError('missing selected relocation')
    return found


def relative_target(rel, expected=None):
    if rel['info'] != 8 or rel['addend'] < 0:
        raise ValueError('expected symbol-free R_X86_64_RELATIVE')
    if expected is not None and rel['addend'] != expected:
        raise ValueError('unexpected relocation target')
    return rel['addend']


def check_address09(key, relocation):
    if key != bytes(19)+b'\x09':
        raise ValueError('address-09 key mismatch')
    return relative_target(relocation,0x5c165b0)


def symbol_name(data, sec, info):
    index = info >> 32
    if not index:
        return ''
    sym = section_named(sec, '.dynsym')
    strings = section_named(sec, '.dynstr')
    if sym['size'] % 24 or index >= sym['size'] // 24:
        raise ValueError('invalid dynamic symbol index')
    noff = struct.unpack_from('<I',data,sym['offset']+index*24)[0]
    if noff >= strings['size']:
        raise ValueError('dynamic symbol name outside string table')
    a = strings['offset'] + noff
    b = data.find(b'\0',a,strings['offset']+strings['size'])
    if b < 0:
        raise ValueError('unterminated dynamic symbol')
    return data[a:b].decode('ascii')


def branch(data, sec, site, expected):
    a = read_va(data,sec,site,1,True)[0]
    if a == 0x0f:
        raw = read_va(data,sec,site,6,True)
        if not 0x80 <= raw[1] <= 0x8f:
            raise ValueError('unsupported near branch')
        disp = struct.unpack_from('<i',raw,2)[0]
    elif a in (0xe8,0xe9):
        raw = read_va(data,sec,site,5,True)
        disp = struct.unpack_from('<i',raw,1)[0]
    elif 0x70 <= a <= 0x7f or a == 0xeb:
        raw = read_va(data,sec,site,2,True)
        disp = struct.unpack_from('<b',raw,1)[0]
    else:
        raise ValueError('unsupported relative branch')
    dest = site + len(raw) + disp
    if dest != expected:
        raise ValueError('relative branch target mismatch')
    read_va(data,sec,dest,1,True)
    return raw, dest


def rip_target(data, sec, site, expected, prefix):
    raw = read_va(data,sec,site,len(prefix)+4,True)
    if not raw.startswith(prefix):
        raise ValueError('RIP-relative instruction mismatch')
    target = site + len(raw) + struct.unpack_from('<i',raw,len(prefix))[0]
    if target != expected:
        raise ValueError('RIP-relative target mismatch')
    return raw, target


# Common interpreter-object field loads and adds. Equality is checked from
# decoded displacements; sharing the runtime object remains conditional.
FIELD_SITES = [
    ('memory_object','copy',0x2997d0c,'4c8b7f',1),
    ('memory_object','load',0x299747f,'488b5f',1),
    ('memory_object','store',0x299763e,'488b5f',1),
    ('memory_object','store_byte',0x2997758,'488b5f',1),
    ('memory_object','action',0x299919e,'4d8b7e',1),
    ('window_base','copy',0x2997d10,'488b47',1),
    ('window_base','load',0x2997483,'488b47',1),
    ('window_base','store',0x299764a,'4c0377',1),
    ('window_base','store_byte',0x2997764,'4c0377',1),
    ('window_base','action',0x29991a2,'498b4e',1),
    ('backing_pointer','copy',0x2997d1c,'4d8b77',1),
    ('backing_pointer','load',0x29974a0,'488b43',1),
    ('backing_pointer','store',0x2997662,'488b43',1),
    ('backing_pointer','store_byte',0x2997770,'488b43',1),
    ('backing_pointer','action',0x29991da,'4d8b6f',1),
    ('return_length','copy',0x2997c70,'4c8b87',4),
    ('return_length','size',0x2997e75,'488b8f',4),
    ('return_pointer','copy',0x2997d05,'488bb7',4),
]


def field_rows(data,sec):
    out=[]
    groups={}
    for group,consumer,site,hexprefix,width in FIELD_SITES:
        prefix=bytes.fromhex(hexprefix)
        raw=read_va(data,sec,site,len(prefix)+width,True)
        if not raw.startswith(prefix):
            raise ValueError('field instruction mismatch')
        value=int.from_bytes(raw[-width:],'little')
        _,off=file_offset(sec,site,len(raw),True)
        groups.setdefault(group,set()).add(value)
        out.append([group,consumer,hex(site),hex(off),raw.hex(),hex(value)])
    if any(len(values)!=1 for values in groups.values()):
        raise ValueError('shared field displacement differs')
    return out


# Register-specific instruction shapes, used only for these two selected
# windows. Displacements are read from the authenticated bytes.
LOAD_LANES = [
    (0x29974a4, '4a8b4c20', 1, 0x29974a9, '480fc9', 0x29974c3, '49894e'),
    (0x29974ac, '4a8b5420', 1, 0x29974b1, '480fca', 0x29974c7, '498956'),
    (0x29974b8, '4a8b4420', 1, 0x29974bd, '480fc8', 0x29974cb, '498946'),
    (0x29974b4, '4a8b3420', 0, 0x29974c0, '480fce', 0x29974cf, '498976'),
]
STORE_LANES = [
    (0x2997601, '4a8b6c08', 1, 0x2997656, '480fcd', 0x2997666, '4a892c30', 0),
    (0x29975f7, '4e8b6c08', 1, 0x2997659, '490fcd', 0x299766a, '4e896c30', 1),
    (0x29975f2, '4e8b6408', 1, 0x299765c, '490fcc', 0x299766f, '4e896430', 1),
    (0x29975ee, '4e8b3c08', 0, 0x299765f, '490fcf', 0x2997674, '4e897c30', 1),
]


def shaped_displacement(data, sec, site, prefix_hex, width, signed=False):
    prefix = bytes.fromhex(prefix_hex)
    if width not in (0,1):
        raise ValueError('unsupported selected displacement width')
    raw = read_va(data,sec,site,len(prefix)+width,True)
    if not raw.startswith(prefix):
        raise ValueError('selected lane instruction mismatch')
    return 0 if width == 0 else int.from_bytes(raw[-1:], 'little', signed=signed)


def lane_rows(data, sec):
    out = []
    for load, prefix, width, swap, swap_hex, store, store_prefix in LOAD_LANES:
        memory = shaped_displacement(data,sec,load,prefix,width)
        checked_bytes(data,sec,swap,bytes.fromhex(swap_hex))
        stack = shaped_displacement(data,sec,store,store_prefix,1,True) + 32
        for j in range(8):
            out.append(['load',memory + 7-j,stack+j,hex(load),hex(swap),hex(store)])
    for load, prefix, width, swap, swap_hex, store, store_prefix, store_width in STORE_LANES:
        stack = shaped_displacement(data,sec,load,prefix,width)
        checked_bytes(data,sec,swap,bytes.fromhex(swap_hex))
        memory = shaped_displacement(data,sec,store,store_prefix,store_width)
        for j in range(8):
            out.append(['store',stack+7-j,memory+j,hex(load),hex(swap),hex(store)])
    for operation in ('load','store'):
        pairs = sorted((r[1],r[2]) for r in out if r[0] == operation)
        if pairs != [(i,31-i) for i in range(32)]:
            raise ValueError('selected byte lanes are not a 32-byte reversal')
    return sorted(out,key=lambda row:(row[0],row[1]))


def call_sites(data, sec, fde, label, headers=None):
    if fde['lsda'] is None:
        return []
    table = section_named(sec, '.gcc_except_table')
    va = fde['lsda']
    if not table['address'] <= va < table['address'] + table['size']:
        raise ValueError('LSDA outside exception section')
    p = table['offset'] + va - table['address']
    header_start = p
    limit = table['offset'] + table['size']
    if p < 0 or limit > len(data):
        raise ValueError('exception section outside file')
    if p + 2 > limit or data[p] != 0xff:
        raise ValueError('unsupported LSDA base encoding')
    type_encoding = data[p+1]
    p += 2
    type_base = None
    if type_encoding != 0xff:
        if type_encoding != 0x9b:
            raise ValueError('unsupported LSDA type encoding')
        distance, p = uleb(data,p,limit)
        type_base = p + distance
        if type_base > limit:
            raise ValueError('LSDA type table outside section')
    if p >= limit or data[p] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    length, p = uleb(data,p+1,limit)
    end = p + length
    if end > limit or (type_base is not None and end > type_base):
        raise ValueError('LSDA call-site table outside bounds')
    if headers is not None:
        headers.append([label,hex(va),hex(header_start),hex(type_encoding),
                        '' if type_base is None else hex(type_base),
                        hex(p),length,data[header_start:p].hex()])
    out = []
    previous_end = 0
    while p < end:
        start = p
        delta, p = uleb(data,p,end)
        size, p = uleb(data,p,end)
        landing, p = uleb(data,p,end)
        action, p = uleb(data,p,end)
        span = fde['end'] - fde['start']
        if delta < previous_end or delta + size > span or (landing and landing >= span):
            raise ValueError('LSDA sites overlap or leave FDE')
        previous_end = delta + size
        out.append([label,hex(va),hex(start),hex(fde['start']+delta),
                    hex(fde['start']+delta+size),
                    '' if not landing else hex(fde['start']+landing), action,
                    data[start:p].hex()])
    return out


VTABLES = [
    ('odd_allocation',0x2999214,'4c8b2d',0x64df8c8,0x64040c0,0x161c5d0,0x161c3f0),
    ('even_allocation',0x299921b,'4c0f442d',0x64df8c0,0x64040e8,0x161c620,0x161c4c0),
]
SHARED_TABLE = 0x6404008


def vtable_rows(data,sec,rel):
    def file_slot(va):
        raw=read_va(data,sec,va,8)
        _,offset=file_offset(sec,va,8)
        return hex(offset),raw.hex()

    rows=[]
    for label,site,prefix,slot,table,clone,drop in VTABLES:
        raw,_=rip_target(data,sec,site,slot,bytes.fromhex(prefix))
        relative_target(rel[slot],table)
        relative_target(rel[table],clone)
        relative_target(rel[table+0x20],drop)
        _,off=file_offset(sec,site,len(raw),True)
        rows.append([label,hex(site),hex(off),raw.hex(),hex(slot),*file_slot(slot),rel[slot]['raw'],
                     hex(table),hex(table),*file_slot(table),hex(clone),rel[table]['raw'],
                     hex(table+0x20),*file_slot(table+0x20),hex(drop),rel[table+0x20]['raw']])
    raw,_=rip_target(data,sec,0x161bf36,SHARED_TABLE,b'\x48\x8d\x05')
    relative_target(rel[SHARED_TABLE],0x161bcf0)
    relative_target(rel[SHARED_TABLE+0x20],0x161bc50)
    _,off=file_offset(sec,0x161bf36,len(raw),True)
    rows.append(['promoted_shared',hex(0x161bf36),hex(off),raw.hex(),'','','','',hex(SHARED_TABLE),
                 hex(SHARED_TABLE),*file_slot(SHARED_TABLE),hex(rel[SHARED_TABLE]['addend']),rel[SHARED_TABLE]['raw'],
                 hex(SHARED_TABLE+0x20),*file_slot(SHARED_TABLE+0x20),hex(rel[SHARED_TABLE+0x20]['addend']),rel[SHARED_TABLE+0x20]['raw']])
    return rows


def shared_table_xrefs(data,sec):
    sites=[('promote_success',0x161bf36),('promote_cas_loser',0x161bf62),
           ('clone_odd_untagged',0x161c5f2),('clone_even_untagged',0x161c642),
           ('clone_shared',0x161bd06)]
    rows=[]
    for label,site in sites:
        raw,target=rip_target(data,sec,site,SHARED_TABLE,b'\x48\x8d\x05')
        _,off=file_offset(sec,site,len(raw),True)
        rows.append([label,hex(site),hex(off),raw.hex(),hex(target)])
    return rows


def source_row(data, sec, name, site, descriptor, rel):
    raw, _ = rip_target(data,sec,site,descriptor,b'\x48\x8d\x3d')
    relative_target(rel)
    descriptor_raw = read_va(data,sec,descriptor,24)
    _, length, line, column = struct.unpack('<QQII',descriptor_raw)
    if not 0 < length < 512:
        raise ValueError('unexpected source descriptor length')
    path = read_va(data,sec,rel['addend'],length)
    marker = b'z_vendor/'
    idx = path.find(marker)
    if idx < 0 or path.find(marker,idx+1) >= 0:
        raise ValueError('expected unique sanitized source suffix')
    suffix = path[idx:].decode('ascii')
    _, ref_off = file_offset(sec,site,len(raw),True)
    _, desc_off = file_offset(sec,descriptor,24)
    return [name,hex(site),hex(ref_off),raw.hex(),hex(descriptor),hex(desc_off),
            descriptor_raw.hex(),hex(rel['file_offset']),rel['raw'],
            hex(rel['addend']),length,suffix,line,column]


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.writer(f,delimiter='\t',lineterminator='\n')
        w.writerow(header)
        w.writerows(rows)


def write_json(path, obj):
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n',encoding='utf-8')


def extract(data, out):
    digest(data,TARGET)
    sec = sections(data)
    for va, raw in CHECKS:
        checked_bytes(data,sec,va,bytes.fromhex(raw))
    functions, bystart = selected_fdes(data,sec)
    opcode_slots = {TABLE + op*8 for op,_,_ in OPCODES}
    vtable_slots={0x64df8c0,0x64df8c8,0x64040c0,0x64040e0,0x64040e8,0x6404108,SHARED_TABLE,SHARED_TABLE+0x20}
    slots = opcode_slots | {slot for _,_,slot in RIP_SITES} | {desc for _,_,desc in SOURCE_SITES} | {0x64c0748} | vtable_slots
    rel = relocations(data,sec,slots)
    key=read_va(data,sec,0x64c0750,20)
    callback=check_address09(key,rel[0x64c0748])
    _,key_offset=file_offset(sec,0x64c0750,20)
    anchor={'role':'previously mapped data-only address-09 dependency',
            'key_va':hex(0x64c0750),'key_file_offset':hex(key_offset),
            'key_bytes':key.hex(),'callback_slot_va':hex(0x64c0748),
            'callback_target_va':hex(callback),'rela_file_offset':hex(rel[0x64c0748]['file_offset']),
            'rela_raw':rel[0x64c0748]['raw']}
    opcode_rows=[]
    for op, label, expected in OPCODES:
        slot = TABLE+op*8
        target = relative_target(rel[slot],expected)
        raw = read_va(data,sec,slot,8)
        _, off = file_offset(sec,slot,8)
        opcode_rows.append([hex(op),label,hex(slot),hex(off),raw.hex(),hex(target),
                            hex(rel[slot]['file_offset']),rel[slot]['raw']])
    window_rows=[]
    for label, start, end in WINDOWS:
        raw = read_va(data,sec,start,end-start,True)
        owners = [f for f in bystart.values() if f['start'] <= start and end <= f['end']]
        if len(owners)!=1:
            raise ValueError('window not in exactly one selected FDE')
        _, off = file_offset(sec,start,len(raw),True)
        window_rows.append([label,hex(start),hex(end),hex(off),len(raw),raw.hex()])
    edge_rows=[]
    for label,site,expected in EDGES:
        raw,dest=branch(data,sec,site,expected)
        _,off=file_offset(sec,site,len(raw),True)
        edge_rows.append([label,hex(site),hex(off),raw.hex(),hex(dest)])
    rip_rows=[]
    for label,site,expected in RIP_SITES:
        opcode=b'\xff\x25' if label.endswith('_tail') else b'\xff\x15'
        raw, target = rip_target(data,sec,site,expected,opcode)
        _,off=file_offset(sec,site,len(raw),True)
        info = rel[target]['info']
        symbol=symbol_name(data,sec,info)
        rip_rows.append([label,hex(site),hex(off),raw.hex(),hex(target),
                         hex(info & 0xffffffff),hex(info>>32),symbol,
                         hex(rel[target]['addend']),hex(rel[target]['file_offset']),rel[target]['raw']])
    if relative_target(rel[0x64e6de0]) != 0x45244c0:
        raise ValueError('unexpected expansion boundary')
    source_rows=[source_row(data,sec,label,site,desc,rel[desc]) for label,site,desc in SOURCE_SITES]
    vtables=vtable_rows(data,sec,rel)
    shared_xrefs=shared_table_xrefs(data,sec)
    lanes=lane_rows(data,sec)
    fields=field_rows(data,sec)
    exception_rows=[]
    exception_headers=[]
    for label,start,_,_ in FUNCTIONS:
        exception_rows.extend(call_sites(data,sec,bystart[start],label,exception_headers))
    constants={
        'revision_minimum': read_va(data,sec,0x2997bdb+6,1,True)[0],
        'stack_word_bytes': 1 << read_va(data,sec,0x2997bff+3,1,True)[0],
        'return_data_length_offset':struct.unpack_from('<I',read_va(data,sec,0x2997c70,7,True),3)[0],
        'copy_schedule_word_offset':read_va(data,sec,0x2997c9d+3,1,True)[0],
        'size_push_stack_limit':struct.unpack_from('<I',read_va(data,sec,0x2997e6d,6,True),2)[0],
        'copy_error_revision':read_va(data,sec,0x2997db5+1,1,True)[0],
        'copy_error_stack':read_va(data,sec,0x2997bec+1,1,True)[0],
        'copy_error_wide':read_va(data,sec,0x2997c4d+1,1,True)[0],
        'copy_error_source_bounds':read_va(data,sec,0x2997c77+1,1,True)[0],
        'copy_error_insufficient_gas':read_va(data,sec,0x2997dd0+1,1,True)[0],
        'size_error_stack_full':read_va(data,sec,0x2997ea9+1,1,True)[0],
        'return_status':struct.unpack_from('<I',read_va(data,sec,0x2999567,5,True),1)[0],
        'revert_status':struct.unpack_from('<I',read_va(data,sec,0x29996e0,5,True),1)[0],
        'scope':'Raw values extracted from selected instruction shapes; enum and type names are inferred.'}
    out.mkdir(parents=True,exist_ok=True)
    write_json(out/'address-anchor.json',anchor)
    write_json(out/'functions.json',functions)
    write_json(out/'constants.json',constants)
    write_tsv(out/'opcode-table.tsv',['opcode','inferred_role','slot_va','slot_file_offset','slot_raw','relocated_target','rela_file_offset','rela_raw'],opcode_rows)
    write_tsv(out/'windows.tsv',['label','start_va','end_va_exclusive','file_offset','size','raw'],window_rows)
    write_tsv(out/'edges.tsv',['label','instruction_va','file_offset','raw','target_va'],edge_rows)
    write_tsv(out/'indirect-transfers.tsv',['label','instruction_va','file_offset','raw','slot_va','relocation_type','symbol_index','symbol','addend','rela_file_offset','rela_raw'],rip_rows)
    write_tsv(out/'output-vtables.tsv',['label','selector_va','selector_file_offset','selector_raw','pointer_slot_va','pointer_slot_file_offset','pointer_slot_raw','pointer_rela_raw','table_va','clone_slot_va','clone_slot_file_offset','clone_slot_raw','clone_target_va','clone_rela_raw','drop_slot_va','drop_slot_file_offset','drop_slot_raw','drop_target_va','drop_rela_raw'],vtables)
    write_tsv(out/'shared-table-xrefs.tsv',['label','instruction_va','file_offset','raw','target_va'],shared_xrefs)
    write_tsv(out/'field-lineage.tsv',['group','consumer','instruction_va','file_offset','raw','displacement'],fields)
    write_tsv(out/'byte-lanes.tsv',['operation','input_byte_index','output_byte_index','load_va','bswap_va','store_va'],lanes)
    write_tsv(out/'sources.tsv',['label','reference_va','reference_file_offset','reference_raw','descriptor_va','descriptor_file_offset','descriptor_raw','rela_file_offset','rela_raw','path_va','original_byte_length','sanitized_suffix','line','column'],source_rows)
    write_tsv(out/'exception-headers.tsv',['function','lsda_va','header_file_offset','type_encoding','type_base_file_offset','call_table_file_offset','call_table_size','header_raw'],exception_headers)
    write_tsv(out/'exception-sites.tsv',['function','lsda_va','row_file_offset','start_va','end_va_exclusive','landing_va','action_index','raw'],exception_rows)
    summary={'target_sha256':TARGET,'selected_fdes':len(functions),
             'selected_body_bytes':sum(x['size'] for x in functions),
             'selected_opcode_slots':len(opcode_rows),'selected_windows':len(window_rows),
             'selected_relative_edges':len(edge_rows),'selected_indirect_transfers':len(rip_rows),
             'selected_source_descriptors':len(source_rows),'byte_lane_rows':len(lanes),
             'selected_field_instructions':len(fields),'output_vtables':len(vtables),
             'shared_table_xrefs':len(shared_xrefs),
             'lsda_headers':len(exception_headers),'lsda_call_sites':len(exception_rows),
             'limitations':'Selected instruction ranges and static unwind records, not a complete CFG, execution or component coverage.'}
    write_json(out/'summary.json',summary)
    return summary


def legacy_check(data, current):
    """Optional #94 comparison; output files remain entirely #115-derived."""
    digest(data,LEGACY)
    oldsec=sections(data)
    oldslot=0x56ac788 + 0x3e*8
    old_return_slot=0x56ac788 + 0xf3*8
    oldrel=relocations(data,oldsec,{oldslot,old_return_slot,0x574f0b0})
    relative_target(oldrel[oldslot],0x26bdc30)
    relative_target(oldrel[old_return_slot],0x26beaf0)
    relative_target(oldrel[0x574f0b0],0x4e9d2a0)
    _, oldindex=unwind_index(data)
    oldentries=[e for e in oldindex if e['start']==0x26bdc30]
    action_entries=[e for e in oldindex if e['start']==0x26be730]
    _, oldfdes=eh_frame_records(data,oldsec)
    fdes=[f for f in oldfdes if f['start']==0x26bdc30]
    actions=[f for f in oldfdes if f['start']==0x26be730]
    if (len(fdes)!=1 or len(oldentries)!=1 or fdes[0]['end']!=0x26bdddb
            or oldentries[0]['fde']!=fdes[0]['fde']):
        raise ValueError('unexpected legacy FDE')
    if (len(actions)!=1 or len(action_entries)!=1 or actions[0]['end']!=0x26bea52
            or action_entries[0]['fde']!=actions[0]['fde']):
        raise ValueError('unexpected legacy action FDE')
    action=read_va(data,oldsec,actions[0]['start'],actions[0]['end']-actions[0]['start'],True)
    if hashlib.sha256(action).hexdigest()!='1cf433b09a9a8caf59981328b526da36d847e48dec6c89e4c1cf9db24bed138a':
        raise ValueError('legacy action body mismatch')
    oldbody=read_va(data,oldsec,0x26bdc30,0x1ab,True)
    if hashlib.sha256(oldbody).hexdigest()!='ac0552be762e3af1570faa2bdfcf32f4bd402d29f4e20c395110a72818472876':
        raise ValueError('legacy body mismatch')
    historical=[(0x26bdcce,'4f8d247f4983c4034c8bbfe00100004d29e7730cc687f301000050e9d60000004c89bfe0010000'),
                (0x26bdcff,'4989d34901cb4d0f42de4c8b8fc00100004d39cb761580bff001000000750cc687f30100005de99a000000'),
                (0x26bdd2a,'4885c90f8491000000'),
                (0x26be8d2,'4088b7f3010000488b442408488b4c2410488b5424184889542440488b5424204889542448488944243048894c24380f1087d80100000f29442450488b87e801000048894424604989fe488d9f500100004889dfe8455e0c00'),
                (0x26beaf0,'be02000000e936fcffff')]
    for va,raw in historical:
        checked_bytes(data,oldsec,va,bytes.fromhex(raw))
    legacy_edges=[]
    for label,site,target in [('gas_sufficient',0x26bdce0,0x26bdcee),
                              ('source_inside',0x26bdd13,0x26bdd2a),
                              ('nonzero_mode_bypass',0x26bdd1c,0x26bdd2a),
                              ('action_drop',0x26be926,0x2784770)]:
        raw,dest=branch(data,oldsec,site,target)
        legacy_edges.append({'label':label,'site':hex(site),'target':hex(dest),'raw':raw.hex()})
    newsec=sections(current)
    newrel=relocations(current,newsec,{0x64c0748})
    relative_target(newrel[0x64c0748],0x5c165b0)
    oldkey=read_va(data,oldsec,0x574f0c0,20)
    newkey=read_va(current,newsec,0x64c0750,20)
    if oldkey != bytes(19)+b'\x09' or oldkey != newkey:
        raise ValueError('address-09 keys differ')
    return {'legacy_sha256':LEGACY,'legacy_opcode_slot':hex(oldslot),
            'legacy_copy_fde_start':hex(fdes[0]['start']),
            'legacy_copy_fde_end':hex(fdes[0]['end']),
            'legacy_fde_va':hex(fdes[0]['fde']),
            'legacy_copy_file_offset':hex(file_offset(oldsec,fdes[0]['start'],1,True)[1]),
            'legacy_copy_body_sha256':hashlib.sha256(oldbody).hexdigest(),
            'legacy_return_opcode_slot':hex(old_return_slot),
            'legacy_return_opcode_target':hex(oldrel[old_return_slot]['addend']),
            'legacy_action_fde_start':hex(actions[0]['start']),
            'legacy_action_fde_end':hex(actions[0]['end']),
            'legacy_action_fde_va':hex(actions[0]['fde']),
            'legacy_action_body_sha256':hashlib.sha256(action).hexdigest(),
            'legacy_key_va':hex(0x574f0c0),'legacy_callback_slot':hex(0x574f0b0),
            'legacy_callback':hex(oldrel[0x574f0b0]['addend']),
            'target_key_va':hex(0x64c0750),'target_callback_slot':hex(0x64c0748),
            'target_callback':hex(newrel[0x64c0748]['addend']),
            'key_bytes':oldkey.hex(),'legacy_selected_edges':legacy_edges,
            'legacy_instruction_windows':[{'va':hex(va),'raw':read_va(data,oldsec,va,len(bytes.fromhex(raw)),True).hex()} for va,raw in historical]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--legacy',type=Path,help='optional authenticated historical #94 ELF')
    args=parser.parse_args()
    data=(ROOT/'artifacts/node/115/hl-node').read_bytes()
    digest(data,TARGET)
    comparison=legacy_check(args.legacy.read_bytes(),data) if args.legacy else None
    summary=extract(data,args.out)
    if comparison is not None:
        summary['optional_legacy_check']=comparison
    print(json.dumps(summary,sort_keys=True))


if __name__=='__main__':
    try:
        main()
    except (OSError,ValueError,struct.error,UnicodeError) as exc:
        print('re21_return_data115: '+str(exc),file=sys.stderr)
        raise SystemExit(1)

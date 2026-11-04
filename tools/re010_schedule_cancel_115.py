#!/usr/bin/env python3
"""Reproduce selected node-115 schedule-cancel core evidence from ELF bytes.

The selected sites are an instruction-boundary list obtained by static review,
not an x86 disassembler or a whole-program control-flow analysis. The input is
never executed. Branch and relocation operands are decoded from the ELF.
"""

import argparse
import csv
import hashlib
import io
import itertools
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# FDE ranges and body hashes are independent pins; they are not source-level
# function-boundary proofs, a function census, or an equivalence denominator.
FDE_PINS = (
    ('core', 0x2c2cb40, 0x2c2cf4a, 'a5e225ba23e16114fb701c7d7faa772f1e6e61d52dd04a0c370f3e15d793b57f'),
    ('aggregate', 0x2a8ae60, 0x2a8b095, 'a127b76dbf13fe80a57ee4b43e61e94ff965bb53c380918add469e8efb14c976'),
    ('dex_lookup', 0x4716be0, 0x4716cb6, '713942c901614f370d45e6a4389b568921d907c03a1b3f5a3de0e90cad07d7d7'),
    ('base_lookup', 0x4716cc0, 0x4716d8d, '6018d62a21a0da654a217c07fa8bd3aeec97b318884973a9b3dbc5e80e8cae3e'),
    ('ordinal', 0x1628f50, 0x16290ca, '3e1c87803439d929d85b9ff77ea4ba6fca238fe6584dfdcea4ea56e4a353581d'),
    ('time_adjust', 0x162a9a0, 0x162ab02, 'ade932303d2cb70bf81c37659061e07cc9a312321e7a3fb1b2a3ffdeba5c348b'),
    ('time_error', 0x1567a50, 0x1567ac8, '4b8199160c11414316fe829c5e1512b384feb3c4b73b87b0abac132c92e30d99'),
    ('map_entry', 0x2db4460, 0x2db48bf, 'e1fb3c76dfd024af99d745a64386795bd32edaffbda23fa3c24c38ad0f0fe419'),
    ('entry_value', 0x2422570, 0x24226bc, '7995404e8aca37f6450299a3066f2492fea904327e31267eddf302583220051c'),
    ('compact_search', 0x24cb7e0, 0x24cb9dd, 'fe89bd943da7bf29ba38d8b4686903d90cabc7f1818d82e8cdf874e1c4d9c6c0'),
    ('compact_insert', 0x24bb380, 0x24bb485, '373f6f728d93adad23358f408fe60b9dc89be2791352038307343d1f590c30f7'),
    ('dex_default', 0x44e9f40, 0x44e9f8d, 'a8a433e03854cb09a7125413db4fc45cbbfe4d79993216f71da741af50be82ba'),
    ('base_default', 0x3d25c00, 0x3d25c32, '9294f2c8200cb52f36621e27de5a50b647691a4603b17493e9fb21dbbcdba2c7'),
    ('dex_once_a', 0x44dd1b0, 0x44dd23a, '62530fc2aa4e8ec35776268309d0e0db6b5aae06ea986704b239324bc2cfbbf6'),
    ('dex_once_b', 0x44db370, 0x44db3fa, '018225d55e6fb670eafb822b86b24a839071a4462b905dfc590c44f417e3993b'),
    ('base_once_a', 0x3ced300, 0x3ced366, '2f19ddfec0b6c9d5ff79da3bb98528c521469bb40fc065542922a42f40b90891'),
    ('base_once_b', 0x3c4c590, 0x3c4c5f6, '85ecb1dfa6ddcd0efd1033fe9daffccb2d9a1f38711518ffc6c6a1a832c030c6'),
    ('clock_entry', 0x2bdf270, 0x2bdf8ee, 'b4271ff9f1761a2c4ef9439594713732161ca337fc9babd220cf42bea41f5129'),
    ('expiry_driver', 0x2bdf8f0, 0x2beafa1, '225649f70f438609a3bf19555e1a01ce18bee7dfa80fb5179ba16225e4fa437c'),
    ('expiry_iterator', 0x262eef0, 0x262f135, '190e83803dd38377cc98636767745421b278aea32f22d037c7d64f389a59ff6b'),
    ('expiry_handoff', 0x2bf9910, 0x2bf9e1a, '45166a193af28748ac16d21bcfc7b7b75ab7dc605ab0cc647933111adfa680a9'),
    ('counter_reset', 0x2dceaf0, 0x2dcf026, 'f37208d86b9358b6eda4e6a96be1b87a7f87d6f6ce7122cc0de1b1e056c6d649'),
    ('compact_reset', 0x24c0ee0, 0x24c109c, '9176b91175c57f9ca4179fe4d17736f2acdb7f1c6222b896fc509e334e1b40e2'),
)

# The two incoming edges are contextual cross-checks of earlier dispatch work.
# That earlier work already identified the callers. This packet studies the
# previously untraced core and its callees, not those callers' full bodies.
DIRECT_CALLS = (
    ('prior_nested_caller_to_core', 0x283c94f, 0x2c2cb40),
    ('prior_direct_caller_to_core', 0x2c067f9, 0x2c2cb40),
    ('core_to_aggregate', 0x2c2cb79, 0x2a8ae60),
    ('core_to_map_entry', 0x2c2ce83, 0x2db4460),
    ('core_to_entry_value', 0x2c2ce8b, 0x2422570),
    ('core_to_compact_search', 0x2c2cea7, 0x24cb7e0),
    ('core_to_time_error', 0x2c2cf21, 0x1567a50),
    ('aggregate_to_dex_lookup', 0x2a8aebc, 0x4716be0),
    ('aggregate_to_base_lookup', 0x2a8afc4, 0x4716cc0),
    ('map_entry_to_compact_search', 0x2db45e1, 0x24cb7e0),
    ('entry_value_to_tree_insert', 0x24225ef, 0x26d71c0),
    ('entry_value_to_compact_insert', 0x242265c, 0x24bb380),
    ('compact_insert_shift_right', 0x24bb3f1, 0x24e2ef0),
    ('compact_insert_shift_left', 0x24bb422, 0x24e2ef0),
    ('dex_lookup_hash', 0x4716c52, 0x4717440),
    ('dex_lookup_index', 0x4716c76, 0x3ee6740),
    ('base_lookup_hash', 0x4716d2c, 0x4717440),
    ('base_lookup_index', 0x4716d50, 0x3ee69c0),
    ('clock_entry_to_expiry', 0x2bdf499, 0x2bdf8f0),
    ('expiry_scan_next', 0x2be22c5, 0x262eef0),
    ('expiry_handoff_by_key', 0x2be2411, 0x2bf9910),
    ('expiry_reset_on_date_order', 0x2be24ae, 0x2dceaf0),
    ('reset_compact', 0x2dceb7f, 0x24c0ee0),
    ('reset_tree_remove', 0x2dcee67, 0x1d5f150),
    ('handoff_dex_collect', 0x2bf9c30, 0x22f2000),
    ('handoff_dex_apply', 0x2bf9c52, 0x2419810),
    ('handoff_base_collect', 0x2bf9ce9, 0x22f2160),
    ('handoff_base_apply', 0x2bf9d0a, 0x241a3c0),
)

INDIRECT_CALLS = (
    ('core_ordinal', 0x2c2cc13, 0x64dfff0),
    ('core_time_adjust', 0x2c2cc77, 0x64e0f78),
    ('core_date_adjust', 0x2c2ccec, 0x64e0aa0),
    ('aggregate_lazy_dex', 0x2a8af45, 0x64df9f0),
    ('aggregate_overflow_dex_first', 0x2a8af5b, 0x64e4ea8),
    ('aggregate_overflow_dex_second', 0x2a8af8d, 0x64e4ea8),
    ('aggregate_lazy_base', 0x2a8b03d, 0x64df9f0),
    ('aggregate_overflow_base_first', 0x2a8b051, 0x64e4ea8),
    ('aggregate_overflow_base_second', 0x2a8b079, 0x64e4ea8),
    ('compact_compare_first', 0x24cb822, 0x64dfb50),
    ('compact_compare_search', 0x24cb8c6, 0x64dfb50),
    ('map_release_storage', 0x2db46ca, 0x64df4a0),
    ('compact_grow', 0x24bb3a9, 0x64e5ce8),
    ('time_error_format', 0x1567aa8, 0x64df6e8),
    ('expiry_key_vector_grow', 0x2be233f, 0x64e4d18),
)

# These calls use a function pointer loaded from a RIP-relative dynamic slot.
REGISTER_CALLS = (
    ('core_tree_compare', 0x2c2cd5e, b'\x4c\x8b\x2d', 0x2c2cdb1, b'\x41\xff\xd5', 0x64dfb50),
    ('map_tree_compare', 0x2db4764, b'\x4c\x8b\x25', 0x2db47ba, b'\x41\xff\xd4', 0x64dfb50),
)

# These are selected branch instruction starts, checked against complete body
# hashes above. Branch destinations are decoded from the original operands.
BRANCHES = {
    'core': (
        0x2c2cb84, 0x2c2cba9, 0x2c2cbec, 0x2c2cc1f, 0x2c2cc9c,
        0x2c2ccbc, 0x2c2ccf4, 0x2c2cd1f, 0x2c2cd25, 0x2c2cd3c,
        0x2c2cd4c, 0x2c2cda3, 0x2c2cdd1, 0x2c2cdd8, 0x2c2cdf6,
        0x2c2ce09, 0x2c2ce36, 0x2c2ce3e, 0x2c2ce49, 0x2c2ce50,
        0x2c2ce57, 0x2c2ce94, 0x2c2ce9b, 0x2c2ceae, 0x2c2ceb7,
        0x2c2ceea, 0x2c2cf2b, 0x2c2cf3b, 0x2c2cf45,
    ),
    'aggregate': (
        0x2a8ae82, 0x2a8aecc, 0x2a8aeea, 0x2a8aef2, 0x2a8af0c,
        0x2a8af0e, 0x2a8af4b, 0x2a8af6b, 0x2a8af7b, 0x2a8afa0,
        0x2a8afa9, 0x2a8afd1, 0x2a8afef, 0x2a8aff7, 0x2a8b046,
        0x2a8b06b, 0x2a8b090,
    ),
    'map_entry': (0x2db4499, 0x2db45d3, 0x2db45e9, 0x2db45f4,
                  0x2db4683, 0x2db468d, 0x2db4755, 0x2db47d3, 0x2db47da,
                  0x2db47e9),
    'entry_value': (0x2422589, 0x242258e, 0x24225ad, 0x2422601,
                    0x2422665, 0x24226a1),
    'compact_search': (0x24cb7f5, 0x24cb813, 0x24cb83a, 0x24cb845,
                       0x24cb890, 0x24cb89d, 0x24cb8dc, 0x24cb900),
    'compact_insert': (0x24bb38f, 0x24bb3a4, 0x24bb3c0),
    'dex_lookup': (0x4716bf2, 0x4716bfc, 0x4716c37, 0x4716c7e, 0x4716c87),
    'base_lookup': (0x4716cd2, 0x4716cdc, 0x4716d11, 0x4716d58, 0x4716d61),
    'ordinal': (0x1628f59, 0x1628fc7, 0x1628fcf, 0x162901b, 0x1629057),
    'time_adjust': (0x162a9cf, 0x162a9d4, 0x162a9f2, 0x162aa15,
                    0x162aa1d, 0x162aa23, 0x162aa2b, 0x162aa30),
    'dex_once_a': (0x44dd1c8, 0x44dd1ce),
    'dex_once_b': (0x44db388, 0x44db38e),
    'base_once_a': (0x3ced315, 0x3ced31b),
    'base_once_b': (0x3c4c5a5, 0x3c4c5ab),
    'clock_entry': (0x2bdf2a6, 0x2bdf2b1, 0x2bdf2b9, 0x2bdf2bb,
                    0x2bdf2bf, 0x2bdf47c),
    'expiry_driver': (0x2be21bb, 0x2be22c0, 0x2be22cd, 0x2be22f2,
                      0x2be22f7, 0x2be2310, 0x2be2335, 0x2be241d,
                      0x2be2422, 0x2be24a3),
    'expiry_iterator': (0x262eef8, 0x262ef09, 0x262ef22, 0x262ef3c,
                        0x262ef4c, 0x262ef59, 0x262f001),
    'counter_reset': (0x2dceb13, 0x2dceb20, 0x2dceb9a, 0x2dceda7,
                      0x2dcedb0, 0x2dceec5),
    'compact_reset': (0x24c0eee, 0x24c0f3b, 0x24c0f47, 0x24c0fb9,
                      0x24c0fc5, 0x24c1068, 0x24c1071),
    'expiry_handoff': (0x2bf9935, 0x2bf993b, 0x2bf994b, 0x2bf996e),
}

# Windows have half-open linked-VA bounds and are for instruction review.
# The complete selected FDE bytes are separately hashed and retained.
WINDOWS = (
    ('core_volume_gate', 0x2c2cb60, 0x2c2cba5),
    ('core_optional_and_time_bound', 0x2c2cba5, 0x2c2cbf2),
    ('core_ordinal_call', 0x2c2cbf2, 0x2c2cc25),
    ('core_five_seconds', 0x2c2cc52, 0x2c2cc7d),
    ('core_deadline_date_compare', 0x2c2cd0a, 0x2c2cd2a),
    ('core_absent_lookup_setup', 0x2c2cd2a, 0x2c2cd65),
    ('core_tree_key_compare', 0x2c2cd65, 0x2c2ce0e),
    ('core_cutoff_fallback', 0x2c2ce0e, 0x2c2ce38),
    ('core_deadline_subfield_compare', 0x2c2ce2b, 0x2c2ce59),
    ('core_entry_and_count', 0x2c2ce59, 0x2c2ce9d),
    ('core_compact_clear', 0x2c2ce9d, 0x2c2ceec),
    ('core_write_and_success', 0x2c2ceec, 0x2c2cf02),
    ('core_time_error', 0x2c2cf17, 0x2c2cf4a),
    ('aggregate_dex_vector', 0x2a8ae6e, 0x2a8aec4),
    ('aggregate_dex_values', 0x2a8aece, 0x2a8af13),
    ('aggregate_lazy_dex_context', 0x2a8af13, 0x2a8af4d),
    ('aggregate_base_values', 0x2a8afae, 0x2a8b008),
    ('aggregate_lazy_base_context', 0x2a8b008, 0x2a8b048),
    ('aggregate_overflow_last', 0x2a8b048, 0x2a8b095),
    ('entry_representation', 0x2db447d, 0x2db449f),
    ('entry_compact_boundary', 0x2db45c6, 0x2db45fa),
    ('entry_tree_keys', 0x2db474a, 0x2db481c),
    ('value_zero_initializer', 0x2422595, 0x24225af),
    ('value_compact_insert_call', 0x242261e, 0x2422661),
    ('compact_search_key_width', 0x24cb815, 0x24cb845),
    ('compact_insert_record_write', 0x24bb43a, 0x24bb460),
    ('dex_lookup_single_key', 0x4716bfe, 0x4716c39),
    ('base_lookup_single_key', 0x4716cde, 0x4716d13),
    ('time_adjust_arguments', 0x162a9a0, 0x162a9cf),
    ('time_adjust_day_split', 0x162aa4d, 0x162aaa2),
    ('ordinal_checked_add', 0x1628f50, 0x1628f5f),
    ('time_error_normal_tag', 0x1567aae, 0x1567ac0),
    ('dex_default_all', 0x44e9f40, 0x44e9f8d),
    ('base_default_all', 0x3d25c00, 0x3d25c32),
    ('dex_once_first_callback', 0x44dd1b0, 0x44dd227),
    ('dex_once_second_callback', 0x44db370, 0x44db3e7),
    ('base_once_first_callback', 0x3ced300, 0x3ced353),
    ('base_once_second_callback', 0x3c4c590, 0x3c4c5e3),
    ('clock_entry_compare', 0x2bdf281, 0x2bdf2c1),
    ('clock_entry_advance', 0x2bdf2c1, 0x2bdf2de),
    ('clock_entry_context', 0x2bdf41b, 0x2bdf448),
    ('clock_entry_conditional_handoff', 0x2bdf448, 0x2bdf49e),
    ('expiry_driver_context', 0x2bdf8f0, 0x2bdf932),
    ('expiry_clock_fields', 0x2be216d, 0x2be217e),
    ('expiry_collection_setup', 0x2be21a2, 0x2be22af),
    ('expiry_iterator_and_presence', 0x2be22c2, 0x2be22f4),
    ('expiry_due_comparison', 0x2be22f4, 0x2be2312),
    ('expiry_enqueue_key', 0x2be2312, 0x2be2375),
    ('expiry_counter_and_clear', 0x2be2375, 0x2be2393),
    ('expiry_forward_key', 0x2be23e0, 0x2be2416),
    ('expiry_reset_guard', 0x2be2498, 0x2be24b3),
    ('expiry_iterator_compact', 0x262eef0, 0x262ef35),
    ('expiry_iterator_tree_value', 0x262f0d1, 0x262f0fd),
    ('expiry_handoff_entry', 0x2bf9910, 0x2bf9958),
    ('expiry_handoff_dex_ids', 0x2bf9b51, 0x2bf9b86),
    ('expiry_handoff_dex_iteration', 0x2bf9b90, 0x2bf9c66),
    ('expiry_handoff_base', 0x2bf9c91, 0x2bf9d0f),
    ('reset_compact_handoff', 0x2dceb77, 0x2dceb9a),
    ('reset_tree_counter', 0x2dced94, 0x2dcedad),
    ('reset_tree_erase', 0x2dcee44, 0x2dcee6c),
    ('reset_compact_counter', 0x24c0efb, 0x24c0f49),
    ('reset_compact_filter', 0x24c0fac, 0x24c0fc7),
    ('reset_compact_length', 0x24c1065, 0x24c1083),
)


def check_digest(data, expected=TARGET_SHA256):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('target SHA-256 mismatch')


def section_offset(secs, va, size, *, executable=False):
    """Translate a fully file-backed VA range; reject NOBITS and ambiguity."""
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid VA range')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               (not executable or s['flags'] & 4) and s['address'] <= va and
               va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('VA range is not unambiguously file-backed')
    sec = matches[0]
    return sec['offset'] + va - sec['address']


def read_va(data, secs, va, size, *, executable=False):
    off = section_offset(secs, va, size, executable=executable)
    result = data[off:off + size]
    if len(result) != size:
        raise ValueError('file-backed range truncated')
    return result


def unique_section(secs, name):
    matches = [s for s in secs if s['name'] == name]
    if len(matches) != 1 or matches[0]['type'] == 8:
        raise ValueError('missing, duplicated, or non-file-backed section')
    return matches[0]


def checked_relocations(data, sec, wanted):
    """Read only selected Elf64_Rela slots; reject malformed and duplicate rows."""
    if sec['type'] != 4 or sec['size'] % 24 or sec['offset'] + sec['size'] > len(data):
        raise ValueError('invalid relocation section')
    out = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        if slot in out:
            raise ValueError('duplicate relocation for selected slot')
        out[slot] = (info & 0xffffffff, info >> 32, addend, off)
    if set(out) != set(wanted):
        raise ValueError('selected relocation missing')
    return out


def symbol_name(data, secs, index):
    if index == 0:
        return ''
    sym = unique_section(secs, '.dynsym')
    names = unique_section(secs, '.dynstr')
    if sym['size'] % 24 or index >= sym['size'] // 24:
        raise ValueError('dynamic symbol index outside section')
    name_off = struct.unpack_from('<I', data, sym['offset'] + index * 24)[0]
    if name_off >= names['size']:
        raise ValueError('dynamic symbol name outside section')
    begin = names['offset'] + name_off
    end = data.find(b'\0', begin, names['offset'] + names['size'])
    if end < 0:
        raise ValueError('unterminated dynamic symbol name')
    return data[begin:end].decode('ascii')


CONDITIONS = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
              's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')


def decode_control(site, raw):
    """Decode the small rel8/rel32 control-transfer subset selected above."""
    if len(raw) < 2:
        raise ValueError('truncated control transfer')
    op = raw[0]
    if 0x70 <= op <= 0x7f or op == 0xeb:
        return ('j' + CONDITIONS[op - 0x70] if op != 0xeb else 'jmp',
                site + 2 + struct.unpack_from('<b', raw, 1)[0], raw[:2])
    if op in (0xe8, 0xe9):
        if len(raw) < 5:
            raise ValueError('truncated relative control transfer')
        return ('call' if op == 0xe8 else 'jmp',
                site + 5 + struct.unpack_from('<i', raw, 1)[0], raw[:5])
    if op == 0x0f and 0x80 <= raw[1] <= 0x8f:
        if len(raw) < 6:
            raise ValueError('truncated conditional transfer')
        return ('j' + CONDITIONS[raw[1] - 0x80],
                site + 6 + struct.unpack_from('<i', raw, 2)[0], raw[:6])
    raise ValueError('unsupported selected control-transfer opcode')


def decode_rip(site, raw, prefix):
    if len(raw) != len(prefix) + 4 or not raw.startswith(prefix):
        raise ValueError('unexpected RIP-relative instruction')
    return site + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def check_direct_call(site, raw, expected):
    op, target, used = decode_control(site, raw)
    if op != 'call' or target != expected:
        raise ValueError('selected direct call changed')
    return used


def decode_immediate(data, secs, site, prefix, fmt):
    width = struct.calcsize(fmt)
    raw = read_va(data, secs, site, len(prefix) + width, executable=True)
    if not raw.startswith(prefix):
        raise ValueError('unexpected immediate instruction')
    return struct.unpack_from(fmt, raw, len(prefix))[0], raw


def check_body(data, secs, start, end, expected_hash):
    if end <= start:
        raise ValueError('invalid selected FDE range')
    body = read_va(data, secs, start, end - start, executable=True)
    digest = hashlib.sha256(body).hexdigest()
    if digest != expected_hash:
        raise ValueError('selected FDE body mismatch')
    return body, digest


def indexed_functions(data, secs):
    _, index = unwind_index(data)
    _, records = eh_frame_records(data, secs)
    indexed = {row['start']: row for row in index}
    selected = {}
    rows = []
    for role, start, expected_end, expected_hash in FDE_PINS:
        matches = [f for f in records if f['start'] == start]
        if len(matches) != 1 or start not in indexed:
            raise ValueError('selected FDE missing or ambiguous')
        f = matches[0]
        if f['fde'] != indexed[start]['fde'] or f['end'] != expected_end:
            raise ValueError('selected FDE/index mismatch')
        body, digest = check_body(data, secs, start, f['end'], expected_hash)
        selected[role] = f
        rows.append((role, hex(start), hex(f['end']),
                     hex(section_offset(secs, start, len(body), executable=True)),
                     hex(f['fde']), hex(f['cie']), '' if f['lsda'] is None else hex(f['lsda']),
                     len(body), digest))
    return selected, rows


def extract_constants(data, secs):
    specs = (
        ('volume_minimum', 0x2c2cb7e, b'\x48\x3d', '<I'),
        ('status_volume', 0x2c2cb96, b'\x66\xc7\x03', '<H'),
        ('present_mask', 0x2c2cba5, b'\x41\xf6\xc5', '<B'),
        ('millisecond_division_magic', 0x2c2cbb6, b'\x48\xb9', '<Q'),
        ('seconds_per_day_division_magic', 0x2c2cbca, b'\x48\xb9', '<Q'),
        ('fast_time_limit', 0x2c2cbdf, b'\x48\xb8', '<Q'),
        ('day_division_magic', 0x2c2cbfc, b'\x48\xb9', '<Q'),
        ('epoch_day_bias', 0x2c2cc0d, b'\x8d\xba', '<I'),
        ('milliseconds_per_second', 0x2c2cc25, b'\x41\x69\xc5', '<I'),
        ('nanoseconds_per_millisecond', 0x2c2cc2f, b'\x41\x69\xc4', '<I'),
        ('delay_seconds', 0x2c2cc6d, b'\xba', '<I'),
        ('status_early', 0x2c2ce4b, b'\x66\xc7\x03', '<H'),
        ('state_map_offset', 0x2c2ce59, b'\x49\x81\xc7', '<I'),
        ('counter_max', 0x2c2ce90, b'\x48\x83\x38', '<B'),
        ('status_counter', 0x2c2ce96, b'\x66\xc7\x03', '<H'),
        ('status_success', 0x2c2cefd, b'\x66\xc7\x03', '<H'),
        ('status_bad_time', 0x2c2cf32, b'\x66\xc7\x03', '<H'),
        ('request_state_time_date_offset', 0x2c2cc5a, b'\x49\x8b\x47', '<B'),
        ('request_state_time_nanos_offset', 0x2c2cc52, b'\x41\x8b\x47', '<B'),
        ('dex_vector_len_offset', 0x2a8ae73, b'\x48\x8b\x87', '<I'),
        ('dex_vector_ptr_offset', 0x2a8ae88, b'\x4c\x8b\xbf', '<I'),
        ('dex_vector_stride', 0x2a8ae8f, b'\x4c\x69\xe8', '<I'),
        ('base_lookup_offset', 0x2a8afb8, b'\x48\x81\xc7', '<I'),
        ('tree_to_compact_below', 0x2db448d, b'\x48\x83\xf8', '<B'),
        ('tree_representation_marker', 0x2db45c6, b'\x48\xbd', '<Q'),
        ('compact_threshold_minus_one', 0x2db45ef, b'\x49\x83\x7f\x18', '<B'),
        ('lookup_key_bytes', 0x24cb819, b'\xba', '<I'),
        ('compact_record_stride', 0x24c0f40, b'\x49\x83\xc0', '<B'),
        ('seconds_per_day', 0x162aa6b, b'\x48\x69\xc2', '<I'),
        ('nanoseconds_per_second', 0x162a9c9, b'\x81\xfe', '<I'),
        ('ordinal_year_addend_bits', 0x162904b, b'\x81\xc6', '<I'),
        ('ordinal_year_unsigned_floor', 0x1629051, b'\x81\xfe', '<I'),
        ('expiry_handoff_selector', 0x2be23fb, b'\xba', '<I'),
        ('expiry_handoff_flag', 0x2be2408, b'\x41\xb8', '<I'),
        ('expiry_state_time_date_offset', 0x2be2172, b'\x45\x8b\x61', '<B'),
        ('expiry_state_time_seconds_offset', 0x2be2176, b'\x41\x8b\x69', '<B'),
        ('expiry_state_time_nanos_offset', 0x2be217a, b'\x45\x8b\x79', '<B'),
        ('expiry_state_previous_date_offset', 0x2be249d, b'\x8b\x43', '<B'),
    )
    values, rows = {}, []
    for name, site, prefix, fmt in specs:
        value, raw = decode_immediate(data, secs, site, prefix, fmt)
        values[name] = value
        rows.append((name, hex(site), hex(section_offset(secs, site, len(raw))), raw.hex(), value, hex(value)))
    site = 0x2c2cb8e
    raw = read_va(data, secs, site, 8, executable=True)
    addr = decode_rip(site, raw, b'\xf2\x0f\x5e\x05')
    literal = read_va(data, secs, addr, 8)
    values['volume_divisor'] = struct.unpack('<d', literal)[0]
    rows.append(('volume_divisor_binary64', hex(addr), hex(section_offset(secs, addr, 8)),
                 literal.hex(), values['volume_divisor'], ''))
    for name, site, prefix in (
            ('fallback_date', 0x2c2ce16, b'\x4c\x8d\x25'),
            ('fallback_seconds', 0x2c2ce24, b'\x48\x8d\x0d'),
            ('fallback_nanoseconds', 0x2c2ce1d, b'\x48\x8d\x05')):
        raw = read_va(data, secs, site, 7, executable=True)
        addr = decode_rip(site, raw, prefix)
        literal = read_va(data, secs, addr, 4)
        values[name] = struct.unpack('<I', literal)[0]
        rows.append((name, hex(addr), hex(section_offset(secs, addr, 4)), literal.hex(),
                     values[name], hex(values[name])))
    # These exact shifts combine with the three extracted multiply constants in
    # time_fields_from_magic. The checks are independent of disassembler text.
    for site, expected in (
            (0x2c2cbb2, b'\x48\xc1\xe8\x03'),
            (0x2c2cbc6, b'\x49\xc1\xed\x04'),
            (0x2c2cbf8, b'\x48\xc1\xe8\x0a'),
            (0x2c2cc09, b'\x48\xc1\xea\x06'),
            (0x2c2cc36, b'\x48\xc1\xed\x06')):
        if read_va(data, secs, site, len(expected), executable=True) != expected:
            raise ValueError('time quotient shift changed')
    return values, rows


def state_writes(data, secs):
    specs = (
        ('clear_existing_date', 0x2c2cee3, b'\xc7\x43\x08\x00\x00\x00\x00', 8, 4, 'zero'),
        ('store_deadline_date', 0x2c2cef1, b'\x89\x68\x08', 8, 4, 'ebp'),
        ('store_deadline_time', 0x2c2cef4, b'\x4c\x89\x68\x0c', 12, 8, 'r13'),
    )
    rows = []
    for label, site, expected, displacement, width, source in specs:
        raw = read_va(data, secs, site, len(expected), executable=True)
        if raw != expected:
            raise ValueError('selected state write changed')
        rows.append((label, hex(site), hex(section_offset(secs, site, len(raw))),
                     raw.hex(), displacement, width, source))
    return rows


def expiry_writes(data, secs):
    specs = (
        ('increment_saturating_counter', 0x2be2375,
         bytes.fromhex('498b450048ffc048c7c1ffffffff480f44c149894500')),
        ('clear_due_date', 0x2be238b, bytes.fromhex('41c7450800000000')),
        ('reset_tree_counter', 0x2dced98, bytes.fromhex('49c744c30800000000')),
        ('reset_compact_counter_a', 0x24c0f2f, bytes.fromhex('49c742f800000000')),
        ('reset_compact_counter_b', 0x24c0fac, bytes.fromhex('49c7431800000000')),
    )
    rows = []
    for label, site, expected in specs:
        raw = read_va(data, secs, site, len(expected), executable=True)
        if raw != expected:
            raise ValueError('selected expiry write changed')
        rows.append((label, hex(site), hex(section_offset(secs, site, len(raw))), raw.hex()))
    return rows


def lazy_descriptors(data, secs):
    """Extract the two selected once cells and their callback vtables."""
    specs = (
        ('dex', 0x2a8af13, b'\x48\x8d\x05', 0x64fda80,
         0x2a8af28, 0x64fdaf8, 0x2a8af37, 0x648c498,
         (0x44e9f40, 0x44dd1b0, 0x44db370)),
        ('base', 0x2a8b008, b'\x48\x8d\x0d', 0x64fd958,
         0x2a8b01b, 0x64fd9a8, 0x2a8b022, 0x6476b20,
         (0x3d25c00, 0x3ced300, 0x3c4c590)),
    )
    descriptors = []
    expectations = {}
    for role, global_site, prefix, expected_global, state_site, expected_state, table_site, expected_table, targets in specs:
        global_va = decode_rip(global_site, read_va(data, secs, global_site, 7, executable=True), prefix)
        state_va = decode_rip(state_site, read_va(data, secs, state_site, 7, executable=True), b'\x48\x8d\x3d')
        table_va = decode_rip(table_site, read_va(data, secs, table_site, 7, executable=True), b'\x48\x8d\x0d')
        if (global_va, state_va, table_va) != (expected_global, expected_state, expected_table):
            raise ValueError('selected lazy descriptor changed')
        header = read_va(data, secs, table_va, 24)
        if struct.unpack('<QQQ', header) != (0, 8, 8):
            raise ValueError('selected callback vtable header changed')
        state_raw = read_va(data, secs, state_va, 4)
        descriptors.append((role, hex(global_va), hex(section_offset(secs, global_va, 8)),
                            hex(state_va), state_raw.hex(), struct.unpack('<I', state_raw)[0],
                            hex(table_va), header.hex()))
        for suffix, slot, target in zip(('initializer', 'once_first', 'once_second'),
                                        (global_va, table_va + 24, table_va + 32), targets):
            if slot in expectations:
                raise ValueError('duplicate selected lazy relocation slot')
            expectations[slot] = (role + '_' + suffix, target)
    return descriptors, expectations


def check_lazy_relocations(relocations, expectations):
    rows = []
    for slot, (role, target) in sorted(expectations.items()):
        if slot not in relocations:
            raise ValueError('missing lazy relocation')
        rtype, sym, addend, file_offset = relocations[slot]
        if (rtype, sym, addend) != (8, 0, target):
            raise ValueError('lazy relocation does not match selected callback')
        rows.append((role, hex(slot), rtype, hex(addend), hex(file_offset)))
    return rows


def signed32(v):
    if not 0 <= v <= 0xffffffff:
        raise ValueError('expected unsigned 32-bit value')
    return v if v < 0x80000000 else v - 0x100000000


def packed_later(deadline, cutoff):
    """The selected date/seconds/nanoseconds compares; not a date decoder."""
    if len(deadline) != 3 or len(cutoff) != 3:
        raise ValueError('expected three fields')
    left = (signed32(deadline[0]), deadline[1], deadline[2])
    right = (signed32(cutoff[0]), cutoff[1], cutoff[2])
    if any(not 0 <= v <= 0xffffffff for v in deadline[1:] + cutoff[1:]):
        raise ValueError('seconds and nanoseconds must be unsigned dwords')
    return left > right


def ordinal_year_gate(c, candidate):
    """Evaluate only the final 32-bit year guard in the ordinal helper."""
    if not -(1 << 31) <= candidate < (1 << 31):
        raise ValueError('year outside signed dword')
    adjusted = (candidate + signed32(c['ordinal_year_addend_bits'])) & 0xffffffff
    return adjusted >= c['ordinal_year_unsigned_floor']


def due_at(deadline, now):
    """Selected scan predicate over already decoded date/time fields."""
    return deadline[0] != 0 and not packed_later(deadline, now)


def expiry_case(deadline, now, counter, previous_marker):
    """Synthetic normal-return expiry and reset for one selected record."""
    if not 0 <= counter < 1 << 64:
        raise ValueError('out-of-range synthetic counter')
    due = due_at(deadline, now)
    counter_after_expiry = saturating_add_on_return(counter, 1) if due else counter
    date_after_expiry = 0 if due else deadline[0]
    reset = signed32(previous_marker) < signed32(now[0])
    removed = bool(reset and date_after_expiry == 0)
    return due, reset, 0 if reset else counter_after_expiry, date_after_expiry, removed


def abstract_case(c, volume, present, time_valid, ordering, found, counter):
    """Synthetic decision model; helpers, storage validity and panics are inputs."""
    if not 0 <= volume < 1 << 64 or not 0 <= counter < 1 << 64:
        raise ValueError('out-of-range synthetic input')
    if not 0 <= present < 1 << 64 or time_valid not in (0, 1) or found not in (0, 1):
        raise ValueError('invalid synthetic selector')
    if ordering not in (-1, 0, 1):
        raise ValueError('invalid synthetic ordering')
    if volume < c['volume_minimum']:
        return c['status_volume'], 'no_map_operation'
    if not present & c['present_mask']:
        return c['status_success'], 'clear_date' if found else 'leave_map'
    if not time_valid:
        return c['status_bad_time'], 'no_map_operation'
    if ordering <= 0:
        return c['status_early'], 'no_map_operation'
    if counter > c['counter_max']:
        return c['status_counter'], 'entry_materialized_no_date_store'
    return c['status_success'], 'store_date_and_time'


def saturating_add_on_return(left, right):
    """Model one add assuming the observed overflow hook returns normally."""
    if not 0 <= left < 1 << 64 or not 0 <= right < 1 << 64:
        raise ValueError('out-of-range synthetic addend')
    return min(left + right, (1 << 64) - 1)


def time_fields_from_magic(c, raw_milliseconds):
    """Evaluate the selected unsigned arithmetic, not the ordinal helper."""
    if not 0 <= raw_milliseconds <= c['fast_time_limit']:
        raise ValueError('outside selected fast-conversion branch')
    seconds = (((raw_milliseconds >> 3) * c['millisecond_division_magic']) >> 64) >> 4
    days_from_seconds = ((seconds * c['seconds_per_day_division_magic']) >> 64) >> 6
    direct_days = (((raw_milliseconds >> 10) * c['day_division_magic']) >> 64) >> 6
    remainder_seconds = seconds - days_from_seconds * c['seconds_per_day']
    remainder_ms = raw_milliseconds - seconds * c['milliseconds_per_second']
    return direct_days, days_from_seconds, remainder_seconds, remainder_ms * c['nanoseconds_per_millisecond']


def source_locations(data, secs):
    """Read three Location pointers used by the selected aggregate's hooks."""
    specs = (
        ('dex_overflow', 0x2a8af54, 0x6493948, b'l1/src/qtys/impl_ntl.rs'),
        ('base_first_overflow', 0x2a8b048, 0x6492e68, b'l1/src/scaled_vlm.rs'),
        ('base_second_overflow', 0x2a8b06d, 0x6483fe0, b'l1/src/raw_vlm.rs'),
    )
    reloc = checked_relocations(data, unique_section(secs, '.rela.dyn'),
                                {slot for _, _, slot, _ in specs})
    rows = []
    for role, site, slot, expected in specs:
        raw = read_va(data, secs, site, 7, executable=True)
        if decode_rip(site, raw, b'\x48\x8d\x35') != slot:
            raise ValueError('source location reference changed')
        rtype, symbol, path_va, rela_off = reloc[slot]
        length, line, column = struct.unpack('<QII', read_va(data, secs, slot + 8, 16))
        if (rtype, symbol, length) != (8, 0, len(expected)) or not line or not column:
            raise ValueError('source location relocation or fields changed')
        path = read_va(data, secs, path_va, length)
        if path != expected:
            raise ValueError('source location path changed')
        rows.append((role, hex(site), raw.hex(), hex(slot), hex(rela_off), hex(path_va),
                     length, line, column, path.decode('ascii')))
    return rows


def dispatch_context(data, secs):
    """Recheck one previously mapped serializer/execute index as context.

    The execute-name join is inferred: the three tables share the index idiom,
    but the handoff from deserialization to execute is not established here.
    These short earlier-known sites are not added to the selected FDE set.
    """
    index = 18
    name_slot = 0x644cc40 + 16 * index
    rtype, symbol, literal, rela_off = checked_relocations(
        data, unique_section(secs, '.rela.dyn'), {name_slot})[name_slot]
    length = struct.unpack('<Q', read_va(data, secs, name_slot + 8, 8))[0]
    if (rtype, symbol, length) != (8, 0, 14):
        raise ValueError('variant name relocation or length changed')
    name = read_va(data, secs, literal, length)
    if name != b'scheduleCancel':
        raise ValueError('variant name changed')
    specs = (
        ('serializer', 0x2bc95f7, 0x60946c, 0x2bcaeba, None, None, b''),
        ('execute_r12', 0x2bdbb10, 0x60a360, 0x2bdc4f1, 0x2bdc514, 0x283c900,
         bytes.fromhex('4983c408418b451089442410410f1045000f290424488d7c24704889e24c89e64c89f9')),
        ('execute_r15', 0x2bda82d, 0x609f00, 0x2bdae46, 0x2bdae57, 0x2c06530,
         bytes.fromhex('498b4f084d8b47104889e74c89ee4c89e2')),
    )
    rows = []
    for role, site, expected_table, expected_arm, call_site, target, prefix in specs:
        raw = read_va(data, secs, site, 31, executable=True)
        if (raw[:2] != b'\x48\x2d' or raw[6:7] != b'\xb9' or
                raw[11:15] != b'\x48\x0f\x43\xc8' or
                raw[22:] != b'\x48\x63\x0c\x88\x48\x01\xc1\xff\xe1'):
            raise ValueError('dispatch context idiom changed')
        bias = struct.unpack_from('<I', raw, 2)[0]
        default = struct.unpack_from('<I', raw, 7)[0]
        table = decode_rip(site + 15, raw[15:22], b'\x48\x8d\x05')
        if (bias, default, table) != (0x86, 0x14, expected_table):
            raise ValueError('dispatch context bias or table changed')
        slot = table + 4 * index
        slot_raw = read_va(data, secs, slot, 4)
        arm = table + struct.unpack('<i', slot_raw)[0]
        if arm != expected_arm:
            raise ValueError('dispatch context table entry changed')
        if call_site is None:
            lea_site = arm + 0x42
            lea = read_va(data, secs, lea_site, 7, executable=True)
            store = read_va(data, secs, lea_site + 7, 14, executable=True)
            if (decode_rip(lea_site, lea, b'\x48\x8d\x05') != literal or
                    store != b'\x48\x89\x44\x24\x30\x48\xc7\x44\x24\x38\x0e\x00\x00\x00'):
                raise ValueError('serializer name store changed')
            arm_bytes = read_va(data, secs, arm, lea_site + 21 - arm, executable=True)
            call_hex = ''
        else:
            arm_bytes = read_va(data, secs, arm, call_site - arm, executable=True)
            if arm_bytes != prefix:
                raise ValueError('dispatch arm prefix changed')
            call_hex = check_direct_call(call_site,
                read_va(data, secs, call_site, 5, executable=True), target).hex()
        rows.append((role, hex(site), raw.hex(), hex(bias), default, index, hex(bias + index),
                     hex(table), hex(slot), hex(section_offset(secs, slot, 4)), slot_raw.hex(),
                     hex(arm), arm_bytes.hex(), '' if call_site is None else hex(call_site),
                     call_hex, '' if target is None else hex(target), hex(name_slot),
                     hex(rela_off), hex(literal), length, name.decode('ascii')))
    return rows


def tsv(header, rows):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return buf.getvalue().encode('utf-8')


def generate_evidence(data):
    check_digest(data)
    secs = sections(data)
    selected, fde_rows = indexed_functions(data, secs)
    constants, constant_rows = extract_constants(data, secs)
    write_rows = state_writes(data, secs)
    expiry_write_rows = expiry_writes(data, secs)
    lazy_rows, lazy_expectations = lazy_descriptors(data, secs)
    locations = source_locations(data, secs)
    dispatch_rows = dispatch_context(data, secs)

    branch_rows = []
    for role, sites in BRANCHES.items():
        f = selected[role]
        for site in sites:
            if not f['start'] <= site < f['end']:
                raise ValueError('selected branch outside declared FDE')
            raw = read_va(data, secs, site, 6, executable=True)
            op, target, used = decode_control(site, raw)
            if not f['start'] <= target < f['end']:
                raise ValueError('selected local branch leaves FDE')
            branch_rows.append((role, hex(site), hex(section_offset(secs, site, len(used))),
                                used.hex(), op, hex(target)))

    calls = []
    for role, site, expected in DIRECT_CALLS:
        raw = read_va(data, secs, site, 5, executable=True)
        used = check_direct_call(site, raw, expected)
        calls.append((role, hex(site), hex(section_offset(secs, site, len(used))),
                      used.hex(), 'direct', hex(expected), '', '', '', ''))
    slots = ({slot for _, _, slot in INDIRECT_CALLS} |
             {entry[-1] for entry in REGISTER_CALLS} | set(lazy_expectations))
    reloc = checked_relocations(data, unique_section(secs, '.rela.dyn'), slots)
    lazy_reloc_rows = check_lazy_relocations(reloc, lazy_expectations)
    for role, site, expected_slot in INDIRECT_CALLS:
        raw = read_va(data, secs, site, 6, executable=True)
        slot = decode_rip(site, raw, b'\xff\x15')
        if slot != expected_slot:
            raise ValueError('selected indirect slot changed')
        rtype, sym, addend, rela_off = reloc[slot]
        if rtype not in (6, 8) or (rtype == 8 and sym != 0):
            raise ValueError('unsupported selected relocation')
        calls.append((role, hex(site), hex(section_offset(secs, site, 6)), raw.hex(),
                      'rip_slot', hex(slot), rtype, hex(addend), hex(rela_off), symbol_name(data, secs, sym)))

    register_calls = []
    for role, load_site, prefix, call_site, expected_call, expected_slot in REGISTER_CALLS:
        load = read_va(data, secs, load_site, 7, executable=True)
        slot = decode_rip(load_site, load, prefix)
        call = read_va(data, secs, call_site, len(expected_call), executable=True)
        if slot != expected_slot or call != expected_call:
            raise ValueError('selected register-indirect call changed')
        rtype, sym, addend, rela_off = reloc[slot]
        register_calls.append((role, hex(load_site), load.hex(), hex(call_site), call.hex(),
                               hex(slot), rtype, hex(addend), hex(rela_off), symbol_name(data, secs, sym)))

    windows = []
    for role, start, end in WINDOWS:
        owners = [name for name, f in selected.items() if f['start'] <= start < end <= f['end']]
        if len(owners) != 1:
            raise ValueError('window has no unique selected FDE owner')
        raw = read_va(data, secs, start, end - start, executable=True)
        windows.append((role, owners[0], hex(start), hex(end),
                        hex(section_offset(secs, start, len(raw))), raw.hex()))

    bodies = []
    for role, start, end, _ in FDE_PINS:
        raw = read_va(data, secs, start, end - start, executable=True)
        bodies.append((role, hex(start), hex(end), raw.hex()))

    variants = []
    levels = (0, constants['volume_minimum'] - 1, constants['volume_minimum'],
              constants['volume_minimum'] + 1, (1 << 64) - 1)
    counts = (0, constants['counter_max'], constants['counter_max'] + 1)
    for volume, present, valid, ordering, found, counter in itertools.product(
            levels, (0, 1), (0, 1), (-1, 0, 1), (0, 1), counts):
        status, mutation = abstract_case(constants, volume, present, valid, ordering, found, counter)
        variants.append((volume, present, valid, ordering, found, counter, hex(status), mutation))

    time_rows = []
    billion = constants['nanoseconds_per_second']
    day = constants['seconds_per_day']
    delay = constants['delay_seconds']
    for now_seconds, nanos, delta_ns in itertools.product(
            (0, day - delay - 1, day - delay, day - 1),
            (0, billion - 1), (-1, 0, 1)):
        cutoff_ns = now_seconds * billion + nanos + delay * billion
        candidate_ns = cutoff_ns + delta_ns
        cutoff_day, cutoff_remainder = divmod(cutoff_ns, day * billion)
        candidate_day, candidate_remainder = divmod(candidate_ns, day * billion)
        cutoff = (cutoff_day + 10, cutoff_remainder // billion, cutoff_remainder % billion)
        candidate = (candidate_day + 10, candidate_remainder // billion, candidate_remainder % billion)
        time_rows.append((now_seconds, nanos, delta_ns, *cutoff, *candidate,
                          str(packed_later(candidate, cutoff)).lower()))

    top = (1 << 64) - 1
    sums = [(left, right, saturating_add_on_return(left, right))
            for left, right in itertools.product((0, 1, top - 1, top), repeat=2)]
    sec_ms = constants['milliseconds_per_second']
    day_ms = constants['seconds_per_day'] * sec_ms
    limit = constants['fast_time_limit']
    inputs = sorted({0, 1, sec_ms - 1, sec_ms, sec_ms + 1,
                     day_ms - 1, day_ms, day_ms + 1} |
                    {limit * i // 256 for i in range(257)})
    arithmetic = [(x, *time_fields_from_magic(constants, x)) for x in inputs]
    bias = signed32(constants['ordinal_year_addend_bits'])
    minimum_year = signed32(constants['ordinal_year_unsigned_floor']) - bias
    maximum_year = -1 - bias
    years = sorted({minimum_year - 1, minimum_year, minimum_year + 1, -1, 0, 1,
                    maximum_year - 1, maximum_year, maximum_year + 1})
    year_rows = [(y, str(ordinal_year_gate(constants, y)).lower()) for y in years]

    billion = constants['nanoseconds_per_second']
    now = (100, 100, billion // 2)
    deadlines = ((0, 0, 0), (99, constants['seconds_per_day'] - 1, billion - 1),
                 (100, 99, 0), (100, 100, billion // 2 - 1), now,
                 (100, 100, billion // 2 + 1), (100, 101, 0), (101, 0, 0))
    expiry_rows = []
    for deadline, counter, marker in itertools.product(deadlines, (0, 9, 10, top), (99, 100, 101)):
        due, reset, after_count, after_date, removed = expiry_case(deadline, now, counter, marker)
        expiry_rows.append((*deadline, *now, counter, marker, str(due).lower(), str(reset).lower(),
                            after_count, after_date, str(removed).lower()))

    files = {
        'functions.tsv': tsv(('role', 'start_va', 'end_va_exclusive', 'file_offset', 'fde_va',
                              'cie_va', 'lsda_va', 'body_size', 'body_sha256'), fde_rows),
        'body-bytes.tsv': tsv(('role', 'start_va', 'end_va_exclusive', 'body_hex'), bodies),
        'branches.tsv': tsv(('role', 'site_va', 'file_offset', 'instruction_hex', 'operation', 'target_va'), branch_rows),
        'calls.tsv': tsv(('role', 'site_va', 'file_offset', 'instruction_hex', 'kind', 'target_or_slot_va',
                          'rela_type', 'rela_addend', 'rela_file_offset', 'dynamic_symbol'), calls),
        'register-calls.tsv': tsv(('role', 'load_va', 'load_hex', 'call_va', 'call_hex', 'slot_va',
                                   'rela_type', 'rela_addend', 'rela_file_offset', 'dynamic_symbol'), register_calls),
        'windows.tsv': tsv(('role', 'fde_owner', 'start_va', 'end_va_exclusive', 'file_offset', 'bytes_hex'), windows),
        'constants.tsv': tsv(('name', 'source_va', 'file_offset', 'bytes_hex', 'value', 'value_hex'), constant_rows),
        'state-writes.tsv': tsv(('role', 'site_va', 'file_offset', 'instruction_hex', 'value_offset',
                                 'width_bytes', 'source'), write_rows),
        'expiry-writes.tsv': tsv(('role', 'site_va', 'file_offset', 'instruction_hex'), expiry_write_rows),
        'lazy-defaults.tsv': tsv(('role', 'global_va', 'global_file_offset', 'once_state_va',
                                  'once_state_initial_hex', 'once_state_initial_u32', 'vtable_va',
                                  'vtable_header_hex'), lazy_rows),
        'lazy-relocations.tsv': tsv(('role', 'slot_va', 'rela_type', 'rela_addend', 'rela_file_offset'),
                                    lazy_reloc_rows),
        'source-locations.tsv': tsv(('role', 'reference_va', 'reference_hex', 'location_va',
                                     'rela_file_offset', 'path_va', 'length', 'line', 'column', 'path'), locations),
        'dispatch-context.tsv': tsv(('family', 'bias_site_va', 'idiom_hex', 'bias', 'default_index',
                                     'selected_index', 'derived_tag', 'table_va', 'table_slot_va',
                                     'table_slot_file_offset', 'slot_hex', 'arm_va', 'arm_prefix_hex',
                                     'first_call_va', 'first_call_hex', 'first_call_target_va',
                                     'serializer_variant_slot_va', 'serializer_variant_rela_file_offset',
                                     'serializer_name_va', 'serializer_name_length', 'serializer_name'), dispatch_rows),
        'decision-vectors.tsv': tsv(('volume', 'present', 'time_valid', 'ordering_to_cutoff',
                                     'entry_found_for_clear', 'materialized_counter', 'status', 'map_action'), variants),
        'time-vectors.tsv': tsv(('now_seconds', 'now_nanos', 'deadline_delta_ns_from_cutoff',
                                 'cutoff_day', 'cutoff_seconds', 'cutoff_nanos', 'deadline_day',
                                 'deadline_seconds', 'deadline_nanos', 'strictly_later'), time_rows),
        'addition-vectors.tsv': tsv(('left', 'right', 'saturated_sum_if_hook_returns'), sums),
        'time-arithmetic-vectors.tsv': tsv(('input_milliseconds', 'direct_days', 'days_from_seconds',
                                            'seconds_of_day', 'nanoseconds'), arithmetic),
        'ordinal-year-vectors.tsv': tsv(('candidate_year', 'passes_final_year_guard'), year_rows),
        'expiry-vectors.tsv': tsv(('deadline_date', 'deadline_seconds', 'deadline_nanos',
                                   'now_date', 'now_seconds', 'now_nanos', 'counter_before', 'previous_marker',
                                   'due', 'reset_after_handoff', 'counter_after', 'date_after', 'removed'), expiry_rows),
    }
    summary = {
        'artifact_sha256': hashlib.sha256(data).hexdigest(),
        'coordinate_system': 'linked ELF virtual addresses; file offsets are zero-based',
        'fde_count_selected': len(fde_rows),
        'branches_selected': len(branch_rows),
        'direct_calls_selected': len(DIRECT_CALLS),
        'indirect_calls_selected': len(INDIRECT_CALLS),
        'register_calls_selected': len(register_calls),
        'windows_selected': len(windows),
        'state_writes_selected': len(write_rows),
        'expiry_writes_selected': len(expiry_write_rows),
        'lazy_defaults_selected': len(lazy_rows),
        'lazy_relocations_selected': len(lazy_reloc_rows),
        'source_locations_selected': len(locations),
        'dispatch_context_rows': len(dispatch_rows),
        'decision_vectors_synthetic': len(variants),
        'time_vectors_synthetic': len(time_rows),
        'addition_vectors_synthetic': len(sums),
        'time_arithmetic_vectors_synthetic': len(arithmetic),
        'ordinal_year_vectors_synthetic': len(year_rows),
        'expiry_vectors_synthetic': len(expiry_rows),
        'limitations': 'Selected static evidence and synthetic predicates; no captured execution or full helper closure.',
    }
    files['summary.json'] = (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode('utf-8')
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    data = BINARY.read_bytes()
    files = generate_evidence(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, payload in sorted(files.items()):
        (args.out / name).write_bytes(payload)
    print('Generated %d deterministic evidence files.' % len(files))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error, UnicodeError) as exc:
        print('schedule-cancel evidence error: %s' % exc, file=sys.stderr)
        raise SystemExit(1)

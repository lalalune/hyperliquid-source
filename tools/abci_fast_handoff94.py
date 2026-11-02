#!/usr/bin/env python3
"""Reproduce selected node #94 fast-worker handoff and guarded-update evidence.

All addresses are linked ELF virtual addresses. The selected FDEs and boundary
windows are an explicit research scope, not a whole-binary function census.
"""
import argparse
import bisect
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import unwind_index  # noqa: E402
from fde_extents import eh_frame_records, uleb  # noqa: E402

ARTIFACT = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# FDE-described extents are independently pinned, including all bytes in each
# extent. They are not a claim that unwind data provides complete functions.
OWNED = (
    ('launch_builder', 0x1f85740, 0x1f85d71, 'ae902a1e41b78b2b8cb58f9b694d4d218e893a1cfb8fee9aa5ce9d8b6040c517'),
    ('closure_entry', 0x1f9a9f0, 0x1f9ac00, 'e7e261c2a8648c7d1144fbdcd5c9a0c9e48a7ece8ad02e95fcbc62d1d95710fe'),
    ('worker_adapter', 0x432f5f0, 0x432f679, '8c8628d413a4a6241976f04d7d8627d8ffde4e42d14408ea7b616331ec9efee9'),
    ('replace_three_fields', 0x4523e00, 0x452422b, '53b04c0f997cc776a8aa98a99b4aa8cb0fe92dee97f1ec75ab5c78eb376a4bf4'),
    ('compare_three_fields', 0x4526490, 0x45266fd, '0c01d33950a1ab661d21def0b5c15d03f70a30a25e55bada08f1bb1142eeab85'),
    ('replace_five_byte_list', 0x4527d40, 0x4527f5f, '1e8863db47a03adbba4f1516177d03786f428c89969dee2c67a854a688d0f441'),
    ('refresh_guard', 0x45292b0, 0x45294ca, '33ad3f9edae326cf035bf0ec0880c63dd56536bf1c8de200770d6ab71b3519fb'),
    ('worker_constructor', 0x4548b40, 0x4548cb6, '12ae1b128c5354786b733f185034daad4fcede1f76e8b06381ee23ae99688a67'),
    ('two_tree_last_words', 0x4b31790, 0x4b31a67, '2c323d4f48b4c5aa5647dd8a1a99657e216b4b4c9bb9c291d3d5cd8047460866'),
)

# Pinned LSDA headers and call-site tables. Action records are not interpreted.
LSDA_DIGESTS = {
    'launch_builder': 'cff67cbb2d3a84fe0081e0f756ea241cf397aa3ae1fc14e13b0745e07ab5b737',
    'closure_entry': '2777fbf061c9950fe38548a8aef2448506501d3c969ea8af6ac0b89d4c0fd2d1',
    'worker_adapter': '430eb64e14e61e13d35be42d603db232e6064d940b36be415b72825ea725b4e2',
    'replace_three_fields': '6dd2baa90cc47936c98bd80be27316eb90a3f21514ee7eaa86547e8a02463243',
    'compare_three_fields': '9ad61c3bc787997764c19da3d651735ad5d8d44c5603c903c3384f0463546496',
    'replace_five_byte_list': 'f663dd910b573312836ba5338d089abdd1df6f593d56f008ba0881937491e12c',
    'refresh_guard': '0fe56acedf3a62f1748a2107ed83b3da4fa7dd7cb59111cce753afd19beed7bc',
    'worker_constructor': '021e95931ac243bfeb22649c05cb918382f91e4b11a197dfa29c0f774a8c74a9',
    'two_tree_last_words': '997a3066c031fe8a3d92b79dcf3c1c913e61e7d164113a0da813005e74d2d833',
}

# New short connection windows in previously investigated enclosing FDEs.
# The earlier loader call and existing GOT/call sites are not reproduced here.
BOUNDARIES = (
    ('parent_sret', 0x226c2ff, 0x226c31e, '62bffe48e9d2dfdba3867a08923ed13b7709dc4046102230b1719cf853a10dff'),
    ('state_result_copy', 0x226c9b8, 0x226c9d5, 'fa195e70e2872e9d2ee31056f13c6a954b088bda2ac54d24cf37eb733a71663c'),
    ('config_input', 0x226cd83, 0x226cd98, '595b91392f636d62091aa3a78a4acb3d864ff987a9f49f824501f42a9f50d18e'),
    ('state_pair_and_constructor', 0x226d1f6, 0x226d27b, '56b1f7694fdebea7e741aa0d4f8bb3f49b94f759fc634628bc2a72b499fe3747'),
    ('state_parent_copy', 0x226fd20, 0x226fd3e, 'b425ab46c87a9b31f661ac00ed0990fa66ed29fc7231029d04a2964728149651'),
    ('object_parent_copy', 0x226fd5e, 0x226fd75, '0e98d908ea710f48df8d5c938cd7734696636283550ef8f26d205f6981e1a97c'),
    ('aggregate_copy', 0x226fe17, 0x226fe37, 'dfe9906473bf780e7e716ec5ca251b2e75bf2cb71b86889c2eefe870ebe85d30'),
    ('aggregate_move_a', 0x226ce3d, 0x226ce5f, '11b808ecff2eea166b90f4563c8992569f4ab5a6496aa68527e4d13b69f1f89e'),
    ('aggregate_move_b', 0x226cee8, 0x226cefb, '8d0c6f4f58810b9caa2e6f756f90f94bcf95485d46238765d2935e7f34d5a53f'),
    ('aggregate_tail', 0x226ed1d, 0x226ed35, 'b37d6d59a3f78b25e1ecf4e655162ecf6665d821f9390b5bafe30d84692a287c'),
    ('worker_parent_base', 0x226f13d, 0x226f155, '81f754031a3c3fe0eba44fd7cc26c5bd6d2f869b8a6d3dbe9433b64366099944'),
    ('worker_parent_slot', 0x226f1dd, 0x226f1f5, '675258c4f5d09e0a1b91d6caa0253e52f2b5a86bf4ca45675311c2e60a55bd87'),
    ('parent_destination', 0x226f2d7, 0x226f2df, 'debb5c7271e5e195a3a7b6d5b6f5dac9ca4f2aecedd1775b6bc675518e944940'),
    ('parent_return', 0x226f404, 0x226f416, '7a33ddc4d25dd802874267ba464094175c55d27554ad937b4225cc149c3e13ec'),
    ('outer_poll_result', 0x2276920, 0x227694c, '1c7337c7b9f92056e90af399629bbf1f24148fccd9e2299799f432f7fd621b35'),
    ('outer_parent_save', 0x227696b, 0x2276988, '617e44619fff2bb392f11ee266192911807ad1469a80aa4405f7f7a518a95359'),
    ('outer_spawn_parent', 0x22780a0, 0x22780dd, '604fa4ffd5e77dd1be6a69908fad7bb91ed722d870247f7812c5a8b3dd8d0c41'),
    ('outer_spawn_args', 0x2278149, 0x2278158, '7ac3901caa28203ea4b459da9c8d5a8686a4240c0c2125e5c571eb43bd7b43bf'),
    ('fast_worker_object', 0x474c01b, 0x474c02a, '1a7a358718ff1a7baf7a4609b8fb283d949e74dc6d8ef45471175c277d676837'),
    ('fast_worker_args', 0x474c72b, 0x474c75a, '15c527e876f3b7efb98ed231f898fac5a501d37c67463189592b37c7d2fa79b7'),
    ('bridge_arguments', 0x2236b11, 0x2236b1f, 'a279877dc4660dbcc665a4d0fb8813060107c073ae971ff2c6f0c14a9e33a34d'),
    ('bridge_handoff', 0x2236bf0, 0x2236c31, '86fa9129c767c68552d0ea5724f37d84c4f07a7ffebbeb51f5a4cee192b65e2a'),
    ('guard_arguments', 0x45271ae, 0x45271bb, '4473898a1bb9cff7d69341e9af28706e497ff22e302f7cced7f71da00099d43d'),
    ('guard_acquire', 0x45271cb, 0x452720b, '8dc01cf4779a803d1a20962502aff628e45520c77bb9a5340dad5d25d783d93e'),
    ('guard_call_release', 0x452724f, 0x452727d, '7452a29829301a73a057fbb34f18a89e46969165784b8948bf935ad0d9128f65'),
    ('update_tag', 0x4548ce0, 0x4548d19, 'c56be2896ebc49b358f11dcf200b717cbe29cdf94cb99d3ecfd61ef9dd3118b0'),
    ('timer_marker_gate', 0x4548d42, 0x4548d50, '50a814af7e9bd96ee54eec28f0603a924efa89ae60efb2cf110ab383d599e505'),
    ('timer_compare_gate', 0x4548dd5, 0x4548de1, '48aa0793ad473dd21ece65ef657e948816054511fd3e0c5cf9bc2412b39df7c6'),
    ('timer_skip_target', 0x4548ec6, 0x4548ed7, '09f0239a2f769ed30a3c95cd28e5ec3a103a6e6a5c7b0f5355fe9e9572a83f6a'),
    ('update_refresh', 0x4548dfd, 0x4548e2e, '4729e59c457b051d28b19535e0c45bd98f53b74532779fa884bc0bf5e7e82fb4'),
    ('update_compare_call', 0x4548f41, 0x4548f7f, 'ce2ced45f3b6d13a599b74bf957c88ca06641f2fb30c746664c4c23c49610cbc'),
    ('update_compare_result', 0x4548f91, 0x4548fa1, 'd5abd48aead95e16f755b35cd0033f322c707df9544ae036b8ccbc7e774bc618'),
    ('update_unchanged', 0x4548fd8, 0x4548fe7, '7a96542d641bde8a0640e468035e68ba3d0c41828c5058f5218cb1b9ff090405'),
    ('update_replace_call', 0x454903d, 0x4549067, '07305f0dc368bfe4a6403746bec74c3af9ec215382d9e4c044391b900b41c372'),
    ('update_publish_call', 0x454a390, 0x454a404, '9c752f3532d0c32c8c5c419de17ff5f89fe4ebf02d9ed5857cff00a878179238'),
)

# Only these selected instruction starts are interpreted. Branch destinations
# are decoded from signed displacements, not from disassembler text.
BRANCHES = (
    ('poll_tag_two', 0x2276928), ('tree_one_null_root', 0x4b3179a),
    ('tree_one_zero_count', 0x4b317a5), ('tree_one_zero_depth', 0x4b317b2),
    ('tree_one_unroll', 0x4b317bf), ('tree_one_first_loop', 0x4b317e6),
    ('tree_one_short_depth', 0x4b317f2), ('tree_one_eight_loop', 0x4b3187c),
    ('tree_one_parent_needed', 0x4b31888), ('tree_one_missing_parent', 0x4b318a6),
    ('tree_one_parent_loop', 0x4b318bc), ('tree_one_null_computed_address', 0x4b318c7),
    ('tree_two_null_root', 0x4b318d9), ('tree_two_zero_count', 0x4b318e4),
    ('tree_two_zero_depth', 0x4b318f1), ('tree_two_parent_needed', 0x4b319c8),
    ('tree_two_missing_parent', 0x4b319e6), ('tree_two_parent_loop', 0x4b319f8),
    ('tree_two_null_computed_address', 0x4b31a03),
    ('constructor_cleanup_ref_a', 0x4548c5e), ('constructor_cleanup_ref_b', 0x4548c7a),
    ('constructor_cleanup_ref_c', 0x4548c93), ('builder_option', 0x1f85778),
    ('builder_cached_default', 0x1f8578b), ('builder_rejected_parse', 0x1f857ee),
    ('builder_empty_parse', 0x1f857f8), ('builder_id_overflow', 0x1f85854),
    ('builder_cas_retry', 0x1f85867), ('builder_null_allocation_a', 0x1f85899),
    ('builder_option_branch', 0x1f858cb), ('builder_null_allocation_b', 0x1f85927),
    ('builder_ref_overflow_a', 0x1f85953), ('builder_ref_overflow_b', 0x1f859a4),
    ('builder_null_allocation_c', 0x1f859d0), ('builder_null_allocation_d', 0x1f85a27),
    ('builder_launch_result', 0x1f85a4c), ('closure_no_result', 0x1f9aac4),
    ('closure_no_value', 0x1f9aacd), ('closure_no_drop', 0x1f9aada),
    ('closure_zero_size', 0x1f9aaec), ('read_guard_fast', 0x45271ec),
    ('read_guard_failed_cas', 0x4527209), ('read_guard_wake', 0x4527277),
    ('refresh_slow_acquire', 0x45292f4),
    ('refresh_slow_release', 0x4529368), ('compare_fast_acquire', 0x45264d7),
    ('compare_failed_cas', 0x45264f4), ('compare_first_unequal', 0x4526552),
    ('compare_second_unequal', 0x4526566), ('compare_wake', 0x45265a5),
    ('compare_optional_delay', 0x45265ea), ('compare_cleanup_wake_a', 0x45266b2),
    ('compare_cleanup_wake_b', 0x45266e1), ('update_tag_nonzero', 0x4548d13),
    ('timer_zero_marker', 0x4548d4a), ('timer_below_or_unordered', 0x4548ddb),
    ('update_unchanged', 0x4548fda),
    ('replace_slow_acquire', 0x4523e42), ('replace_first_empty', 0x4523ea9),
    ('replace_first_drop_loop', 0x4523f21), ('replace_second_empty', 0x4523f2d),
    ('replace_second_drop_loop', 0x4523fa1), ('replace_third_empty', 0x4523fad),
    ('replace_third_drop_loop', 0x4524021), ('replace_slow_release', 0x452405e),
    ('replace_optional_delay', 0x45240ad), ('replace_cleanup_slow_a', 0x4524184),
    ('replace_cleanup_slow_b', 0x4524206), ('list_slow_acquire', 0x4527d82),
    ('list_old_empty', 0x4527ddd), ('list_slow_release', 0x4527e11),
    ('list_optional_delay', 0x4527e56), ('list_cleanup_slow', 0x4527f28),
    ('list_cleanup_input_empty', 0x4527f30),
)

# Direct E8 edges and FF /2 RIP-relative indirect calls. A non-relative
# relocation is left unresolved; no dynamic binding is guessed.
CALLS = (
    ('two_tree_call', 0x226d1fd, 0x4b31790),
    ('constructor_call', 0x226d275, 0x4548b40),
    ('bridge_builder', 0x2236c2c, 0x1f85740),
    ('launch_api', 0x1f85a44, None),
    ('closure_adapter', 0x1f9aab2, 0x432f5f0),
    ('adapter_worker_boundary', 0x432f64a, 0x474bfa0),
    ('guard_update_boundary', 0x452725e, 0x4548cc0),
    ('refresh_boundary', 0x4548e29, 0x45292b0),
    ('refresh_opaque_helper', 0x4529350, 0x47202c0),
    ('compare_boundary', 0x4548f7a, 0x4526490),
    ('compare_first', 0x4526548, 0x49a7470),
    ('compare_second', 0x452655f, 0x49a58f0),
    ('compare_third', 0x4526579, 0x49a58f0),
    ('replace_boundary', 0x4549062, 0x4523e00),
    ('drop_first_loop', 0x4523f16, 0x494a1b0),
    ('drop_second_loop', 0x4523f96, 0x49478b0),
    ('drop_third_loop', 0x4524016, 0x49478b0),
    ('list_boundary', 0x454a3ff, 0x4527d40),
    ('list_old_drop', 0x4527dec, None),
    ('tree_one_failure', 0x4b31a4c, None),
    ('tree_two_failure', 0x4b31a5b, None),
)

# Pointer/length pairs are anchored in the selected code, then read from ELF.
LABELS = (
    ('thread_stack_setting', 0x1f8579b, '488d35', 0x1f857aa, 'ba',
     '72da5aadcb8f95f28b8303cf45c43330d4fa0fc1455fca2b7f51f4436864b0f1'),
    ('outer_launch_label', 0x2278149, '488d3d', 0x2278150, 'be',
     '8785ab7476b54e7d739fc005eaf3d014c754f99f0915ac252a91927f5f66461f'),
    ('worker_read_label', 0x474c74e, '488d0d', 0x474c73a, '41b8',
     '9aa6e34ca1dfa893a299ae8926fe9c14789c4d16b2afc959ba4be727d8b80269'),
    ('refresh_label', 0x4548e14, '488d0d', 0x4548e23, '41b8',
     '2f5fa3d0330d4c6dd996cf631a0d270862be53ef46f4cac38c46cb6582f76377'),
    ('compare_label', 0x4548f5d, '4c8d05', 0x4548f6c, '41b9',
     '2ae7bc46f879aaa05eea134eb06194664aae63a8205248b36202a389c47b9e1d'),
    ('replace_label', 0x454904d, '488d0d', 0x454905c, '41b8',
     'cd63bb303eb631ae8aeecaa4f05e82fdf397e6e3f029320255577968b1a04358'),
    ('list_label', 0x454a3e1, '488d0d', 0x454a3f0, '41b8',
     '2937013f2181810606b2a799b05bda2849f3e369a20982a4138f0e0a55984ce4'),
)

CC = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
      's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')


def authenticate(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET_SHA256:
        raise ValueError('node #94 SHA-256 mismatch')
    return digest


def file_offset(secs, data_length, va, size, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid virtual address range')
    found = [s for s in secs if s['type'] != 8 and (not executable or s['flags'] & 4)
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('virtual range is unmapped, NOBITS, or ambiguous')
    sec = found[0]
    off = sec['offset'] + va - sec['address']
    if off < 0 or off + size > data_length:
        raise ValueError('virtual range is outside file')
    return off, sec


class Image:
    def __init__(self, data, secs):
        self.data, self.secs = data, secs

    def read(self, va, size, executable=True):
        off, _ = file_offset(self.secs, len(self.data), va, size, executable)
        return bytes(self.data[off:off + size])

    def u8(self, va):
        return self.read(va, 1)[0]

    def u32(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]

    def u64(self, va, executable=True):
        return struct.unpack('<Q', self.read(va, 8, executable))[0]

    def expect(self, va, raw):
        wanted = bytes.fromhex(raw)
        if self.read(va, len(wanted)) != wanted:
            raise ValueError('fixed instruction bytes differ at ' + hex(va))


def decode_branch(image, va):
    first = image.read(va, 2)
    if 0x70 <= first[0] <= 0x7f:
        raw = first
        cc = first[0] & 15
        displacement = struct.unpack('<b', raw[1:])[0]
    elif first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
        raw = image.read(va, 6)
        cc = first[1] & 15
        displacement = struct.unpack('<i', raw[2:])[0]
    else:
        raise ValueError('unsupported branch opcode at ' + hex(va))
    target = va + len(raw) + displacement
    file_offset(image.secs, len(image.data), target, 1, True)
    return {'site': hex(va), 'condition': CC[cc], 'target': hex(target),
            'fallthrough': hex(va + len(raw)), 'bytes': raw.hex()}


def relocation_map(image, wanted_slots):
    rows = [s for s in image.secs if s['name'] == '.rela.dyn']
    if len(rows) != 1 or rows[0]['type'] != 4 or rows[0]['size'] % 24:
        raise ValueError('unsupported dynamic relocation section')
    sec = rows[0]
    result = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, off)
        if slot not in wanted_slots:
            continue
        row = {'slot': hex(slot), 'type': info & 0xffffffff, 'symbol_index': info >> 32,
               'addend': hex(addend) if addend >= 0 else '-' + hex(-addend),
               'file_offset': hex(off), 'bytes': bytes(image.data[off:off + 24]).hex()}
        result.setdefault(slot, []).append(row)
    return result


def unique_relocation(relocations, slot, required=False):
    rows = relocations.get(slot, [])
    if len(rows) > 1 or (required and len(rows) != 1):
        raise ValueError('ambiguous or missing relocation at ' + hex(slot))
    if not rows:
        return None
    return dict(rows[0])


def decode_call(image, relocations, va):
    first = image.read(va, 2)
    if first[0] == 0xe8:
        raw = image.read(va, 5)
        target = va + 5 + struct.unpack('<i', raw[1:])[0]
        file_offset(image.secs, len(image.data), target, 1, True)
        return {'site': hex(va), 'kind': 'rel32', 'bytes': raw.hex(),
                'target': hex(target), 'slot': None, 'relocation': None}
    if first == b'\xff\x15':
        raw = image.read(va, 6)
        slot = va + 6 + struct.unpack('<i', raw[2:])[0]
        file_offset(image.secs, len(image.data), slot, 8, False)
        rel = unique_relocation(relocations, slot)
        target = rel['addend'] if rel and rel['type'] == 8 and rel['symbol_index'] == 0 else None
        if target is not None:
            file_offset(image.secs, len(image.data), int(target, 16), 1, True)
        return {'site': hex(va), 'kind': 'rip_indirect', 'bytes': raw.hex(),
                'target': target, 'slot': hex(slot), 'relocation': rel}
    raise ValueError('unsupported call opcode at ' + hex(va))


def decode_label(image, spec):
    name, site, lea_prefix, length_site, length_prefix, expected = spec
    lea = image.read(site, 7)
    if lea[:3] != bytes.fromhex(lea_prefix):
        raise ValueError('label pointer instruction differs: ' + name)
    prefix = bytes.fromhex(length_prefix)
    load = image.read(length_site, len(prefix) + 4)
    if not load.startswith(prefix):
        raise ValueError('label length instruction differs: ' + name)
    target = site + len(lea) + struct.unpack('<i', lea[3:])[0]
    size = struct.unpack('<I', load[len(prefix):])[0]
    if not 0 < size <= 128:
        raise ValueError('label length outside bounded range: ' + name)
    off, sec = file_offset(image.secs, len(image.data), target, size, False)
    raw = image.read(target, size, False)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('label bytes differ: ' + name)
    if any(byte < 0x20 or byte > 0x7e for byte in raw):
        raise ValueError('label is not printable ASCII: ' + name)
    return {'name': name, 'pointer_site': hex(site), 'length_site': hex(length_site),
            'address': hex(target), 'size': size, 'file_offset': hex(off),
            'section': sec['name'], 'bytes': raw.hex(), 'text': raw.decode('ascii')}


def validate_pins(image, fdes, index):
    by_start = {f['start']: f for f in fdes}
    if len(by_start) != len(fdes):
        raise ValueError('duplicate FDE start')
    by_index = {f['start']: f for f in index}
    header = next(s for s in image.secs if s['name'] == '.eh_frame_hdr')
    starts = sorted(by_start)
    owned = []
    for name, start, end, expected in OWNED:
        fde, entry = by_start.get(start), by_index.get(start)
        if not fde or not entry or fde['end'] != end or entry['fde'] != fde['fde']:
            raise ValueError('selected FDE or index mismatch: ' + name)
        raw = image.read(start, end - start)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise ValueError('selected FDE bytes differ: ' + name)
        off, sec = file_offset(image.secs, len(image.data), start, end - start, True)
        fde_off, fde_sec = file_offset(image.secs, len(image.data), fde['fde'], 4, False)
        if fde_sec['name'] != '.eh_frame':
            raise ValueError('FDE is not in the frame section: ' + name)
        fde_length = struct.unpack_from('<I', image.data, fde_off)[0]
        if not fde_length or fde_length == 0xffffffff:
            raise ValueError('unsupported FDE record length: ' + name)
        fde_raw = image.read(fde['fde'], fde_length + 4, False)
        index_offset = header['offset'] + 12 + entry['index'] * 8
        if index_offset + 8 > header['offset'] + header['size']:
            raise ValueError('selected unwind index outside header: ' + name)
        owned.append({'name': name, 'start': hex(start), 'end': hex(end),
                      'size': len(raw), 'file_offset': hex(off), 'section': sec['name'],
                      'fde': hex(fde['fde']), 'cie': hex(fde['cie']),
                      'lsda': hex(fde['lsda']) if fde['lsda'] is not None else None,
                      'fde_file_offset': hex(fde_off), 'fde_bytes': fde_raw.hex(),
                      'index_file_offset': hex(index_offset),
                      'index_bytes': bytes(image.data[index_offset:index_offset + 8]).hex(),
                      'sha256': digest, 'bytes': raw.hex()})
    boundaries = []
    for name, start, end, expected in BOUNDARIES:
        i = bisect.bisect_right(starts, start) - 1
        fde = by_start[starts[i]] if i >= 0 else None
        if fde is None or end > fde['end']:
            raise ValueError('boundary window is outside its FDE: ' + name)
        entry = by_index.get(fde['start'])
        if not entry or entry['fde'] != fde['fde']:
            raise ValueError('boundary FDE index mismatch: ' + name)
        raw = image.read(start, end - start)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise ValueError('boundary bytes differ: ' + name)
        off, sec = file_offset(image.secs, len(image.data), start, end - start, True)
        boundaries.append({'name': name, 'start': hex(start), 'end': hex(end),
                           'file_offset': hex(off), 'section': sec['name'],
                           'containing_fde_start': hex(fde['start']), 'sha256': digest,
                           'bytes': raw.hex()})
    return owned, boundaries


def parse_lsda(image, name, fde):
    """Decode only the observed LSDA header and ULEB call-site records."""
    if fde['lsda'] is None:
        raise ValueError('selected FDE lacks LSDA: ' + name)
    start = fde['start']
    offset, sec = file_offset(image.secs, len(image.data), fde['lsda'], 1, False)
    if sec['name'] != '.gcc_except_table':
        raise ValueError('LSDA is outside exception table: ' + name)
    data = image.data
    limit = sec['offset'] + sec['size']
    pos = offset
    if pos + 2 > limit or data[pos] != 0xff:
        raise ValueError('unsupported LSDA landing-pad base: ' + name)
    pos += 1
    type_encoding = data[pos]
    pos += 1
    type_base = None
    if type_encoding == 0x9b:
        type_delta, pos = uleb(data, pos, limit)
        type_base = pos + type_delta
        if type_base > limit:
            raise ValueError('LSDA type table outside section: ' + name)
    elif type_encoding != 0xff:
        raise ValueError('unsupported LSDA type encoding: ' + name)
    if pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding: ' + name)
    pos += 1
    length, pos = uleb(data, pos, limit)
    table_end = pos + length
    if table_end > limit or (type_base is not None and table_end > type_base):
        raise ValueError('LSDA call-site table outside its bounds: ' + name)
    rows, previous_end = [], start
    while pos < table_end:
        relative, pos = uleb(data, pos, table_end)
        size, pos = uleb(data, pos, table_end)
        landing, pos = uleb(data, pos, table_end)
        action, pos = uleb(data, pos, table_end)
        begin, end = start + relative, start + relative + size
        target = start + landing if landing else None
        if (not size or begin < previous_end or end > fde['end'] or
                (target is not None and not start <= target < fde['end'])):
            raise ValueError('LSDA call-site range or landing pad outside FDE: ' + name)
        previous_end = end
        rows.append({'function': name, 'start': hex(begin), 'end': hex(end),
                     'landing_pad': hex(target) if target is not None else None,
                     'action': action})
    digest = hashlib.sha256(data[offset:table_end]).hexdigest()
    if digest != LSDA_DIGESTS[name]:
        raise ValueError('LSDA header or call-site bytes differ: ' + name)
    return {'address': hex(fde['lsda']), 'file_offset': hex(offset),
            'size': table_end - offset, 'sha256': digest,
            'bytes': bytes(data[offset:table_end]).hex(), 'entries': rows}


def read_layout(image):
    # Check the instruction forms before interpreting their displacement bytes.
    for va, raw in (
        (0x226c9b8, '4c8db3480b0000'), (0x226c9c7, 'bae83a0000'),
        (0x226cd83, '4c8da358460000'), (0x226d1f6, '488dbbf8460000'),
        (0x226d254, '488dbb98470000'), (0x226f13d, '488dbc2460170000'),
        (0x226f1dd, '488dbc24c0190000'), (0x474c01b, '488d8560020000'),
        (0x226fd2e, '488dbc24884c0100'), (0x226fd36, 'bae03a0000'),
        (0x226fd65, '488dbc2468870100'), (0x226fd6d, 'bae0020000'),
        (0x226fe2c, 'bac03d0000'), (0x226f404, 'ba80070000'),
        (0x2276941, 'ba90070000'), (0x227696b, '498dbee8000000'),
        (0x2276981, 'ba98060000'), (0x22780a0, '498db6e8000000'),
        (0x22780cf, 'ba98060000'),
        (0x4b31791, '488b4f28'), (0x4b317a0, '48837f3800'),
        (0x4b317ab, '488b5730'), (0x4b318d0, '488b4f08'),
        (0x4b318df, '48837f1800'), (0x4b318ea, '488b7710'),
        (0x4548bc4, '4989aed0020000'), (0x4548bcb, '4d89aed8020000'),
        (0x4548bec, '41c6866002000000'), (0x4548c0b, '48b80000000000003e40'),
        (0x4548bf8, '410f118661020000'), (0x4548c04, '41898671020000'),
        (0x4548c15, '49898678020000'), (0x4548c1c, '41c7868002000000000000'),
        (0x2236bf0, 'baf0060000'), (0x1f85961, 'baf0060000'),
        (0x1f857c0, '41bd00002000'), (0x1f85959, '488dbc2498070000'),
        (0x1f859af, '488db42470070000'),
        (0x1f859b7, 'ba18070000'), (0x1f9aa13, '4c8b67284c8b6f304c8d7738'),
        (0x1f9aa2e, 'bae0060000'),
        (0x45264b8, '4d8dbe68050000'), (0x4523e2b, '4d8dbd68050000'),
        (0x45264c8, '83e108c1e903'), (0x45264ce, '4883f8f0'),
        (0x452653e, '498dbe70050000'), (0x4526554, '498dbe88050000'),
        (0x4526568, '4981c6a0050000'), (0x452657f, 'c54080f501'),
        (0x4524023, '488b4340498947400f10030f104b100f1053200f105b30410f115f30410f115720410f114f10410f1107'),
        (0x4527d69, '498d85a0020000'), (0x4527dcc, '4d8dbda8020000'),
        (0x4527de6, '488d3480'), (0x4527df2, '410f1006410f104e10410f114f10410f1107'),
        (0x454a3a1, '4883c205'), (0x454a3a5, '4983c050'),
    ):
        image.expect(va, raw)
    return {
        'state_copy_bytes': image.u32(0x226c9c8),
        'state_in_outer_offset': image.u32(0x226c9bb),
        'config_in_outer_offset': image.u32(0x226cd86),
        'two_tree_input_in_outer_offset': image.u32(0x226d1f9),
        'constructor_output_in_outer_offset': image.u32(0x226d257),
        'state_body_stack_base': image.u32(0x226fd32),
        'state_body_copy_bytes': image.u32(0x226fd37),
        'object_stack_base': image.u32(0x226fd69),
        'object_copy_bytes': image.u32(0x226fd6e),
        'aggregate_copy_bytes': image.u32(0x226fe2d),
        'worker_parent_stack_base': image.u32(0x226f141),
        'worker_parent_stack_slot': image.u32(0x226f1e1),
        'worker_parent_relative_offset': image.u32(0x226f1e1) - image.u32(0x226f141),
        'worker_callee_relative_offset': image.u32(0x474c01e),
        'parent_return_prefix_bytes': image.u32(0x226f405),
        'outer_result_copy_bytes': image.u32(0x2276942),
        'outer_parent_save_offset': image.u32(0x227696e),
        'outer_parent_copy_bytes': image.u32(0x2276982),
        'outer_parent_spawn_offset': image.u32(0x22780a3),
        'outer_spawn_copy_bytes': image.u32(0x22780d0),
        'tree_one': {'root': image.u8(0x4b31794), 'depth': image.u8(0x4b317ae), 'count': image.u8(0x4b317a3)},
        'tree_two': {'root': image.u8(0x4b318d3), 'depth': image.u8(0x4b318ed), 'count': image.u8(0x4b318e2)},
        'constructor_first_tree_word_offset': image.u32(0x4548bc7),
        'constructor_second_tree_word_offset': image.u32(0x4548bce),
        'constructor_tag_offset': image.u32(0x4548bef),
        'constructor_identifier_offset': image.u32(0x4548bfc),
        'constructor_identifier_bytes': image.u32(0x4548c07) - image.u32(0x4548bfc) + 4,
        'constructor_float_offset': image.u32(0x4548c18),
        'constructor_float_bits': hex(image.u64(0x4548c0d)),
        'constructor_clock_marker_offset': image.u32(0x4548c1f),
        'launch_copy_bytes': image.u32(0x2236bf1),
        'closure_input_copy_bytes': image.u32(0x1f85962),
        'closure_bytes': image.u32(0x1f859b8),
        'closure_input_offset': image.u32(0x1f8595d) - image.u32(0x1f859b3),
        'thread_stack_fallback_bytes': image.u32(0x1f857c2),
        'callback_prefix_copy_bytes': image.u8(0x1f9aa1e) - image.u8(0x1f9aa16),
        'callback_tail_copy_bytes': image.u32(0x1f9aa2f),
        'read_lock_offset': image.u32(0x45264bb),
        'write_lock_offset': image.u32(0x4523e2e),
        'read_lock_exclusion_mask': image.u8(0x45264ca),
        'read_lock_unsigned_limit': hex(struct.unpack('<b', image.read(0x45264d1, 1))[0] % (1 << 64)),
        'compared_field_offsets': [image.u32(0x4526541), image.u32(0x4526557), image.u32(0x452656b)],
        'replacement_span_bytes': image.u8(0x4524026) + (8 if image.u8(0x4524023) & 8 else 4),
        'list_lock_offset': image.u32(0x4527d6c),
        'list_value_offset': image.u32(0x4527dcf),
        'list_deallocation_multiplier': 1 + (1 << (image.u8(0x4527de9) >> 6)),
        'list_copy_bytes': image.u8(0x4527dfb + 4) + 16,
        'list_source_stride': image.u8(0x454a3a8),
        'list_destination_stride': image.u8(0x454a3a4),
    }


def comparison_paths(image):
    # The first two zero returns branch to the common store with bpl = 1.
    # Otherwise the third byte is XORed with the immediate before the store.
    image.expect(0x452654d, '40b50184c07430')
    image.expect(0x4526564, '84c0741c')
    image.expect(0x452657e, '89c54080f501')
    image.expect(0x4526679, '40886810')
    default, mask = image.u8(0x452654f), image.u8(0x4526583)
    rows = []
    for first, second, third in ((0, None, None), (1, 0, None),
                                 (1, 1, 0), (1, 1, 1),
                                 (1, 1, 2), (1, 1, 255)):
        result = default if first == 0 or second == 0 else third ^ mask
        count = 1 if first == 0 else 2 if second == 0 else 3
        rows.append({'first_al': first, 'second_al': second, 'third_al': third,
                     'helpers_called': count, 'stored_byte': result,
                     'zero_test_would_skip_replace': int(result == 0)})
    return rows


def inspect(data):
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    image = Image(data, secs)
    owned, boundaries = validate_pins(image, fdes, index)
    by_start = {fde['start']: fde for fde in fdes}
    lsdas = []
    for name, start, _, _ in OWNED:
        table = parse_lsda(image, name, by_start[start])
        table['function'] = name
        lsdas.append(table)
    selected_ranges = [(start, end) for _, start, end, _ in OWNED + BOUNDARIES]
    fde_starts = sorted(by_start)

    def in_scope(va, size):
        if not any(start <= va and va + size <= end for start, end in selected_ranges):
            raise ValueError('instruction outside selected windows: ' + hex(va))

    image.expect(0x1f85a0d, '488d0594ca7003')
    descriptor_va = 0x1f85a0d + 7 + struct.unpack('<i', image.read(0x1f85a10, 4))[0]
    tentative = [decode_call(image, {}, va) for _, va, _ in CALLS]
    slots = {int(row['slot'], 16) for row in tentative if row['slot'] is not None}
    slots.update((descriptor_va, descriptor_va + 24))
    rels = relocation_map(image, slots)

    branches = []
    for name, va in BRANCHES:
        row = decode_branch(image, va)
        in_scope(va, len(row['bytes']) // 2)
        fde_index = bisect.bisect_right(fde_starts, va) - 1
        fde = by_start[fde_starts[fde_index]] if fde_index >= 0 else None
        target = int(row['target'], 16)
        if not fde or not fde['start'] <= target < fde['end']:
            raise ValueError('selected branch target outside enclosing FDE: ' + name)
        row['name'] = name
        branches.append(row)
    calls = []
    for name, va, expected in CALLS:
        row = decode_call(image, rels, va)
        in_scope(va, len(row['bytes']) // 2)
        row['name'] = name
        if expected is not None and row['target'] != hex(expected):
            raise ValueError('call target mismatch: ' + name)
        calls.append(row)
    labels = []
    for spec in LABELS:
        in_scope(spec[1], 7)
        in_scope(spec[3], len(bytes.fromhex(spec[4])) + 4)
        labels.append(decode_label(image, spec))
    drop = unique_relocation(rels, descriptor_va, True)
    callback = unique_relocation(rels, descriptor_va + 24, True)
    if not (drop['type'] == callback['type'] == 8 and drop['symbol_index'] == callback['symbol_index'] == 0
            and callback['addend'] == hex(0x1f9a9f0)):
        raise ValueError('unexpected closure descriptor relocation')
    descriptor = {'address': hex(descriptor_va), 'bytes_before_relocation': image.read(descriptor_va, 32, False).hex(),
                  'size': image.u64(descriptor_va + 8, False),
                  'alignment': image.u64(descriptor_va + 16, False),
                  'drop_slot': drop, 'callback_slot': callback}
    layout = read_layout(image)
    if layout['closure_bytes'] != descriptor['size']:
        raise ValueError('closure allocation and descriptor sizes differ')
    if layout['closure_input_offset'] + layout['closure_input_copy_bytes'] != layout['closure_bytes']:
        raise ValueError('closure input does not fill the observed allocation')
    if layout['worker_parent_relative_offset'] != layout['worker_callee_relative_offset']:
        raise ValueError('worker object offset differs across the inspected boundaries')
    if (layout['object_stack_base'] - layout['state_body_stack_base'] != layout['state_body_copy_bytes'] or
            layout['state_body_copy_bytes'] + layout['object_copy_bytes'] != layout['aggregate_copy_bytes']):
        raise ValueError('state and worker object do not form the observed aggregate')
    if (layout['outer_parent_save_offset'] != layout['outer_parent_spawn_offset'] or
            layout['outer_parent_copy_bytes'] != layout['outer_spawn_copy_bytes'] or
            layout['launch_copy_bytes'] != layout['closure_input_copy_bytes'] or
            layout['launch_copy_bytes'] != layout['callback_tail_copy_bytes'] + layout['callback_prefix_copy_bytes'] or
            layout['worker_parent_relative_offset'] + layout['object_copy_bytes'] > layout['outer_parent_copy_bytes']):
        raise ValueError('inconsistent worker handoff layout')
    relocation_rows = [unique_relocation(rels, slot, True) for slot in sorted(slots)]
    return {'target_sha256': TARGET_SHA256, 'coordinate_system': 'linked ELF virtual addresses; file offsets are from file start',
            'owned': owned, 'boundaries': boundaries, 'branches': branches, 'calls': calls,
            'descriptor': descriptor, 'layout': layout, 'lsdas': lsdas, 'relocations': relocation_rows,
            'labels': labels,
            'comparison_paths': comparison_paths(image)}


def tsv(out, filename, fields, rows):
    with (out / filename).open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter='\t', lineterminator='\n', extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow({key: '' if row.get(key) is None else row.get(key) for key in fields})


def generate(data, out):
    authenticate(data)
    record = inspect(data)
    out.mkdir(parents=True, exist_ok=True)
    tsv(out, 'fdes.tsv', ('name', 'start', 'end', 'size', 'file_offset', 'section', 'fde', 'cie', 'lsda',
                          'fde_file_offset', 'fde_bytes', 'index_file_offset', 'index_bytes',
                          'sha256', 'bytes'), record['owned'])
    tsv(out, 'boundaries.tsv', ('name', 'start', 'end', 'file_offset', 'section', 'containing_fde_start', 'sha256', 'bytes'), record['boundaries'])
    tsv(out, 'branches.tsv', ('name', 'site', 'condition', 'fallthrough', 'target', 'bytes'), record['branches'])
    rows = [{**r, 'relocation': json.dumps(r['relocation'], sort_keys=True, separators=(',', ':')) if r['relocation'] else None}
            for r in record['calls']]
    tsv(out, 'calls.tsv', ('name', 'site', 'kind', 'slot', 'target', 'relocation', 'bytes'), rows)
    tsv(out, 'relocations.tsv', ('slot', 'type', 'symbol_index', 'addend', 'file_offset', 'bytes'), record['relocations'])
    tsv(out, 'labels.tsv', ('name', 'pointer_site', 'length_site', 'address', 'size',
                            'file_offset', 'section', 'bytes', 'text'), record['labels'])
    lsda_rows = [row for table in record['lsdas'] for row in table['entries']]
    tsv(out, 'lsda.tsv', ('function', 'start', 'end', 'landing_pad', 'action'), lsda_rows)
    tsv(out, 'lsda-headers.tsv', ('function', 'address', 'file_offset', 'size', 'sha256', 'bytes'), record['lsdas'])
    tsv(out, 'comparison-paths.tsv', ('first_al', 'second_al', 'third_al', 'helpers_called',
                                     'stored_byte', 'zero_test_would_skip_replace'), record['comparison_paths'])
    summary = {key: value for key, value in record.items()
               if key not in ('owned', 'boundaries', 'branches', 'calls', 'lsdas', 'comparison_paths', 'relocations', 'labels')}
    summary['counts'] = {'owned_fdes': len(record['owned']), 'boundary_windows': len(record['boundaries']),
                         'selected_branches': len(record['branches']), 'selected_calls': len(record['calls']),
                         'lsda_tables': len(record['lsdas']), 'lsda_call_sites': len(lsda_rows),
                         'comparison_path_examples': len(record['comparison_paths']),
                         'relocations': len(record['relocations']), 'labels': len(record['labels'])}
    summary['limitations'] = ('Selected byte windows and FDEs only; no target execution, whole-node equivalence, '
                              'complete scheduler proof, or component milestone claim.')
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(ARTIFACT.read_bytes(), args.out)
    print('Generated 10 deterministic evidence files for node #94.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print('abci_fast_handoff94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)

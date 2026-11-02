#!/usr/bin/env python3
"""Static, digest-bound spot-cancellation index failure evidence; no target execution."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = (
    ('slot_search_and_delete', 0x2866e70, 0x2866f81, 'a601b6b08ff888d361d8d3fdb91fbe8511ef398016593b58441291ffa4fd55d2'),
    ('outer_index_split', 0x1a6caa0, 0x1a6d917, '32ffa7365c08f133a94e28aa3d6260ec4bd8662a7ae9488bef5aeb3984562743'),
    ('inner_index_split', 0x1ade160, 0x1adea8c, '1108223a9b8e3740f1c6fc6dc932bd922997f1583e7c1644a28917b55bbbbec2'),
    ('outer_cleanup_a', 0x28ae330, 0x28ae3bb, 'bdbe4eb01a71c70f9577e68bb0f69e6e4e25aefadd6d43202fd52a73b440a14c'),
    ('outer_cleanup_b', 0x2834030, 0x28340bb, '32793003610b3cdd35d9662bd1d5020eed8c6727a9c48c3fd763039a86df807a'),
    ('inner_drain_step', 0x2875a00, 0x2875dc1, '94d633cee1fde81dff110dbf0f3892e6d2e7c9c2b1550f946431cd3169af149f'),
)
WINDOWS = (
    ('spot_outer_handoff', 0x26df054, 0x26df08f, '3df3f8243d6f936549d02e31a797ba8766eddb8e8aa92c3101ae65cd9e904ac8'),
    ('spot_key_and_slab', 0x26de979, 0x26de9e9, '48a93f84f283912e0641225e3f19e2e10cd68c4c6345bb29efa5b6ebb6060305'),
    ('spot_map_root', 0x26deee1, 0x26def04, '70252f11ce9d58d86f509fc80bb790160ee59cc715277a2a8eb49389ed7ce1ce'),
    ('spot_slot_gate', 0x26dee71, 0x26dee98, '9f408e5e87c9ceda87b10bfd6796004c006b8111a29c3fe29213aa14442e53e7'),
    ('spot_counter', 0x26dee98, 0x26deee1, 'c71cd866f07798d926066b2a7e667f775da3086bb0656f120d5f2f69b04b8403'),
    ('spot_tag', 0x26df08f, 0x26df0a1, 'd60333204150652531c49dda9a702b7bd757532fe5ace1e826abcbb57de8a234'),
    ('outer_handoff', 0x287a7b2, 0x287a7d0, '30d66ba59a4dc33fe9b7b846102ed1e120f96cf6072222c6b33f11a97b74382c'),
    ('inner_handoff', 0x2854feb, 0x2855000, '926d0a1f2a7ea3c3139f489fe0ae138b49a87a26a2182c375569c3c4920b8683'),
    ('wrapper_unwind', 0x287a8b2, 0x287a8d3, 'c842950d847fdecefda2d205784b45a1d94a45c56763448792fdaded53f6220b'),
    ('outer_split', 0x1a6cab5, 0x1a6cafb, '934e34198c0a8c8ec4cc5379f9b9fd5611e564c60a5fd622430a2a9b3df8d8dd'),
    ('inner_split', 0x1ade17a, 0x1ade200, '7518a0824e03d67c69a90de6ec4fbfa56c92b39397402684c63dd42d76e02113'),
    ('outer_root', 0x1a6d427, 0x1a6d4aa, '9323ac0b8a2b4c16c5b4351af04d8dc3da526dfa97fa25adb59a9a8f72ad6ad6'),
    ('inner_root', 0x1ade6c5, 0x1ade750, 'b8bcc7e1d3f4b06665d14f63ace3dcbb64a1f5e11c509cf48a0aeeefb578d242'),
    ('outer_overflow', 0x1a6d7fb, 0x1a6d80a, '004bdbfc73deb342f65f589ba34473b265ebe1f872453f0f5cdfb3a1913dfe5c'),
    ('outer_free', 0x1a6d83a, 0x1a6d84e, '3bab504d848e06093f4a9050ce754256ba803d1f5e436bb4481f4777abfccb29'),
    ('inner_overflow', 0x1adea10, 0x1adea1f, '3a0dd9d9729d4fbc3ec0d50e3d580f36ddd9952a97c8579a97c335b433ae919c'),
    ('inner_free', 0x1adea51, 0x1adea65, 'adbbc5b651867801ce883217f94cfa6cd8b807c03ad59c24833069a6ce8e7687'),
    ('outer_cleanup', 0x1a6d84e, 0x1a6d90b, 'fbd09b83aef402812c7547d87d6b2f9b88cfae02690f7120d929f2d778b224de'),
    ('inner_cleanup', 0x1adea65, 0x1adea8c, 'de5f1f2f9dbdb188c4b315c803eab13d4ca449e5b6f67652b676f4f177182a5b'),
    ('iter_start', 0x2875a0b, 0x2875a36, '4b502d74b78166d079eaae257b57807918e4b92da496fbe448cd5a4bbdece172'),
    ('iter_free', 0x2875b49, 0x2875bba, '8dd34301122f2b35a63a9851fe0ed76a5f02ace46d525f34340a0ab18ebc34f1'),
    ('iter_end', 0x2875d51, 0x2875dc1, '27b36b15ebf7b46eda9cc88c375ae169eead30bddddb1922294c84467731f12b'),
)
BRANCH_SITES = (
    0x26de9e3, 0x26dee92, 0x26deed8, 0x2866e7b, 0x2866ed7, 0x2866f16, 0x2866f1e, 0x2866f27,
    0x1a6cac8, 0x1a6cae2, 0x1a6cb48, 0x1a6cb52, 0x1a6cc8e, 0x1a6cd06,
    0x1a6cf65, 0x1a6cf92, 0x1a6cfa2, 0x1a6cfc4, 0x1a6cfca, 0x1a6d00e,
    0x1a6d08f, 0x1a6d156, 0x1a6d166, 0x1a6d430, 0x1a6d448, 0x1a6d46e,
    0x1a6d492, 0x1a6d4a4, 0x1ade182, 0x1ade217, 0x1ade228, 0x1ade22e,
    0x1ade26f, 0x1ade2a8, 0x1ade39a, 0x1ade3cb, 0x1ade3da, 0x1ade3f4,
    0x1ade3f9, 0x1ade43e, 0x1ade47e, 0x1ade4d0, 0x1ade4dc, 0x1ade6d3,
    0x1ade6eb, 0x1ade715, 0x1ade738, 0x1ade74a, 0x2875a15, 0x2875a25,
    0x2875a30, 0x2875ae5, 0x2875b5f, 0x2875b68, 0x2875b7b,
)
DIRECT_CALLS = (
    ('slab_remove_context',0x26de9d6,0x232c6b0),
    ('tracker_context',0x26deecc,0x1f849b0),
    ('spot_to_outer_wrapper_context',0x26df06e,0x287a770),
    ('spot_to_inner_wrapper_context',0x26df09c,0x2854ed0),
    ('slot_delete_context',0x26dee86,0x2866e70),
    ('slot_cursor_delete_context',0x2866f08,0x1b22d70),
    ('outer_split_context',0x287a7cb,0x1a6caa0),
    ('inner_split_context',0x2854ffb,0x1ade160),
    ('wrapper_cleanup_a',0x287a8b8,0x28ae330),
    ('wrapper_cleanup_b',0x287a8cb,0x2834030),
    ('outer_cleanup_0',0x1a6d859,0x28ae330),
    ('outer_cleanup_1',0x1a6d874,0x28ae330),
    ('outer_cleanup_2',0x1a6d88f,0x28ae330),
    ('outer_cleanup_3',0x1a6d8a7,0x28ae330),
    ('outer_cleanup_4',0x1a6d8cc,0x28ae330),
    ('outer_cleanup_5',0x1a6d8e4,0x28ae330),
    ('outer_cleanup_6',0x1a6d8fe,0x28ae330),
    ('cleanup_a_iterator',0x28ae3a6,0x2875a00),
    ('cleanup_b_iterator',0x28340a6,0x2875a00),
    ('outer_resume_edge',0x1a6d906,0x5660110),
    ('inner_resume_edge',0x1adea87,0x5660110),
)
FIELDS = (
    ('spot_tracker_offset',0x26deea4,'498dbe',4),
    ('tracker_count_offset',0x26deed1,'488b48',1),
    ('spot_change_map_offset',0x26deee1,'498bae',4),
    ('slot_node_count_offset',0x2866e8b,'0fb778',1),
    ('slot_child_offset',0x2866ed9,'488b44f0',1),
    ('slot_old_root_release_size',0x2866f3e,'be',4),
    ('outer_node_count_offset',0x1a6cab7,'450fb7b5',4),
    ('outer_key_array_offset',0x1a6cb0e,'4881c3',4),
    ('outer_child_offset',0x1a6d461,'4c89a0',4),
    ('outer_key_capacity',0x1a6cabf,'4983fe',1),
    ('outer_split_boundary_five',0x1a6cad1,'4983fc',1),
    ('outer_split_boundary_six',0x1a6cb4e,'4983fc',1),
    ('inner_node_count_offset',0x1ade177,'0fb79d',4),
    ('inner_child_offset',0x1ade708,'4c89a0',4),
    ('inner_key_capacity',0x1ade17e,'4883fb',1),
    ('inner_split_boundary_five',0x1ade204,'4983ff',1),
    ('inner_split_boundary_six',0x1ade22a,'4983ff',1),
    ('inner_pivot_below_five',0x1ade21e,'41bf',4),
    ('inner_pivot_above_six',0x1ade255,'41bf',4),
    ('inner_right_index_adjust',0x1ade24c,'4983c7',1),
    ('outer_leaf_allocation',0x1a6cc80,'bf',4),
    ('outer_root_allocation',0x1a6d43a,'bf',4),
    ('inner_leaf_allocation',0x1ade261,'bf',4),
    ('inner_root_allocation',0x1ade6dd,'bf',4),
    ('drain_leaf_release_size',0x2875b81,'41bf',4),
    ('drain_internal_release_size',0x2875b9a,'be',4),
)
RIP_SITES = (
    ('slot_old_root_release', 0x2866f45, 0x576e010),
    ('slot_missing_root_failure', 0x2866f62, 0x576e470),
    ('slot_zero_height_failure', 0x2866f7b, 0x576e108),
    ('outer_root_allocate', 0x1a6d43f, 0x576dfd8),
    ('outer_leaf_alloc_failure', 0x1a6d7d2, 0x576e020),
    ('outer_root_alloc_failure', 0x1a6d7f3, 0x576e020),
    ('outer_height_mismatch', 0x1a6d832, 0x576e108),
    ('outer_height_failure', 0x1a6d802, 0x576e470),
    ('outer_height_release', 0x1a6d844, 0x576e010),
    ('inner_root_allocate', 0x1ade6e2, 0x576dfd8),
    ('inner_leaf_alloc_failure', 0x1ade9eb, 0x576e020),
    ('inner_root_alloc_failure', 0x1adea08, 0x576e020),
    ('inner_height_mismatch', 0x1adea32, 0x576e108),
    ('inner_height_failure', 0x1adea17, 0x576e470),
    ('inner_height_release', 0x1adea5b, 0x576e010),
    ('drain_release_load', 0x2875b87, 0x576e010),
    ('drain_release_load_second', 0x2875bca, 0x576e010),
    ('drain_release_call', 0x2875d6d, 0x576e010),
)
EXPECTED_SLOTS = {0x576dfd8:0x54c06b0, 0x576e470:0x157a9f0, 0x576e010:0x54c8cb0,
                  0x576e020:0x1345e2a, 0x576e108:0x157b7f0}
FAILURES = (
    ('outer_leaf_allocation',0x1a6caa0,0x1a6cc8e,0x1a6d7c8,0x1a6d7d2,0x1a6d869),
    ('outer_root_allocation',0x1a6caa0,0x1a6d448,0x1a6d7e9,0x1a6d7f3,0x1a6d84c),
    ('outer_height_overflow',0x1a6caa0,0x1a6d46e,0x1a6d7fb,0x1a6d802,0x1a6d83a),
    ('outer_height_mismatch',0x1a6caa0,0x1a6d492,0x1a6d80a,0x1a6d832,0x1a6d86e),
    ('inner_leaf_allocation',0x1ade160,0x1ade26f,0x1ade9e1,0x1ade9eb,None),
    ('inner_root_allocation',0x1ade160,0x1ade6eb,0x1ade9fe,0x1adea08,0x1adea63),
    ('inner_height_overflow',0x1ade160,0x1ade715,0x1adea10,0x1adea17,0x1adea51),
    ('inner_height_mismatch',0x1ade160,0x1ade738,0x1adea1f,0x1adea32,None),
)
LSDA_DIGESTS = {
    0x1a6caa0: 'b59265a5f745b138681fc4811b970c908651b1616d7e06beb3be607b7c2ea369',
    0x1ade160: '008aa00d3de063db849c73ceeabbb54375d731436f1b1a003f68c2c6c3180fd6',
    0x2875a00: '941f31b4c7b371388da86cca11445136e2d00bb02957f26d515137ad607b2d43',
}

class EvidenceError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_identity(data):
    if digest(data) != DIGEST:
        raise EvidenceError('target SHA-256 mismatch')


def file_offset(secs, va, size, executable=False):
    if va < 0 or size <= 0:
        raise EvidenceError('invalid virtual range')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               (not executable or s['flags'] & 4) and s['address'] <= va and
               va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise EvidenceError('unmapped or ambiguous file-backed range')
    return matches[0]['offset'] + va - matches[0]['address']


def read_va(data, secs, va, size, executable=False):
    off = file_offset(secs, va, size, executable)
    if off + size > len(data):
        raise EvidenceError('file range outside artifact')
    return bytes(data[off:off + size])


def checked_window(data, secs, start, end, expected):
    raw = read_va(data, secs, start, end - start, True)
    if digest(raw) != expected:
        raise EvidenceError('pinned instruction window differs')
    return raw


def decode_branch(data, secs, site):
    raw = read_va(data, secs, site, 2, True)
    if 0x70 <= raw[0] <= 0x7f:
        length, cc = 2, raw[0] & 15
        disp = struct.unpack('<b', raw[1:])[0]
    elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        raw = read_va(data, secs, site, 6, True)
        length, cc = 6, raw[1] & 15
        disp = struct.unpack('<i', raw[2:])[0]
    else:
        raise EvidenceError('conditional opcode differs')
    return {'site': hex(site), 'bytes': raw.hex(), 'cc': cc,
            'taken': hex(site + length + disp), 'fallthrough': hex(site + length)}


def decode_call(data, secs, site, expected):
    raw = read_va(data, secs, site, 5, True)
    if raw[0] != 0xe8:
        raise EvidenceError('direct-call opcode differs')
    target = site + 5 + struct.unpack('<i', raw[1:])[0]
    if target != expected:
        raise EvidenceError('direct-call target differs')
    return {'site': hex(site), 'bytes': raw.hex(), 'target': hex(target)}


def extract_field(data, secs, label, site, prefix, width):
    lead = bytes.fromhex(prefix)
    raw = read_va(data, secs, site, len(lead) + width, True)
    if not raw.startswith(lead):
        raise EvidenceError('field instruction differs')
    return {'label':label, 'site':hex(site), 'raw':raw.hex(),
            'value':int.from_bytes(raw[len(lead):], 'little')}


def compare_cleanup(data, secs):
    first = read_va(data, secs, 0x28ae330, 0x8b, True)
    second = read_va(data, secs, 0x2834030, 0x8b, True)
    mask_start = 0x77
    mask_end = mask_start + 4
    if first[mask_start-1] != 0xe8 or second[mask_start-1] != 0xe8:
        raise EvidenceError('cleanup call opcode differs')
    actual_differences = [i for i,(a,b) in enumerate(zip(first,second)) if a != b]
    if not actual_differences or any(not mask_start <= x < mask_end for x in actual_differences):
        raise EvidenceError('unmasked cleanup bytes differ')
    masked_a = first[:mask_start] + bytes(4) + first[mask_end:]
    masked_b = second[:mask_start] + bytes(4) + second[mask_end:]
    if masked_a != masked_b:
        raise EvidenceError('cleanup comparison failed')
    return {'size':len(first),'displacement_mask_start':mask_start,
            'displacement_mask_end':mask_end,'different_byte_offsets':actual_differences,
            'masked_sha256':digest(masked_a), 'unmasked_sha256_a':digest(first),
            'unmasked_sha256_b':digest(second), 'limitations':'Both call operands are resolved separately; no helper or ELF equivalence is implied.'}


def rip_site(data, secs, site, expected):
    raw = read_va(data, secs, site, 6, True)
    if raw[:2] == b'\xff\x15':
        size, disp, kind = 6, struct.unpack('<i', raw[2:6])[0], 'call'
    elif raw[:3] == b'\x48\x8b\x1d':
        raw = read_va(data, secs, site, 7, True)
        size, disp, kind = 7, struct.unpack('<i', raw[3:7])[0], 'load'
    else:
        raise EvidenceError('RIP-relative opcode differs')
    slot = site + size + disp
    if slot != expected:
        raise EvidenceError('RIP-relative slot differs')
    return {'site':hex(site),'raw':raw.hex(),'slot':hex(slot),'kind':kind}


def relocations(data, secs):
    rel = [s for s in secs if s['name']=='.rela.dyn' and s['type']==4]
    if len(rel) != 1 or rel[0]['size'] % 24:
        raise EvidenceError('missing or invalid relocation section')
    s = rel[0]
    found = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in EXPECTED_SLOTS:
            if slot in found or info != 8 or addend != EXPECTED_SLOTS[slot]:
                raise EvidenceError('unexpected or duplicate relocation')
            found[slot] = {'slot':hex(slot), 'type':info, 'addend':hex(addend),
                           'file_offset':hex(off), 'raw':bytes(data[off:off+24]).hex()}
    if len(found) != len(EXPECTED_SLOTS):
        raise EvidenceError('missing relative relocation')
    return [found[x] for x in sorted(found)]


def parse_lsda(data, secs, fde, expected_hash):
    sec = next((s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8), None)
    va = fde['lsda']
    if sec is None or va is None or not sec['address'] <= va < sec['address'] + sec['size']:
        raise EvidenceError('missing exception table')
    offset = file_offset(secs, va, 1)
    raw = bytes(data[offset:sec['offset'] + sec['size']])
    if len(raw) < 4 or raw[0] != 0xff or raw[1] not in (0xff, 0x9b):
        raise EvidenceError('unsupported exception encoding')
    p = 2
    type_offset = None
    if raw[1] != 0xff:
        type_offset, p = uleb(raw, p, len(raw))
        if p + type_offset > len(raw):
            raise EvidenceError('type table outside section')
    if p >= len(raw) or raw[p] != 1:
        raise EvidenceError('unsupported call-site encoding')
    p += 1
    count, p = uleb(raw, p, len(raw))
    end = p + count
    if end > len(raw):
        raise EvidenceError('truncated call-site table')
    entries, previous = [], 0
    while p < end:
        before = p
        start, p = uleb(raw, p, end)
        size, p = uleb(raw, p, end)
        landing, p = uleb(raw, p, end)
        action, p = uleb(raw, p, end)
        if start < previous or start + size > fde['end'] - fde['start']:
            raise EvidenceError('invalid call-site interval')
        if landing and landing >= fde['end'] - fde['start']:
            raise EvidenceError('invalid landing offset')
        previous = start + size
        entries.append({'function': hex(fde['start']), 'start': hex(fde['start'] + start),
                        'end': hex(fde['start'] + start + size),
                        'landing': hex(fde['start'] + landing) if landing else None,
                        'action': action, 'record': hex(va + before),
                        'raw': raw[before:p].hex()})
    if p != end or digest(raw[:end]) != expected_hash:
        raise EvidenceError('exception table differs')
    return {'function': hex(fde['start']), 'va': hex(va), 'file_offset': hex(offset),
            'type_encoding': raw[1], 'type_offset': type_offset, 'raw': raw[:end].hex(),
            'sha256': digest(raw[:end]), 'entries': entries}


def tracker_counter_projection(value, slot_found):
    """Project the caller's guarded u64 decrement on the selected branch."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= 1 << 64:
        raise EvidenceError('counter outside u64')
    return value - 1 if slot_found and value else value


def root_projection(root_present, allocation_succeeds, height, expected_height):
    """Project only the pinned root-growth branches; never interpret target code."""
    if height < 0 or height > (1 << 64) - 1 or expected_height < 0 or expected_height > (1 << 64) - 1:
        raise EvidenceError('height outside u64')
    if not root_present:
        return {'outcome': 'missing_root', 'child_written': False, 'header_written': False}
    if not allocation_succeeds:
        return {'outcome': 'allocation_failure', 'child_written': False, 'header_written': False}
    if height == (1 << 64) - 1:
        return {'outcome': 'height_overflow', 'child_written': True, 'header_written': False}
    return {'outcome': 'normal' if height == expected_height else 'height_mismatch',
            'child_written': True, 'header_written': True}


def split_projection(position):
    """Project twelve insertion gaps of one valid full eleven-key node."""
    if not isinstance(position, int) or isinstance(position, bool) or not 0 <= position <= 11:
        raise EvidenceError('position outside full-node gaps')
    if position < 5:
        pivot, side, local = 4, 'left', position
    elif position == 5:
        pivot, side, local = 5, 'left', 5
    elif position == 6:
        pivot, side, local = 5, 'right', 0
    else:
        pivot, side, local = 6, 'right', position - 7
    old = list(range(2, 24, 2))
    new_key = position * 2 + 1
    left, right = old[:pivot], old[pivot + 1:]
    (left if side == 'left' else right).insert(local, new_key)
    return {'position':position, 'new_key':new_key, 'pivot_index':pivot,
            'promoted':old[pivot], 'side':side, 'local_index':local,
            'left':left, 'right':right}


def collect(data, authenticate=True):
    if authenticate:
        verify_identity(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    index_by = {r['start']: r for r in index}
    if len(index_by) != len(index):
        raise EvidenceError('duplicate unwind starts')
    by_start = {}
    for f in fdes:
        if f['start'] in by_start:
            raise EvidenceError('duplicate FDE starts')
        by_start[f['start']] = f
    funcs = []
    for name, start, end, expected in FUNCTIONS:
        f = by_start.get(start)
        idx = index_by.get(start)
        if f is None or idx is None or f['fde'] != idx['fde'] or f['end'] != end:
            raise EvidenceError('FDE extent or header entry differs')
        raw = checked_window(data, secs, start, end, expected)
        funcs.append({'role': name, 'start': hex(start), 'end': hex(end),
                      'file_offset': hex(file_offset(secs, start, end-start, True)),
                      'fde': hex(f['fde']), 'cie': hex(f['cie']),
                      'lsda': hex(f['lsda']) if f['lsda'] is not None else None,
                      'size': len(raw), 'sha256': digest(raw), 'bytes': raw.hex()})
    wins = []
    for name, start, end, expected in WINDOWS:
        raw = checked_window(data, secs, start, end, expected)
        wins.append({'label': name, 'start': hex(start), 'end': hex(end),
                     'file_offset': hex(file_offset(secs, start, end-start, True)),
                     'size': len(raw), 'sha256': digest(raw), 'bytes': raw.hex()})
    fields = [extract_field(data, secs, *item) for item in FIELDS]
    comparison = compare_cleanup(data, secs)
    branches = [decode_branch(data, secs, site) for site in BRANCH_SITES]
    calls = []
    for label, site, target in DIRECT_CALLS:
        item = decode_call(data, secs, site, target)
        item['label'] = label
        calls.append(item)
    indirect = []
    for label, site, slot in RIP_SITES:
        row = rip_site(data, secs, site, slot)
        row['label'] = label
        indirect.append(row)
    register_calls = []
    for label, site in (('drain_ancestor_release',0x2875ba5),('drain_exhausted_release',0x2875c0a)):
        raw = read_va(data, secs, site, 2, True)
        if raw != bytes.fromhex('ffd3'):
            raise EvidenceError('release register call differs')
        register_calls.append({'label':label, 'site':hex(site), 'raw':raw.hex(), 'register':'rbx'})
    relocs = relocations(data, secs)
    lsdas = [parse_lsda(data, secs, by_start[a], h) for a, h in LSDA_DIGESTS.items()]
    failures = []
    for label, start, branch_site, failure, call, expected_landing in FAILURES:
        branch = decode_branch(data, secs, branch_site)
        if branch['taken'] != hex(failure):
            raise EvidenceError('failure branch target differs')
        table = next(x for x in lsdas if int(x['function'],16) == start)
        rows = [e for e in table['entries'] if int(e['start'],16) <= call < int(e['end'],16)]
        expected = hex(expected_landing) if expected_landing is not None else None
        if len(rows) != 1 or rows[0]['landing'] != expected:
            raise EvidenceError('failure call-site landing differs')
        failures.append({'label':label, 'function':hex(start), 'branch':hex(branch_site),
                         'failure_arm':hex(failure), 'failure_call':hex(call),
                         'landing':rows[0]['landing'], 'action':rows[0]['action'],
                         'callsite_record':rows[0]['record']})
    # The call to the local height-overflow handler must be in a protected range
    # whose landing instruction begins with the node's deallocation-size load.
    controls = []
    for start, site, landing, free_size in ((0x1a6caa0,0x1a6d802,0x1a6d83a,0x250),
                                           (0x1ade160,0x1adea17,0x1adea51,0x120)):
        lsda = next(x for x in lsdas if int(x['function'],16) == start)
        matching = [e for e in lsda['entries'] if int(e['start'],16) <= site < int(e['end'],16)]
        if len(matching) != 1 or matching[0]['landing'] != hex(landing):
            raise EvidenceError('height failure has unexpected landing')
        raw = read_va(data, secs, landing, 18, True)
        if raw[0] != 0xbe or struct.unpack('<I', raw[1:5])[0] != free_size or raw[-2:] != b'\x0f\x0b':
            raise EvidenceError('height cleanup release size differs')
        controls.append({'function': hex(start), 'failure_call': hex(site),
                         'landing': hex(landing), 'release_size': free_size,
                         'landing_bytes': raw.hex(), 'terminator':'ud2'})
    cases = []
    for root, allocated, height, expected_height in (
            (False, False, 0, 0), (True, False, 0, 0), (True, True, 0, 0),
            (True, True, 1, 1), (True, True, 1, 0),
            (True, True, (1 << 64) - 2, (1 << 64) - 2),
            (True, True, (1 << 64) - 1, (1 << 64) - 1)):
        cases.append({'root_present':root,'allocation_succeeds':allocated,'height':height,
                      'expected_height':expected_height, **root_projection(root, allocated, height, expected_height)})
    return {'target_sha256': DIGEST, 'coordinates': 'linked ELF virtual addresses, half-open ends',
            'functions': funcs, 'windows': wins, 'fields':fields, 'cleanup_comparison':comparison,
            'branches': branches, 'direct_calls': calls,
            'indirect_sites': indirect, 'register_calls':register_calls, 'relocations': relocs,
            'exception_tables': lsdas, 'failure_routes':failures, 'height_failure_landings': controls,
            'synthetic_counter_cases':[{'before':v,'slot_found':found,
                                         'after':tracker_counter_projection(v,found)}
                                        for found in (False,True) for v in (0,1,2,(1 << 64)-1)],
            'synthetic_root_cases': cases, 'synthetic_split_cases':[split_projection(i) for i in range(12)],
            'limitations': 'Selected static byte sites only; unwind actions, allocator behavior and runtime rollback are not established.'}


def write_tsv(path, rows, fields):
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter='\t', lineterminator='\n', extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def generate(out):
    result = collect(TARGET.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    write_tsv(out / 'branches.tsv', result['branches'], ('site','bytes','cc','taken','fallthrough'))
    records = [row for table in result['exception_tables'] for row in table['entries']]
    write_tsv(out / 'exception-sites.tsv', records, ('function','start','end','landing','action','record','raw'))
    write_tsv(out / 'calls.tsv', result['direct_calls'], ('label','site','bytes','target'))
    write_tsv(out / 'failure-routes.tsv', result['failure_routes'],
              ('label','function','branch','failure_arm','failure_call','landing','action','callsite_record'))
    write_tsv(out / 'counter-cases.tsv', result['synthetic_counter_cases'], ('before','slot_found','after'))
    write_tsv(out / 'root-cases.tsv', result['synthetic_root_cases'],
              ('root_present','allocation_succeeds','height','expected_height','outcome','child_written','header_written'))
    write_tsv(out / 'split-cases.tsv', result['synthetic_split_cases'],
              ('position','new_key','pivot_index','promoted','side','local_index','left','right'))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(args.out)


if __name__ == '__main__':
    main()

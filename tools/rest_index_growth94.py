#!/usr/bin/env python3
"""Record the node 94 resting-order index update and its growth decisions.

This is a bounded static byte collector. It never starts a target program or a
native tool. The two context copies and the enclosing caller were researched
previously; only the selected three FDEs are subjects of this packet.
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
from fde_extents import fde_extents  # noqa: E402

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BIN = ROOT / 'artifacts/node/94/hl-node'
U64 = (1 << 64) - 1
SELECTED = {
    'oid_put_counterpart': (0x379d360, 0x379d4ee, 'f5a8b2c47cc5de5aa054df07380acd9dbcf30822a4b3a1c874f446db9dcc9c71'),
    'oid_table_grow': (0x357a6d0, 0x357ab95, 'e89f1caad1fe470073b4768da4948fcbd92067be9c97cde2efd1e0723eb9d5c2'),
    'tracker_entry': (0x3597020, 0x3597192, '62a7dcf9363b2b6e8be596ba401687524272180271d5a29573763c76ccb6f7ec'),
}
# Bounded context, not newly selected function extents.
COPIES = {'perp_book_put': 0x488da60, 'spot_book_put': 0x27ca640}
MASKS = ((0x116, 4), (0x164, 4))
WINDOWS = {
    'rest_old_tail_guard': (0x4312f4b, '41837d1001488b742478753c498b4d18488b442418483b48100f83ad1a0000488b442418488b40084869c9f8000000833c08020f84931a00004801c848c74010010000004c897018'),
    'rest_tracker_pointer': (0x4311df4, '488d85c01100004889842498050000'),
    'rest_head_tail_and_oid_call': (0x4312f93, '49c74510010000004d897518488b442418488d782831db4c89f2e8aeaa5700'),
    'rest_optional_client_index': (0x4312fb2, '807c2427007440488b442418488d7848488b8c24c00000008b411089842430060000f30f6f01660f7f84242006000031db488db42420060000488b5424784c89e1ff1517184601488b4424184c8db8b8000000'),
    'rest_user_slot_set': (0x4313031, 'e8fa0a29004883c02031db4889c74c89f6e8d9e36100'),
    'rest_user_to_counter': (0x4313047, '488b8c24c00000008b411089842430060000f30f6f01660f7f84242006000031db488db42420060000488bbc2498050000ff15d2174601'),
    'rest_tracker_call': (0x4313068, '488db42420060000488bbc2498050000ff15d2174601'),
    'tracker_increment_context': (0x327b210, '50e80abe3100488b482048ffc148c7c2ffffffff480f45d14889502058c3'),
    'put_hash': (0x379d368, '49bec5a9622eea7a35f14c0faff649c1c614'),
    'put_probe': (0x379d385, '488b074c8b47084c89f148c1e939660f6ec1660f60c0f20f70c000660f70c0444531db660f76c94531d24d21c6f3420f6f1430660f6fda660f74d8660fd7db85db7428'),
    'put_existing': (0x379d434, '498b4ff8498957f8b801'),
    'put_control_store': (0x379d443, '460fb614084584d20f89850000004180e2014d8d59f04d21c342880c0842884c1810f30f6f4710410fb6ca660f6ec9660fc60d0560a6fc02660ffbc1f30f7f4710'),
    'put_new_pair': (0x379d484, '49c1e1044889c14c29c949f7d94a897408f0488951f831c04889ca'),
    'put_grow_handoff': (0x379d4a8, '488d47204989f7be010000004889fb4989d44889c2b901000000ff159062fd014889df4c89fe4c89e2e9affeffff'),
    'grow_capacity_decision': (0x357a6de, '4c8b7f184c01fe0f827f0400004889fb4c8b7708498d56014889d748c1ef034889d04883e0f84829f84983fe08490f42c64889c748d1ef4839fe0f865e010000'),
    'grow_allocate': (0x357a71e, '48ffc04839f0480f46c60fb6c9488d7c2418be100000004889c2e823caffff488b742418488b4c2420488b5424284885f60f845c010000'),
    'rehash_key': (0x357a7c7, '4c89e848c1e0044d89c74929c7498b2f480fafea48c1c5144989ef4921cf'),
    'rehash_copy': (0x357a803, '458d7c24ff4521e749ffcb48c1ed394c8d60f04921cc40882c0642886c261049f7d549c1e50448f7d048c1e004f3420f6f042ff30f7f04064589fc'),
    'inplace_distance': (0x357a9b4, '4989cb4d29cb4d89d54d29cd4d31dd4d21c54983fd100f82a0000000'),
    'inplace_remark': (0x357a8c0, '48b9feffffffffffff1f4821c131ff660f6f05a9d0c8fc660f1f840000000000660fefc966410f640c3f660febc866410f7f0c3f488d7720660fefc966410f644c3f10660febc866410f7f4c3f104889f74883c1fe75c9a8017418660fefc066410f640437660feb0553d0c8fc66410f7f0437'),
    'inplace_swap': (0x357a9d0, '4d89d149f7d149c1e1044d01f9470fb61c1748c1ef394d8d6af04d21c543883c174c8b3b43887c2f104180fbff0f84af000000488b3a4d8b014c8902498939488b7a084d8b41084c894208498979084c8b3b'),
    'inplace_move': (0x357aab2, '488d71f04823730841c6040fff41c6443710fff30f6f02f3410f7f01'),
    'new_header': (0x357ab12, '488b3b48b801000000000000804c29fa48893348894b08488953104d85f6'),
    'grow_overflow': (0x357ab6a, '84c9750431c0eb91488d3ded5cd0fc488d1528af1002be39000000ff150d351f02'),
    'tracker_lookup': (0x3597029, '4889f24889fe488d7c2408e8d7302000488b5c24084885db0f84f00000004c8b7c24104c8b7424180f104424200f29442440'),
    'tracker_date': (0x359705b, 'bf3bf90a00ff152a781d0285c00f84170100000f57c00f1144242c0f1144241c0f1144240c'),
    'tracker_insert': (0x35970b5, '49c1ef394c8d47f04921c844883c3a46887c021048f7df486bff584080e601400fb6ce48294b10488d0c3a4c89743aa8488b7424404889743ab08b74244889743ab80f104424080f104c24180f105424280f11443abc0f114c3acc0f11543adc8b74243889743aec89443af048c7443af40000000066c7443afc000048ff4318'),
    'tracker_growth_context': (0x379a230, 'be010000004c89f74c89e2b9010000004989c4ff157795fd014c89e0ebbb'),
    'tracker_found_or_absent_context': (0x379a1b3, '4181fbffff00007432458d51ff664521ca4589d175af0f1f8000000000660f74d166440fd7ca4585c975244901f84983c0104883c710e96fffffff4c01d148894b084c89731048c70300000000eb1f49837e10007427418b4f10894b20f3410f6f07f30f7f43104c8933488943084889d84883c4085b415c415e415fc3be010000004c89f74c89e2b9010000004989c4ff157795fd014c89e0ebbb'),
}
BRANCHES = {
    'oid_put_counterpart': (0x379d37f,0x379d3c6,0x379d3e1,0x379d3eb,0x379d3f4,0x379d3fe,0x379d417,0x379d44b),
    'oid_table_grow': (0x357a6e5,0x357a718,0x357a74f,0x357a758,0x357a794,0x357a7ba,0x357a7f1,0x357a801,0x357a841,0x357a86a,0x357a87f,0x357a89c,0x357a915,0x357a919,0x357a937,0x357a998,0x357a9ae,0x357a9ca,0x357a9fd,0x357aa48,0x357aa8e,0x357aa94,0x357ab30,0x357ab48,0x357ab6c),
    'tracker_entry': (0x3597041,0x3597068,0x3597098,0x35970af,0x3597168),
}
# Explicit call sites, including four context edges. Do not scan for opcodes:
# an opcode byte inside an immediate is not necessarily an instruction.
CALLS = {
    'rest_to_slab_insert': (0x4312f2b, 'direct', 0x42e8710),
    'rest_to_book_oid_put': (0x4312fad, 'direct', 0x488da60),
    'rest_to_client_index': (0x4312ff3, 'relative', 0x342aa50),
    'rest_to_book_user_entry': (0x4313031, 'direct', 0x45a3b30),
    'rest_to_user_slot_set': (0x4313042, 'direct', 0x4931420),
    'rest_to_tracker_counter': (0x4313078, 'relative', 0x327b210),
    'counter_to_tracker_entry': (0x327b211, 'direct', 0x3597020),
    'tracker_entry_to_probe': (0x3597034, 'direct', 0x379a110),
    'probe_to_growth': (0x379a243, 'relative', 0x357a0f0),
    'counterpart_to_growth': (0x379d4c2, 'relative', 0x357a6d0),
    'book_to_growth': (0x488dbc2, 'relative', 0x357a6d0),
    'spot_to_growth': (0x27ca7a2, 'relative', 0x357a6d0),
    'growth_to_allocator': (0x357a738, 'direct', 0x3577160),
    'tracker_to_calendar': (0x3597060, 'relative', 0x151f6f0),
    'growth_overflow_handler': (0x357ab85, 'relative', 0x157b810),
    'tracker_date_handler': (0x359718c, 'relative', 0x157a9f0),
    'old_table_release_edge': (0x357ab5f, 'relative', 0x54c8cb0),
}
TRACKER_STORES = {
    'key_first_8': (0x35970e0, '4c89743aa8', 8, 4),
    'key_next_8': (0x35970ea, '4889743ab0', 8, 4),
    'key_last_4': (0x35970f3, '89743ab8', 4, 3),
    'scratch_copy_a': (0x3597106, '0f11443abc', 16, 4),
    'scratch_copy_b': (0x359710b, '0f114c3acc', 16, 4),
    'scratch_copy_c': (0x3597110, '0f11543adc', 16, 4),
    'scratch_copy_d': (0x3597119, '89743aec', 4, 3),
    'calendar_word': (0x359711d, '89443af0', 4, 3),
    'zero_qword': (0x3597121, '48c7443af400000000', 8, 4),
    'zero_word': (0x359712a, '66c7443afc0000', 2, 4),
}
CONSTANTS = {
    'hash_multiplier': (0x379d368, '49bec5a9622eea7a35f1', 2, 8),
    'hash_rotate': (0x379d376, '49c1c614', 3, 1),
    'fingerprint_shift': (0x379d38f, '48c1e939', 3, 1),
    'probe_group_step': (0x379d427, '4983c610', 3, 1),
    'pair_stride_shift': (0x379d3d3, '49c1e404', 3, 1),
    'capacity_mask_cutoff': (0x357a707, '4983fe08', 3, 1),
    'capacity_fraction_shift': (0x357a6f9, '48c1ef03', 3, 1),
    'same_group_cutoff': (0x357a9c6, '4983fd10', 3, 1),
    'put_growth_error_mode': (0x379d4bd, 'b901000000', 1, 4),
    'tracker_bucket_stride': (0x35970cc, '486bff58', 3, 1),
    'tracker_default_day': (0x359705b, 'bf3bf90a00', 1, 4),
    'tracker_counter_offset': (0x327b216, '488b4820', 3, 1),
    'book_oid_table_offset': (0x4312fa4, '488d7828', 3, 1),
    'book_client_table_offset': (0x4312fbe, '488d7848', 3, 1),
    'book_user_tree_offset': (0x4312ffe, '4c8db8b8000000', 3, 4),
    'state_tracker_table_offset': (0x4311df4, '488d85c0110000', 3, 4),
    'table_allowance_offset': (0x379d37a, '48837f1000', 3, 1),
    'table_live_count_offset': (0x357a6de, '4c8b7f18', 3, 1),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verified_data(data, expected=TARGET):
    if digest(data) != expected:
        raise ValueError('target SHA-256 mismatch')
    return data


def offset_for(secs, va, length, *, executable=False):
    if not isinstance(va, int) or not isinstance(length, int) or va < 0 or length <= 0:
        raise ValueError('invalid virtual range')
    found = [s for s in secs if s['type'] != 8 and s['address'] <= va and
             va + length <= s['address'] + s['size'] and (not executable or s['flags'] & 4)]
    if len(found) != 1:
        raise ValueError('virtual range is not uniquely file backed')
    return found[0]['offset'] + va - found[0]['address']


def read_va(data, secs, va, length, *, executable=False):
    o = offset_for(secs, va, length, executable=executable)
    out = data[o:o + length]
    if len(out) != length:
        raise ValueError('truncated virtual range')
    return out


def check_window(data, secs, va, expected):
    wanted = bytes.fromhex(expected)
    got = read_va(data, secs, va, len(wanted), executable=True)
    if got != wanted:
        raise ValueError('instruction witness mismatch')
    return got


def verify_indexed(frame, table):
    index = frame.get('index')
    if type(index) is not int or not 0 <= index < len(table):
        raise ValueError('FDE is not indexed by the unwind header')
    entry = table[index]
    if entry['start'] != frame['start'] or entry['fde'] != frame['fde']:
        raise ValueError('unwind header and FDE disagree')
    return index


def branch(data, secs, va):
    lead = read_va(data, secs, va, 2, executable=True)
    if 0x70 <= lead[0] <= 0x7f:
        raw = lead
        size = 2
        disp = struct.unpack('<b', raw[1:])[0]
        condition = lead[0] & 15
    elif lead[0] == 0x0f and 0x80 <= lead[1] <= 0x8f:
        raw = read_va(data, secs, va, 6, executable=True)
        size = 6
        disp = struct.unpack('<i', raw[2:])[0]
        condition = lead[1] & 15
    else:
        raise ValueError('expected a selected conditional branch')
    return {'site': va, 'bytes': raw.hex(), 'condition': condition,
            'taken': va + size + disp, 'fallthrough': va + size}


def relative_relocations(data, secs):
    tables = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(tables) != 1 or tables[0]['size'] % 24:
        raise ValueError('invalid relative relocation table')
    section = tables[0]
    entries = {}
    for pos in range(section['offset'], section['offset'] + section['size'], 24):
        if pos + 24 > len(data):
            raise ValueError('truncated relocation table')
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if info == 8:
            if slot in entries:
                raise ValueError('duplicate relative relocation')
            entries[slot] = addend
    return entries


def call_edge(data, secs, relocs, site, kind, expected):
    if kind == 'direct':
        raw = read_va(data, secs, site, 5, executable=True)
        if raw[0] != 0xe8:
            raise ValueError('expected direct call')
        target = site + 5 + struct.unpack_from('<i', raw, 1)[0]
        slot = None
    elif kind == 'relative':
        raw = read_va(data, secs, site, 6, executable=True)
        if raw[:2] != b'\xff\x15':
            raise ValueError('expected RIP-relative indirect call')
        slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
        # A relocation slot is data, and must itself be file backed.
        read_va(data, secs, slot, 8)
        if slot not in relocs:
            raise ValueError('missing relative call relocation')
        target = relocs[slot]
    else:
        raise ValueError('unknown call kind')
    if target != expected:
        raise ValueError('call target mismatch')
    return {'site': site, 'bytes': raw.hex(), 'kind': kind, 'slot': slot, 'target': target}


def relocation_records(data, secs, slots):
    table = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(table) != 1 or table[0]['size'] % 24:
        raise ValueError('invalid relative relocation table')
    table = table[0]
    records = {}
    for pos in range(table['offset'], table['offset'] + table['size'], 24):
        raw = data[pos:pos + 24]
        if len(raw) != 24:
            raise ValueError('truncated relocation table')
        slot, info, addend = struct.unpack('<QQq', raw)
        if info == 8 and slot in slots:
            if slot in records:
                raise ValueError('duplicate relative relocation')
            records[slot] = (table['address'] + pos - table['offset'], pos, raw, addend)
    if set(records) != set(slots):
        raise ValueError('missing selected relative relocation')
    return records


def normalized(body):
    result = bytearray(body)
    for off, count in MASKS:
        if off + count > len(result):
            raise ValueError('comparison mask outside body')
        result[off:off + count] = b'\0' * count
    return bytes(result)


def shuffle_target(data, secs, va):
    raw = read_va(data, secs, va, 9, executable=True)
    if raw[:4] != bytes.fromhex('660fc60d') or raw[8] != 2:
        raise ValueError('unexpected RIP-relative shuffle')
    return va + 9 + struct.unpack_from('<i', raw, 4)[0]


def lea_target(data, secs, va):
    raw = read_va(data, secs, va, 7, executable=True)
    if raw[:3] != bytes.fromhex('488d3d'):
        raise ValueError('unexpected RIP-relative address instruction')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def growth_decision(mask, items, additional):
    """A mathematical projection of the recorded capacity guard, not a target run."""
    if any(type(v) is not int or v < 0 or v > U64 for v in (mask, items, additional)):
        raise ValueError('expected unsigned 64-bit words')
    if mask not in (0, 3, 7) and (mask < 15 or (mask & (mask + 1)) != 0):
        raise ValueError('mask is not an admitted bucket shape')
    if items + additional > U64:
        return 'overflow', None, None
    buckets = (mask + 1) & U64
    cap = mask if mask < 8 else ((buckets & (U64 ^ 7)) - (buckets >> 3)) & U64
    required = items + additional
    return ('rehash_in_place' if required <= cap // 2 else 'allocate', cap, required)


def hash_key(key, multiplier, rotate):
    if type(key) is not int or key < 0 or key > U64 or not 0 < rotate < 64:
        raise ValueError('invalid key or rotate')
    x = (key * multiplier) & U64
    return ((x << rotate) | (x >> (64 - rotate))) & U64


def counter_after_rest(value):
    if type(value) is not int or not 0 <= value <= U64:
        raise ValueError('counter must be an unsigned 64-bit word')
    return min(value + 1, U64)


def tracker_route(found, has_capacity, grow_ok, date_ok):
    """Project selected branches; failure handler and unwind effects are unknown."""
    if any(type(x) is not bool for x in (found, has_capacity, grow_ok, date_ok)):
        raise ValueError('tracker route inputs must be booleans')
    if found:
        return 'existing', 'none', 'increment'
    growth = 'none' if has_capacity else 'called'
    if not has_capacity and not grow_ok:
        return 'vacant', growth, 'growth_failure'
    if not date_ok:
        return 'vacant', growth, 'date_failure'
    return 'vacant', growth, 'insert_and_increment'


class LogicalIndex:
    """Synthetic structural projection, not target execution or an x86 emulator.

    The model keeps the target's 16-byte group probe, control markers and the
    three in-place choices. It models only tables with at least 16 buckets,
    ignores mirror storage, and assumes successful allocation and valid state.
    Its result is checked against independent key/value expectations, not a
    captured runtime fixture.
    """
    def __init__(self, multiplier, rotate, buckets=16):
        if buckets < 16 or buckets & (buckets - 1):
            raise ValueError('synthetic table requires a power of two >= 16')
        self.multiplier, self.rotate = multiplier, rotate
        self.buckets = buckets
        self.control = [0xff] * buckets
        self.pairs = [None] * buckets
        self.items = 0
        self.available = buckets - buckets // 8
        self.events = []
        self.rehash_counts = {'same_group': 0, 'move': 0, 'swap': 0}

    def _search(self, key):
        h = hash_key(key, self.multiplier, self.rotate)
        tag = h >> 57
        mask = self.buckets - 1
        start = h & mask
        step = 0
        free = None
        for _ in range(self.buckets // 16 + 1):
            group = [(start + i) & mask for i in range(16)]
            for i in group:
                if self.control[i] == tag and self.pairs[i] is not None and self.pairs[i][0] == key:
                    return i, True
            if free is None:
                free = next((i for i in group if self.control[i] & 0x80), None)
            if any(self.control[i] == 0xff for i in group):
                if free is None:
                    raise ValueError('synthetic probe has no free bucket')
                return free, False
            step += 16
            start = (start + step) & mask
        raise ValueError('synthetic probe did not terminate')

    def _first_negative(self, key):
        mask = self.buckets - 1
        home = hash_key(key, self.multiplier, self.rotate) & mask
        start, step = home, 0
        for _ in range(self.buckets // 16 + 1):
            for i in range(16):
                candidate = (start + i) & mask
                if self.control[candidate] & 0x80:
                    return home, candidate
            step += 16
            start = (start + step) & mask
        raise ValueError('synthetic rehash found no negative control')

    def _inplace_rehash(self):
        self.control = [0x80 if c < 0x80 else 0xff for c in self.control]
        mask = self.buckets - 1
        i, steps = 0, 0
        while i < self.buckets:
            if self.control[i] != 0x80:
                i += 1
                continue
            steps += 1
            if steps > self.buckets * self.buckets:
                raise ValueError('synthetic in-place rehash did not terminate')
            pair = self.pairs[i]
            if pair is None:
                raise ValueError('synthetic live control has no pair')
            home, dest = self._first_negative(pair[0])
            tag = hash_key(pair[0], self.multiplier, self.rotate) >> 57
            same = ((((i - home) & mask) ^ ((dest - home) & mask)) < 16)
            if same:
                self.control[i] = tag
                self.rehash_counts['same_group'] += 1
                i += 1
            else:
                old_control = self.control[dest]
                self.control[dest] = tag
                if old_control == 0xff:
                    self.control[i] = 0xff
                    self.pairs[dest], self.pairs[i] = pair, None
                    self.rehash_counts['move'] += 1
                    i += 1
                elif old_control == 0x80:
                    self.pairs[dest], self.pairs[i] = pair, self.pairs[dest]
                    self.rehash_counts['swap'] += 1
                else:
                    raise ValueError('synthetic destination is not available')
        self.available = self.buckets - self.buckets // 8 - self.items

    def _store_without_growth(self, key, value):
        if type(value) is not int or not 0 <= value <= U64:
            raise ValueError('synthetic value must be a 64-bit word')
        i, found = self._search(key)
        if found:
            old = self.pairs[i][1]
            self.pairs[i] = (key, value)
            return old
        self.available -= self.control[i] & 1
        self.control[i] = hash_key(key, self.multiplier, self.rotate) >> 57
        self.pairs[i] = (key, value)
        self.items += 1
        return None

    def put(self, key, value):
        if self.available == 0:
            decision, capacity, required = growth_decision(self.buckets - 1, self.items, 1)
            self.events.append(decision)
            if decision == 'rehash_in_place':
                self._inplace_rehash()
            else:
                pairs = [p for p in self.pairs if p is not None]
                buckets = self.buckets
                requested = max(capacity + 1, required)
                while buckets - buckets // 8 < requested:
                    buckets *= 2
                self.buckets = buckets
                self.control = [0xff] * buckets
                self.pairs = [None] * buckets
                self.items = 0
                self.available = buckets - buckets // 8
                for old_key, old_value in pairs:
                    self._store_without_growth(old_key, old_value)
        return self._store_without_growth(key, value)

    def force_tombstone(self, key):
        """Set a synthetic deleted control; no target deletion behavior is asserted."""
        i, found = self._search(key)
        if not found:
            raise ValueError('no such synthetic key')
        self.control[i] = 0x80
        self.pairs[i] = None
        self.items -= 1

    def logical_pairs(self):
        return dict(pair for pair in self.pairs if pair is not None)

    def validate(self):
        if self.items != sum(c < 0x80 for c in self.control):
            raise ValueError('synthetic live count mismatch')
        tombstones = 0
        for i, ctrl in enumerate(self.control):
            pair = self.pairs[i]
            if ctrl < 0x80:
                if pair is None or hash_key(pair[0], self.multiplier, self.rotate) >> 57 != ctrl:
                    raise ValueError('synthetic fingerprint mismatch')
                if self._search(pair[0]) != (i, True):
                    raise ValueError('synthetic live key is not uniquely reachable')
            elif ctrl == 0x80:
                if pair is not None:
                    raise ValueError('synthetic tombstone retains a live pair')
                tombstones += 1
            elif ctrl != 0xff or pair is not None:
                raise ValueError('synthetic invalid control')
        if self.available != self.buckets - self.buckets // 8 - self.items - tombstones:
            raise ValueError('synthetic growth allowance mismatch')
        if len(self.logical_pairs()) != self.items:
            raise ValueError('synthetic duplicate keys')


def rehash_trial(seed, multiplier, rotate):
    """Deterministic synthetic table with collisions, tombstones and all repair arms."""
    table = LogicalIndex(multiplier, rotate, 64)
    x, keys = seed + 1, []
    for i in range(56):
        x = (x * 6364136223846793005 + 1442695040888963407) & U64
        keys.append(x)
        table.put(x, i)
    order = sorted(range(56), key=lambda i: ((i * 2654435761) ^ (seed * 2246822519)) & 0xffffffff)
    for i in order[:29]:
        table.force_tombstone(keys[i])
    table.validate()
    expected = {key: i for i, key in enumerate(keys) if i not in set(order[:29])}
    if seed in expected:
        raise ValueError('synthetic added key collides with a fixture key')
    expected[seed] = 9999
    table.put(seed, 9999)
    table.validate()
    if table.logical_pairs() != expected or table.events != ['rehash_in_place']:
        raise ValueError('synthetic rehash disagrees with logical pairs')
    return table


def logical_scenarios(multiplier, rotate):
    table = LogicalIndex(multiplier, rotate)
    collisions = [k for k in range(256) if hash_key(k, multiplier, rotate) & 15 == 15][:4]
    if len(collisions) != 4:
        raise ValueError('fixture did not find four colliding keys')
    rows = []
    for n, key in enumerate(collisions):
        table.put(key, n + 1)
    rows.append(('colliding_inserts', table.buckets, table.items, table.available,
                 len(table.logical_pairs()), '-', '-'))
    old = table.put(collisions[0], 99)
    rows.append(('replace_existing', table.buckets, table.items, table.available,
                 len(table.logical_pairs()), old, '-'))
    full = LogicalIndex(multiplier, rotate)
    for key in range(14):
        full.put(key, key + 10)
    old = full.put(0, 777)
    rows.append(('full_existing_key', full.buckets, full.items, full.available,
                 len(full.logical_pairs()), old, full.events[-1]))
    sparse = LogicalIndex(multiplier, rotate)
    for key in range(14):
        sparse.put(key, key + 10)
    for key in range(8):
        sparse.force_tombstone(key)
    sparse.put(42, 1000)
    sparse.validate()
    rows.append(('tombstone_rebuild', sparse.buckets, sparse.items, sparse.available,
                 len(sparse.logical_pairs()), '-', sparse.events[-1]))
    return rows


def tsv(headers, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue().encode()


def generate(data):
    verified_data(data)
    secs = sections(data)
    _, fs, _ = fde_extents(data)
    _, unwind = unwind_index(data)
    frames = {}
    for f in fs:
        if f['start'] in frames:
            raise ValueError('duplicate FDE start')
        frames[f['start']] = f
    functions = []
    for name, (start, end, expected_sha) in SELECTED.items():
        f = frames.get(start)
        if f is None or f['end'] != end:
            raise ValueError('selected unwind extent mismatch')
        index = verify_indexed(f, unwind)
        raw = read_va(data, secs, start, end - start, executable=True)
        if digest(raw) != expected_sha:
            raise ValueError('selected function bytes mismatch')
        functions.append({'role': name, 'start_va': hex(start), 'end_va': hex(end),
                          'file_offset': hex(offset_for(secs, start, len(raw), executable=True)),
                          'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']),
                          'unwind_index': index,
                          'lsda_va': None if f['lsda'] is None else hex(f['lsda']),
                          'length': len(raw), 'sha256': digest(raw), 'raw_hex': raw.hex()})
    witnesses = []
    for label, (va, expected) in WINDOWS.items():
        raw = check_window(data, secs, va, expected)
        witnesses.append((label, hex(va), hex(offset_for(secs, va, len(raw), executable=True)), len(raw), raw.hex()))
    constant_rows, decoded_constants = [], {}
    for label, (site, expected, immediate_offset, width) in CONSTANTS.items():
        raw = check_window(data, secs, site, expected)
        operand = raw[immediate_offset:immediate_offset + width]
        if len(operand) != width:
            raise ValueError('immediate outside instruction witness')
        value = int.from_bytes(operand, 'little')
        decoded_constants[label] = value
        constant_rows.append((label, hex(site), raw.hex(), immediate_offset, width, hex(value), value))
    stride_insn = check_window(data, secs, 0x35970cc, '486bff58')
    stride = stride_insn[3]
    store_rows = []
    for label, (site, expected, width, displacement_index) in TRACKER_STORES.items():
        raw = check_window(data, secs, site, expected)
        displacement = struct.unpack_from('<b', raw, displacement_index)[0]
        begin = stride + displacement
        if not 0 <= begin < begin + width <= stride:
            raise ValueError('selected tracker store outside bucket')
        store_rows.append((label, hex(site), raw.hex(), hex(begin), width, hex(begin + width)))
    body = read_va(data, secs, SELECTED['oid_put_counterpart'][0], 398, executable=True)
    norm = normalized(body)
    copy_rows = []
    operands = []
    for label, va in [('selected_counterpart', SELECTED['oid_put_counterpart'][0]), *COPIES.items()]:
        site = va + 0x112
        target = shuffle_target(data, secs, site)
        if target != 0x203480:
            raise ValueError('copy shuffle target mismatch')
        operands.append((label, hex(site), read_va(data, secs, site, 9, executable=True).hex(), hex(target)))
    for label, va in COPIES.items():
        raw = read_va(data, secs, va, len(body), executable=True)
        frame = frames.get(va)
        if frame is None or frame['end'] != va + len(body):
            raise ValueError('context copy unwind extent mismatch')
        index = verify_indexed(frame, unwind)
        if normalized(raw) != norm:
            raise ValueError('context copy differs outside explicit masks')
        comparison = 'raw_equal' if raw == body else 'normalized_only'
        copy_rows.append((label, hex(va), hex(frame['end']), hex(frame['fde']), index, len(raw), comparison, digest(raw), raw.hex(), digest(norm),
                          ','.join(hex(i) for i, (x, y) in enumerate(zip(body, raw)) if x != y)))
    branch_rows = []
    for role, addresses in BRANCHES.items():
        lo, hi, _ = SELECTED[role]
        for va in addresses:
            b = branch(data, secs, va)
            if not (lo <= b['taken'] < hi and lo <= b['fallthrough'] < hi):
                raise ValueError('branch leaves selected FDE')
            branch_rows.append((role, hex(va), b['bytes'], hex(b['condition']), hex(b['taken']), hex(b['fallthrough'])))
    relocs = relative_relocations(data, secs)
    call_rows = []
    selected_slots = set()
    for label, (site, kind, target) in CALLS.items():
        c = call_edge(data, secs, relocs, site, kind, target)
        if c['slot'] is not None:
            selected_slots.add(c['slot'])
        call_rows.append((label, hex(site), c['bytes'], kind, '' if c['slot'] is None else hex(c['slot']), hex(c['target'])))
    selected_relocations = relocation_records(data, secs, selected_slots)
    relocation_rows = [(hex(slot), hex(rec_va), hex(pos), raw.hex(), hex(addend))
                       for slot, (rec_va, pos, raw, addend) in sorted(selected_relocations.items())]
    multiplier = decoded_constants['hash_multiplier']
    rotate = decoded_constants['hash_rotate']
    if multiplier != 0xf1357aea2e62a9c5 or rotate != 20:
        raise ValueError('unexpected multiplier or rotate')
    lanes = read_va(data, secs, 0x203480, 16)
    negative_controls = read_va(data, secs, 0x207980, 16)
    if lanes != bytes.fromhex('0000000000000000ffffffffffffffff') or negative_controls != b'\x80' * 16:
        raise ValueError('unexpected control-byte constants')
    diagnostic_va = lea_target(data, secs, 0x357ab72)
    length_insn = read_va(data, secs, 0x357ab80, 5, executable=True)
    if diagnostic_va != 0x280866 or length_insn[0] != 0xbe:
        raise ValueError('unexpected diagnostic operand')
    diagnostic_len = struct.unpack_from('<I', length_insn, 1)[0]
    diagnostic = read_va(data, secs, diagnostic_va, diagnostic_len)
    if not diagnostic.startswith(b'Hash table capacity overflow'):
        raise ValueError('unexpected capacity diagnostic span')
    literals = [('counter_update_lanes', '0x203480', len(lanes), lanes.hex()),
                ('inplace_rehash_marker', '0x207980', len(negative_controls), negative_controls.hex()),
                ('capacity_failure_span', hex(diagnostic_va), len(diagnostic), diagnostic.hex())]
    cap_cases = []
    for mask in (0, 3, 7, 15, 31, 63):
        _, cap, _ = growth_decision(mask, 0, 0)
        for items, additional in sorted({(0, 1), (cap // 2, 0), (cap // 2, 1), (cap, 0), (cap, 1)}):
            mode, actual_cap, required = growth_decision(mask, items, additional)
            cap_cases.append((hex(mask), cap, items, additional, required, mode))
    mode, _, _ = growth_decision(15, U64, 1)
    cap_cases.append(('0xf', 14, U64, 1, 'overflow', mode))
    hash_cases = []
    for key in (0, 1, 2, 3, 0xffff, 0x10000, 1 << 63, U64):
        value = hash_key(key, multiplier, rotate)
        hash_cases.append((hex(key), hex(value), hex(value >> 57), hex(value & 15)))
    counters = [(hex(n), hex(counter_after_rest(n))) for n in (0, 1, U64 - 1, U64)]
    logical_cases = logical_scenarios(multiplier, rotate)
    rehash_cases = []
    for seed in range(16):
        table = rehash_trial(seed, multiplier, rotate)
        pairs = b''.join(struct.pack('<QQ', key, value) for key, value in sorted(table.logical_pairs().items()))
        rehash_cases.append((seed, table.buckets, table.items, table.available,
                             table.rehash_counts['same_group'], table.rehash_counts['move'],
                             table.rehash_counts['swap'], digest(pairs)))
    tracker_cases = [(int(found), int(has_capacity), int(grow_ok), int(date_ok), *tracker_route(found, has_capacity, grow_ok, date_ok))
                     for found in (False, True) for has_capacity in (False, True)
                     for grow_ok in (False, True) for date_ok in (False, True)]
    results = {
        'functions.json': (json.dumps({'target_sha256': TARGET, 'functions': functions}, indent=2, sort_keys=True) + '\n').encode(),
        'witnesses.tsv': tsv(('label','va','file_offset','length','raw_hex'), witnesses),
        'constants.tsv': tsv(('label','instruction_va','raw_hex','operand_offset','operand_width','value_hex','value_decimal'), constant_rows),
        'tracker-stores.tsv': tsv(('label','site','raw_hex','bucket_offset','width','end_offset'), store_rows),
        'branches.tsv': tsv(('role','site','raw_hex','condition_nibble','taken','fallthrough'), branch_rows),
        'calls.tsv': tsv(('label','site','raw_hex','kind','relocation_slot','target'), call_rows),
        'relocations.tsv': tsv(('slot','record_va','file_offset','raw_hex','relative_addend'), relocation_rows),
        'context-copies.tsv': tsv(('role','start','end','fde','unwind_index','length','classification','raw_sha256','raw_hex','masked_sha256','different_byte_offsets'), copy_rows),
        'copy-operands.tsv': tsv(('role','shuffle_site','raw_hex','target'), operands),
        'literals.tsv': tsv(('label','va','length','raw_hex'), literals),
        'capacity-projections.tsv': tsv(('mask','capacity','items','additional','required','decision'), cap_cases),
        'hash-projections.tsv': tsv(('key','hash','fingerprint','bucket_mask_15'), hash_cases),
        'counter-projections.tsv': tsv(('before','after'), counters),
        'logical-projections.tsv': tsv(('scenario','buckets','items','available','logical_pairs','replaced_value','growth_decision'), logical_cases),
        'rehash-projections.tsv': tsv(('seed','buckets','items','available','same_group','moves','swaps','logical_pairs_sha256'), rehash_cases),
        'tracker-projections.tsv': tsv(('found','has_capacity','grow_ok','date_ok','lookup','growth','result'), tracker_cases),
    }
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    results = generate(BIN.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in results.items():
        (args.out / name).write_bytes(data)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as exc:
        print(f'rest_index_growth94: {exc}', file=sys.stderr)
        raise SystemExit(1)

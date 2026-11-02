#!/usr/bin/env python3
"""Recover the selected node-94 preparation and account-cache path from ELF bytes.

Only static file data is read. This is a bounded byte-pattern extractor, not an
x86 decoder, a runtime trace, or a reconstruction of the target executable.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_index
import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64 = (1 << 64) - 1

# Actual .eh_frame intervals, not next-start estimates. The hashes pin each
# complete selected body in addition to the authenticated whole artifact.
FUNCTIONS = {
    0x4e758a0: (0x4e76117, '5efb691b457f4bbe95f0fe80b61286342724b9384e4690ee89ddd1be6dc3f01b', 'account table reserve and rehash'),
    0x4e76b20: (0x4e76bb8, '8a9e3caa7492b8920713ab77a2dbeafb10a55fb57b5aaf089defa53b297d458c', 'preparation descriptor method 28'),
    0x4e76c20: (0x4e76cb8, '8e0ac6ac599fb75d07b1db9f1e6f7c4395eed92401db967bd918bb18519570f1', 'preparation descriptor method 20'),
    0x4e76d40: (0x4e76dd8, 'ac05befd7457cdd49cf0ad2c74dc8a1f663536982254bb58bdefbcea62a2c490', 'preparation descriptor method 18'),
    0x4e77060: (0x4e7738c, '8fd9d7d4200ec1edf009ef4bba93f26991fc3c25fed66c60bc5244dffae5dbad', 'account access and journal decision'),
    0x4e77390: (0x4e77914, '1a9bb698d73da84e5edca08d4786c9c58ad7e466bc6be04e83e2d369665605d1', 'address and slot preparation walker'),
    0x4e77920: (0x4e77ad6, 'e154de00f61345d427432872cae23e2b71e78ee39b8b4e87a192f4375d44e871', 'four callback pair constructor'),
    0x4e8c100: (0x4e8c286, '24ca60d09dac417769b94f3e3c4ae0e2a6da7108c075af68919c15553ec63064', 'account table entry probe'),
    0x4e8c420: (0x4e8c52f, '303ad5f76fc661bdb1ba37acf6340cfa7caec6308de4832636ab3fd3f1ff6893', 'address set membership probe'),
    0x4e8c640: (0x4e8c827, '872411e22196290f28329c19ae20e8ba3f3c6a4196fbaff17edc9ea6f1ee35d6', 'address set insertion'),
}

# Windows were selected by manual instruction inspection. Boundaries, output
# bytes and digests below are recovered again from the authenticated ELF.
WINDOWS = (
    ('construct_first_pair', 0x4e7792e, 0x4e77968),
    ('construct_preparation_pair', 0x4e77968, 0x4e7799f),
    ('construct_other_pairs', 0x4e7799f, 0x4e77a26),
    ('constructor_failure_cleanup', 0x4e77a38, 0x4e77ad6),
    ('prepare_inputs_and_return', 0x4e76b20, 0x4e76bb8),
    ('access_account_entry', 0x4e77060, 0x4e770b8),
    ('access_missing_account', 0x4e770b8, 0x4e77178),
    ('access_set_membership', 0x4e77178, 0x4e771a3),
    ('access_publish_account', 0x4e771a3, 0x4e77251),
    ('access_miss_journal_decision', 0x4e77251, 0x4e772b5),
    ('access_hit_flag_and_return', 0x4e772b5, 0x4e77308),
    ('access_seed_and_cleanup', 0x4e77330, 0x4e7738c),
    ('walk_rows_and_entry', 0x4e773ab, 0x4e77451),
    ('walk_miss_default_and_guard', 0x4e77451, 0x4e774d6),
    ('walk_prepare_miss_record', 0x4e774d6, 0x4e77521),
    ('walk_find_free_control', 0x4e77521, 0x4e7758c),
    ('walk_publish_account_bucket', 0x4e7758c, 0x4e775e0),
    ('walk_existing_and_empty_slots', 0x4e775e0, 0x4e77610),
    ('walk_slot_probe', 0x4e77610, 0x4e776b0),
    ('walk_new_slot_zero_payload', 0x4e776b0, 0x4e77778),
    ('walk_slot_endianness_and_hash', 0x4e77781, 0x4e77819),
    ('walk_slot_reserve_boundary', 0x4e7783b, 0x4e7785f),
    ('walk_normal_and_unwind', 0x4e778bd, 0x4e77914),
    ('entry_hash_and_key_loads', 0x4e8c100, 0x4e8c15d),
    ('entry_candidates_and_empty', 0x4e8c15d, 0x4e8c21e),
    ('entry_hit_record', 0x4e8c21e, 0x4e8c232),
    ('entry_miss_record', 0x4e8c232, 0x4e8c258),
    ('entry_reserve_boundary', 0x4e8c258, 0x4e8c286),
    ('set_contains_empty_and_hash', 0x4e8c420, 0x4e8c49f),
    ('set_contains_probe', 0x4e8c49f, 0x4e8c52f),
    ('resize_choose_rehash_or_growth', 0x4e758ae, 0x4e75918),
    ('resize_large_bucket_count', 0x4e7594a, 0x4e75993),
    ('resize_allocation_size_gates', 0x4e75993, 0x4e759d8),
    ('resize_allocation_and_init', 0x4e759d8, 0x4e75a54),
    ('resize_move_to_new_allocation', 0x4e75a54, 0x4e75b96),
    ('resize_reclassify_controls', 0x4e75bd2, 0x4e75c65),
    ('resize_in_place_target_and_control', 0x4e75c80, 0x4e75d58),
    ('resize_swap_full_bucket', 0x4e75d58, 0x4e75f74),
    ('resize_rehash_moves', 0x4e75fc0, 0x4e7602b),
    ('resize_publish_and_failures', 0x4e7602b, 0x4e76117),
    ('set_hash_and_budget', 0x4e8c647, 0x4e8c698),
    ('set_candidates', 0x4e8c698, 0x4e8c740),
    ('set_insert_and_count', 0x4e8c740, 0x4e8c7e2),
    ('set_reserve', 0x4e8c7e2, 0x4e8c827),
)

# Each item is (name, site, expected destination). The type, displacement,
# fallthrough and destination are decoded from the original byte shape.
EDGES = (
    ('pair_alloc_1_null', 0x4e7793f, 0x4e77a38),
    ('pair_alloc_2_null', 0x4e77976, 0x4e77a48),
    ('pair_alloc_3_null', 0x4e779ad, 0x4e77a5a),
    ('pair_alloc_4_null', 0x4e779e4, 0x4e77a6c),
    ('prepare_first_set', 0x4e76b62, 0x4e8c640),
    ('prepare_second_set', 0x4e76b80, 0x4e8c640),
    ('prepare_walk', 0x4e76b8b, 0x4e77390),
    ('prepare_nonfive', 0x4e76b94, 0x4e76b9b),
    ('access_account_entry', 0x4e770a5, 0x4e8c100),
    ('access_account_hit', 0x4e770b2, 0x4e772b5),
    ('access_seed_unready', 0x4e7712c, 0x4e77330),
    ('access_set_membership', 0x4e77182, 0x4e8c420),
    ('access_find_control_slow', 0x4e771bd, 0x4e77308),
    ('access_set_hit_no_journal', 0x4e77256, 0x4e772ca),
    ('access_no_journal_frame', 0x4e7725f, 0x4e772fb),
    ('access_frame_capacity_available', 0x4e7727b, 0x4e7728b),
    ('access_hit_flag_set', 0x4e772c8, 0x4e772e8),
    ('access_hit_frame_exists', 0x4e772f5, 0x4e77265),
    ('walk_empty', 0x4e773bc, 0x4e778bd),
    ('walk_next_row_end', 0x4e77406, 0x4e778bd),
    ('walk_account_entry', 0x4e77439, 0x4e8c100),
    ('walk_account_hit', 0x4e7744b, 0x4e775f0),
    ('walk_seed_unready', 0x4e774d0, 0x4e7789c),
    ('walk_find_control_slow', 0x4e7753d, 0x4e77874),
    ('walk_control_nonnegative', 0x4e77559, 0x4e778a6),
    ('walk_miss_slots_nonempty', 0x4e775e3, 0x4e775fe),
    ('walk_hit_slots_empty', 0x4e775f8, 0x4e773f0),
    ('slot_full_key_hit', 0x4e7766d, 0x4e77778),
    ('slot_empty_control', 0x4e77690, 0x4e776b0),
    ('slot_needs_reserve', 0x4e776b6, 0x4e7783b),
    ('slot_next_or_row', 0x4e7777b, 0x4e773f0),
    ('entry_full_key_hit', 0x4e8c1e8, 0x4e8c21e),
    ('entry_empty_control', 0x4e8c20c, 0x4e8c232),
    ('entry_needs_reserve', 0x4e8c237, 0x4e8c258),
    ('set_contains_count_zero', 0x4e8c425, 0x4e8c52c),
    ('set_contains_full_key_hit', 0x4e8c4fb, 0x4e8c52e),
    ('set_contains_empty_control', 0x4e8c51a, 0x4e8c52c),
    ('reserve_count_carry', 0x4e758bb, 0x4e759c8),
    ('reserve_in_place', 0x4e758ee, 0x4e75918),
    ('reserve_large_request', 0x4e758fe, 0x4e7594a),
    ('reserve_request_too_large', 0x4e7595a, 0x4e759c8),
    ('reserve_mul_overflow', 0x4e7599e, 0x4e759c8),
    ('reserve_size_ok', 0x4e759c6, 0x4e759d8),
    ('reserve_overflow_fatal', 0x4e759cb, 0x4e760e6),
    ('reserve_alloc_null', 0x4e759fc, 0x4e7607c),
    ('reserve_old_count_zero', 0x4e75a4e, 0x4e76089),
    ('reserve_rehash_empty_destination', 0x4e75d52, 0x4e76008),
    ('reserve_alloc_error_fatal', 0x4e76080, 0x4e760ff),
    ('set_reserve_first', 0x4e8c692, 0x4e8c7e2),
    ('set_full_key_hit', 0x4e8c720, 0x4e8c7d7),
)

# RELA slots and expected symbol-free R_X86_64_RELATIVE addends. The provider
# entry is an earlier endpoint; it is not one of the selected function bodies.
RELA = {
    0x574bea0: (8, 0x4e76bc0, 'prior provider method'),
    0x574bec0: (8, 0x4e76d40, 'preparation method 18'),
    0x574bec8: (8, 0x4e76c20, 'preparation method 20'),
    0x574bed0: (8, 0x4e76b20, 'preparation method 28'),
    0x576dfd8: (8, 0x54c06b0, 'allocation boundary'),
    0x576dfe0: (0x600000006, 0, 'external copy import'),
    0x576e010: (8, 0x54c8cb0, 'deallocation boundary'),
    0x576e020: (8, 0x1345e2a, 'allocation failure boundary'),
    0x576e098: (8, 0x157b810, 'capacity failure boundary'),
    0x576e1f8: (0xa00000006, 0, 'external fill import'),
    0x576e3e0: (8, 0x5788348, 'process seed pointer'),
    0x576e470: (8, 0x157a9f0, 'missing journal frame boundary'),
    0x5773268: (8, 0x4ea53c0, 'default record boundary'),
    0x5773270: (8, 0x4e7c4e0, 'journal record reserve boundary'),
    0x5773718: (8, 0x4e758a0, 'account table reserve'),
    0x5773780: (8, 0x4e742e0, 'prior slot reserve boundary'),
    0x5773790: (8, 0x4e95b80, 'address set reserve boundary'),
}

INDIRECT = (
    ('constructor_allocate', 0x4e77936, 0x576dfd8),
    ('access_default_record', 0x4e770d6, 0x5773268),
    ('access_record_copy', 0x4e7723d, 0x576dfe0),
    ('access_journal_reserve', 0x4e77285, 0x5773270),
    ('access_missing_journal_frame', 0x4e77302, 0x576e470),
    ('walker_default_record', 0x4e77479, 0x5773268),
    ('walker_account_record_copy', 0x4e775c7, 0x576dfe0),
    ('walker_slot_reserve', 0x4e7784f, 0x5773780),
    ('entry_account_reserve', 0x4e8c275, 0x5773718),
    ('set_reserve', 0x4e8c7fc, 0x5773790),
    ('reserve_allocate', 0x4e759f3, 0x576dfd8),
    ('reserve_control_fill', 0x4e75a40, 0x576e1f8),
    ('reserve_bucket_copy', 0x4e75b7f, 0x576dfe0),
    ('reserve_old_allocation_release', 0x4e760d1, 0x576e010),
    ('reserve_capacity_failure', 0x4e760f9, 0x576e098),
    ('reserve_allocation_failure', 0x4e76107, 0x576e020),
)


def check_digest(data: bytes, expected: str = TARGET_SHA256) -> None:
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('target SHA-256 mismatch')


def file_offset(sections: list[dict], va: int, size: int, executable: bool = False) -> int:
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid VA range')
    end = va + size
    if end > 1 << 64:
        raise ValueError('VA range overflow')
    matches = [s for s in sections if s['type'] != 8 and s['size'] and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and end <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('VA range is not uniquely file-backed')
    s = matches[0]
    return s['offset'] + va - s['address']


def data_at(data: bytes, sections: list[dict], va: int, size: int, executable: bool = False) -> bytes:
    off = file_offset(sections, va, size, executable)
    chunk = data[off:off + size]
    if len(chunk) != size:
        raise ValueError('truncated VA range')
    return chunk


def expect_bytes(data: bytes, secs: list[dict], va: int, expected: bytes) -> bytes:
    actual = data_at(data, secs, va, len(expected), True)
    if actual != expected:
        raise ValueError('instruction byte predicate mismatch')
    return actual


def require_body(body: bytes, digest: str) -> None:
    if hashlib.sha256(body).hexdigest() != digest:
        raise ValueError('selected body byte mismatch')


def decode_rel_branch(site: int, raw: bytes) -> tuple[str, int, int]:
    if len(raw) >= 5 and raw[0] in (0xe8, 0xe9):
        length, kind = 5, ('call' if raw[0] == 0xe8 else 'jmp')
        disp = struct.unpack_from('<i', raw, 1)[0]
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        length, kind = 6, f'jcc_{raw[1] & 15:x}'
        disp = struct.unpack_from('<i', raw, 2)[0]
    elif len(raw) >= 2 and (0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb):
        length = 2
        kind = f'jcc_{raw[0] & 15:x}' if raw[0] != 0xeb else 'jmp'
        disp = struct.unpack_from('<b', raw, 1)[0]
    else:
        raise ValueError('unsupported or truncated relative transfer')
    target = site + length + disp
    if not 0 <= target <= U64:
        raise ValueError('relative target outside address space')
    return kind, length, target


def rip_destination(site: int, raw: bytes, prefix: bytes) -> int:
    if not raw.startswith(prefix) or len(raw) != len(prefix) + 4:
        raise ValueError('unexpected RIP-relative byte shape')
    dest = site + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]
    if not 0 <= dest <= U64:
        raise ValueError('RIP target outside address space')
    return dest


def read_relocations(data: bytes, secs: list[dict], wanted: dict = RELA) -> list[dict]:
    found: dict[int, list[tuple]] = {slot: [] for slot in wanted}
    for s in secs:
        if s['type'] != 4:
            continue
        if s['size'] % 24:
            raise ValueError('RELA size is not a multiple of 24')
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            if slot in found:
                found[slot].append((info, addend, off, data[off:off + 24]))
    rows = []
    for slot, (expected_info, expected_addend, role) in sorted(wanted.items()):
        if len(found[slot]) != 1:
            raise ValueError('missing or duplicate relocation')
        info, addend, off, raw = found[slot][0]
        if info != expected_info or addend != expected_addend:
            raise ValueError('unexpected relocation type or addend')
        rows.append(dict(slot=hex(slot), info=hex(info), addend=hex(addend),
                         rela_file_offset=hex(off), rela_bytes=raw.hex(), role=role))
    return rows


def fold(a: int, b: int) -> int:
    if not 0 <= a <= U64 or not 0 <= b <= U64:
        raise ValueError('word out of range')
    product = a * b
    return (product & U64) ^ (product >> 64)


def hash_address(key: bytes, table_seed: int, k0: int, k1: int) -> int:
    if len(key) != 20 or any(not 0 <= x <= U64 for x in (table_seed, k0, k1)):
        raise ValueError('invalid address or seed')
    w0, w4, w8, w12 = (int.from_bytes(key[i:i + 8], 'little') for i in (0, 4, 8, 12))
    return fold(fold(w8 ^ k1, w12 ^ k0) ^ fold(w0 ^ table_seed, w4 ^ k0) ^ 20, k0)


def probe_key(controls: bytes, keys: dict[int, bytes], digest: int, key: bytes) -> int | None:
    """Synthetic 16-control lookup model, not captured-code execution."""
    n = len(controls)
    if n < 16 or n & (n - 1) or not 0 <= digest <= U64 or len(key) != 20:
        raise ValueError('invalid control table, hash or key')
    if any(not isinstance(i, int) or not 0 <= i < n or len(k) != 20 for i, k in keys.items()):
        raise ValueError('invalid key mapping')
    if any(c >= 0x80 and c not in (0x80, 0xff) for c in controls):
        raise ValueError('invalid control byte')
    if {i for i, c in enumerate(controls) if c < 0x80} != set(keys):
        raise ValueError('occupied controls and key mapping differ')
    mask, fingerprint = n - 1, digest >> 57
    pos, step = digest & mask, 0
    for _ in range(n // 16):
        indexes = [(pos + i) & mask for i in range(16)]
        for i in indexes:
            if controls[i] == fingerprint and keys.get(i) == key:
                return i
        if any(controls[i] == 0xff for i in indexes):
            return None
        step += 16
        pos = (pos + step) & mask
    raise ValueError('table has no terminating empty control in probed groups')


def capacity(mask: int) -> int:
    if not 0 <= mask < U64 or ((mask + 1) & mask):
        raise ValueError('mask must be one less than a power of two')
    buckets = mask + 1
    return mask if mask < 8 else buckets - (buckets >> 3)


def reserve_plan(mask: int, count: int, additional: int, stride: int) -> dict:
    """Project the checked sizing branches for a well-formed table."""
    cap = capacity(mask)
    if not 0 <= count <= cap or not 0 <= additional <= U64 or stride <= 0:
        raise ValueError('invalid table count, addition or stride')
    if count + additional > U64:
        return {'kind': 'overflow'}
    need = count + additional
    if need <= cap // 2:
        return {'kind': 'rehash', 'buckets': mask + 1}
    request = max(cap + 1, need)
    if request < 15:
        n = 4 if request < 4 else 8 if request < 8 else 16
    else:
        if request > 0x1fffffffffffffff:
            return {'kind': 'overflow'}
        n = 1 << ((request * 8 // 7 - 1).bit_length())
    size = stride * n + n + 16
    if stride * n > U64 or size > 0x7ffffffffffffff0:
        return {'kind': 'overflow'}
    return {'kind': 'allocate', 'buckets': n, 'bytes': size}


def _record_bytes(data: bytes, secs: list[dict], va: int) -> bytes:
    length = struct.unpack('<I', data_at(data, secs, va, 4))[0]
    if length in (0, 0xffffffff):
        raise ValueError('unexpected unwind record length')
    return data_at(data, secs, va, 4 + length)


def parse_lsda(data: bytes, pos: int, limit: int, start: int, end: int) -> tuple[bytes, list[dict]]:
    """Read the observed LSDA call-site encoding; actions and types stay opaque."""
    begin = pos
    if not 0 <= pos < limit <= len(data) or start >= end:
        raise ValueError('invalid exception table bounds')
    if pos + 2 > limit or data[pos:pos + 2] != b'\xff\x9b':
        raise ValueError('unsupported exception table header')
    pos += 2
    type_offset, pos = fde_extents.uleb(data, pos, limit)
    type_table = pos + type_offset
    if type_table > limit:
        raise ValueError('exception type table beyond section')
    if pos >= limit or data[pos] != 1:
        raise ValueError('unsupported exception call-site encoding')
    pos += 1
    length, pos = fde_extents.uleb(data, pos, limit)
    table_end = pos + length
    if table_end > type_table:
        raise ValueError('truncated exception call-site table')
    header = data[begin:pos]
    rows = []
    previous_end = start
    while pos < table_end:
        row_begin = pos
        relative, pos = fde_extents.uleb(data, pos, table_end)
        size, pos = fde_extents.uleb(data, pos, table_end)
        landing, pos = fde_extents.uleb(data, pos, table_end)
        action, pos = fde_extents.uleb(data, pos, table_end)
        call_start, call_end = start + relative, start + relative + size
        destination = start + landing if landing else None
        if (call_start < previous_end or call_start > call_end or call_end > end or
                (destination is not None and not start <= destination < end)):
            raise ValueError('exception interval or landing outside selected FDE')
        previous_end = call_end
        rows.append(dict(function_va=hex(start), start_va=hex(call_start),
                         end_va_exclusive=hex(call_end),
                         landing_va='' if destination is None else hex(destination),
                         action_index=action, bytes=data[row_begin:pos].hex()))
    if pos != table_end:
        raise ValueError('exception call-site table length mismatch')
    return header, rows


def _tsv(rows: list[dict], columns: list[str]) -> bytes:
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=columns, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode('ascii')


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def collect(data: bytes) -> dict[str, bytes]:
    check_digest(data)  # Never interpret an unauthenticated input as an ELF.
    secs, index = elf_index.unwind_index(data)
    _, fdes = fde_extents.eh_frame_records(data, secs)
    by_start: dict[int, list[dict]] = {}
    for f in fdes:
        if f['start'] in FUNCTIONS:
            by_start.setdefault(f['start'], []).append(f)
    index_by_start = {r['start']: r for r in index if r['start'] in FUNCTIONS}
    if set(by_start) != set(FUNCTIONS) or set(index_by_start) != set(FUNCTIONS):
        raise ValueError('selected FDE or index entry missing')
    header = next(s for s in secs if s['name'] == '.eh_frame_hdr')
    funcs, bodies, unwind, exceptions = [], [], [], []
    exception_section = next(s for s in secs if s['name'] == '.gcc_except_table')
    for start, (end, digest, role) in sorted(FUNCTIONS.items()):
        if len(by_start[start]) != 1:
            raise ValueError('duplicate selected FDE')
        f = by_start[start][0]
        ix = index_by_start[start]
        if f['end'] != end or ix['fde'] != f['fde']:
            raise ValueError('FDE extent or unwind index mismatch')
        body = data_at(data, secs, start, end - start, True)
        require_body(body, digest)
        funcs.append(dict(start_va=hex(start), end_va_exclusive=hex(end), size=len(body),
                          file_offset=hex(file_offset(secs, start, len(body), True)),
                          fde_va=hex(f['fde']), cie_va=hex(f['cie']),
                          lsda_va='' if f['lsda'] is None else hex(f['lsda']),
                          sha256=hashlib.sha256(body).hexdigest(), role=role))
        bodies.append(dict(start_va=hex(start), bytes=body.hex()))
        header_va = header['address'] + 12 + 8 * ix['index']
        exception_header = None
        if f['lsda'] is not None:
            off = file_offset(secs, f['lsda'], 1)
            if not (exception_section['offset'] <= off < exception_section['offset'] + exception_section['size']):
                raise ValueError('LSDA outside exception section')
            header_bytes, rows = parse_lsda(data, off, exception_section['offset'] + exception_section['size'], start, end)
            exceptions.extend(rows)
            exception_header = header_bytes.hex()
        unwind.append(dict(start_va=hex(start), fde_va=hex(f['fde']),
                           fde_bytes=_record_bytes(data, secs, f['fde']).hex(),
                           cie_va=hex(f['cie']), cie_bytes=_record_bytes(data, secs, f['cie']).hex(),
                           index=ix['index'], index_va=hex(header_va),
                           index_bytes=data_at(data, secs, header_va, 8).hex(),
                           lsda_va=None if f['lsda'] is None else hex(f['lsda']),
                           lsda_header_bytes=exception_header))
    relas = read_relocations(data, secs)
    windows = []
    for label, start, end in WINDOWS:
        owners = [a for a, (z, _, _) in FUNCTIONS.items() if a <= start < end <= z]
        if len(owners) != 1:
            raise ValueError('window is not inside one selected FDE')
        raw = data_at(data, secs, start, end - start, True)
        windows.append(dict(label=label, function_va=hex(owners[0]), start_va=hex(start),
                            end_va_exclusive=hex(end), file_offset=hex(file_offset(secs, start, len(raw), True)),
                            bytes=raw.hex()))
    edges = []
    for label, site, expected in EDGES:
        owners = [a for a, (z, _, _) in FUNCTIONS.items() if a <= site < z]
        if len(owners) != 1:
            raise ValueError('transfer outside selected FDE')
        raw = data_at(data, secs, site, 6, True)
        kind, length, target = decode_rel_branch(site, raw)
        if target != expected or site + length > FUNCTIONS[owners[0]][0]:
            raise ValueError('unexpected branch target or extent')
        edges.append(dict(label=label, function_va=hex(owners[0]), site_va=hex(site),
                          kind=kind, bytes=raw[:length].hex(), next_va=hex(site + length),
                          target_va=hex(target)))
    indirect = []
    for label, site, expected_slot in INDIRECT:
        owners = [a for a, (z, _, _) in FUNCTIONS.items() if a <= site and site + 6 <= z]
        if len(owners) != 1:
            raise ValueError('indirect call outside selected FDE')
        raw = data_at(data, secs, site, 6, True)
        slot = rip_destination(site, raw, b'\xff\x15')
        if slot != expected_slot or slot not in RELA:
            raise ValueError('unexpected indirect call slot')
        info, addend, _ = RELA[slot]
        indirect.append(dict(label=label, function_va=hex(owners[0]), site_va=hex(site),
                             bytes=raw.hex(), slot_va=hex(slot), rela_info=hex(info),
                             target_va=hex(addend) if info == 8 else 'dynamic'))
    methods = (0x4e76b20, 0x4e76c20, 0x4e76d40)
    masks = (0x43, 0x4a, 0x61, 0x6c)
    method_rows = []
    masked_reference = None
    for start in methods:
        body = bytearray(data_at(data, secs, start, FUNCTIONS[start][0] - start, True))
        for off in masks:
            body[off:off + 4] = bytes(4)
        masked = bytes(body)
        if masked_reference is None:
            masked_reference = masked
        elif masked != masked_reference:
            raise ValueError('preparation method shapes differ outside displacements')
        for off, dest in ((0x42, 0x4e8c640), (0x60, 0x4e8c640), (0x6b, 0x4e77390)):
            code = data_at(data, secs, start + off, 5, True)
            kind, _, actual = decode_rel_branch(start + off, code)
            if kind != 'call' or actual != dest:
                raise ValueError('method call target mismatch')
        insn = data_at(data, secs, start + 0x47, 7, True)
        if rip_destination(start + 0x47, insn, b'\x0f\x10\x05') != 0x7c360c:
            raise ValueError('method constant target mismatch')
        method_rows.append(dict(start_va=hex(start), masked_sha256=hashlib.sha256(masked).hexdigest(),
                                masked_displacements=[hex(x) for x in masks]))
    descriptor_refs = []
    for site, prefix, expected in ((0x4e7795c, b'\x48\x8d\x05', 0x574be78),
                                   (0x4e77993, b'\x48\x8d\x2d', 0x574bea8),
                                   (0x4e779ca, b'\x4c\x8d\x2d', 0x574bed8),
                                   (0x4e77a1b, b'\x48\x8d\x05', 0x574bf08)):
        insn = data_at(data, secs, site, 7, True)
        dest = rip_destination(site, insn, prefix)
        if dest != expected:
            raise ValueError('constructor descriptor target mismatch')
        descriptor_refs.append(dict(site_va=hex(site), bytes=insn.hex(), descriptor_va=hex(dest)))
    prefix = data_at(data, secs, 0x7c360c, 16)
    suffix_insn = data_at(data, secs, 0x4e76b72, 8, True)
    if suffix_insn[:4] != b'\xc7\x44\x24\x10':
        raise ValueError('constant suffix instruction changed')
    addr_const = prefix + suffix_insn[4:]
    stride_insn = data_at(data, secs, 0x4e75993, 5, True)
    if stride_insn[0] != 0xb9:
        raise ValueError('bucket stride instruction changed')
    stride = struct.unpack_from('<I', stride_insn, 1)[0]
    if stride != 208:
        raise ValueError('account bucket stride changed')
    row_shift = expect_bytes(data, secs, 0x4e773cd, bytes.fromhex('48c1e004'))[-1]
    key_offset = expect_bytes(data, secs, 0x4e77416, bytes.fromhex('f30f6f4318'))[-1]
    slot_pointer_offset = expect_bytes(data, secs, 0x4e77424, bytes.fromhex('4c8b6b08'))[-1]
    slot_count_offset = expect_bytes(data, secs, 0x4e77428, bytes.fromhex('4c8b7310'))[-1]
    set_base_insn = expect_bytes(data, secs, 0x4e8c6b9, bytes.fromhex('4c8d59ec'))
    expect_bytes(data, secs, 0x4e8c6ee, bytes.fromhex('488d0480'))  # 5 * -index
    expect_bytes(data, secs, 0x4e8c6f6, bytes.fromhex('f3410f6f2483'))  # scale 4
    flag_test = expect_bytes(data, secs, 0x4e772c5, bytes.fromhex('f6c110'))
    flag_clear = expect_bytes(data, secs, 0x4e772e8, bytes.fromhex('80e1ef'))
    journal_stride = expect_bytes(data, secs, 0x4e7728f, bytes.fromhex('496bcd58'))
    journal_tag = expect_bytes(data, secs, 0x4e77293, bytes.fromhex('c6040800'))
    hit_value = expect_bytes(data, secs, 0x4e772ba, bytes.fromhex('4c8da048ffffff'))
    copy_insn = expect_bytes(data, secs, 0x4e775ba, bytes.fromhex('baac000000'))
    flag_insn = expect_bytes(data, secs, 0x4e775d7, bytes.fromhex('c6441df808'))
    slot_stride_insn = expect_bytes(data, secs, 0x4e7779d, bytes.fromhex('4983c520'))
    expect_bytes(data, secs, 0x4e773c9, bytes.fromhex('488d0449'))  # 3 * count
    expect_bytes(data, secs, 0x4e77581, bytes.fromhex('4869dad0000000'))
    expect_bytes(data, secs, 0x4e77752, bytes.fromhex('660fefc0'))
    zero_displacements = []
    for site in (0x4e77756, 0x4e7775c, 0x4e77762, 0x4e77768):
        insn = data_at(data, secs, site, 6, True)
        if insn[:5] != bytes.fromhex('f30f7f4408'):
            raise ValueError('slot zero-store shape changed')
        zero_displacements.append(struct.unpack('<b', insn[5:])[0])
    if zero_displacements != [-0x48, -0x38, -0x28, -0x18]:
        raise ValueError('slot zero-store offsets changed')
    record = dict(target_sha256=hashlib.sha256(data).hexdigest(),
                  constant_address=addr_const.hex(),
                  constant_address_file_offset=hex(file_offset(secs, 0x7c360c, 16)),
                  stride_immediate_bytes=stride_insn.hex(), account_bucket_stride=stride,
                  methods=method_rows, constructor_descriptor_refs=descriptor_refs,
                  provider_descriptor_slot=hex(0x574bea0),
                  preparation_descriptor_base=hex(0x574bea8),
                  note='The provider method is an earlier boundary; its body is not selected.')
    layout = dict(outer_row_stride=3 * (1 << row_shift), outer_row_address_offset=key_offset,
                  outer_row_slot_pointer_offset=slot_pointer_offset,
                  outer_row_slot_count_offset=slot_count_offset,
                  address_set_bucket_stride=-struct.unpack('<b', set_base_insn[-1:])[0],
                  account_bucket_stride=stride, account_record_copy_bytes=struct.unpack_from('<I', copy_insn, 1)[0],
                  account_flag_written=flag_insn[-1], slot_input_stride=slot_stride_insn[-1],
                  account_access_flag_test=flag_test[-1], account_access_flag_clear_mask=flag_clear[-1],
                  account_access_return_offset=stride + struct.unpack('<i', hit_value[-4:])[0],
                  journal_entry_stride=journal_stride[-1], journal_entry_tag=journal_tag[-1],
                  slot_zero_store_displacements=zero_displacements,
                  slot_zero_store_width=16, slot_zero_payload_bytes=16 * len(zero_displacements))
    summary = dict(target_sha256=hashlib.sha256(data).hexdigest(),
                   selected_fdes=len(funcs), selected_body_bytes=sum(x['size'] for x in funcs),
                   fixed_windows=len(windows), selected_transfers=len(edges),
                   relocations=len(relas), method_shapes=len(method_rows),
                   selected_indirect_calls=len(indirect), exception_intervals=len(exceptions),
                   scope='Finite selected FDEs and fixed windows; not a node coverage denominator.')
    return {
        'functions.tsv': _tsv(funcs, ['start_va', 'end_va_exclusive', 'size', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'sha256', 'role']),
        'function-bytes.json': _json(bodies),
        'unwind.json': _json(unwind),
        'windows.tsv': _tsv(windows, ['label', 'function_va', 'start_va', 'end_va_exclusive', 'file_offset', 'bytes']),
        'branches.tsv': _tsv(edges, ['label', 'function_va', 'site_va', 'kind', 'bytes', 'next_va', 'target_va']),
        'indirect-calls.tsv': _tsv(indirect, ['label', 'function_va', 'site_va', 'bytes', 'slot_va', 'rela_info', 'target_va']),
        'exceptions.tsv': _tsv(exceptions, ['function_va', 'start_va', 'end_va_exclusive', 'landing_va', 'action_index', 'bytes']),
        'relocations.tsv': _tsv(relas, ['slot', 'info', 'addend', 'rela_file_offset', 'rela_bytes', 'role']),
        'bindings.json': _json(record),
        'layout.json': _json(layout),
        'summary.json': _json(summary),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    generated = collect(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, contents in sorted(generated.items()):
        (args.out / name).write_bytes(contents)
    print(f'Generated {len(generated)} deterministic evidence files.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print(f're21_account_cache94: {exc}', file=sys.stderr)
        raise SystemExit(1)

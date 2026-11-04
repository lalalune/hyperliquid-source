#!/usr/bin/env python3
"""Extract a selected node 115 compact-state result path without executing the node."""
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
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are selections, not a function census. Existing work is marked context.
FUNCTIONS = [
    ('loaded_owner_parent', 0x2cb6500, 'context'),
    ('location_caller', 0x3c13520, 'context'),
    ('result_task_constructor', 0x5a6cbc0, 'new'),
    ('result_callback', 0x5a34440, 'new'),
    ('owner_result_wrapper', 0x5647720, 'new'),
    ('owner_instrumentation', 0x4e46b50, 'new'),
    ('owner_dispatch', 0x4f21a90, 'new'),
    ('height_gate', 0x4fc3490, 'new'),
    ('state_result', 0x5484670, 'new'),
    ('compact_instrumentation', 0x4e46090, 'new'),
    ('compact_capture_builder', 0x4e34ce0, 'new'),
    ('result_queue', 0x581a4f0, 'new'),
    ('work_queue_receiver', 0x58189f0, 'new'),
    ('work_item_view', 0x59edc50, 'new'),
    ('apply_instrumentation', 0x4e47900, 'new'),
    ('apply_dispatch', 0x4f152a0, 'new'),
    ('write_dispatch', 0x4f18bd0, 'new'),
    ('write_owner_update', 0x4fcbe60, 'new'),
]

# Ranges are explicit instruction selections, not disassembler-generated text.
WINDOWS = [
    ('context_constructor_return', 0x2cb7a15, 0x2cb7a36),
    ('context_parent_stage_to_second', 0x2cb7e27, 0x2cb8010),
    ('context_parent_stage_tail', 0x2cb7ffe, 0x2cb8085),
    ('parent_owner_to_call', 0x2cb8863, 0x2cb891b),
    ('context_location_reference', 0x3c1352f, 0x3c1353f),
    ('constructor_arguments', 0x5a6cbd8, 0x5a6cc18),
    ('constructor_early_allocations', 0x5a6ccca, 0x5a6cd49),
    ('constructor_capture', 0x5a6cd71, 0x5a6cd79),
    ('constructor_task_schedule', 0x5a6ce10, 0x5a6ce6d),
    ('constructor_allocation_failures', 0x5a6ce9c, 0x5a6ceec),
    ('callback_result_and_sentinel', 0x5a34440, 0x5a3449a),
    ('callback_result_to_record', 0x5a3449a, 0x5a3454f),
    ('callback_queue_and_notify', 0x5a3454f, 0x5a345f8),
    ('callback_work_receive', 0x5a34896, 0x5a34935),
    ('callback_work_payload', 0x5a34a10, 0x5a34a85),
    ('callback_work_state_select', 0x5a34acf, 0x5a34aea),
    ('callback_work_repack', 0x5a34c40, 0x5a34d1c),
    ('callback_work_view', 0x5a34dcc, 0x5a34e4e),
    ('callback_apply_and_write', 0x5a34e4e, 0x5a34fb8),
    ('callback_finish_and_drop', 0x5a350c5, 0x5a35137),
    ('callback_unwind_landing', 0x5a351d7, 0x5a351f3),
    ('callback_apply_unwind_cleanup', 0x5a35204, 0x5a35230),
    ('callback_unwind_resume', 0x5a35318, 0x5a35380),
    ('owner_pair_and_guard', 0x5647720, 0x5647786),
    ('owner_time_and_bucket', 0x5647833, 0x56478c2),
    ('owner_counter_and_return_copy', 0x5647bb5, 0x5647c60),
    ('instrumentation_test', 0x4e46b50, 0x4e46ba8),
    ('instrumentation_selected_arm', 0x4e46c37, 0x4e46c8f),
    ('dispatch_selection', 0x4f21a90, 0x4f21b22),
    ('gate_owner_guard', 0x4fc3490, 0x4fc352b),
    ('gate_first_height_branch', 0x4fc35a9, 0x4fc3626),
    ('gate_second_height_branch', 0x4fc3706, 0x4fc3780),
    ('gate_copy_to_intermediate', 0x4fc3780, 0x4fc3818),
    ('gate_second_sentinel', 0x4fc3818, 0x4fc382a),
    ('gate_copy_to_output', 0x4fc3c25, 0x4fc3c8a),
    ('gate_unwind_release', 0x4fc3d3e, 0x4fc3db5),
    ('state_result_calls', 0x5484670, 0x5484704),
    ('state_result_pack', 0x548475b, 0x5484827),
    ('state_result_unwind', 0x5484841, 0x54848cf),
    ('compact_wrapper_branch', 0x4e46090, 0x4e4613e),
    ('compact_wrapper_instrumented_arm', 0x4e461b0, 0x4e461ce),
    ('compact_wrapper_failure', 0x4e4623c, 0x4e4626c),
    ('compact_pointer_capture', 0x4e34cf1, 0x4e35155),
    ('capture_descriptor_init', 0x4e35155, 0x4e35329),
    ('capture_reducer_branch', 0x4e35329, 0x4e353bc),
    ('capture_result_copy', 0x4e355b8, 0x4e355fc),
    ('queue_ticket_and_fastpath', 0x581a4f0, 0x581a53b),
    ('queue_allocation_and_link', 0x581a552, 0x581a5bc),
    ('queue_publish_and_failures', 0x581a620, 0x581a6db),
    ('receiver_group_selection', 0x58189f0, 0x5818a2e),
    ('receiver_slot_and_status', 0x5818b5b, 0x5818bf3),
    ('work_view_tls_and_return', 0x59edc50, 0x59edd1c),
    ('work_view_unwind', 0x59edd1c, 0x59edd37),
    ('apply_wrapper_condition', 0x4e47900, 0x4e47951),
    ('apply_wrapper_repack', 0x4e479ff, 0x4e47a94),
    ('apply_direct_dispatch', 0x4f152a0, 0x4f15346),
    ('write_direct_dispatch', 0x4f18bd0, 0x4f18c75),
    ('write_input_and_guard', 0x4fcbe60, 0x4fcbed3),
    ('write_old_value_check', 0x4fcbfd7, 0x4fcbfee),
    ('write_old_value_release', 0x4fcc034, 0x4fcc078),
    ('write_store_and_unlock', 0x4fcc078, 0x4fcc0a9),
]

# Direct control transfers: label, site, expected kind, expected target.
TRANSFERS = [
    ('constructor_refcount_failure', 0x5a6cd01, 'jle', 0x5a6ceea),
    ('callback_calculate', 0x5a34472, 'call', 0x5647720),
    ('callback_non_sentinel', 0x5a3448b, 'jno', 0x5a3449a),
    ('callback_skip_record', 0x5a3451a, 'jne', 0x5a345f8),
    ('callback_closed', 0x5a34572, 'jne', 0x5a345f3),
    ('callback_counter_limit', 0x5a34578, 'je', 0x5a35137),
    ('callback_enqueue', 0x5a3459c, 'call', 0x581a4f0),
    ('callback_receive_first', 0x5a348b6, 'call', 0x58189f0),
    ('callback_receive_closed', 0x5a348cb, 'jo', 0x5a349e0),
    ('callback_receive_payload_first', 0x5a348de, 'jne', 0x5a34a10),
    ('callback_receive_retry', 0x5a34904, 'call', 0x58189f0),
    ('callback_retry_closed', 0x5a34919, 'jo', 0x5a349e0),
    ('callback_receive_payload_retry', 0x5a3492f, 'jne', 0x5a34a24),
    ('callback_leave_wait', 0x5a34ae4, 'jne', 0x5a34c40),
    ('callback_finish_on_sentinel', 0x5a34cab, 'je', 0x5a350c5),
    ('callback_build_view', 0x5a34e49, 'call', 0x59edc50),
    ('callback_apply', 0x5a34f0d, 'call', 0x4e47900),
    ('callback_skip_write', 0x5a34f24, 'je', 0x5a34fb8),
    ('callback_write_boundary', 0x5a34fb3, 'call', 0x4f18bd0),
    ('callback_loop', 0x5a35081, 'jmp', 0x5a34710),
    ('callback_drop_boundary', 0x5a35120, 'call', 0x5a579d0),
    ('callback_unwind_view_cleanup', 0x5a3520f, 'call', 0x5a451c0),
    ('callback_unwind_item_cleanup', 0x5a35226, 'call', 0x5a50310),
    ('callback_unwind_to_common', 0x5a3522b, 'jmp', 0x5a35318),
    ('callback_unwind_timer_cleanup', 0x5a35320, 'call', 0x5a51670),
    ('callback_unwind_owner_drop', 0x5a35373, 'call', 0x5a579d0),
    ('callback_unwind_resume', 0x5a3537b, 'call', 0x63f0a50),
    ('owner_to_instrumentation', 0x5647767, 'call', 0x4e46b50),
    ('instrumentation_error', 0x4e46b97, 'jne', 0x4e46c8f),
    ('instrumentation_simple_arm', 0x4e46ba2, 'je', 0x4e46c37),
    ('instrumentation_to_dispatch', 0x4e46c78, 'call', 0x4f21a90),
    ('dispatch_direct_arm', 0x4f21aad, 'je', 0x4f21b02),
    ('dispatch_to_gate', 0x4f21b08, 'call', 0x4fc3490),
    ('gate_context_null', 0x4fc35e3, 'je', 0x4fc3c95),
    ('gate_context_mismatch', 0x4fc35f0, 'jne', 0x4fc3cdd),
    ('gate_height_mismatch', 0x4fc3606, 'jne', 0x4fc376e),
    ('gate_calculate', 0x4fc361c, 'call', 0x5484670),
    ('gate_other_height_mismatch', 0x4fc374e, 'jne', 0x4fc3818),
    ('gate_other_calculate', 0x4fc3764, 'call', 0x5484670),
    ('gate_unwind_resume', 0x4fc3da3, 'call', 0x63f0a50),
    ('state_snapshot_boundary', 0x54846a3, 'call', 0x4e48ee0),
    ('state_to_compact_wrapper', 0x54846e5, 'call', 0x4e46090),
    ('state_pair_boundary', 0x54847aa, 'call', 0x452aab0),
    ('state_unwind_resume', 0x5484898, 'call', 0x63f0a50),
    ('compact_wrapper_helper', 0x4e460c1, 'call', 0x5a9f900),
    ('compact_wrapper_helper_error', 0x4e460c9, 'jne', 0x4e4613e),
    ('compact_wrapper_simple_arm', 0x4e460d0, 'je', 0x4e46123),
    ('compact_wrapper_builder', 0x4e46129, 'call', 0x4e34ce0),
    ('compact_wrapper_builder_alt', 0x4e461c9, 'call', 0x4e34ce0),
    ('capture_allocation_failure', 0x4e35163, 'je', 0x4e35637),
    ('capture_job_boundary', 0x4e35324, 'call', 0x54423c0),
    ('capture_other_result', 0x4e3532b, 'jne', 0x4e3538f),
    ('queue_same_block', 0x581a51a, 'jne', 0x581a524),
    ('queue_group_overflow', 0x581a571, 'ja', 0x581a6ce),
    ('queue_allocation_failure', 0x581a585, 'je', 0x581a6be),
    ('receiver_no_ready_slot', 0x5818b69, 'jae', 0x5818bc3),
    ('receiver_terminal_flag', 0x5818bc8, 'jb', 0x5818bd6),
    ('receiver_counter_skip', 0x5818bb8, 'jl', 0x5818be6),
    ('view_null_context', 0x59edc6e, 'je', 0x59edcea),
    ('view_other_context', 0x59edc7e, 'jne', 0x59edd0f),
    ('view_build_boundary', 0x59edcc5, 'call', 0x3d9ce60),
    ('view_unwind_cleanup', 0x59edd24, 'call', 0x452db50),
    ('view_unwind_resume', 0x59edd2c, 'call', 0x63f0a50),
    ('apply_instrument_helper', 0x4e47938, 'call', 0x5aa3e60),
    ('apply_instrument_error', 0x4e47940, 'jne', 0x4e47a94),
    ('apply_instrument_simple', 0x4e4794b, 'je', 0x4e479ff),
    ('apply_to_dispatch', 0x4e47a7c, 'call', 0x4f152a0),
    ('apply_direct_arm', 0x4f152c3, 'je', 0x4f15326),
    ('apply_existing_owner_boundary', 0x4f1532c, 'call', 0x4fcac10),
    ('write_direct_arm', 0x4f18bed, 'je', 0x4f18c5c),
    ('write_direct_owner_update', 0x4f18c70, 'jmp', 0x4fcbe60),
    ('write_old_present', 0x4fcbfe7, 'jno', 0x4fcc046),
    ('write_old_sentinel', 0x4fcc044, 'jo', 0x4fcc078),
    ('write_unlock_contention', 0x4fcc0a3, 'jne', 0x4fcc20c),
]

# The parent/Location/formatter are existing context, not newly owned functions.
RELOCS = [
    ('parent_dispatch_context', 0x64e7458, 0x5a6cbc0, 'context'),
    ('task_drop', 0x64b8a00, 0x5a579d0, 'new'),
    ('task_callback', 0x64b8a18, 0x5a34440, 'new'),
    ('result_formatter_context', 0x64e7820, 0x41c5140, 'context'),
    ('capture_reducer', 0x64df500, 0x141a250, 'boundary'),
    ('location_path_context', 0x64767a8, None, 'context'),
]


def verify_digest(data, expected=TARGET):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('artifact SHA-256 mismatch')


def mapping(secs, address, length, executable=False):
    if type(address) is not int or type(length) is not int or address < 0 or length <= 0:
        raise ValueError('invalid file mapping request')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and (not executable or s['flags'] & 4)
               and s['address'] <= address and address + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('no unique file-backed mapping')
    s = matches[0]
    return s, s['offset'] + address - s['address']


def ensure_no_fde_overlap(fde, all_fdes):
    for other in all_fdes:
        if other is not fde and fde['start'] < other['end'] and other['start'] < fde['end']:
            raise ValueError('selected unwind range overlaps another FDE')


def read_va(data, secs, address, length, executable=False):
    _, off = mapping(secs, address, length, executable)
    if off + length > len(data):
        raise ValueError('mapping extends beyond file')
    return data[off:off + length]


def require_bytes(read, addr, expected):
    actual = read(addr, len(expected))
    if actual != expected:
        raise ValueError(f'unexpected instruction bytes at {addr:#x}')
    return actual


def direct_transfer(read, addr):
    op = read(addr, 1)[0]
    names = {0x70: 'jo', 0x71: 'jno', 0x72: 'jb', 0x73: 'jae', 0x74: 'je',
             0x75: 'jne', 0x76: 'jbe', 0x77: 'ja', 0x78: 'js',
             0x79: 'jns', 0x7c: 'jl', 0x7d: 'jge', 0x7e: 'jle', 0x7f: 'jg'}
    if op in (0xe8, 0xe9):
        raw = read(addr, 5)
        return ('call' if op == 0xe8 else 'jmp', addr + 5 + struct.unpack_from('<i', raw, 1)[0], raw)
    if op in names:
        raw = read(addr, 2)
        return names[op], addr + 2 + struct.unpack_from('<b', raw, 1)[0], raw
    if op == 0x0f:
        raw = read(addr, 6)
        if raw[1] - 0x10 in names:
            return names[raw[1] - 0x10], addr + 6 + struct.unpack_from('<i', raw, 2)[0], raw
    raise ValueError('unsupported direct transfer')


def checked_transfer(read, site, expected_op, expected_target):
    op, target, raw = direct_transfer(read, site)
    if (op, target) != (expected_op, expected_target):
        raise ValueError('unexpected transfer target or condition')
    return op, target, raw


def relative_relocations(data, secs, wanted):
    candidates = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(candidates) != 1 or candidates[0]['size'] % 24:
        raise ValueError('invalid relocation section')
    sec = candidates[0]
    raw = data[sec['offset']:sec['offset'] + sec['size']]
    if len(raw) != sec['size']:
        raise ValueError('truncated relocation section')
    wanted = set(wanted)
    found = {}
    for i, (slot, info, addend) in enumerate(struct.iter_unpack('<QQq', raw)):
        if slot in wanted:
            if slot in found or info != 8:
                raise ValueError('ambiguous or non-relative relocation')
            found[slot] = (addend, sec['offset'] + 24 * i)
    if set(found) != wanted:
        raise ValueError('missing selected relocation')
    return found


def parse_captures(raw, start=0x4e34d06):
    """Decode only the fixed sequence that builds 74 pointer arguments."""
    if len(raw) != 0x4e35155 - start or raw[:3] != b'\x49\x8d\x87':
        raise ValueError('invalid first capture')
    if raw[7:11] != b'\x4c\x89\xbc\x24' or raw[15:19] != b'\x48\x89\x84\x24':
        raise ValueError('invalid initial stores')
    first_state = struct.unpack_from('<I', raw, 3)[0]
    base = struct.unpack_from('<I', raw, 11)[0]
    first_slot = struct.unpack_from('<I', raw, 19)[0]
    if first_slot != base + 8:
        raise ValueError('discontinuous initial captures')
    rows = [(0, start + 7, base, 0), (1, start, first_slot, first_state)]
    pos = 23
    while pos < len(raw):
        if pos + 15 > len(raw) or raw[pos:pos + 3] != b'\x49\x8d\x87' or raw[pos + 7:pos + 11] != b'\x48\x89\x84\x24':
            raise ValueError('unsupported capture instruction')
        state = struct.unpack_from('<I', raw, pos + 3)[0]
        stack = struct.unpack_from('<I', raw, pos + 11)[0]
        if stack != base + len(rows) * 8:
            raise ValueError('capture stack slots not contiguous')
        rows.append((len(rows), start + pos, stack, state))
        pos += 15
    if len(rows) != 74:
        raise ValueError('unexpected capture count')
    return rows


def parse_descriptor_stores(raw, start=0x4e35173):
    """Decode the bounded unrolled stores of the same descriptor tag."""
    rows, pos = [], 0
    while pos < len(raw):
        if raw[pos:pos + 3] == b'\x4c\x89\x20':
            offset, size = 0, 3
        elif raw[pos:pos + 3] == b'\x4c\x89\x60' and pos + 4 <= len(raw):
            offset, size = struct.unpack_from('<b', raw, pos + 3)[0], 4
        elif raw[pos:pos + 3] == b'\x4c\x89\xa0' and pos + 7 <= len(raw):
            offset, size = struct.unpack_from('<i', raw, pos + 3)[0], 7
        else:
            raise ValueError('unsupported descriptor store')
        if offset != len(rows) * 24:
            raise ValueError('noncontiguous descriptor stores')
        rows.append((len(rows), start + pos, offset))
        pos += size
    if len(rows) != 59:
        raise ValueError('unexpected descriptor count')
    return rows


def parse_lsda(data, secs, fde):
    """Read selected call-site records, without interpreting their action tables."""
    if fde['lsda'] is None:
        return []
    matches = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(matches) != 1:
        raise ValueError('missing exception section')
    sec = matches[0]
    if not sec['address'] <= fde['lsda'] < sec['address'] + sec['size']:
        raise ValueError('LSDA outside exception section')
    _, pos = mapping(secs, fde['lsda'], 1)
    limit = sec['offset'] + sec['size']
    if limit > len(data) or pos + 2 > limit or data[pos] != 0xff or data[pos + 1] not in (0xff, 0x9b):
        raise ValueError('unsupported exception header')
    encoding = data[pos + 1]
    pos += 2
    type_base = limit
    if encoding == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
    if type_base > limit or pos >= limit or data[pos] != 1:
        raise ValueError('unsupported call-site encoding')
    length, pos = uleb(data, pos + 1, limit)
    end = pos + length
    if end > limit or end > type_base:
        raise ValueError('call-site table outside section')
    rows = []
    while pos < end:
        before = pos
        start, pos = uleb(data, pos, end)
        size, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        span = fde['end'] - fde['start']
        if start + size > span or (landing and landing >= span):
            raise ValueError('call-site outside FDE')
        rows.append((before, fde['start'] + start, fde['start'] + start + size,
                     fde['start'] + landing if landing else None, action, data[before:pos]))
    return rows


def callsite_witness(rows, site, length):
    if length <= 0:
        raise ValueError('invalid call length')
    partial = [r for r in rows if site < r[2] and r[1] < site + length
               and not (r[1] <= site and site + length <= r[2])]
    if partial:
        raise ValueError('call crosses LSDA boundary')
    hits = [r for r in rows if r[1] <= site and site + length <= r[2]]
    if len(hits) > 1:
        raise ValueError('ambiguous call-site')
    return hits[0] if hits else None


def map_copy(position, source, destination, size, width):
    if min(position, source, destination) < 0 or size < 0 or width <= 0 or position < source or position + width > source + size:
        raise ValueError('tracked bytes outside copy')
    return destination + position - source


def tsv(header, rows):
    result = io.StringIO(newline='')
    writer = csv.writer(result, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return result.getvalue().encode('ascii')


def as_hex(value):
    return '' if value is None else hex(value)


def validate_historical(data):
    verify_digest(data, HISTORICAL_TARGET)
    secs = sections(data)
    read = lambda a, n: read_va(data, secs, a, n)
    slot = 0x56dfbf8
    pointer, size, line, column = struct.unpack('<QQII', read(slot, 24))
    if pointer != 0 or (size, line, column) != (49, 107, 37):
        raise ValueError('historical Location differs')
    path = relative_relocations(data, secs, [slot])[slot][0]
    if not read(path, size).endswith(b'l1/src/abci/state.rs'):
        raise ValueError('historical path suffix differs')
    raw = read(0x3273856, 7)
    if raw[:3] != b'\x48\x8d\x0d' or 0x327385d + struct.unpack_from('<i', raw, 3)[0] != slot:
        raise ValueError('historical Location reference differs')
    if read(0x3273871, 4) != bytes.fromhex('4983fd02'):
        raise ValueError('historical result comparison differs')
    call = read(0x3272785, 6)
    if call[:2] != b'\xff\x15' or 0x327278b + struct.unpack_from('<i', call, 2)[0] != 0x57755a8:
        raise ValueError('historical loader indirect call differs')
    old_callee = relative_relocations(data, secs, [0x57755a8])[0x57755a8][0]
    if old_callee != 0x3273810:
        raise ValueError('historical loader target differs')
    _, location_off = mapping(secs, slot, 24)
    _, call_off = mapping(secs, 0x3272785, 6, True)
    _, reference_off = mapping(secs, 0x3273856, 7, True)
    return {'artifact_sha256': HISTORICAL_TARGET, 'release': 94,
            'location_va': hex(slot), 'location_file_offset': hex(location_off),
            'line': line, 'column': column, 'file_name_length': size,
            'name_suffix': 'l1/src/abci/state.rs',
            'location_reference_va': hex(0x3273856), 'location_reference_file_offset': hex(reference_off),
            'comparison_va': hex(0x3273871), 'comparison_hex': read(0x3273871, 4).hex(),
            'call_va': hex(0x3272785), 'call_file_offset': hex(call_off),
            'relocation_slot_va': hex(0x57755a8), 'relocation_addend': hex(old_callee)}


def rip_target(read, site, opcode):
    raw = read(site, len(opcode) + 4)
    if raw[:len(opcode)] != opcode:
        raise ValueError('unexpected RIP-relative encoding')
    return site + len(raw) + struct.unpack_from('<i', raw, len(opcode))[0], raw


def immediate(read, site, opcode, fmt):
    count = struct.calcsize(fmt)
    raw = read(site, len(opcode) + count)
    if raw[:len(opcode)] != opcode:
        raise ValueError('unexpected immediate encoding')
    return struct.unpack_from(fmt, raw, len(opcode))[0], raw


def selected_copies(read):
    """Decode matching fixed-register load/store pairs on the selected return arm."""
    specs = [
        # label, width, load VA/prefix/format, store VA/prefix/format
        ('gate_height_chunk', 16, 0x4fc37e2, '660f109424', '<I', 0x4fc37eb, '660f295424', '<B'),
        ('gate_mix_first', 16, 0x4fc37b0, '0f108424', '<I', 0x4fc37b8, '0f298424', '<I'),
        ('gate_mix_second', 16, 0x4fc37a0, '0f108424', '<I', 0x4fc37a8, '0f298424', '<I'),
        ('gate_out_height_chunk', 16, 0x4fc3c64, '0f285c24', '<B', 0x4fc3c69, '0f115b', '<B'),
        ('gate_out_mix_first', 16, 0x4fc3c49, '0f288424', '<I', 0x4fc3c51, '0f1143', '<B'),
        ('gate_out_mix_second', 16, 0x4fc3c3d, '0f288424', '<I', 0x4fc3c45, '0f1143', '<B'),
        ('wrapper_out_height_chunk', 16, 0x5647c30, '0f109c24', '<I', 0x5647c38, '410f115f', '<B'),
        ('wrapper_out_mix_first', 16, 0x5647c0b, '0f108424', '<I', 0x5647c13, '410f1147', '<B'),
        ('wrapper_out_mix_second', 16, 0x5647bfe, '0f108424', '<I', 0x5647c06, '410f1147', '<B'),
        ('callback_height_chunk', 16, 0x5a344f4, '0f109c24', '<I', 0x5a344fc, '0f295c24', '<B'),
        ('callback_mix_first', 16, 0x5a344ca, '0f108424', '<I', 0x5a344d2, '0f298424', '<I'),
        ('callback_mix_second', 16, 0x5a344ba, '0f108424', '<I', 0x5a344c2, '0f298424', '<I'),
        ('record_height', 8, 0x5a34520, '488b4424', '<B', 0x5a34547, '48898424', '<I'),
        ('record_mix_first', 16, 0x5a34525, '0f288424', '<I', 0x5a3452d, '0f118424', '<I'),
        ('record_mix_second', 16, 0x5a34535, '660f288424', '<I', 0x5a3453e, '660f118424', '<I'),
        ('write_callback_first', 16, 0x5a34f43, '660f108424', '<I', 0x5a34f5b, '660f294424', '<B'),
        ('write_callback_second', 16, 0x5a34f4c, '660f108c24', '<I', 0x5a34f55, '660f294c24', '<B'),
        ('write_callback_last', 8, 0x5a34f36, '488b8424', '<I', 0x5a34f3e, '48894424', '<B'),
        ('write_stage_first', 16, 0x4fcbe7b, '660f1007', 'zero', 0x4fcbe8a, '660f294424', '<B'),
        ('write_stage_second', 16, 0x4fcbe7f, '660f104f', '<B', 0x4fcbe84, '660f294c24', '<B'),
        ('write_stage_last', 8, 0x4fcbe72, '488b47', '<B', 0x4fcbe76, '48894424', '<B'),
        ('write_store_first', 16, 0x4fcc081, '660f284424', '<B', 0x4fcc092, '660f1145', '<B'),
        ('write_store_second', 16, 0x4fcc087, '660f284c24', '<B', 0x4fcc08d, '660f114d', '<B'),
        ('write_store_last', 8, 0x4fcc078, '488b4424', '<B', 0x4fcc07d, '488945', '<B'),
    ]
    result = {}
    for name, width, load, load_op, load_fmt, store, store_op, store_fmt in specs:
        if load_fmt == 'zero':
            source, load_raw = 0, require_bytes(read, load, bytes.fromhex(load_op))
        else:
            source, load_raw = immediate(read, load, bytes.fromhex(load_op), load_fmt)
        destination, store_raw = immediate(read, store, bytes.fromhex(store_op), store_fmt)
        result[name] = (source, destination, width, load, store, load_raw, store_raw)
    return result


def track_projection(copies, gate_base, wrapper_base, callback_base, result_offset, width, suffix):
    """Join a result slice through three return copies to the 40-byte queue input."""
    position = gate_base + result_offset
    for name in ('gate_' + suffix, 'gate_out_' + suffix):
        source, destination, size = copies[name][:3]
        position = map_copy(position, source, destination, size, width)
    if position != result_offset:
        raise ValueError('gate output projection mismatch')
    position += wrapper_base
    source, destination, size = copies['wrapper_out_' + suffix][:3]
    position = map_copy(position, source, destination, size, width)
    if position != result_offset:
        raise ValueError('wrapper output projection mismatch')
    position += callback_base
    source, destination, size = copies['callback_' + suffix][:3]
    position = map_copy(position, source, destination, size, width)
    record_name = 'record_height' if suffix == 'height_chunk' else 'record_' + suffix
    source, destination, size = copies[record_name][:3]
    return map_copy(position, source, destination, size, width) - callback_base


def queue_geometry(read, mask, block_group_offset):
    lea, store = read(0x581a680, 4), read(0x581a688, 5)
    if lea[:3] != bytes.fromhex('488d04') or lea[3] & 0x3f != 0x1b:
        raise ValueError('queue index multiplication differs')
    if store[:3] != bytes.fromhex('48894c') or store[3] & 0x3f != 0x02:
        raise ValueError('queue slot addressing differs')
    index_factor = 1 + (1 << (lea[3] >> 6))
    address_scale = 1 << (store[3] >> 6)
    stride, slots = index_factor * address_scale, mask + 1
    if slots * stride != block_group_offset:
        raise ValueError('queue slots do not end at group metadata')
    return slots, stride


def work_queue_geometry(mask, stride, group_offset):
    if mask < 0 or stride <= 0 or (mask + 1) * stride != group_offset:
        raise ValueError('work queue record geometry differs')
    return mask + 1, stride


def check_apply_projection(fields, context):
    callback_input = fields['apply_callback_body_stack'] - fields['apply_callback_input_stack']
    forwarded_input = fields['apply_wrapper_owner_stack'] - fields['apply_dispatch_input_stack']
    state_slot = context['existing_owner_context'] + context['existing_context_state_slot']
    if not (fields['apply_callback_owner_pointer'] == fields['callback_owner_slot']
            and fields['apply_callback_body_adjustment'] == fields['callback_owner_body']
            and callback_input == fields['apply_wrapper_owner_input']
            and forwarded_input == context['existing_owner_input']
            and state_slot == fields['gate_compact_pointer_slot']):
        raise ValueError('owner and block context projection does not join')
    return callback_input, forwarded_input, state_slot


def check_write_projection(copies, result_stack, callback_input_stack):
    rows = []
    for name, offset, width in [('first', 0, 16), ('second', 16, 16), ('last', 32, 8)]:
        position = result_stack + offset
        for label in ('write_callback_' + name, 'write_stage_' + name, 'write_store_' + name):
            source, destination, size = copies[label][:3]
            position = map_copy(position, source, destination, size, width)
            if label.startswith('write_callback_'):
                position -= callback_input_stack
        if position != offset:
            raise ValueError('write result projection differs')
        rows.append((name, offset, width, position))
    return rows


def check_write_capture(fields):
    closure_offset = map_copy(fields['constructor_write_capture_stack'],
                              fields['constructor_copy_source_stack'], 0,
                              fields['constructor_copy_length'], 8)
    input_offset = fields['callback_write_body_stack'] - fields['callback_write_input_stack']
    if not (fields['constructor_write_arg_save'] == fields['constructor_write_arg_load']
            and closure_offset == fields['callback_write_owner_slot']
            and input_offset == fields['write_owner_body_input']):
        raise ValueError('second owner capture does not reach write input')
    return closure_offset, input_offset


def project_parent_owner(fields):
    if fields['parent_return_saved_stack'] != fields['parent_return_load_stack']:
        raise ValueError('parent saved return slot does not join')
    position = fields['parent_pointer_stage_stack']
    rows = []
    for i in range(1, 5):
        source = fields['parent_copy_source_' + str(i)]
        destination = fields['parent_copy_destination_' + str(i)]
        size = fields['parent_copy_size_' + str(i)]
        result = map_copy(position, source, destination, size, 8)
        rows.append((i, position, source, destination, size, result))
        position = result
    if position != fields['parent_owner_slot']:
        raise ValueError('parent copy chain does not reach owner slot')
    return rows


def generate(data):
    verify_digest(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    index_by_start = {row['start']: row for row in index}
    read = lambda a, n: read_va(data, secs, a, n, True)
    selected = []
    fde_rows = []
    lsda_by_start = {}
    unwind_rows = []
    for label, address, scope in FUNCTIONS:
        if len(by_start.get(address, [])) != 1 or address not in index_by_start:
            raise ValueError('missing or ambiguous selected FDE')
        fde = by_start[address][0]
        indexed = index_by_start[address]
        if indexed['fde'] != fde['fde'] or fde['end'] <= address:
            raise ValueError('FDE and unwind index disagree')
        ensure_no_fde_overlap(fde, fdes)
        sec, off = mapping(secs, address, fde['end'] - address, True)
        body = read(address, fde['end'] - address)
        selected.append((label, scope, fde))
        fde_rows.append((label, scope, hex(address), hex(fde['end']), hex(fde['fde']),
                         indexed['index'], sec['name'], hex(off), len(body),
                         hashlib.sha256(body).hexdigest(), as_hex(fde['lsda'])))
        entries = parse_lsda(data, secs, fde)
        lsda_by_start[address] = entries
        for off, begin, end, landing, action, raw in entries:
            unwind_rows.append((label, hex(fde['lsda']), hex(off), hex(begin), hex(end),
                                as_hex(landing), action, raw.hex()))

    def owner(site, length):
        matches = [(label, scope, fde) for label, scope, fde in selected
                   if fde['start'] <= site and site + length <= fde['end']]
        if len(matches) != 1:
            raise ValueError(f'selected bytes not in exactly one selected FDE: {site:#x}')
        return matches[0]

    window_rows = []
    for label, start, end in WINDOWS:
        if end <= start:
            raise ValueError('invalid window')
        func, scope, _ = owner(start, end - start)
        sec, off = mapping(secs, start, end - start, True)
        raw = read(start, end - start)
        window_rows.append((label, func, scope, hex(start), hex(end), sec['name'], hex(off), raw.hex()))

    transfers, callsites = [], []
    for label, site, expected_op, expected_target in TRANSFERS:
        op, target, raw = checked_transfer(read, site, expected_op, expected_target)
        func, scope, fde = owner(site, len(raw))
        sec, off = mapping(secs, site, len(raw), True)
        transfers.append((label, func, scope, hex(site), hex(off), op, hex(target), raw.hex()))
        if op == 'call':
            match = callsite_witness(lsda_by_start[fde['start']], site, len(raw))
            callsites.append((label, func, hex(site), hex(target),
                              as_hex(match[1]) if match else '', as_hex(match[2]) if match else '',
                              as_hex(match[3]) if match else '', str(match[4]) if match else '',
                              'covered' if match else ('no_lsda' if fde['lsda'] is None else 'no_entry')))

    rels = relative_relocations(data, secs, [slot for _, slot, _, _ in RELOCS])
    reloc_rows = []
    for label, slot, expected, scope in RELOCS:
        addend, rel_off = rels[slot]
        if expected is not None and addend != expected:
            raise ValueError('relocation addend differs: ' + label)
        sec, slot_off = mapping(secs, slot, 8)
        reloc_rows.append((label, scope, hex(slot), sec['name'], hex(slot_off),
                           hex(rel_off), 'R_X86_64_RELATIVE', hex(addend),
                           read_va(data, secs, slot, 8).hex()))

    rip_specs = [
        ('parent_dispatch_context', 0x2cb8915, b'\xff\x15', 0x64e7458),
        ('task_descriptor', 0x5a6ce58, b'\x48\x8d\x0d', 0x64b8a00),
        ('formatter_context', 0x54846f7, b'\xff\x15', 0x64e7820),
        ('capture_reducer', 0x4e35359, b'\xff\x15', 0x64df500),
        ('location_context', 0x3c1352f, b'\x48\x8d\x15', 0x64767a8),
    ]
    rip_rows = []
    for label, site, opcode, expected in rip_specs:
        dest, raw = rip_target(read, site, opcode)
        if dest != expected:
            raise ValueError('RIP-relative target differs: ' + label)
        func, scope, _ = owner(site, len(raw))
        rip_rows.append((label, func, scope, hex(site), hex(dest), raw.hex()))

    literal_specs = [
        ('task_name', 0x5a6ce51, '488d3d', 0x5a6ce5f, 'be', b'node slow abci_state driver'),
        ('callback_operation', 0x5a3445e, '488d15', 0x5a3446d, 'b9', b'hardfork_hashes'),
        ('owner_increment_label', 0x564787a, '488d05', 0x5647886, '48c7442478', b'slow_abci_engine_read_increment'),
        ('apply_block_operation', 0x5a34e74, '488d0d', 0x5a34e83, '48c78424f0000000', b'spawn_slow_abci_driver_apply_block'),
        ('write_greeting_operation', 0x5a34f65, '488d0d', 0x5a34f74, '48c78424f8000000', b'spawn_slow_abci_driver_write_greeting'),
    ]
    literal_rows = []
    for label, ref_site, ref_opcode, length_site, length_opcode, expected in literal_specs:
        literal_va, ref_raw = rip_target(read, ref_site, bytes.fromhex(ref_opcode))
        length, length_raw = immediate(read, length_site, bytes.fromhex(length_opcode), '<I')
        raw = read_va(data, secs, literal_va, length)
        if raw != expected:
            raise ValueError('selected literal differs: ' + label)
        sec, off = mapping(secs, literal_va, length)
        literal_rows.append((label, hex(ref_site), ref_raw.hex(), hex(length_site), length_raw.hex(),
                             hex(literal_va), sec['name'], hex(off), length, raw.hex(), raw.decode('ascii')))

    field_specs = [
        ('parent_owner_slot', 0x2cb8863, '488bb3', '<I'),
        ('parent_write_owner_slot', 0x2cb8887, '488b93', '<I'),
        ('parent_return_saved_stack', 0x2cb7a31, '48895424', '<B'),
        ('parent_return_load_stack', 0x2cb7e27, '488b4c24', '<B'),
        ('parent_pointer_stage_stack', 0x2cb7e2c, '48898c24', '<I'),
        ('parent_copy_source_1', 0x2cb7e6c, '488db424', '<I'),
        ('parent_copy_destination_1', 0x2cb7e74, '4c8dbc24', '<I'),
        ('parent_copy_size_1', 0x2cb7e7c, 'ba', '<I'),
        ('parent_copy_destination_2', 0x2cb7ffe, '488dbc24', '<I'),
        ('parent_copy_size_2', 0x2cb8006, 'ba', '<I'),
        ('parent_copy_destination_3', 0x2cb8039, '488dbc24', '<I'),
        ('parent_copy_source_3', 0x2cb8041, '488db424', '<I'),
        ('parent_copy_size_3', 0x2cb8049, 'ba', '<I'),
        ('parent_copy_destination_4', 0x2cb806f, '488dbb', '<I'),
        ('parent_copy_source_4', 0x2cb8076, '488db424', '<I'),
        ('parent_copy_size_4', 0x2cb807e, 'ba', '<I'),
        ('constructor_capture_stack', 0x5a6cd71, '4c89b424', '<I'),
        ('constructor_write_arg_save', 0x5a6cbe9, '48895424', '<B'),
        ('constructor_write_arg_load', 0x5a6ce17, '488b4424', '<B'),
        ('constructor_write_capture_stack', 0x5a6ce1c, '48898424', '<I'),
        ('constructor_alloc_size', 0x5a6ce24, 'bf', '<I'),
        ('constructor_copy_source_stack', 0x5a6ce3b, '488db424', '<I'),
        ('constructor_copy_length', 0x5a6ce43, 'ba', '<I'),
        ('callback_owner_slot', 0x5a34456, '488b77', '<B'),
        ('callback_owner_body', 0x5a3445a, '4883c6', '<B'),
        ('callback_sentinel', 0x5a34477, '48b9', '<Q'),
        ('callback_write_owner_slot', 0x5a34f2f, '488bb8', '<I'),
        ('callback_write_body_adjustment', 0x5a34f61, '488d47', '<B'),
        ('callback_write_body_stack', 0x5a34f93, '48894424', '<B'),
        ('callback_write_input_stack', 0x5a34fa5, '488d7424', '<B'),
        ('callback_write_dispatch_base', 0x5a34f8c, '4881c7', '<I'),
        ('callback_apply_result_stack', 0x5a34efb, '488dbc24', '<I'),
        ('write_dispatch_mode_offset', 0x4f18be9, '807f', '<B'),
        ('write_owner_body_input', 0x4fcbe6e, '488b5f', '<B'),
        ('write_owner_destination', 0x4fcbfd7, '488dab', '<I'),
        ('callback_result_stack', 0x5a34465, '488dbc24', '<I'),
        ('apply_callback_owner_pointer', 0x5a34e22, '488b43', '<B'),
        ('apply_callback_body_adjustment', 0x5a34e52, '4883c0', '<B'),
        ('apply_callback_body_stack', 0x5a34e8f, '48898424', '<I'),
        ('apply_callback_input_stack', 0x5a34f03, '488d7424', '<B'),
        ('apply_wrapper_owner_input', 0x4e47a39, '498b76', '<B'),
        ('apply_wrapper_owner_stack', 0x4e47a52, '48897424', '<B'),
        ('apply_wrapper_dispatch_base', 0x4e47a57, '4881c6', '<I'),
        ('apply_dispatch_input_stack', 0x4e47a72, '488d5424', '<B'),
        ('apply_dispatch_mode_offset', 0x4f152bf, '807e', '<B'),
        ('wrapper_result_stack', 0x5647755, '488dbc24', '<I'),
        ('root_wrapper_dispatch_base', 0x4e46c4e, '4981c7', '<I'),
        ('root_dispatch_mode_offset', 0x4f21aa9, '807e', '<B'),
        ('gate_compact_pointer_slot', 0x4fc35f6, '498b8424', '<I'),
        ('gate_height_first', 0x4fc35fe, '488b48', '<B'),
        ('gate_height_second', 0x4fc3602, '483b48', '<B'),
        ('gate_result_stack', 0x4fc3614, '488dbc24', '<I'),
        ('state_result_height_slot', 0x54847da, '4d897d', '<B'),
        ('state_result_mixed_first', 0x54847ee, '410f1145', '<B'),
        ('state_result_mixed_second', 0x54847f3, '410f114d', '<B'),
        ('state_result_root_first', 0x5484808, '410f1145', '<B'),
        ('state_result_root_second', 0x548480d, '410f114d', '<B'),
        ('capture_allocation_size', 0x4e35155, 'bf', '<I'),
        ('capture_initial_tag', 0x4e35169, '49bc', '<Q'),
        ('queue_index_mask', 0x581a51c, '83e3', '<B'),
        ('queue_block_group_slot', 0x581a513, '482b82', '<I'),
        ('queue_block_allocation_size', 0x581a577, 'bf', '<I'),
        ('queue_block_bitmap_slot', 0x581a6a7, 'f04809b2', '<I'),
        ('work_queue_index_mask', 0x5818b6d, '83e2', '<B'),
        ('work_queue_record_stride', 0x5818b70, '486bd2', '<B'),
        ('work_queue_group_slot', 0x5818a04, '483988', '<I'),
        ('work_queue_bitmap_slot', 0x5818b5f, '488b90', '<I'),
        ('work_queue_empty_tag', 0x5818bca, '48b8', '<Q'),
    ]
    field_rows, fields = [], {}
    for name, site, opcode, fmt in field_specs:
        value, raw = immediate(read, site, bytes.fromhex(opcode), fmt)
        func, scope, _ = owner(site, len(raw))
        fields[name] = value
        field_rows.append((name, func, scope, hex(site), fmt, hex(value), raw.hex()))

    patterns = [
        ('constructor_owner_argument', 0x5a6cbde, '4989f6'),
        ('owner_pair', 0x5647741, '48897424104889742418'),
        ('root_wrapper_owner_pair', 0x4e46c49, '4c897c24104981c7300100004c896c2418'),
        ('root_dispatch_pair_forward', 0x4f21b02, '4889fb4889d6'),
        ('gate_owner_from_pair', 0x4fc34a1, '4889fb4c8b26'),
        ('compact_state_argument', 0x4e34cf1, '4989f7'),
        ('parent_second_copy_source', 0x2cb800b, '4c89feffd5'),
        ('gate_height_compare', 0x4fc35f6, '498b8424000b0000488b4828483b4810'),
        ('gate_sentinel', 0x4fc376e, '48b80000000000000080'),
        ('state_height_load', 0x5484684, '488b1e4c8b7b28'),
        ('result_mixer_input', 0x5484784, '488d4424604889442428488d4424584889442430'),
        ('callback_sentinel_test', 0x5a34481, '31c0483b8424b8020000710d'),
        ('callback_height_load', 0x5a34520, '488b442478'),
        ('callback_height_store', 0x5a34547, '48898424b8020000'),
        ('callback_queue_arguments', 0x5a3458d, '488dbb80000000488db424b8020000'),
        ('queue_ticket', 0x581a4fb, 'bb01000000f0480fc15f08'),
        ('queue_slot_stride', 0x581a680, '488d049b488b4e2048894cc220'),
        ('queue_publication', 0x581a69e, '89d948d3e60f1104c2f04809b210050000'),
        ('counter_saturating', 0x5647bb5, '498b85680b000048ffc048c7c1ffffffff480f45c849898d680b0000'),
        ('callback_apply_input', 0x5a34f03, '488d742440ba01000000'),
        ('apply_owner_load_and_save', 0x4e47a39, '498b7658498b46600f10000f1144241048c7442408000000004889742478'),
        ('apply_dispatch_copy_argument', 0x4f15326, '4889df4889ee'),
        ('apply_dispatch_input_capture', 0x4f152b1, '4889d5'),
        ('apply_dispatch_zero_mode', 0x4f152bf, '807e2000'),
        ('root_dispatch_zero_mode', 0x4f21aa9, '807e2000'),
        ('write_dispatch_zero_mode', 0x4f18be9, '807f2000'),
        ('write_dispatch_tail_input', 0x4f18c5c, '4889ef'),
        ('work_queue_status_result', 0x5818bca, '48b80100000000000080eb0d48b8010000000000008048ffc8488907'),
    ]
    pattern_rows = []
    for name, site, encoded in patterns:
        raw = require_bytes(read, site, bytes.fromhex(encoded))
        func, scope, _ = owner(site, len(raw))
        pattern_rows.append((name, func, scope, hex(site), raw.hex()))

    # The second copy's source is the retained r15 set to copy 1's destination.
    fields['parent_copy_source_2'] = fields['parent_copy_destination_1']
    parent_projection = project_parent_owner(fields)
    parent_projection_rows = [(i, hex(pos), hex(src), hex(dst), hex(size), hex(out))
                              for i, pos, src, dst, size, out in parent_projection]

    copies = selected_copies(read)
    copy_rows = [(name, hex(v[3]), hex(v[4]), hex(v[0]), hex(v[1]), v[2],
                  v[5].hex(), v[6].hex()) for name, v in copies.items()]
    projections = []
    for name, offset, width, suffix in [
        ('height', fields['state_result_height_slot'], 8, 'height_chunk'),
        ('mixed_digest_first', fields['state_result_mixed_first'], 16, 'mix_first'),
        ('mixed_digest_second', fields['state_result_mixed_second'], 16, 'mix_second'),
    ]:
        out = track_projection(copies, fields['gate_result_stack'], fields['wrapper_result_stack'],
                               fields['callback_result_stack'], offset, width, suffix)
        projections.append((name, hex(offset), width, hex(out)))
    if [row[3] for row in projections] != ['0x0', '0x8', '0x18']:
        raise ValueError('selected 40-byte record layout differs')

    slots, stride = queue_geometry(read, fields['queue_index_mask'], fields['queue_block_group_slot'])

    # These three small observations are explicitly contextual: their FDEs and
    # block-state semantics were mapped by the earlier preflight-result packet.
    context_specs = [
        ('existing_owner_input', 0x4fcac2c, '4c8b7e', '<B'),
        ('existing_owner_context', 0x4fcae24, '498d8f', '<I'),
        ('existing_context_state_slot', 0x5a04ebb, '498b8c24', '<I'),
    ]
    context_rows, context = [], {}
    for name, site, opcode, fmt in context_specs:
        value, raw = immediate(read, site, bytes.fromhex(opcode), fmt)
        _, off = mapping(secs, site, len(raw), True)
        context[name] = value
        context_rows.append((name, 'previously mapped boundary', hex(site), hex(off), hex(value), raw.hex()))
    callback_input_offset, forwarded_input_offset, owner_state_slot = check_apply_projection(fields, context)
    root_mode = fields['root_wrapper_dispatch_base'] + fields['root_dispatch_mode_offset']
    apply_mode = fields['apply_wrapper_dispatch_base'] + fields['apply_dispatch_mode_offset']
    if root_mode != apply_mode:
        raise ValueError('root and apply direct dispatch use different owner mode offsets')
    work_slots, work_stride = work_queue_geometry(fields['work_queue_index_mask'],
                                                  fields['work_queue_record_stride'],
                                                  fields['work_queue_group_slot'])

    captures = parse_captures(read(0x4e34d06, 0x4e35155 - 0x4e34d06))
    stores = parse_descriptor_stores(read(0x4e35173, 0x4e352fd - 0x4e35173))
    if fields['capture_allocation_size'] != len(stores) * 24:
        raise ValueError('descriptor allocation/stride mismatch')
    if fields['capture_initial_tag'] != 0x8000000000000001:
        raise ValueError('unexpected descriptor tag')

    descriptor = read_va(data, secs, 0x64b8a00, 32)
    _, size, alignment, _ = struct.unpack('<QQQQ', descriptor)
    if size != fields['constructor_alloc_size'] or alignment != 8:
        raise ValueError('task descriptor layout differs')
    capture_in_closure = map_copy(fields['constructor_capture_stack'],
                                  fields['constructor_copy_source_stack'], 0,
                                  fields['constructor_copy_length'], 8)
    if capture_in_closure != fields['callback_owner_slot']:
        raise ValueError('owner capture does not reach callback slot')
    write_capture_in_closure, write_input_offset = check_write_capture(fields)
    write_rows = check_write_projection(copies, fields['callback_apply_result_stack'],
                                        fields['callback_write_input_stack'])
    write_projection_rows = [(name, hex(src), width, hex(dst)) for name, src, width, dst in write_rows]

    location = read_va(data, secs, 0x64767a8, 24)
    pointer, name_length, line, column = struct.unpack('<QQII', location)
    name_va = rels[0x64767a8][0]
    if (pointer, name_length, line, column) != (0, 20, 123, 37):
        raise ValueError('node 115 Location differs')
    name = read_va(data, secs, name_va, name_length)
    if name != b'l1/src/abci/state.rs':
        raise ValueError('node 115 Location name differs')
    require_bytes(read, 0x3c1353b, bytes.fromhex('4883f801'))
    sec, loc_off = mapping(secs, 0x64767a8, 24)
    location_record = {
        'component_id': 'abci', 'artifact_sha256': TARGET, 'scope': 'existing context only',
        'location_va': hex(0x64767a8), 'location_file_offset': hex(loc_off),
        'location_raw_hex': location.hex(), 'name_va': hex(name_va), 'name': name.decode('ascii'),
        'line': line, 'column': column, 'reference_va': hex(0x3c1352f),
        'comparison_va': hex(0x3c1353b), 'comparison_hex': read(0x3c1353b, 4).hex(),
    }
    flow = [
        ('parent_owner_slot', hex(fields['parent_owner_slot']), 'context'),
        ('constructor_source_stack', hex(fields['constructor_copy_source_stack']), 'selected'),
        ('constructor_saved_pointer_stack', hex(fields['constructor_capture_stack']), 'selected'),
        ('constructor_copy_bytes', hex(fields['constructor_copy_length']), 'selected'),
        ('closure_pointer_offset', hex(capture_in_closure), 'derived from selected copy'),
        ('callback_pointer_offset', hex(fields['callback_owner_slot']), 'selected'),
        ('owner_body_adjustment', hex(fields['callback_owner_body']), 'selected'),
        ('owner_compact_pointer_offset', hex(fields['gate_compact_pointer_slot']), 'selected'),
        ('state_height_offsets', hex(fields['gate_height_first']) + ',' + hex(fields['gate_height_second']), 'selected'),
        ('result_height_offset', hex(fields['state_result_height_slot']), 'selected'),
        ('result_mixed_digest_offsets', hex(fields['state_result_mixed_first']) + ',' + hex(fields['state_result_mixed_second']), 'selected'),
        ('result_raw_digest_offsets', hex(fields['state_result_root_first']) + ',' + hex(fields['state_result_root_second']), 'selected'),
        ('task_descriptor_size', hex(size), 'selected data'),
        ('task_descriptor_alignment', hex(alignment), 'selected data'),
        ('apply_callback_owner_input_offset', hex(callback_input_offset), 'selected stack projection'),
        ('apply_forwarded_owner_input_offset', hex(forwarded_input_offset), 'selected stack projection'),
        ('existing_owner_context_offset', hex(context['existing_owner_context']), 'existing boundary context'),
        ('existing_context_state_slot_offset', hex(context['existing_context_state_slot']), 'existing boundary context'),
        ('existing_owner_state_slot_sum', hex(owner_state_slot), 'derived context'),
        ('shared_direct_mode_byte_offset', hex(root_mode), 'selected'),
        ('parent_write_owner_slot', hex(fields['parent_write_owner_slot']), 'context'),
        ('write_closure_pointer_offset', hex(write_capture_in_closure), 'selected stack projection'),
        ('write_body_adjustment', hex(fields['callback_write_body_adjustment']), 'selected'),
        ('write_body_input_offset', hex(write_input_offset), 'selected stack projection'),
        ('write_owner_destination_offset', hex(fields['write_owner_destination']), 'selected'),
        ('write_mode_from_allocation_offset', hex(fields['callback_write_dispatch_base'] + fields['write_dispatch_mode_offset']), 'selected'),
        ('work_queue_slots_per_block', hex(work_slots), 'selected'),
        ('work_queue_record_stride', hex(work_stride), 'selected'),
        ('work_queue_bitmap_offset', hex(fields['work_queue_bitmap_slot']), 'selected'),
        ('queue_slots_per_block', hex(slots), 'decoded index mask'),
        ('queue_record_stride', hex(stride), 'decoded SIB factors'),
        ('queue_group_metadata_offset', hex(fields['queue_block_group_slot']), 'selected'),
        ('queue_bitmap_offset', hex(fields['queue_block_bitmap_slot']), 'selected'),
        ('queue_block_allocation_bytes', hex(fields['queue_block_allocation_size']), 'selected'),
    ]
    capture_rows = [(i, hex(site), hex(stack), hex(state)) for i, site, stack, state in captures]
    store_rows = [(i, hex(site), hex(offset)) for i, site, offset in stores]
    summary = {
        'artifact_sha256': TARGET, 'component_id': 'abci',
        'coordinate_system': 'ELF link-time virtual address and file offset',
        'new_unwind_extents': sum(scope == 'new' for _, scope, _ in selected),
        'context_unwind_extents': sum(scope == 'context' for _, scope, _ in selected),
        'selected_instruction_windows': len(window_rows),
        'direct_transfers': len(transfers), 'rip_relative_references': len(rip_rows),
        'relative_relocations': len(reloc_rows), 'fixed_instruction_patterns': len(pattern_rows),
        'selected_literals': len(literal_rows),
        'decoded_immediates': len(field_rows), 'compact_pointer_captures': len(captures),
        'decoded_copy_pairs': len(copy_rows), 'joined_result_slices': len(projections),
        'joined_write_slices': len(write_projection_rows),
        'context_parent_copy_stages': len(parent_projection_rows),
        'descriptor_tag_stores': len(stores), 'lsda_callsite_rows': len(unwind_rows),
        'direct_call_unwind_links': len(callsites),
        'limitations': 'Selected static evidence only; FDE extents do not establish complete function boundaries or coverage. Scheduler execution, helper effects, aliasing, state-root algorithm, persistence, and full block transitions remain unresolved.',
    }
    def encoded(value):
        return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')
    return {
        'functions.tsv': tsv(['label', 'scope', 'start_va', 'end_va', 'fde_va', 'unwind_index', 'section', 'file_offset', 'size', 'sha256', 'lsda_va'], fde_rows),
        'windows.tsv': tsv(['label', 'function', 'scope', 'start_va', 'end_va', 'section', 'file_offset', 'raw_hex'], window_rows),
        'transfers.tsv': tsv(['label', 'function', 'scope', 'site_va', 'file_offset', 'kind', 'target_va', 'raw_hex'], transfers),
        'rip_refs.tsv': tsv(['label', 'function', 'scope', 'site_va', 'target_va', 'raw_hex'], rip_rows),
        'relocations.tsv': tsv(['label', 'scope', 'slot_va', 'section', 'slot_file_offset', 'reloc_file_offset', 'type', 'addend', 'slot_raw_hex'], reloc_rows),
        'literals.tsv': tsv(['label', 'reference_va', 'reference_hex', 'length_instruction_va', 'length_hex', 'literal_va', 'section', 'file_offset', 'length', 'raw_hex', 'text'], literal_rows),
        'immediates.tsv': tsv(['label', 'function', 'scope', 'site_va', 'format', 'value', 'raw_hex'], field_rows),
        'patterns.tsv': tsv(['label', 'function', 'scope', 'site_va', 'raw_hex'], pattern_rows),
        'captures.tsv': tsv(['index', 'instruction_va', 'stack_offset', 'state_offset'], capture_rows),
        'descriptor_stores.tsv': tsv(['index', 'instruction_va', 'allocation_offset'], store_rows),
        'flow.tsv': tsv(['fact', 'value', 'basis'], flow),
        'parent_projection.tsv': tsv(['stage', 'input_offset', 'source_base', 'destination_base', 'copy_size', 'output_offset'], parent_projection_rows),
        'context_operands.tsv': tsv(['label', 'scope', 'site_va', 'file_offset', 'value', 'raw_hex'], context_rows),
        'copies.tsv': tsv(['label', 'load_va', 'store_va', 'source_offset', 'destination_offset', 'width', 'load_hex', 'store_hex'], copy_rows),
        'projection.tsv': tsv(['slice', 'result_offset', 'width', 'record_offset'], projections),
        'write_projection.tsv': tsv(['slice', 'apply_result_offset', 'width', 'owner_slot_offset'], write_projection_rows),
        'unwind.tsv': tsv(['function', 'lsda_va', 'file_offset', 'start_va', 'end_va', 'landing_va', 'action_raw', 'row_hex'], unwind_rows),
        'unwind_links.tsv': tsv(['transfer', 'function', 'call_va', 'target_va', 'start_va', 'end_va', 'landing_va', 'action_raw', 'status'], callsites),
        'location.json': encoded(location_record), 'summary.json': encoded(summary),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--historical', type=Path, help='optional separately authenticated node 94 capture')
    args = parser.parse_args()
    data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
    verify_digest(data)
    if args.historical is not None:
        print(json.dumps(validate_historical(args.historical.read_bytes()), sort_keys=True))
    outputs = generate(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(outputs):
        (args.out / name).write_bytes(outputs[name])
    print(f'Wrote {len(outputs)} deterministic evidence files for node 115')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print(f'abci_compact_root115: {error}', file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Extract and evaluate the node #94 post-only admission window from ELF bytes.

This is a narrow instruction evaluator for two fixed, fully checked byte strings,
not a general x86 emulator. Existing caller and status-dispatch windows are
read for context. No target code is executed.
"""
import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
GATES = (0x4d8c270, 0x4d8c2e0)
FORMATTER = 0x37ecea0
CALLS = (0x4c1811f, 0x4c18992, 0x4c19272, 0x4c19a2f)
TABLE = 0x59a8d0
WORD_BITS = 64
MAX = (1 << WORD_BITS) - 1
TEMPLATE = bytes.fromhex(
    '8b4760488b4f283b87244500000f9cc0751b8b47643b87284500000f92c0'
    '750d8b47683b872c4500007306eb0f84c0750bb002483b8f08440000732b'
    '488b4710483d78ecffff721348058813000048c7c2ffffffff480f42c2'
    'eb064805881300004839c10f93c0c3')
FORMAT_BYTES = bytes.fromhex(
    '488b0f488b3e488b4608488b4018803900740e488d35cd1ddbfcba1c000000ffe0'
    '488d359e1ddbfcba21000000ffe0')


class EvidenceError(ValueError):
    pass


def authenticate(data, expected=SHA256):
    if hashlib.sha256(data).hexdigest() != expected:
        raise EvidenceError('artifact SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def offset(self, address, length, executable=False):
        if address < 0 or length < 0:
            raise EvidenceError('negative address or length')
        hits = [s for s in self.sections if s['type'] != 8 and
                (not executable or s['flags'] & 4) and
                s['address'] <= address and address + length <= s['address'] + s['size']]
        if len(hits) != 1:
            raise EvidenceError('address lacks one file-backed section')
        return hits[0]['offset'] + address - hits[0]['address']

    def read(self, address, length, executable=False):
        offset = self.offset(address, length, executable)
        return self.data[offset:offset + length]


def i32(data, off):
    return struct.unpack_from('<i', data, off)[0]


def u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def relative(base, data, pos, size):
    if size == 1:
        value = struct.unpack_from('<b', data, pos)[0]
    elif size == 4:
        value = i32(data, pos)
    else:
        raise EvidenceError('unsupported relative width')
    return base + pos + size + value


def gate_info(code):
    if len(code) != len(TEMPLATE):
        raise EvidenceError('unexpected gate extent')
    masked = bytearray(code)
    for offset in (9, 23, 37, 54):
        masked[offset:offset + 4] = TEMPLATE[offset:offset + 4]
    if bytes(masked) != TEMPLATE:
        raise EvidenceError('unexpected gate instruction bytes')
    fields = [u32(code, p) for p in (9, 23, 37, 54)]
    if fields[1:3] != [fields[0] + 4, fields[0] + 8]:
        raise EvidenceError('noncontiguous time threshold')
    immediate = u32(code, 74)
    if immediate != u32(code, 93) or ((1 << 64) - immediate) & MAX != int.from_bytes(code[66:70], 'little', signed=True) & MAX:
        raise EvidenceError('inconsistent saturation constant')
    return {'time_fields': fields[:3], 'height_field': fields[3],
            'current_time_fields': [code[2], code[20], code[34]],
            'height_field_input': code[6], 'start_height_field': code[63],
            'window': immediate, 'free_code': code[50],
            'branches': {hex(p): hex(relative(0, code, p + 1, 1)) for p in (16, 30, 41, 43, 47, 58, 70, 89)}}


def signed32(value):
    value &= 0xffffffff
    return value - (1 << 32) if value & (1 << 31) else value


def evaluate(code, current, threshold, height, min_height, start_height):
    """Step the validated instruction sequence; return AL and visited offsets."""
    info = gate_info(code)
    memory = dict(zip(info['current_time_fields'], current))
    memory.update(zip(info['time_fields'], threshold))
    memory[info['height_field_input']] = height
    memory[info['height_field']] = min_height
    memory[info['start_height_field']] = start_height
    pc = 0
    eax = rcx = rdx = 0
    zf = cf = sf_less = False
    visited = []
    while True:
        if len(visited) > 50:
            raise EvidenceError('gate did not terminate')
        visited.append(pc)
        if pc in (0, 18, 32):
            eax = memory[code[pc + 2]] & 0xffffffff
            pc += 3
        elif pc == 3:
            rcx = memory[code[pc + 3]] & MAX
            pc += 4
        elif pc in (7, 21, 35):
            value = memory[u32(code, pc + 2)] & 0xffffffff
            zf, cf, sf_less = eax == value, eax < value, signed32(eax) < signed32(value)
            pc += 6
        elif pc in (13, 27):
            eax = (eax & ~255) | int(sf_less if pc == 13 else cf)
            pc += 3
        elif pc in (16, 30, 41, 43, 47, 58, 70, 89):
            condition = {16: not zf, 30: not zf, 41: not cf, 43: True,
                         47: not zf, 58: not cf, 70: cf, 89: True}[pc]
            pc = relative(0, code, pc + 1, 1) if condition else pc + 2
        elif pc == 45:
            zf = (eax & 255) == 0
            pc += 2
        elif pc == 49:
            eax = (eax & ~255) | code[pc + 1]
            pc += 2
        elif pc == 51:
            value = memory[u32(code, pc + 3)] & MAX
            zf, cf = rcx == value, rcx < value
            pc += 7
        elif pc == 60:
            eax = memory[code[pc + 3]] & MAX
            pc += 4
        elif pc == 64:
            value = i32(code, pc + 2) & MAX
            zf, cf = eax == value, eax < value
            pc += 6
        elif pc in (72, 91):
            value = u32(code, pc + 2)
            total = eax + value
            eax, cf = total & MAX, total > MAX
            pc += 6
        elif pc == 78:
            rdx = i32(code, pc + 3) & MAX
            pc += 7
        elif pc == 85:
            if cf:
                eax = rdx
            pc += 4
        elif pc == 97:
            zf, cf = rcx == eax, rcx < eax
            pc += 3
        elif pc == 100:
            eax = (eax & ~255) | int(not cf)
            pc += 3
        elif pc == 103:
            return eax & 255, visited
        else:
            raise EvidenceError('unsupported instruction offset')


def specification(current, threshold, height, min_height, start_height, window, free_code):
    # Separate high-level formula; the selected x86 tests the first component signed.
    left = (signed32(current[0]), current[1] & 0xffffffff, current[2] & 0xffffffff)
    right = (signed32(threshold[0]), threshold[1] & 0xffffffff, threshold[2] & 0xffffffff)
    if left >= right and height >= min_height:
        return free_code
    return int(height >= min(MAX, start_height + window))


def vectors(window):
    # Synthetic boundary inputs, not node execution or captured state.
    time_pairs = [((0, 0, 0), (0, 0, 0)), ((0, 0, 0), (0, 0, 1)),
                  ((0, 0, 2), (0, 0, 1)), ((0, 1, 0), (0, 0, 0xffffffff)),
                  ((0, 0xffffffff, 0xffffffff), (1, 0, 0)),
                  ((0xffffffff, 0, 0), (0, 0, 0)),
                  ((0, 0, 0), (0xffffffff, 0, 0)),
                  ((0x80000000, 0, 0), (0x7fffffff, 0, 0)),
                  ((0x7fffffff, 0, 0), (0x80000000, 0, 0))]
    starts = (0, 1, MAX - window, MAX - window + 1, MAX)
    for (current, threshold), start, min_height in itertools.product(time_pairs, starts, (0, 1, MAX)):
        saturation = min(MAX, start + window)
        heights = sorted({0, 1, min_height, max(0, min_height - 1),
                          saturation, max(0, saturation - 1), MAX})
        for height in heights:
            yield current, threshold, height, min_height, start


def call_info(image, site):
    code = image.read(site, 5, True)
    if code[0] != 0xe8:
        raise EvidenceError('expected direct call')
    target = relative(site, code, 1, 4)
    if target not in GATES:
        raise EvidenceError('unexpected call target')
    # Two layouts: spot tests a predicate saved before the call; perp tests after.
    if site in (CALLS[0], CALLS[3]):
        start = site - 12
        data = image.read(start, 41, True)
        expected = bytearray.fromhex('0fb66c240b4080f5024c89efe800000000400a6c240c0f94c13c02742c84c9752866c7037400884302')
        expected[13:17] = data[13:17]
        if data != expected:
            raise EvidenceError('unexpected spot caller')
        accept_a = relative(start, data, 28, 1)
        accept_b = relative(start, data, 32, 1)
        if accept_a != accept_b:
            raise EvidenceError('spot success destinations differ')
        failure = start + 33
        tag = struct.unpack_from('<H', data, 36)[0]
        byte_offsets = [data[4], data[21]]
    else:
        start = site
        data = image.read(start, 27, True)
        expected = bytearray.fromhex('e8000000003c0274120fb64c241180f1020a4c24120f8500000000')
        expected[1:5] = data[1:5]
        expected[23:27] = data[23:27]
        if data != expected:
            raise EvidenceError('unexpected perp caller')
        accept_a = relative(start, data, 8, 1)
        failure = relative(start, data, 23, 4)
        fail = image.read(failure, 8, True)
        if fail[:3] != bytes.fromhex('66c703') or fail[5:] != bytes.fromhex('884302'):
            raise EvidenceError('unexpected perp status write')
        tag = struct.unpack_from('<H', fail, 3)[0]
        byte_offsets = [data[13], data[20]]
        accept_b = start + len(data)
        if accept_a != accept_b:
            raise EvidenceError('perp success destinations differ')
    rejection = image.read(failure, 13, True)
    if rejection[:3] != bytes.fromhex('66c703') or rejection[5:9] != bytes.fromhex('884302e9'):
        raise EvidenceError('unexpected caller rejection return')
    epilogue_va = relative(failure, rejection, 9, 4)
    epilogue = image.read(epilogue_va, 21, True)
    expected_frame = 0x138 if site in (CALLS[0], CALLS[3]) else 0x158
    expected_epilogue = bytes.fromhex('4889d84881c4') + struct.pack('<I', expected_frame) + bytes.fromhex('5b415c415d415e415f5dc3')
    if epilogue != expected_epilogue:
        raise EvidenceError('unexpected caller return epilogue')
    return {'call': hex(site), 'target': hex(target), 'kind': 'spot' if site in (CALLS[0], CALLS[3]) else 'perp',
            'window_start': hex(start), 'window_bytes': data.hex(), 'stack_byte_offsets': byte_offsets,
            'accept': hex(accept_a), 'failure': hex(failure), 'status_tag': tag,
            'rejection_bytes': rejection.hex(), 'return': hex(epilogue_va), 'return_bytes': epilogue.hex()}




def modify_context(image, site, expected_target):
    """Pin the existing modify path's call and early status branch as context."""
    code = image.read(site, 21, True)
    expected = bytearray.fromhex('e8000000000fb74424103d860100000f8500000000')
    expected[1:5], expected[17:21] = code[1:5], code[17:21]
    if code != expected or relative(site, code, 1, 4) != expected_target:
        raise EvidenceError('unexpected modify check call')
    return {'call': hex(site), 'target': hex(expected_target), 'bytes': code.hex(),
            'success_word': u32(code, 11), 'failure_branch': hex(relative(site, code, 17, 4))}


def evaluate_caller(image, site, gate_al, order_byte_9, order_byte_0):
    """Evaluate the pinned caller window after substituting the gate return."""
    if gate_al not in (0, 1, 2) or not all(0 <= b <= 255 for b in (order_byte_9, order_byte_0)):
        raise EvidenceError('caller inputs outside byte/gate domain')
    row = call_info(image, site)
    code = bytes.fromhex(row['window_bytes'])
    if row['kind'] == 'spot':
        # xor bpl, imm8; or bpl, stack byte; sete cl; cmp/test; branches.
        register = (order_byte_9 ^ code[8]) | order_byte_0
        cl = int(register == 0)
        success = gate_al == code[26] or cl != 0
    else:
        # cmp gate result; otherwise xor/or the two saved order bytes.
        register = (order_byte_9 ^ code[16]) | order_byte_0
        success = gate_al == code[6] or register == 0
    return (None, None) if success else (row['status_tag'], gate_al)


def status_info(image, tag):
    dispatch_va = 0x37ffd40
    dispatch = image.read(dispatch_va, 23, True)
    shape = bytearray.fromhex('4883ec480fb707488d0d00000000486304814801c8ffe0')
    shape[10:14] = dispatch[10:14]
    if dispatch != shape or relative(dispatch_va, dispatch, 10, 4) != TABLE:
        raise EvidenceError('unexpected status dispatch')
    entry = image.read(TABLE + 4 * tag, 4)
    arm = TABLE + i32(entry, 0)
    data = image.read(arm, 58, True)
    shape = bytearray.fromhex('4883c70248893c244889e04889442410488d05000000004889442418488b3e488b7608488d1500000000488d4c2410ff15000000004883c448c3')
    for p in (19, 38, 49):
        shape[p:p + 4] = data[p:p + 4]
    if data != shape:
        raise EvidenceError('unexpected display arm')
    formatter = relative(arm, data, 19, 4)
    piece = relative(arm, data, 38, 4)
    if formatter != FORMATTER:
        raise EvidenceError('unexpected formatter target')
    length = image.read(piece, 1)[0]
    prefix = image.read(piece + 1, length).decode('ascii')
    code = image.read(formatter, len(FORMAT_BYTES), True)
    if code != FORMAT_BYTES:
        raise EvidenceError('unexpected payload formatter')
    strings = []
    for p in (19, 33):
        address = relative(formatter, code, p + 3, 4)
        length = u32(code, p + 8)
        strings.append({'address': hex(address), 'text': image.read(address, length).decode('ascii')})
    # The first arm is nonzero; the second is zero.
    return {'dispatch': hex(dispatch_va), 'dispatch_bytes': dispatch.hex(),
            'table': hex(TABLE), 'table_entry': entry.hex(), 'tag': tag, 'arm': hex(arm), 'arm_bytes': data.hex(),
            'prefix_address': hex(piece), 'prefix': prefix, 'formatter': hex(formatter),
            'formatter_bytes': code.hex(), 'nonzero': strings[0], 'zero': strings[1]}




def modify_rejection_path(image, contexts):
    """Pin both failure-copy sequences and the common return in each copy."""
    templates = (
        bytes.fromhex('0f104424500f118424be0300000f104424120f104c24220f105424320f105c24420f299c24b00300000f299424a00300000f298c24900300000f298424800300000f104424600f1143500f108424be0300000f1143400f288424800300000f288c24900300000f289424a00300000f289c24b0030000'),
        bytes.fromhex('0f104424500f1184243e0200000f104424120f104c24220f105424320f105c24420f299c24300200000f299424200200000f298c24100200000f298424000200000f104424600f1143500f1084243e0200000f1143400f288424000200000f288c24100200000f289424200200000f289c2430020000'))
    tail_prefix = bytes.fromhex('0f115b320f1153220f114b120f114302668903e9')
    epilogue = bytes.fromhex('4889d84881c4280500005b415c415d415e415f5dc3')
    result = []
    for first in (0, 2):
        branches = [int(contexts[first + n]['failure_branch'], 16) for n in range(2)]
        blocks = [image.read(va, len(template), True) for va, template in zip(branches, templates)]
        if tuple(blocks) != templates:
            raise EvidenceError('unexpected modify rejection copy')
        short = image.read(branches[0] + len(templates[0]), 2, True)
        if short[0] != 0xeb:
            raise EvidenceError('unexpected modify rejection jump')
        tail = relative(branches[0] + len(templates[0]), short, 1, 1)
        if tail != branches[1] + len(templates[1]):
            raise EvidenceError('modify rejection paths do not join')
        common = image.read(tail, len(tail_prefix) + 4, True)
        if common[:len(tail_prefix)] != tail_prefix:
            raise EvidenceError('unexpected status copy tail')
        exit_va = relative(tail, common, len(tail_prefix), 4)
        if image.read(exit_va, len(epilogue), True) != epilogue:
            raise EvidenceError('unexpected modify return')
        result.append({'perp_failure': hex(branches[0]), 'perp_copy_bytes': blocks[0].hex(),
                       'perp_jump': short.hex(), 'spot_failure': hex(branches[1]),
                       'spot_copy_bytes': blocks[1].hex(), 'common_tail': hex(tail),
                       'common_tail_bytes': common.hex(), 'return': hex(exit_va),
                       'return_bytes': epilogue.hex()})
    return result


def context_fields(image):
    """Extract fields identified by the existing Context debug-writer packet."""
    result = []
    for name_at, length_at, offset_at in (
            (0x4c6985c, 0x4c69879, 0x4c6970a),
            (0x4c6989d, 0x4c698a4, 0x4c69712),
            (0x4c698e6, 0x4c698ed, 0x4c6971a)):
        name_code = image.read(name_at, 7, True)
        length_code = image.read(length_at, 5, True)
        offset_code = image.read(offset_at, 4, True)
        if name_code[:3] != bytes.fromhex('488d35') or length_code[0] != 0xba or offset_code[1] != 0x8d:
            raise EvidenceError('unexpected Context debug-writer window')
        address = relative(name_at, name_code, 3, 4)
        length = u32(length_code, 1)
        result.append({'name_site': hex(name_at), 'name_bytes': name_code.hex(),
                       'length_site': hex(length_at), 'length_bytes': length_code.hex(),
                       'offset_site': hex(offset_at), 'offset_bytes': offset_code.hex(),
                       'field': image.read(address, length).decode('ascii'),
                       'name_address': hex(address), 'offset': hex(offset_code[3])})
    return result


def analyse(data):
    authenticate(data)
    image = Image(data)
    _, fdes, _ = fde_extents(data)
    by_start = {row['start']: row for row in fdes}
    selected = []
    for va in (*GATES, FORMATTER):
        row = by_start.get(va)
        if row is None:
            raise EvidenceError('selected address has no FDE start')
        size = row['end'] - row['start']
        raw = image.read(va, size, True)
        if size != (len(FORMAT_BYTES) if va == FORMATTER else len(TEMPLATE)):
            raise EvidenceError('unexpected FDE length')
        selected.append({'start': hex(va), 'end_exclusive': hex(row['end']),
                         'fde': hex(row['fde']), 'file_offset': hex(image.offset(va, size, True)),
                         'bytes': raw.hex()})
    gates = []
    for row in selected[:2]:
        code = bytes.fromhex(row['bytes'])
        info = gate_info(code)
        info['start'] = row['start']
        gates.append(info)
    calls = [call_info(image, site) for site in CALLS]
    if len({row['status_tag'] for row in calls}) != 1:
        raise EvidenceError('caller status tags disagree')
    status = status_info(image, calls[0]['status_tag'])
    modify = [modify_context(image, site, target) for site, target in (
        (0x4d1c2ad, 0x4c18260), (0x4d1c499, 0x4c17b10),
        (0x4d1e0dd, 0x4c18b40), (0x4d1e2c9, 0x4c19420))]
    # This window binds stack predicate bytes to the first and tenth order bytes.
    start = 0x4c17b8f
    trace = image.read(start, 85, True)
    expected = bytes.fromhex('410f10060f298424e0000000f30f6f00f30f7f8424080100000fb64010888424180100000fb68424080100008844240e0fb68424e00000008844240c488b8424e100000048894424180fb68424e90000008844240b')
    if trace != expected:
        raise EvidenceError('unexpected order-byte trace')
    # Existing serializer evidence is used only as context, not a selected body.
    keys = []
    for addr, load_opcode in ((0x275b1fa, '4d8d86'), (0x275b222, '4d8b86')):
        code = image.read(addr, 30, True)
        if code[:3].hex() != load_opcode or code[7:10] != bytes.fromhex('488d15') or code[17] != 0xb9:
            raise EvidenceError('unexpected serializer context')
        field = u32(code, 3)
        string_addr = relative(addr, code, 10, 4)
        length = u32(code, 18)
        keys.append({'context': hex(addr), 'bytes': code.hex(), 'field': hex(field),
                     'key_address': hex(string_addr), 'key': image.read(string_addr, length).decode('ascii')})
    perp_parts = []
    for addr, expected_hex in (
            (0x4c18346, '410f10070f29842400010000'),
            (0x4c1839c, '0fb684240001000088442412'),
            (0x4c183b8, '0fb684240901000088442411')):
        expected_part = bytes.fromhex(expected_hex)
        actual = image.read(addr, len(expected_part), True)
        if actual != expected_part:
            raise EvidenceError('unexpected perp order-byte trace')
        perp_parts.append({'start': hex(addr), 'bytes': actual.hex()})
    return image, {'sha256': SHA256, 'coordinate_system': 'linked ELF virtual address',
                   'selected_fdes': selected, 'gates': gates, 'callers': calls, 'modify_context': modify,
                   'modify_rejection_paths': modify_rejection_path(image, modify),
                   'spot_order_byte_trace': {'start': hex(start), 'bytes': trace.hex()},
                   'perp_order_byte_trace': perp_parts, 'serializer_key_context': keys,
                   'previous_context_field_evidence': context_fields(image), 'status': status}


def write(out, summary, image):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    with (out / 'cases.tsv').open('w', encoding='utf-8', newline='') as handle:
        w = csv.writer(handle, delimiter='\t', lineterminator='\n')
        w.writerow(('gate', 'current_time_components', 'threshold_components', 'height', 'minimum_height', 'start_height', 'actual_al', 'expected_al', 'visited_offsets'))
        for row, info in zip(summary['selected_fdes'], summary['gates']):
            code = bytes.fromhex(row['bytes'])
            for current, threshold, height, minimum, start in vectors(info['window']):
                got, visited = evaluate(code, current, threshold, height, minimum, start)
                expected = specification(current, threshold, height, minimum, start, info['window'], info['free_code'])
                if got != expected:
                    raise EvidenceError('evaluator and specification disagree')
                w.writerow((row['start'], ','.join(map(str, current)), ','.join(map(str, threshold)), height,
                            minimum, start, got, expected, ','.join(hex(x) for x in visited)))


    with (out / 'admission.tsv').open('w', encoding='utf-8', newline='') as handle:
        w = csv.writer(handle, delimiter='\t', lineterminator='\n')
        w.writerow(('call', 'gate_al', 'order_byte_9', 'order_byte_0', 'result', 'status_tag', 'payload'))
        for site, gate_al, byte9, byte0 in itertools.product(CALLS, range(3), (0, 1, 2, 3, 255), (0, 1, 255)):
            tag, payload = evaluate_caller(image, site, gate_al, byte9, byte0)
            expected_success = gate_al == 2 or (byte9 == 2 and byte0 == 0)
            if (tag is None) != expected_success or (tag is not None and (tag != 0x74 or payload != gate_al)):
                raise EvidenceError('caller specification mismatch')
            w.writerow((hex(site), gate_al, byte9, byte0, 'continue' if tag is None else 'status',
                        '' if tag is None else hex(tag), '' if payload is None else payload))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    data = BINARY.read_bytes()
    image, summary = analyse(data)
    write(args.out, summary, image)


if __name__ == '__main__':
    try:
        main()
    except (EvidenceError, OSError, ValueError, struct.error) as exc:
        print('post_only_window: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)

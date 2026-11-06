#!/usr/bin/env python3
"""Regenerate the RE-005 node 115 rmp-signable serializer packet.

The serializer at 0x36aa9a0 is the only retained owner whose panic path
names l1/src/action/rmp_signable.rs (line 14, column 55). This tool pins
the exact payload write order it performs on its source record, the
variant rule that extends the payload, the tag rule that selects the
one-byte result string, and the constants of the result record it
returns, without executing the captured code.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-005-node115-rmp-signable-layout'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SERIALIZER = (0x36aa9a0, 0x36aade6)
CALLER_A = (0x36aadf0, 0x36aaf0e)
CALLER_B = (0x36aaf10, 0x36aaff6)
OWNERS = {'serializer': SERIALIZER, 'caller_a': CALLER_A, 'caller_b': CALLER_B}
WRITER_CTOR = 0x36b1600
GROW_HELPER = 0x43bd910
SOURCE_FILE = b'l1/src/action/rmp_signable.rs'
SOURCE_FILE_VA = 0x4470c4
LOC_VA = 0x6468c58
PANIC_MESSAGE = b'called `Result::unwrap()` on an `Err` value'
PANIC_MESSAGE_VA = 0x79dbe4
CALLER_B_MESSAGE_VA = 0x7c6275
CONTINUE_HEAD = 0x8000000000000004
TAG_EQUAL = 3
TAG_BYTE_BASE = 0x62
RESULT_MARK = 0x539


def read(data, va, n):
    for sec in sections(data):
        if sec['type'] != 8 and sec['address'] <= va and va + n <= sec['address'] + sec['size']:
            return data[sec['offset'] + va - sec['address']:sec['offset'] + va - sec['address'] + n]
    raise ValueError(f'unmapped read {va:#x}+{n}')


def relocations(data):
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    out = {}
    for off, info, add in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
        if info & 0xffffffff == 8:
            out[off] = add
    return out


def _pin(body, base, va, hexbytes, what):
    want = bytes.fromhex(hexbytes)
    if body[va - base:va - base + len(want)] != want:
        raise ValueError(f'byte pin failed for {what} at {va:#x}')


def _call_target(body, base, va, insn_len=5):
    disp = struct.unpack_from('<i', body, va - base + 1)[0]
    return va + insn_len + disp


def _rip_target(body, base, va, insn_len, disp_at):
    disp = struct.unpack_from('<i', body, va - base + disp_at)[0]
    return va + insn_len + disp


# (va, hex bytes, what) pins inside the serializer body. Together they fix
# the write order, the variant rule, the tag rule and the result record.
SERIALIZER_PINS = [
    (0x36aa9dc, 'c744242800040001', 'writer spec dword 0x01000400'),
    (0x36aa9fb, '48b80400000000000080', 'writer continuation head immediate'),
    (0x36aaa05, '4839842420010000', 'compare returned writer head'),
    (0x36aaa13, '4c8b742450', 'load helper-produced initial buffer length'),
    (0x36aaa26, '4d8b6710', 'load u64 field at source +0x10'),
    (0x36aaa3e, '490fcc', 'bswap of the +0x10 field'),
    (0x36aaa46, '4e892431', 'store of the big-endian +0x10 field'),
    (0x36aaa53, '41807f1801', 'compare byte at source +0x18 against 1'),
    (0x36aaa6d, '42c644310801', 'write payload byte 0x01 for a set flag'),
    (0x36aaaca, '42c644310800', 'write payload byte 0x00 for a clear flag'),
    (0x36aaa73, '4983c609', 'cursor advances to 9 after the flag byte'),
    (0x36aaa83, '4883f813', 'capacity check for the 20-byte copy'),
    (0x36aaa8d, '498d4719', 'address of the 20-byte field at source +0x19'),
    (0x36aaa96, '8b5010', 'load of the last 4 of the 20 bytes'),
    (0x36aaa99, '4289543110', 'store of the last 4 of the 20 bytes'),
    (0x36aaa9e, '0f1000', 'load of the first 16 of the 20 bytes'),
    (0x36aaaa1, '420f110431', 'store of the first 16 of the 20 bytes'),
    (0x36aaaa6, '4983c614', 'cursor advances by 0x14'),
    (0x36aaaaf, '41833f01', 'compare variant dword at source +0x00 against 1'),
    (0x36aaab5, 'eb73', 'present-option variant miss skips extra suffix'),
    (0x36aaad0, '4983c609', 'absent-option cursor advances by 9'),
    (0x36aaad9, '41833f01', 'absent-option variant comparison against 1'),
    (0x36aaaf3, '42c6043000', 'variant tag byte 0x00'),
    (0x36aaaf8, '49ffc6', 'variant tag advances cursor by one'),
    (0x36aab00, '4d8b7f08', 'load u64 field at source +0x08'),
    (0x36aab15, '490fcf', 'bswap of the +0x08 field'),
    (0x36aab1d, '4e893c30', 'store of the big-endian +0x08 field'),
    (0x36aab21, '4983c608', 'variant u64 advances cursor by eight'),
    (0x36aab9c, '48c784241001000088000000', 'assembly record length mark 0x88'),
    (0x36aaba8, '66c78424180100000100', 'assembly record word mark 1'),
    (0x36aabd0, 'bae0000000', 'assembly consumes 0xe0 bytes'),
    (0x36aabe3, 'ba20000000', 'assembly consumes 0x20 bytes'),
    (0x36aac32, '4080fd03', 'compare tag argument against 3'),
    (0x36aac39, 'b262', 'tag byte base 0x62'),
    (0x36aac3b, '28ca', 'tag byte subtraction'),
    (0x36aac3d, '8810', 'store of the tag byte'),
    (0x36aac4e, '48c70301000000', 'result word at +0x00 is 1'),
    (0x36aac59, '48c7431001000000', 'result length at +0x10 is 1'),
    (0x36aac79, '48c7433839050000', 'result mark at +0x38 is 0x539'),
    (0x36aad6c, 'be2b000000', 'panic message length 0x2b'),
]
# These are deciding edges, not an instruction evaluator. Decode their
# condition and relative destination, then require the measured relation.
BRANCHES = {
    'writer_head': (0x36aaa0d, 'not_equal', 0x36aad04, 6),
    'optional_field': (0x36aaa58, 'not_equal', 0x36aaab7, 2),
    'variant_after_present_option': (0x36aaab3, 'equal', 0x36aaadf, 2),
    'variant_after_absent_option': (0x36aaadd, 'not_equal', 0x36aab2a, 2),
}
GROW_SITES = [
    (0x36aaca7, 0x36aac94, 8),
    (0x36aacd0, 0x36aacbd, 0x14),
    (0x36aacf5, 0x36aace2, 8),
]
CALLER_PINS = [
    ('caller_a', 0x36aae8f, '66b87e00', 'caller_a first result word 0x007e'),
    ('caller_a', 0x36aaed0, '66b8a201', 'caller_a second result word 0x01a2'),
    ('caller_b', 0x36aafb4, 'be2b000000', 'caller_b panic message length 0x2b'),
]


def tag_byte(tag):
    """Tag policy on the admitted u8 domain used by the measured callers."""
    return TAG_BYTE_BASE - (1 if tag == TAG_EQUAL else 0)


def branch_facts(body, base):
    facts = {}
    for name, (va, expected_condition, expected_target, expected_size) in BRANCHES.items():
        at = va - base
        opcode = body[at]
        if opcode in (0x74, 0x75):
            size, code = 2, opcode
            displacement = struct.unpack_from('<b', body, at + 1)[0]
        elif body[at:at + 2] in (b'\x0f\x84', b'\x0f\x85'):
            size, code = 6, body[at + 1] - 0x10
            displacement = struct.unpack_from('<i', body, at + 2)[0]
        else:
            raise ValueError(f'branch encoding changed for {name} at {va:#x}')
        condition = 'equal' if code == 0x74 else 'not_equal'
        target = va + size + displacement
        if (condition, target, size) != (expected_condition, expected_target, expected_size):
            raise ValueError(f'branch relation changed for {name} at {va:#x}')
        facts[name] = {'site': hex(va), 'condition': condition,
                       'target': hex(target), 'fallthrough': hex(va + size),
                       'bytes_hex': body[at:at + size].hex()}
    return facts


def write_order():
    return [
        {'step': 1, 'source_offset': '0x10', 'width': 8,
         'rule': 'u64 stored big-endian (bswap before the store)',
         'evidence': ['0x36aaa26', '0x36aaa3e', '0x36aaa46']},
        {'step': 2, 'source_offset': '0x18', 'width': 1,
         'rule': 'payload byte 0x01 iff the stored byte equals 1, else 0x00',
         'evidence': ['0x36aaa53', '0x36aaa6d', '0x36aaaca']},
        {'step': 3, 'source_offset': '0x19', 'width': 20,
         'rule': '20 bytes copied verbatim only when the byte at source +0x18 equals 1',
         'condition': {'source_offset': '0x18', 'width': 1, 'equals': 1},
         'evidence': ['0x36aaa53', '0x36aaa58', '0x36aaa8d', '0x36aaa96',
                      '0x36aaa99', '0x36aaa9e', '0x36aaaa1', '0x36aaaa6']},
        {'step': 4, 'source_offset': None, 'width': 1,
         'rule': 'single 0x00 byte, only when the dword at source +0x00 equals 1',
         'evidence': ['0x36aaaaf', '0x36aaab3', '0x36aaad9', '0x36aaadd', '0x36aaaf3']},
        {'step': 5, 'source_offset': '0x08', 'width': 8,
         'rule': 'u64 stored big-endian, only when the dword at source +0x00 equals 1',
         'evidence': ['0x36aaaaf', '0x36aaab3', '0x36aaad9', '0x36aaadd',
                      '0x36aab00', '0x36aab15', '0x36aab1d']},
    ]


def analyze(data):
    if len(data) != TARGET_SIZE:
        raise ValueError('expected pinned node115')
    _summary, extents, _records = fde_extents(data)
    by_start = {e['start']: e for e in extents}
    owners = {}
    text_sec = next(s for s in sections(data) if s['name'] == '.text')
    for role, (start, end) in OWNERS.items():
        ext = by_start.get(start)
        if ext is None or ext['end'] != end:
            raise ValueError(f'FDE extent mismatch for {role}')
        body = read(data, start, end - start)
        owners[role] = {'role': role, 'start': hex(start), 'end': hex(end),
                        'file_offset': hex(text_sec['offset'] + start - text_sec['address']),
                        'bytes': end - start, 'sha256': hashlib.sha256(body).hexdigest(), 'frames': {}}
    body = read(data, SERIALIZER[0], SERIALIZER[1] - SERIALIZER[0])
    base = SERIALIZER[0]
    for va, hexbytes, what in SERIALIZER_PINS:
        _pin(body, base, va, hexbytes, what)
    branches = branch_facts(body, base)
    if _call_target(body, base, 0x36aa9f6) != WRITER_CTOR:
        raise ValueError('writer constructor call target mismatch')
    for site, size_va, size in GROW_SITES:
        _pin(body, base, size_va, 'ba' + struct.pack('<I', size).hex(), f'grow size {size}')
        if _call_target(body, base, site) != GROW_HELPER:
            raise ValueError('grow helper call target mismatch')
    bodies = {role: read(data, rng[0], rng[1] - rng[0]) for role, rng in OWNERS.items()}
    for role, va, hexbytes, what in CALLER_PINS:
        _pin(bodies[role], OWNERS[role][0], va, hexbytes, what)
    callers = direct_callers(data)
    if [c['site'] for c in callers] != ['0x36aae0d', '0x36aaf2a']:
        raise ValueError('direct caller census mismatch')
    loc = unwrap_site(data)
    if read(data, PANIC_MESSAGE_VA, len(PANIC_MESSAGE)) != PANIC_MESSAGE:
        raise ValueError('serializer panic message mismatch')
    if read(data, CALLER_B_MESSAGE_VA, len(PANIC_MESSAGE)) != PANIC_MESSAGE:
        raise ValueError('caller_b panic message mismatch')
    steps = write_order()
    # Cursor increments are read from the authenticated, pinned instructions.
    # The conditional branches above establish which increments are reached.
    base_suffix = body[0x36aaad0 - base + 3]
    optional_width = body[0x36aaaa6 - base + 3]
    variant_width = 1 + body[0x36aab21 - base + 3]
    continuation_head = struct.unpack_from('<Q', body, 0x36aa9fb - base + 2)[0]
    return {'target_sha256': TARGET_SHA256, 'owners': [owners[r] for r in ('serializer', 'caller_a', 'caller_b')],
            'write_order': steps,
            'branches': branches,
            'suffix_bytes': {
                'scope': 'bytes appended after an unresolved helper-produced prefix',
                'option_byte_one': {'variant_other': base_suffix + optional_width,
                                    'variant_one': base_suffix + optional_width + variant_width},
                'option_byte_other': {'variant_other': base_suffix,
                                      'variant_one': base_suffix + variant_width},
                'variant_delta': variant_width},
            'tag_byte': {'argument': 'third argument (edx)', 'compared_against': TAG_EQUAL,
                         'byte_if_equal': hex(tag_byte(TAG_EQUAL)), 'byte_otherwise': hex(tag_byte(TAG_EQUAL + 1)),
                         'allocation_bytes': 1},
            'result_record': {'word_at_0x00': 1, 'string_pointer_at_0x08': 'fresh 1-byte allocation',
                              'string_length_at_0x10': 1, 'bytes_at_0x18': '32 bytes assembled from the '
                              '0xe0-byte record and the 0x20-byte record', 'mark_at_0x38': hex(RESULT_MARK),
                              'zero_at_0x40_to_0x58': True},
            'writer': {'constructor': hex(WRITER_CTOR), 'spec_dword': '0x01000400',
                       'continue_head': hex(continuation_head),
                       'continue_if': 'returned first qword equals continue_head',
                       'otherwise': 'conditional buffer release, then diagnostic call and UD2',
                       'initial_prefix_length': 'loaded from helper-updated [rsp+0x50] at 0x36aaa13; not established zero',
                       'grow_helper': hex(GROW_HELPER),
                       'grow_sizes': [8, 20, 8]},
            'unwrap_site': loc,
            'direct_callers': callers,
            'captured_code_executed': False,
            'limits': ('Static byte pins and one FDE extent census only. The packet names the '
                       'serializer by its own panic location inside l1/src/action/rmp_signable.rs; '
                       'it does not name the action type the source record encodes, does not claim '
                       'the 32 result bytes are any particular hash, does not recover the '
                       'helper-produced prefix or its length, does not close allocation, '
                       'growth, diagnostic or unwind helpers, does not decode the '
                       '0x01000400 writer spec dword, and does not follow the two callers\' own '
                       'callers. The tag argument is forwarded by both callers, so which tags '
                       'occur at runtime is a separate question. Suffix composition assumes '
                       'valid disjoint memory, stable source fields and normally returning '
                       'growth helpers preserving the live prefix, length and source record.')}


def unwrap_site(data):
    rel = relocations(data)
    if rel.get(LOC_VA) != SOURCE_FILE_VA:
        raise ValueError('location relocation mismatch')
    raw = read(data, LOC_VA, 24)
    _ptr, length, line, col = struct.unpack('<QQII', raw)
    if length != len(SOURCE_FILE) or read(data, SOURCE_FILE_VA, length) != SOURCE_FILE:
        raise ValueError('location file string mismatch')
    if (line, col) != (14, 55):
        raise ValueError('location line/column mismatch')
    return {'file': SOURCE_FILE.decode(), 'line': line, 'column': col,
            'location_struct': hex(LOC_VA), 'message': PANIC_MESSAGE.decode(),
            'meaning': 'constructing the writer is unwrapped at this source site; a failed '
                       'construction reaches the panic path instead of returning an error'}


def direct_callers(data):
    text = next(s for s in sections(data) if s['name'] == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    _summary, extents, _records = fde_extents(data)
    starts = sorted(e['start'] for e in extents)
    ends = {e['start']: e['end'] for e in extents}
    import bisect
    sites = []
    idx = blob.find(b'\xe8')
    while idx != -1:
        site = base + idx
        if site + 5 + struct.unpack_from('<i', blob, idx + 1)[0] == SERIALIZER[0]:
            i = bisect.bisect_right(starts, site) - 1
            owner = starts[i] if i >= 0 and starts[i] <= site < ends[starts[i]] else None
            role = next((r for r, rng in OWNERS.items() if rng[0] == owner), None)
            sites.append({'site': hex(site), 'caller': role, 'caller_start': hex(owner) if owner else None})
        idx = blob.find(b'\xe8', idx + 1)
    return sites


def executable(path, args, marker=None):
    out = subprocess.run([path, *args], check=True, stdout=subprocess.PIPE).stdout.decode()
    if 'LLVM' in out or (marker is not None and marker not in out):
        raise ValueError(f'unexpected {path} output')
    return out


def generate(binary, output):
    data = Path(binary).read_bytes()
    if len(data) != TARGET_SIZE or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('expected pinned node115')
    result = analyze(data)
    readelf = executable('readelf', ['-wf', str(binary)], marker='FDE').splitlines()
    for owner in result['owners']:
        start, end = OWNERS[owner['role']]
        lines = [l for l in readelf if 'FDE' in l and f'pc={start:016x}..{end:016x}' in l]
        if len(lines) != 1:
            raise ValueError(f'expected one FDE line for {owner["role"]}')
        fde_line = lines[0]
        cie_ref = fde_line.split('cie=')[1].split()[0]
        cie_lines = [l for l in readelf if len(l.split()) > 3 and l.split()[0] == cie_ref and ' CIE' in l]
        if len(cie_lines) != 1:
            raise ValueError(f'expected one CIE line for {owner["role"]}')
        eh = next(s for s in sections(data) if s['name'] == '.eh_frame')
        def record(line):
            off, size = int(line.split()[0], 16), int(line.split()[1], 16)
            raw = data[eh['offset'] + off:eh['offset'] + off + size + 4]
            return {'va': hex(eh['address'] + off), 'bytes_hex': raw.hex()}
        owner['frames'] = {'fde': record(fde_line), 'cie': record(cie_lines[0])}
    # Native validation: every pinned address must be an instruction start.
    pin_vas = {va for va, _h, _w in SERIALIZER_PINS}
    pin_vas |= {va for va, _condition, _target, _size in BRANCHES.values()}
    pin_vas |= {0x36aa9f6} | {s for s, _v, _z in GROW_SITES}
    pin_vas |= {va for _r, va, _h, _w in CALLER_PINS} | {0x36aae0d, 0x36aaf2a}
    for role, (start, end) in OWNERS.items():
        export = executable('objdump', ['-d', '-M', 'intel', f'--start-address={start:#x}',
                                        f'--stop-address={end:#x}', str(binary)], marker='Disassembly of section')
        starts = set(decode_export(export, start, end, read(data, start, end - start)))
        missing = {hex(v) for v in pin_vas if start <= v < end and v not in starts}
        if missing:
            raise ValueError(f'pinned addresses are not instruction starts in {role}: {missing}')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    frames = []
    for owner in result['owners']:
        start, end = OWNERS[owner['role']]
        frames += [l for l in readelf if 'FDE' in l and f'pc={start:016x}..{end:016x}' in l]
    (output / 'frames.txt').write_text('\n'.join(frames) + '\n')
    for role, (start, end) in OWNERS.items():
        dump = executable('objdump', ['-d', '-M', 'intel', '--insn-width=16', f'--start-address={start:#x}',
                                      f'--stop-address={end:#x}', str(binary)], marker='Disassembly of section')
        (output / f'{role}.objdump.txt').write_text(dump.replace(str(binary), '<authenticated-node115>'))
    (output / 'records.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', default=str(TARGET))
    ap.add_argument('--output', default=str(PACKET))
    a = ap.parse_args()
    generate(a.binary, a.output)


if __name__ == '__main__':
    main()

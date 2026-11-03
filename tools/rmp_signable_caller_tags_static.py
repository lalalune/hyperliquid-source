#!/usr/bin/env python3
"""Regenerate the RE-005 node 115 rmp-signable caller-tag packet.

The rmp-signable serializer at 0x36aa9a0 (packet
RE-005-node115-rmp-signable-layout) takes its tag as its third argument
(edx) and emits result byte 0x61 when the tag equals 3, 0x62 otherwise.
Its only two direct callers forward their own third argument unchanged.
This tool pins who calls those two callers and how the tag argument is
produced at every reaching path of those call sites, without executing
the captured code.
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
PACKET = ROOT / 'research/work-items/RE-005-node115-rmp-signable-caller-tags'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SERIALIZER = (0x36aa9a0, 0x36aade6)
CALLER_A = (0x36aadf0, 0x36aaf0e)
CALLER_B = (0x36aaf10, 0x36aaff6)
GRAND_A = (0x36c2050, 0x36c2f99)
GRAND_B = (0x36c5350, 0x36c5676)
OWNERS = {'serializer': SERIALIZER, 'caller_a': CALLER_A, 'caller_b': CALLER_B,
          'grand_a': GRAND_A, 'grand_b': GRAND_B}
TAG_EQUAL = 3
TAG_BYTE_BASE = 0x62
DISC_BASE = 0x86
DEFAULT_INDEX = 0x14
TABLE_ENTRIES = 92
GRANDS = {
    'grand_a': {'range': GRAND_A, 'caller': 'caller_a', 'table': 0x79a9f0, 'lea': 0x36c2075,
                'pad': 0x36c2085, 'call_site': 0x36c208b, 'fallback': 0x36c2931,
                'success': 0x36c2923, 'gate': 0x36c28a6, 'post_call': 0x36c2090,
                'pad_entries': 70},
    'grand_b': {'range': GRAND_B, 'caller': 'caller_b', 'table': 0x79b290, 'lea': 0x36c5372,
                'pad': 0x36c5382, 'call_site': 0x36c5388, 'fallback': 0x36c5663,
                'success': 0x36c562c, 'gate': None, 'post_call': 0x36c538d,
                'pad_entries': 71},
}
ARM_COUNT = 21
# mov r14,rsi / add rsi,0x8 / movzx ebp,dl  (tag capture at each arm head)
ARM_HEAD = bytes.fromhex('4989f64883c6080fb6ea')
# mov rdi,rsp / mov edx,ebp / mov r12,rcx / mov r15,r8 / call QWORD PTR [rip+..]
ARM_TAIL = bytes.fromhex('4889e789ea4989cc4d89c7ff15')
CALLER_PREFIX = {
    'caller_a': '41574156534881ecf00000004d89c64889fb4c8dbc24980000004c89ff',
    'caller_b': '41574156534881eca00000004c89c34989fe4c8d7c24484c89ff',
}
GRAND_HEAD = {
    'grand_a': ('55415741564154534881ec10030000488b06482d86000000'
                '41b9140000004c0f43c84889fb488d0574890dfd4a633c884801c7ffe7'),
    'grand_b': ('55415741564154534883ec50488b06482d86000000'
                '41b9140000004c0f43c84889fb488d05175f0dfd4a633c884801c7ffe7'),
}
SERIALIZER_TAG_PINS = [
    (0x36aac32, '4080fd03', 'compare tag argument against 3'),
    (0x36aac39, 'b262', 'tag byte base 0x62'),
    (0x36aac3b, '28ca', 'tag byte subtraction'),
    (0x36aac3d, '8810', 'store of the tag byte'),
]
GRAND_A_GATE = ('488b4110483b86980000000f84cef7ffff66c7036000'
                'c6430200e9cbf7ffff')
GRAND_A_INSPECTION = ('0fb70c240fb64424020f104424030f298424700100008b542413'
                      '8994248001000081f9a20100000f856e0600003c01'
                      '0f859f0000008b8424800100008943120f28842470010000eb7d')
GRAND_A_SUCCESS = '0f11430266c703a201e95ff7ffff'
GRAND_A_LAST_TAIL = '8b8424e00200008943120f288424d0020000'
GRAND_B_INSPECTION = ('803c24007431488b442448488943400f104424080f104c2418'
                      '0f105424280f105c24380f115b300f1153200f114b10'
                      '0f1103e92afdffff4889df4c89f689ea4c89e14d89f8'
                      'e912fdffff')
FALLBACK = {
    'grand_a': '4889df4c89f689ea4c89e14d89f8e947f7ffff',
    'grand_b': '4889df4c89f689ea4c89e14d89f8e912fdffff',
}


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


def _branch_target(body, base, va, insn_len, disp_at):
    disp = struct.unpack_from('<i', body, va - base + disp_at)[0]
    return va + insn_len + disp


def _branch_target8(body, base, va):
    disp = struct.unpack_from('<b', body, va - base + 1)[0]
    return va + 2 + disp


def tag_byte(tag):
    return TAG_BYTE_BASE - (1 if tag == TAG_EQUAL else 0)


def arm_heads(body, base):
    """Sites of the 27-byte arm-head template: the incoming tag byte is
    captured into ebp (movzx ebp,dl) before the per-variant helper call."""
    sites = []
    idx = body.find(ARM_HEAD)
    while idx != -1:
        tail = body[idx + len(ARM_HEAD):idx + len(ARM_HEAD) + len(ARM_TAIL)]
        if tail != ARM_TAIL:
            raise ValueError(f'arm head template mismatch at {base + idx:#x}')
        sites.append(base + idx)
        idx = body.find(ARM_HEAD, idx + 1)
    return sites


def branch_sites(body, base, opcode, insn_len, disp_at, target):
    sites = []
    idx = body.find(opcode)
    while idx != -1:
        va = base + idx
        if _branch_target(body, base, va, insn_len, disp_at) == target:
            sites.append(va)
        idx = body.find(opcode, idx + 1)
    return sites


def jmp_sites(body, base, target):
    """All unconditional-jump sites reaching target, in both the rel32
    form (e9) and the rel8 form (eb) the compiler emitted."""
    sites = branch_sites(body, base, b'\xe9', 5, 1, target)
    idx = body.find(b'\xeb')
    while idx != -1:
        va = base + idx
        disp = struct.unpack_from('<b', body, idx + 1)[0]
        if va + 2 + disp == target:
            sites.append(va)
        idx = body.find(b'\xeb', idx + 1)
    return sorted(sites)


def jne_sites(body, base, target):
    """All conditional-jump (jne) sites reaching target, in both the
    rel32 form (0f 85) and the rel8 form (75) the compiler emitted."""
    sites = branch_sites(body, base, b'\x0f\x85', 6, 2, target)
    idx = body.find(b'\x75')
    while idx != -1:
        va = base + idx
        disp = struct.unpack_from('<b', body, idx + 1)[0]
        if va + 2 + disp == target:
            sites.append(va)
        idx = body.find(b'\x75', idx + 1)
    return sorted(sites)


def table_partition(data, grand, arms):
    """Read the dispatcher's jump table and partition its entries into
    the direct-call pad, the arm heads, and (grand_a) the equality gate."""
    table = grand['table']
    counts = {}
    arm_indices = []
    gate_index = None
    for i in range(TABLE_ENTRIES):
        off = struct.unpack('<i', read(data, table + 4 * i, 4))[0]
        target = table + off
        counts[target] = counts.get(target, 0) + 1
        if target in arms:
            arm_indices.append(i)
        elif grand['gate'] is not None and target == grand['gate']:
            gate_index = i
        elif target != grand['pad']:
            raise ValueError(f'jump table entry {i} targets unpinned block {target:#x}')
    if counts.get(grand['pad'], 0) != grand['pad_entries']:
        raise ValueError('jump table pad entry count mismatch')
    if len(arm_indices) != ARM_COUNT:
        raise ValueError('jump table arm entry count mismatch')
    if len(set(arm_indices)) != ARM_COUNT:
        raise ValueError('an arm head is targeted by more than one table entry')
    if struct.unpack('<i', read(data, table + 4 * DEFAULT_INDEX, 4))[0] + table != grand['pad']:
        raise ValueError('default table index does not select the direct pad')
    if grand['gate'] is not None and gate_index is None:
        raise ValueError('equality gate is not a jump table target')
    return {'entries': TABLE_ENTRIES, 'pad_entries': counts[grand['pad']],
            'arm_discriminants': [hex(DISC_BASE + i) for i in sorted(arm_indices)],
            'gate_discriminant': hex(DISC_BASE + gate_index) if gate_index is not None else None}


def call_census(data):
    """Every direct call/jump site in .text for the two callers and the
    serializer, with the containing FDE start for each site."""
    text = next(s for s in sections(data) if s['name'] == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    _summary, extents, _records = fde_extents(data)
    starts = sorted(e['start'] for e in extents)
    ends = {e['start']: e['end'] for e in extents}
    import bisect
    targets = {CALLER_A[0]: 'caller_a', CALLER_B[0]: 'caller_b', SERIALIZER[0]: 'serializer'}
    found = {role: [] for role in targets.values()}
    for opcode in (b'\xe8', b'\xe9'):
        idx = blob.find(opcode)
        while idx != -1:
            site = base + idx
            tgt = site + 5 + struct.unpack_from('<i', blob, idx + 1)[0]
            if tgt in targets:
                i = bisect.bisect_right(starts, site) - 1
                owner = starts[i] if i >= 0 and starts[i] <= site < ends[starts[i]] else None
                role = next((r for r, rng in OWNERS.items() if rng[0] == owner), None)
                found[targets[tgt]].append({'site': hex(site),
                                            'kind': 'call' if opcode == b'\xe8' else 'jump',
                                            'owner': role,
                                            'owner_start': hex(owner) if owner else None})
            idx = blob.find(opcode, idx + 1)
    return found


def analyze(data):
    if len(data) != TARGET_SIZE:
        raise ValueError('expected pinned node115')
    _summary, extents, _records = fde_extents(data)
    by_start = {e['start']: e for e in extents}
    text_sec = next(s for s in sections(data) if s['name'] == '.text')
    owners = {}
    bodies = {}
    for role, (start, end) in OWNERS.items():
        ext = by_start.get(start)
        if ext is None or ext['end'] != end:
            raise ValueError(f'FDE extent mismatch for {role}')
        body = read(data, start, end - start)
        bodies[role] = body
        owners[role] = {'role': role, 'start': hex(start), 'end': hex(end),
                        'file_offset': hex(text_sec['offset'] + start - text_sec['address']),
                        'bytes': end - start, 'sha256': hashlib.sha256(body).hexdigest(),
                        'frames': {}}
    # The sink rule, re-pinned inside the serializer body.
    for va, hexbytes, what in SERIALIZER_TAG_PINS:
        _pin(bodies['serializer'], SERIALIZER[0], va, hexbytes, what)
    # The two callers forward their argument registers untouched: the whole
    # prefix up to the serializer call is pinned, and it contains no write
    # to rsi, rdx or rcx; only rdi is replaced with the local result buffer.
    for role in ('caller_a', 'caller_b'):
        start = OWNERS[role][0]
        _pin(bodies[role], start, start, CALLER_PREFIX[role], f'{role} forwarding prefix')
        site = start + len(bytes.fromhex(CALLER_PREFIX[role]))
        if _call_target(bodies[role], start, site) != SERIALIZER[0]:
            raise ValueError(f'{role} call target mismatch')
    census = call_census(data)
    if [s['site'] for s in census['caller_a']] != ['0x36c208b'] or census['caller_a'][0]['kind'] != 'call':
        raise ValueError('caller_a call census mismatch')
    if [s['site'] for s in census['caller_b']] != ['0x36c5388'] or census['caller_b'][0]['kind'] != 'call':
        raise ValueError('caller_b call census mismatch')
    if [s['site'] for s in census['serializer']] != ['0x36aae0d', '0x36aaf2a']:
        raise ValueError('serializer call census mismatch')
    rel = relocations(data)
    if SERIALIZER[0] in rel.values() or CALLER_A[0] in rel.values() or CALLER_B[0] in rel.values():
        raise ValueError('unexpected relocation reference to the serializer chain')
    dispatchers = {}
    for role, grand in GRANDS.items():
        start, _end = grand['range']
        body = bodies[role]
        _pin(body, start, start, GRAND_HEAD[role], f'{role} dispatch head')
        if _branch_target(body, start, grand['lea'], 7, 3) != grand['table']:
            raise ValueError(f'{role} jump table base mismatch')
        pad = grand['pad']
        _pin(body, start, pad, '0fb6d2', f'{role} pad tag truncation')
        _pin(body, start, pad + 3, '4889df', f'{role} pad out pointer')
        if _call_target(body, start, grand['call_site']) != OWNERS[grand['caller']][0]:
            raise ValueError(f'{role} call target mismatch')
        _pin(body, start, grand['fallback'], FALLBACK[role], f'{role} fallback block')
        if _branch_target(body, start, grand['fallback'] + 14, 5, 1) != grand['call_site']:
            raise ValueError(f'{role} fallback does not jump to the call site')
        arms = arm_heads(body, start)
        if len(arms) != ARM_COUNT:
            raise ValueError(f'{role} arm head count mismatch')
        partition = table_partition(data, grand, set(arms))
        entry = {'table': hex(grand['table']), 'table_entries': partition['entries'],
                 'discriminant_base': hex(DISC_BASE), 'default_index': hex(DEFAULT_INDEX),
                 'direct_pad': {'site': hex(pad), 'call_site': hex(grand['call_site']),
                                'table_entries': partition['pad_entries'],
                                'tag': 'movzx edx,dl at the pad: the low byte of the '
                                       'dispatcher entry edx, upper bytes cleared'},
                 'arms': {'count': ARM_COUNT,
                          'discriminants': partition['arm_discriminants'],
                          'tag_capture': 'movzx ebp,dl at every arm head, before the '
                                         'per-variant helper call',
                          'fallback': hex(grand['fallback']),
                          'tag_at_fallback': 'mov edx,ebp in the fallback block, which '
                                             'jumps straight to the call site'},
                 'tag_rule': 'on every reaching path the tag handed to the caller is '
                             'the zero-extended low byte of the dispatcher entry edx'}
        if role == 'grand_a':
            _pin(body, start, grand['gate'], GRAND_A_GATE, 'grand_a equality gate')
            if _branch_target(body, start, grand['gate'] + 11, 6, 2) != grand['pad']:
                raise ValueError('grand_a gate does not jump to the pad')
            if _branch_target(body, start, grand['gate'] + 26, 5, 1) != grand['post_call']:
                raise ValueError('grand_a gate exit does not jump past the call')
            jne = jne_sites(body, start, grand['fallback'])
            if len(jne) != ARM_COUNT:
                raise ValueError('grand_a inspection fallback branch count mismatch')
            jmp = jmp_sites(body, start, grand['success'])
            if len(jmp) != ARM_COUNT - 1:
                raise ValueError('grand_a inspection success jump count mismatch')
            _pin(body, start, 0x36c285d, GRAND_A_INSPECTION, 'grand_a inspection instance')
            _pin(body, start, grand['success'], GRAND_A_SUCCESS, 'grand_a success block')
            _pin(body, start, 0x36c2911, GRAND_A_LAST_TAIL, 'grand_a last inspection tail')
            if body.count(bytes.fromhex('81f9a2010000')) != ARM_COUNT:
                raise ValueError('grand_a inspection compare count mismatch')
            if body.count(bytes.fromhex('8b542413')) != ARM_COUNT:
                raise ValueError('grand_a inspection field load count mismatch')
            entry['equality_gate'] = {
                'site': hex(grand['gate']), 'discriminant': partition['gate_discriminant'],
                'rule': 'entered from the table with the entry registers untouched; '
                        'when [rcx+0x10] equals [rsi+0x98] it jumps to the direct pad '
                        '(tag is again the entry low byte), otherwise it writes word '
                        '0x60 to the out record and returns without calling'}
            entry['inspection'] = ('each arm inspects the helper-produced record: word '
                                   '0x1a2 and byte 1 select the success block, which '
                                   'copies the record out and returns; any other byte '
                                   'reaches the fallback and calls the caller')
        else:
            jmp = jmp_sites(body, start, grand['success'])
            if len(jmp) != ARM_COUNT - 1:
                raise ValueError('grand_b arm jump count mismatch')
            if arms[-1] + 27 != grand['success']:
                raise ValueError('grand_b last arm does not fall through to the inspection block')
            _pin(body, start, grand['success'], GRAND_B_INSPECTION, 'grand_b inspection block')
            if _branch_target8(body, start, grand['success'] + 4) != grand['fallback']:
                raise ValueError('grand_b inspection does not branch to the fallback')
            if _branch_target(body, start, grand['success'] + 50, 5, 1) != grand['post_call']:
                raise ValueError('grand_b inspection exit does not jump past the call')
            entry['inspection'] = ('all arms converge on one inspection block: a zero '
                                   'first byte in the helper-produced record reaches the '
                                   'fallback and calls the caller; any other byte copies '
                                   'the record out and returns')
        dispatchers[role] = entry
    return {'target_sha256': TARGET_SHA256,
            'owners': [owners[r] for r in ('serializer', 'caller_a', 'caller_b', 'grand_a', 'grand_b')],
            'serializer_tag_rule': {'argument': 'third argument (edx)', 'compared_against': TAG_EQUAL,
                                    'byte_if_equal': hex(tag_byte(TAG_EQUAL)),
                                    'byte_otherwise': hex(tag_byte(TAG_EQUAL + 1))},
            'caller_forwarding': {
                'caller_a': {'call_site': '0x36aae0d', 'tag': 'its own third argument (edx), '
                             'forwarded unchanged; only rdi is replaced'},
                'caller_b': {'call_site': '0x36aaf2a', 'tag': 'its own third argument (edx), '
                             'forwarded unchanged; only rdi is replaced'}},
            'caller_call_sites': {'caller_a': census['caller_a'], 'caller_b': census['caller_b']},
            'dispatchers': dispatchers,
            'tag_provenance': ('both dispatchers pass the zero-extended low byte of their '
                               'own entry edx on every reaching path; no reaching path '
                               'materialises a constant tag or loads the tag from memory, '
                               'so the emitted tag byte is 0x61 exactly when the '
                               'dispatcher entry edx has low byte 3, and 0x62 otherwise'),
            'captured_code_executed': False,
            'limits': ('Static byte pins, one FDE extent census, one .text call census and '
                       'the two jump tables only. The table length (92 entries) is bounded '
                       'by the next referenced table base in .rodata (0x170 bytes later for '
                       'both dispatchers in this family); no stored length field exists. '
                       'Discriminants above the table span are not claimed: the dispatch '
                       'head applies no upper bound check. The packet does not name the '
                       'enum or action types the discriminants denote, does not trace the '
                       'per-variant helper calls the arms make through their relocation '
                       'slots, and does not follow the dispatchers own callers: grand_a has '
                       'exactly one direct call site (0x37133b3) and grand_b none in .text, '
                       'so which entry edx values occur at runtime remains open one level up.')}


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
    # Native validation: every pinned or structural address must be an
    # instruction start in its owner's decoded extent.
    pin_vas = {va for va, _h, _w in SERIALIZER_TAG_PINS}
    for role, (start, end) in OWNERS.items():
        export = executable('objdump', ['-d', '-M', 'intel', f'--start-address={start:#x}',
                                        f'--stop-address={end:#x}', str(binary)],
                            marker='Disassembly of section')
        starts = set(decode_export(export, start, end, read(data, start, end - start)))
        missing = {hex(v) for v in pin_vas if start <= v < end and v not in starts}
        if missing:
            raise ValueError(f'pinned addresses are not instruction starts in {role}: {missing}')
    for role, grand in GRANDS.items():
        start, end = grand['range']
        export = executable('objdump', ['-d', '-M', 'intel', f'--start-address={start:#x}',
                                        f'--stop-address={end:#x}', str(binary)],
                            marker='Disassembly of section')
        starts = set(decode_export(export, start, end, read(data, start, end - start)))
        body = read(data, start, end - start)
        structural = {grand['pad'], grand['call_site'], grand['fallback']} | set(arm_heads(body, start))
        structural |= set(jmp_sites(body, start, grand['success']))
        structural |= set(jne_sites(body, start, grand['fallback']))
        if grand['gate'] is not None:
            structural.add(grand['gate'])
        for i in range(TABLE_ENTRIES):
            off = struct.unpack('<i', read(data, grand['table'] + 4 * i, 4))[0]
            structural.add(grand['table'] + off)
        missing = {hex(v) for v in structural if v not in starts}
        if missing:
            raise ValueError(f'table or structural targets are not instruction starts in {role}: {missing}')
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

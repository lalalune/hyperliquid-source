#!/usr/bin/env python3
"""Bind the node #115 twenty-byte sequence equality leaf; static, stdlib only.

The deliberately finite x86-64 decoder accepts only the encodings used in the
bound leaf and the selected caller slices. It is not a general disassembler.
New code is independently authored under the repository MIT license.
"""
import argparse
from bisect import bisect_right
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET_REL = 'research/work-items/RE-001-node115-slice20-equal'
PACKET = ROOT / PACKET_REL
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
START, END = 0x5436860, 0x54368b6
BODY_SHA = 'a1578fc383b85292cf51fb5c366c98373cbe1a98b10b0c8bdfbd3fe8e19556e5'
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
CALLER_START, CALLER_END = 0x5378220, 0x537aa59
CALL_SITES = (0x53791b1, 0x53791d0)
SOURCE_SITE, LOCATION = 0x53788f2, 0x64a7f08
SOURCE_PATH = b'l1/src/raw_signature_tracker.rs'
U64 = (1 << 64) - 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def encoded_json(record):
    return (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8')


# Fixed register/ModRM forms: exact encodings, no ignored prefixes or operands.
FIXED = {
    '4839ce': ('cmp', ['rsi', 'rcx']),
    '4885f6': ('test', ['rsi', 'rsi']),
    '48ffce': ('dec', ['rsi']),
    '0f1f00': ('nop', ['dword [rax]']),
    '0f1f440000': ('nop', ['dword [rax+rax]']),
    'f30f6f07': ('movdqu', ['xmm0', 'xmmword [rdi]']),
    'f30f6f0a': ('movdqu', ['xmm1', 'xmmword [rdx]']),
    '660f74c8': ('pcmpeqb', ['xmm1', 'xmm0']),
    '660f74d0': ('pcmpeqb', ['xmm2', 'xmm0']),
    '660fdbd1': ('pand', ['xmm2', 'xmm1']),
    '660fd7c2': ('pmovmskb', ['eax', 'xmm2']),
    '0f92c1': ('setb', ['cl']),
    '0f94c0': ('sete', ['al']),
    '84c9': ('test', ['cl', 'cl']),
    '84c0': ('test', ['al', 'al']),
    '31c0': ('xor', ['eax', 'eax']),
    'c3': ('ret', []),
}
FIXED = [(bytes.fromhex(k), op, args) for k, (op, args) in FIXED.items()]


def decode(code, start):
    """Decode all bytes, rejecting unknown encodings and truncated operands."""
    rows, pos = [], 0
    while pos < len(code):
        at = pos

        def take(n):
            require(at + n <= len(code), 'truncated instruction')
            return code[at:at + n]

        row = {'address': start + at}
        if code[pos] in (0x74, 0x75):
            raw = take(2)
            row.update(mnemonic={0x74: 'je', 0x75: 'jne'}[raw[0]], operands=[],
                       target=start + at + 2 + struct.unpack('<b', raw[1:])[0])
        elif code[pos:pos + 2] in (b'\x0f\x84', b'\x0f\x85'):
            raw = take(6)
            row.update(mnemonic='je' if raw[1] == 0x84 else 'jne', operands=[],
                       target=start + at + 6 + struct.unpack('<i', raw[2:])[0])
        elif code[pos] in (0xe8, 0xe9):
            raw = take(5)
            row.update(mnemonic='call' if raw[0] == 0xe8 else 'jmp', operands=[],
                       target=start + at + 5 + struct.unpack('<i', raw[1:])[0])
        elif code[pos:pos + 3] == b'\x48\x8d\x35':
            raw = take(7)
            row.update(mnemonic='lea', operands=['rsi', 'rip-relative'],
                       target=start + at + 7 + struct.unpack('<i', raw[3:])[0])
        elif code[pos] == 0x3d:
            raw = take(5)
            row.update(mnemonic='cmp', operands=['eax'], immediate=struct.unpack('<I', raw[1:])[0])
        elif code[pos] == 0xb0:
            raw = take(2)
            row.update(mnemonic='mov', operands=['al'], immediate=raw[1])
        elif code[pos:pos + 3] in (b'\x48\x83\xc6', b'\x48\x83\xc2', b'\x48\x83\xc7'):
            raw = take(4)
            row.update(mnemonic='add', operands=[{0xc6: 'rsi', 0xc2: 'rdx', 0xc7: 'rdi'}[raw[2]]],
                       immediate=struct.unpack('<b', raw[3:])[0])
        elif code[pos:pos + 4] in (b'\x66\x0f\x6e\x47', b'\x66\x0f\x6e\x52'):
            raw = take(5)
            dst, base = ('xmm0', 'rdi') if raw[3] == 0x47 else ('xmm2', 'rdx')
            row.update(mnemonic='movd', operands=[dst, 'dword memory'], base=base,
                       displacement=struct.unpack('<b', raw[4:])[0])
        elif code[pos:pos + 3] in (b'\x49\x8b\x7d', b'\x49\x8b\x75'):
            raw = take(4)
            row.update(mnemonic='mov', operands=['rdi' if raw[2] == 0x7d else 'rsi', 'qword memory'],
                       base='r13', displacement=struct.unpack('<b', raw[3:])[0])
        elif code[pos:pos + 4] in (b'\x48\x8b\x54\x24', b'\x48\x8b\x4c\x24'):
            raw = take(5)
            row.update(mnemonic='mov', operands=['rdx' if raw[2] == 0x54 else 'rcx', 'qword memory'],
                       base='rsp', displacement=struct.unpack('<b', raw[4:])[0])
        else:
            match = next(((raw, op, args) for raw, op, args in FIXED if code.startswith(raw, pos)), None)
            require(match is not None, f'unsupported instruction at {start + at:#x}')
            raw, op, args = match
            row.update(mnemonic=op, operands=args)
        row.update(size=len(raw), bytes_hex=raw.hex())
        rows.append(row)
        pos += len(raw)
    return rows


def leaf(code):
    rows = decode(code, START)
    # Hash follows decoding, so lower-level controls exercise the strict grammar.
    require(len(code) == END - START and hashlib.sha256(code).hexdigest() == BODY_SHA,
            'leaf body changed')
    starts = {r['address'] for r in rows}
    require(all(r.get('target', START) in starts for r in rows), 'leaf branch leaves instruction boundaries')
    require(not any(r['mnemonic'] in ('call', 'jmp') for r in rows), 'unexpected leaf callee')
    p = {r['address']: r for r in rows}
    rule = {
        'left_pointer_register': 'rdi', 'left_count_register': 'rsi',
        'right_pointer_register': 'rdx', 'right_count_register': 'rcx',
        'return_register': 'al', 'count_bits': 64,
        'head_bytes': 16, 'tail_bytes': 4,
        'tail_offset': p[0x543687c]['displacement'],
        'left_stride': p[0x54368a7]['immediate'],
        'right_stride': p[0x54368a3]['immediate'],
        'mask': p[0x5436899]['immediate'],
        'counter_step': p[0x5436892]['immediate'],
        'true_byte': p[0x54368b3]['immediate'],
        'length_mismatch_target': p[0x5436863]['target'],
        'empty_target': p[0x5436868]['target'],
        'record_mismatch_target': p[0x54368a1]['target'],
        'loop_target': p[0x54368ad]['target'],
        'description': 'AL = 1 iff counts agree and every corresponding byte of every 20-byte record agrees; otherwise AL = 0.',
    }
    require(rule['left_stride'] == rule['right_stride'] == 20 and rule['tail_offset'] == 16
            and rule['mask'] == 0xffff and rule['counter_step'] == -1 and rule['true_byte'] == 1,
            'equality parameters changed')
    return rows, rule


def control_flow(rows):
    """Derive the complete leaf CFG from the decoded instruction boundaries."""
    edges = {}
    for row in rows:
        after = row['address'] + row['size']
        edges[row['address']] = ([] if row['mnemonic'] == 'ret' else
                                 [after, row['target']] if row['mnemonic'] in ('je', 'jne') else [after])
    require(all(target in edges for targets in edges.values() for target in targets),
            'control flow leaves the leaf')
    visited, pending = set(), [START]
    while pending:
        site = pending.pop()
        if site not in visited:
            visited.add(site)
            pending.extend(edges[site])
    require(visited == edges.keys(), 'unreachable decoded leaf instruction')
    return [{'address': site, 'successors': targets} for site, targets in edges.items()]


def sequence_equal(left, right):
    """Independent scalar specification; arguments are sequences of 20-byte rows."""
    require(all(len(row) == 20 for row in (*left, *right)), 'expected 20-byte records')
    return int(len(left) == len(right) and all(a == b for a, b in zip(left, right)))


def lane_mask(left, right):
    """Algebraic SSE2 lane relation, not a target CPU/interpreter execution."""
    require(len(left) == len(right) == 20, 'expected 20-byte records')
    # MOVD clears the upper 96 bits: the upper twelve tail-comparison lanes
    # therefore compare zero with zero and contribute all-one bytes.
    return sum((int(left[i] == right[i]) & (int(left[16+i] == right[16+i]) if i < 4 else 1)) << i
               for i in range(16))


def loop_carry(count_before_add):
    require(type(count_before_add) is int and 0 <= count_before_add <= U64, 'expected u64 count')
    return count_before_add != 0  # unsigned ADD by UINT64_MAX carries iff old value is nonzero


def instruction_relation(left, right):
    require(all(len(row) == 20 for row in (*left, *right)), 'expected 20-byte records')
    if len(left) != len(right):
        return 0
    if not left:
        return 1
    remaining = len(left) - 1  # DEC before the first record
    for a, b in zip(left, right):
        mask = lane_mask(a, b)
        carry = loop_carry(remaining)
        remaining = (remaining - 1) & U64
        if mask != 0xffff:
            return 0
        if not carry:
            return 1
    raise AssertionError('loop exhausted without the final no-carry exit')


def vectors():
    rows = []

    def add(name, left, right, want):
        require(sequence_equal(left, right) == instruction_relation(left, right) == want,
                'instruction-derived vector disagrees with scalar specification')
        rows.append({'name': name, 'left': [b.hex() for b in left],
                     'right': [b.hex() for b in right], 'al': want})

    block = bytes(range(20))
    add('empty', [], [], 1)
    add('unequal-count-left-empty', [], [block], 0)
    add('unequal-count-right-empty', [block], [], 0)
    add('unequal-count-common-prefix', [block], [block, block], 0)
    for count in (1, 2, 3):
        add(f'equal-{count}-records', [block] * count, [block] * count, 1)
    add('all-zero', [bytes(20)], [bytes(20)], 1)
    add('all-one-bits', [b'\xff' * 20], [b'\xff' * 20], 1)
    for record in range(3):
        for offset in range(20):
            right = [block] * 3
            changed = bytearray(block)
            changed[offset] ^= 0x80
            right[record] = bytes(changed)
            add(f'mismatch-record-{record}-byte-{offset}', [block] * 3, right, 0)
    return rows


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def read(self, address, size):
        ss = [s for s in self.sections if s['type'] != 8 and s['address'] <= address
              and address + size <= s['address'] + s['size']]
        require(len(ss) == 1 and size > 0, 'ambiguous or invalid VA mapping')
        s = ss[0]
        offset = s['offset'] + address - s['address']
        return offset, self.data[offset:offset + size]

    def region(self, start, end):
        offset, raw = self.read(start, end - start)
        return {'start': start, 'end': end, 'size': end - start, 'file_offset': offset,
                'sha256': hashlib.sha256(raw).hexdigest(), 'bytes_hex': raw.hex()}

    def frame(self, row):
        result = dict(row)
        for kind in ('fde', 'cie'):
            address = row[kind]
            _, size_bytes = self.read(address, 4)
            size = 4 + struct.unpack('<I', size_bytes)[0]
            result[kind + '_record'] = self.region(address, address + size)
        return result


def caller_census(image, frames):
    """Inspect every .text byte eligible to begin E8/E9 rel32, including unaligned bytes.

    This deliberately over-approximates direct callers; hits are independently
    bound to selected decoded caller slices by inspect(). Indirect calls and
    data references are not included in this denominator.
    """
    text = [s for s in image.sections if s['name'] == '.text']
    require(len(text) == 1, 'ambiguous .text')
    text = text[0]
    require(text['address'] == TEXT_START and text['address'] + text['size'] == TEXT_END
            and text['flags'] == 6 and text['type'] == 1, 'target .text geometry changed')
    ordered = sorted(frames, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]
    hits, examined = [], {}
    begin, end = text['offset'], text['offset'] + text['size']
    for opcode in (0xe8, 0xe9):
        pos, count = begin, 0
        while True:
            pos = image.data.find(bytes([opcode]), pos, end - 4)
            if pos < 0:
                break
            count += 1
            site = text['address'] + pos - begin
            target = site + 5 + struct.unpack_from('<i', image.data, pos + 1)[0]
            if target == START:
                index = bisect_right(starts, site) - 1
                owner = ordered[index] if index >= 0 else None
                require(owner is not None and site + 5 <= owner['end'], 'caller hit has no FDE owner')
                hits.append({'site': site, 'target': target, 'opcode': hex(opcode),
                             'bytes_hex': image.data[pos:pos + 5].hex(),
                             'owner_start': owner['start'], 'owner_end': owner['end']})
            pos += 1
        examined[hex(opcode)] = count
    return {'text_start': TEXT_START, 'text_end': TEXT_END, 'text_size': text['size'],
            'scan': 'every byte position with five bytes remaining; signed rel32, E8 and E9',
            'examined_opcode_positions': examined, 'hits': sorted(hits, key=lambda h: h['site'])}


def inspect(data):
    """Lower-level static analysis for controls. Public collect() authenticates first."""
    image = Image(data)
    _, fs = eh_frame_records(data, image.sections)
    selected = [f for f in fs if f['start'] < END and START < f['end']]
    expected = {'start': START, 'end': END, 'fde': 0xf7e004, 'cie': 0xca6ed8, 'lsda': None}
    require(selected == [expected], 'exact leaf FDE changed')
    caller = [f for f in fs if f['start'] == CALLER_START]
    require(caller == [{'start': CALLER_START, 'end': CALLER_END, 'fde': 0x13479e4,
                        'cie': 0x103d604, 'lsda': 0x3a48c8}], 'caller FDE changed')
    require(min(f['start'] for f in fs if f['start'] > START) == 0x54368c0, 'next FDE start changed')
    body = image.region(START, END)
    walk, rule = leaf(bytes.fromhex(body['bytes_hex']))
    padding = image.region(END, 0x54368c0)
    require(bytes.fromhex(padding['bytes_hex']) == b'\xcc' * padding['size'], 'padding changed')
    function_frame = image.frame(selected[0])
    require(function_frame['fde_record']['bytes_hex'] == '1000000030712d0054884b045600000000000000'
            and function_frame['cie_record']['bytes_hex'] == '1400000000000000017a5200017810011b0c070890010000',
            'leaf unwind bytes changed')
    context = image.region(0x537919f, 0x53791da)
    context['instructions'] = decode(bytes.fromhex(context['bytes_hex']), context['start'])
    calls = [r for r in context['instructions'] if r['mnemonic'] == 'call']
    require([(r['address'], r['target']) for r in calls] == [(s, START) for s in CALL_SITES],
            'caller target changed')
    # Only these exact bounded slices support the caller argument/consumer claim.
    require(context['bytes_hex'] == '498b7d10498b7518488b542418488b4c2420e8aad60b0084c00f84a20b0000498b7d28498b7530488b542430488b4c2438e88bd60b00e9790b0000',
            'caller slice changed')
    consumer = image.region(0x5379d53, 0x5379d5b)
    consumer['instructions'] = decode(bytes.fromhex(consumer['bytes_hex']), consumer['start'])
    require(consumer['bytes_hex'] == '84c00f8565e9ffff', 'second consumer changed')
    census = caller_census(image, fs)
    require([(h['site'], h['opcode'], h['owner_start']) for h in census['hits']]
            == [(s, '0xe8', CALLER_START) for s in CALL_SITES], 'direct caller census changed')
    source_instruction = image.region(SOURCE_SITE, SOURCE_SITE + 7)
    source_instruction['instructions'] = decode(bytes.fromhex(source_instruction['bytes_hex']), SOURCE_SITE)
    require(source_instruction['instructions'][0]['target'] == LOCATION, 'source LEA changed')
    rela = [s for s in image.sections if s['name'] == '.rela.dyn']
    require(len(rela) == 1 and rela[0]['size'] % 24 == 0, 'invalid relocation section')
    relocations = []
    for off in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot == LOCATION:
            relocations.append({'file_offset': off, 'slot': slot, 'info': info, 'addend': addend,
                                'bytes_hex': data[off:off + 24].hex()})
    require(len(relocations) == 1 and relocations[0]['info'] == 8
            and relocations[0]['addend'] == 0x44e7fd, 'source relocation changed')
    loc = image.region(LOCATION, LOCATION + 24)
    require(bytes.fromhex(loc['bytes_hex']) == struct.pack('<QQII', 0, len(SOURCE_PATH), 231, 9),
            'source Location changed')
    source = image.region(0x44e7fd, 0x44e7fd + len(SOURCE_PATH))
    require(bytes.fromhex(source['bytes_hex']) == SOURCE_PATH, 'source path changed')
    cases = vectors()
    return {
        'task': 'RE-001', 'target_release': 115, 'target_sha256': SHA,
        'base_revision': BASE, 'coordinate_system': 'original ELF virtual addresses; half-open extents',
        'function': {**body, 'unwind': function_frame, 'instructions': walk, 'control_flow': control_flow(walk),
                     'padding_after': padding,
                     'callees': [], 'indirect_transfers': [], 'rule': rule},
        'caller_census': census,
        'caller_context': {'unwind': image.frame(caller[0]), 'argument_and_call_slice': context,
                           'second_consumer': consumer,
                           'scope': 'selected instructions only; not the full caller behavior or CFG'},
        'source_association': {'instruction': source_instruction, 'location': loc,
                               'relocation': relocations[0], 'path': source,
                               'path_text': SOURCE_PATH.decode(), 'line': 231, 'column': 9,
                               'scope': 'Location referenced in direct caller; not original leaf identity'},
        'vectors': cases,
        'counter_boundary_vectors': [{'before_add': n, 'after_add': (n - 1) & U64, 'carry': loop_carry(n)}
                                     for n in (0, 1, 2, (1 << 63) - 1, 1 << 63, U64)],
        'metrics': {'body_bytes': body['size'], 'instructions': len(walk),
                    'padding_bytes': padding['size'], 'callees': 0, 'indirect_transfers': 0,
                    'direct_call_sites': len(census['hits']),
                    'direct_caller_fdes': len({h['owner_start'] for h in census['hits']}),
                    'direct_tail_sites': sum(h['opcode'] == '0xe9' for h in census['hits']),
                    'semantic_vectors': len(cases)},
        'non_claims': ['original Rust function/type/crate identity', 'address or signer semantics of records',
                       'full caller semantics', 'indirect caller census', 'target execution',
                       'Rust reconstruction or compiled equivalence', 'whole-node equivalence or any acceptance gate'],
    }


def collect(binary=TARGET):
    # Hash the same read-only mapping that is parsed; no target execution or subprocess.
    with Path(binary).open('rb') as stream:
        require(stream.seek(0, 2) > 0, 'node #115 digest mismatch')
        stream.seek(0)
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            require(hashlib.sha256(data).hexdigest() == SHA, 'node #115 digest mismatch')
            return inspect(data)


def readme(r):
    f, m = r['function'], r['metrics']
    rule = f['rule']
    metric_rows = '\n'.join(f'| `{key}` | {value} |' for key, value in m.items())
    instructions = '\n'.join(
        f"| `0x{i['address']:x}` | `{i['bytes_hex']}` | {i['mnemonic']} "
        + ', '.join(i['operands'])
        + (f" {i['immediate']}" if 'immediate' in i else '')
        + (f" [{i['base']}+{i['displacement']}]" if 'displacement' in i else '')
        + (f" `0x{i['target']:x}`" if 'target' in i else '') + ' |'
        for i in f['instructions'])
    return f'''# RE-001: bind node #115 twenty-byte sequence equality

- Component: foundation / raw-signature-tracker caller association. Bounded function mapping only.
- Target: node #{r['target_release']}, SHA-256 `{r['target_sha256']}`.
- Source/reference base: `{r['base_revision']}`. New producer, model, tests and prose are independently authored under the root MIT license; no private source was copied.
- Bounded question: what does the entire function at `0x{f['start']:x}` return for the pointer/count pairs in RDI/RSI and RDX/RCX?

**Answer (observed instruction rule):** AL is {rule['true_byte']} exactly when the counts agree and all corresponding bytes in all {rule['left_stride']}-byte records agree; otherwise AL is zero. Unequal counts return without reading either sequence. Equal empty sequences return true without reading either sequence. For a nonempty equal-count pair, the function reads each record as an unaligned {rule['head_bytes']}-byte head and a {rule['tail_bytes']}-byte tail, stops at the first differing record, and returns true after the last matching record. It does not write input memory. Only AL is the result contract; the other bits of RAX and the modified argument registers are not a boolean return contract.

## Extent and instruction evidence

All addresses are original ELF virtual addresses, with half-open ranges. The body is `[0x{f['start']:x}, 0x{f['end']:x})`, file offset `0x{f['file_offset']:x}`, SHA-256 `{f['sha256']}`. Its actual FDE is at VA/file offset `0x{f['unwind']['fde']:x}`, referencing CIE `0x{f['unwind']['cie']:x}`; the augmentation has no LSDA. FDE/CIE bytes, all body bytes, instruction operands and caller slices are retained in `records.json`. The complete entry-to-return CFG agrees with this FDE, with no outgoing call or tail jump. The trailing INT3 bytes end at the next FDE start `0x{f['padding_after']['end']:x}`; they are outside the body. No input byte, address, displacement or operand is normalized.

Every metric below is computed from the JSON evidence; the targeted test checks this table and the complete generated README.

| JSON metric | Value |
| --- | ---: |
{metric_rows}

The finite Python decoder accepts exact opcode/ModRM forms, parses relative displacements and immediates, covers the complete body, and rejects unknown or truncated encodings. It also decodes every instruction used in the selected caller/source slices. These slices do not imply a complete caller CFG. The generator and verifier use no native disassembler.

| VA | Raw bytes | Decoded instruction |
| --- | --- | --- |
{instructions}

## Why the SIMD comparison covers every byte

MOVDQU loads the heads. PCMPEQB produces an all-one byte for each matching head lane. Each MOVD loads the tail into the low lanes and zeroes the upper lanes of its XMM destination. The tail PCMPEQB therefore yields tail equality in the low lanes and all-one bytes in the upper lanes. PAND combines the head and tail equalities: low lanes require both their head byte and corresponding tail byte to agree; other lanes require their head byte to agree. PMOVMSKB yields mask `0x{rule['mask']:x}` exactly when every head and tail byte agrees. This is conjunction, so no difference can cancel another difference. `lane_mask()` models this lane equation independently of the scalar `sequence_equal()` specification.

For equal positive counts n, DEC sets RSI to n-1 before the loop. In iteration j, RSI before ADD is n-1-j. Adding the sign-extended immediate {rule['counter_step']} raises unsigned carry exactly when that old value is nonzero. SETB saves carry into CL before the mask CMP overwrites flags. On a matching record, TEST CL / JNE loops iff another record remains; on the final record the old value is zero, the addition wraps to the maximum word, carry is clear and the function returns. This proves the loop bound for every representable valid slice length; large lengths are an algebraic claim under valid memory geometry, not huge allocated test fixtures. The instruction-derived vectors cover empty/unequal/equal lengths and a mismatch at every byte position of the first, middle and final record. Counter-boundary records separately cover unsigned extremes.

Preconditions: readable stable byte sequences for all reads actually reached, nonwrapping address geometry, a valid call/return stack, and the target ISA. Overlapping inputs are allowed because the body only reads them. A mismatching length or equal zero length does not require dereferenceable input pointers. Invalid pointers, data races and faults are outside the rule. The loop exits early; this is not a constant-time comparison claim.

## Caller census and first-party association

The producer scans every eligible byte position in the full `.text` range `[0x{r['caller_census']['text_start']:x}, 0x{r['caller_census']['text_end']:x})` for E8/E9 plus signed rel32. All hits are preserved, including their raw bytes and containing FDE. No E9 hit or unexplained opcode hit names this entry. E8 sites `0x{CALL_SITES[0]:x}` and `0x{CALL_SITES[1]:x}` belong to `[0x{CALLER_START:x}, 0x{CALLER_END:x})` and agree with the explicitly decoded argument/call slice.

The first call loads RDI/RSI from R13-relative pointer/count slots and RDX/RCX from stack slots. Its zero AL branches to `0x5379d60`; nonzero reaches the second call with the next pointer/count pairs. The second call jumps to `0x5379d53`, whose TEST AL / JNE sends nonzero to `0x53786c0` and zero falls through toward `0x5379d60`. These are local consumer observations, not a recovered surrounding type or protocol decision. Complete caller behavior, entry reachability of these slices and all its other callees remain outside scope. Byte scanning over-approximates instruction starts in general; bounded slice decoding supports these particular hits. Indirect/data references, alternate entry points and missing-FDE callers are not a whole-program census.

Within that same caller FDE, LEA at `0x{SOURCE_SITE:x}` addresses Location `0x{LOCATION:x}`. Its R_X86_64_RELATIVE relocation has addend `0x{r['source_association']['relocation']['addend']:x}`; the pointer-length bytes and line/column bind `{r['source_association']['path_text']}:{r['source_association']['line']}:{r['source_association']['column']}`. This is a first-party caller association. The leaf has no source string itself; a monomorphized dependency equality helper is possible. Original leaf ownership/name and whether the records represent addresses, signers or something else are unresolved.

## Novelty before selection

At the recorded base, before creating this packet, each command below produced empty stdout and exit status one:

```sh
rg -i '5436860' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '88303712' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The hexadecimal and decimal start were absent from every searched file. There are no callee behaviors to bind or additional callee starts to check. The new packet necessarily makes a later unfiltered search nonempty. PR lists are the supplied offline snapshots; newer upstream activity was not queried. The selected start is within the assigned band and outside the excluded sub-band and claimed-address list.

## Reproduce and verification scope

Run from the repository root with the authenticated artifact materialized. Python 3.10+ stdlib is sufficient; development used Python 3.13.5 on Linux x86-64. Existing `elf_index.py` and `fde_extents.py` supply ELF/unwind parsing and are manifest-bound. Native GNU objdump 2.44 was used only for exploratory inspection; no committed script or test invokes it. Neither captured executable was run. No network, installation, signing, chain state or live fixture was used.

```sh
python3 tools/node115_slice20_equal.py --out {PACKET_REL}/
python3 -m unittest tests.test_node115_slice20_equal -v
python3 {PACKET_REL}/verify.py
make verify
make catalogue-check
```

`--out` derives `records.json` and this README from the authenticated bytes, copies the packet verifier into a new output directory when needed, and writes the manifest. `verify.py` requires an exact manifest whitelist (including the producer, tests and parser dependencies), authenticates the target, and compares regenerated JSON and README bytes. Records contain semantic evidence, not local paths, native tool banners or run times. The wrong-digest and modified-input controls fail before output creation; lower-level controls also alter the actual body, FDE, relative call operand, source binding and padding. The manifest is an integrity check, not a signature or an independent proof.

Before this packet the selected address had no retained binding in the searched research or PR titles. After it, the complete leaf rule, loop bound, lane relation, extent, callee closure and direct-call sites are reproducible from the pinned target. This is static evidence and an independently authored Python model; no Rust implementation, Cargo graph, compiled-byte comparison, normalization mask or runtime differential result is claimed. Helper closure is empty for the leaf; caller/data/protocol closure and whole-ELF equivalence remain unmeasured. All component gates remain unchanged and false. Hosted CI and container execution are not claimed.

Next bounded question: identify the original types and construction of the caller's pointer/count pairs before assigning protocol meaning to the equal records.
'''.encode('utf-8')


MANIFEST_FILES = ('README.md', 'records.json', 'verify.py',
                  'tools/node115_slice20_equal.py', 'tests/test_node115_slice20_equal.py',
                  'tools/elf_index.py', 'tools/fde_extents.py')


def manifest(packet):
    rows = []
    for name in sorted(MANIFEST_FILES):
        path = ROOT / name if '/' in name else packet / name
        rows.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}\n')
    return ''.join(rows).encode('ascii')


def generate(binary, out):
    record = collect(binary)  # Authenticate/analyze before output creation or writes.
    out = Path(out)
    verifier = (PACKET / 'verify.py').read_bytes()
    out.mkdir(parents=True, exist_ok=True)
    (out / 'records.json').write_bytes(encoded_json(record))
    (out / 'README.md').write_bytes(readme(record))
    (out / 'verify.py').write_bytes(verifier)
    (out / 'MANIFEST.sha256').write_bytes(manifest(out))
    return record['metrics']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(generate(args.binary, args.out), sort_keys=True))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Bind one node #115 wrapped-key search, using static stdlib-only decoding.

New code is independently authored under the repository's MIT license. No
captured code is executed. This is a deliberately restricted x86-64 decoder,
not a general disassembler; unsupported encodings fail closed.
"""
import argparse
import bisect
import hashlib
import json
import mmap
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SLUG = 'RE-001-node115-wrapped-key56-search'
PACKET = ROOT / 'research/work-items' / SLUG
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
BASE_COMMIT = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
START, END = 0x4551810, 0x455192b
BODY_SHA = 'aa8a369d5696b55ad505513bedea408be36ff3115ae4a044755e38bca0148c13'
FDE = {'fde': 0xecfbd0, 'cie': 0xca6ed8, 'start': START, 'end': END, 'lsda': None}
FDE_HEX = '10000000fc8c2200381c68031b01000000000000'
CIE_HEX = '1400000000000000017a5200017810011b0c070890010000'
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
CALL_SITES = (0x368afc0, 0x368bc3d, 0x368c86d, 0x368d830, 0x368e55d,
              0x36c7bde, 0x36c8032, 0x36c84ed, 0x36c95ae, 0x36c9fbe,
              0x36ca66f, 0x36ca9eb, 0x371426b, 0x3cdae9a, 0x44829da)
SOURCE_OWNER = 0x368acd0
SOURCE_LEA, LOCATION = 0x368b335, 0x6468b38
SOURCE_PATH = b'l1/src/raw_signature_tracker.rs'
U64 = (1 << 64) - 1
REG64 = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
REG32 = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
         'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d')
REG8 = ('al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
        'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b')
CONDITIONS = {3: 'ae', 4: 'e', 5: 'ne', 6: 'be', 7: 'a'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reg(index, width, rex):
    require(width != 8 or rex or index < 4, 'unsupported high-byte register')
    return {'kind': 'reg', 'name': {8: REG8, 32: REG32, 64: REG64}[width][index],
            'width': width}


def imm(value):
    return {'kind': 'imm', 'value': value}


def decode_one(data, offset, base):
    """Decode ModRM/SIB, REX widths, immediates and signed relative branches."""
    pos = offset

    def take(n):
        nonlocal pos
        require(pos + n <= len(data), 'truncated instruction')
        out = data[pos:pos+n]
        pos += n
        return out

    def number(n, signed=False):
        return int.from_bytes(take(n), 'little', signed=signed)

    rex = 0
    first = number(1)
    if 0x40 <= first <= 0x4f:
        rex = first
        first = number(1)
    width = 64 if rex & 8 else 32

    def modrm(w):
        byte = number(1)
        mod, r, rm = byte >> 6, (byte >> 3) & 7, byte & 7
        rr = reg(r + (8 if rex & 4 else 0), w, rex)
        if mod == 3:
            return rr, reg(rm + (8 if rex & 1 else 0), w, rex), r
        base_reg, index, scale, disp = None, None, 1, 0
        if rm == 4:
            sib = number(1)
            scale, ix, b = 1 << (sib >> 6), (sib >> 3) & 7, sib & 7
            if ix != 4 or rex & 2:
                index = REG64[ix + (8 if rex & 2 else 0)]
            require(not (mod == 0 and b == 5), 'unsupported no-base SIB')
            base_reg = REG64[b + (8 if rex & 1 else 0)]
        elif mod == 0 and rm == 5:
            base_reg = 'rip'
            disp = number(4, True)
        else:
            base_reg = REG64[rm + (8 if rex & 1 else 0)]
        if mod == 1:
            disp = number(1, True)
        elif mod == 2:
            disp = number(4, True)
        return rr, {'kind': 'mem', 'width': w, 'base': base_reg,
                    'index': index, 'scale': scale, 'disp': disp}, r

    operands, target = [], None
    if first == 0xc3:
        require(not rex, 'prefixed RET unsupported')
        op = 'ret'
    elif first in (0xe8, 0xe9, 0xeb) or first in (0x73, 0x74, 0x75, 0x76, 0x77):
        require(not rex, 'prefixed branch unsupported')
        delta = number(1 if first < 0x80 or first == 0xeb else 4, True)
        op = {0xe8: 'call', 0xe9: 'jmp', 0xeb: 'jmp'}.get(first)
        if op is None:
            op = 'j' + CONDITIONS[first & 15]
        target = base + pos + delta
        operands = [imm(target)]
    elif first == 0x0f:
        second = number(1)
        if 0x83 <= second <= 0x87:
            require(not rex, 'prefixed branch unsupported')
            delta = number(4, True)
            op = 'j' + CONDITIONS[second & 15]
            target = base + pos + delta
            operands = [imm(target)]
        elif second in (0x43, 0x47):
            rr, rm, _ = modrm(width)
            op, operands = 'cmov' + CONDITIONS[second & 15], [rr, rm]
        elif second in (0x95, 0x97):
            _, rm, extension = modrm(8)
            require(extension == 0 and not rex & 4, 'invalid SETcc extension')
            op, operands = 'set' + CONDITIONS[second & 15], [rm]
        elif second == 0xb6:
            rr, rm, _ = modrm(8)
            # MOVZX's destination has operand width, source is byte sized.
            name = rr['name']
            rr = reg(REG8.index(name), width, rex)
            op, operands = 'movzx', [rr, rm]
        elif second == 0x1f:
            _, rm, extension = modrm(width)
            require(not rex and extension == 0, 'unsupported NOP encoding')
            op, operands = 'nop', [rm]
        else:
            raise ValueError('unsupported 0f opcode')
    elif first in (0x8b, 0x89, 0x8d, 0x39, 0x3b, 0x29, 0x31, 0x01, 0x03, 0x85, 0x84):
        w = 8 if first == 0x84 else width
        rr, rm, _ = modrm(w)
        op = {0x8b: 'mov', 0x89: 'mov', 0x8d: 'lea', 0x39: 'cmp',
              0x3b: 'cmp', 0x29: 'sub', 0x31: 'xor', 0x01: 'add',
              0x03: 'add', 0x85: 'test', 0x84: 'test'}[first]
        operands = [rr, rm] if first in (0x8b, 0x8d, 0x3b, 0x03) else [rm, rr]
        if first == 0x8d:
            require(rm['kind'] == 'mem', 'LEA requires memory encoding')
    elif first in (0x83, 0xd1):
        _, rm, extension = modrm(width)
        if first == 0x83:
            require(not rex & 4 and extension in (2, 7), 'unsupported immediate group')
            op = {2: 'adc', 7: 'cmp'}[extension]
            operands = [rm, imm(number(1, True))]
        else:
            require(not rex & 4 and extension == 5, 'unsupported shift group')
            op, operands = 'shr', [rm, imm(1)]
    elif first == 0x6b:
        rr, rm, _ = modrm(width)
        op, operands = 'imul', [rr, rm, imm(number(1, True))]
    elif 0xb8 <= first <= 0xbf:
        require(not rex & 6, 'unsupported MOV immediate prefix')
        op = 'mov'
        operands = [reg(first-0xb8+(8 if rex & 1 else 0), width, rex),
                    imm(number(8 if width == 64 else 4))]
    elif first in (0x1c, 0x3d, 0xa8):
        require(not rex, 'unsupported accumulator prefix')
        op = {0x1c: 'sbb', 0x3d: 'cmp', 0xa8: 'test'}[first]
        operands = [reg(0, 32 if first == 0x3d else 8, rex),
                    imm(number(4 if first == 0x3d else 1))]
    else:
        raise ValueError(f'unsupported opcode at {base+offset:#x}')
    row = {'va': base+offset, 'size': pos-offset, 'bytes': bytes(data[offset:pos]).hex(),
           'op': op, 'operands': operands}
    if target is not None:
        row['target'] = target
    for operand in operands:
        if operand.get('base') == 'rip':
            operand['target'] = base + pos + operand['disp']
    return row


def decode(data, start):
    rows, pos = [], 0
    while pos < len(data):
        row = decode_one(data, pos, start)
        rows.append(row)
        pos += row['size']
    return rows


def operand_text(x):
    if x['kind'] == 'reg':
        return x['name']
    if x['kind'] == 'imm':
        return str(x['value']) if -1 <= x['value'] <= 9 else hex(x['value'])
    value = x['base']
    if x['index']:
        value += '+' + x['index'] + '*' + str(x['scale'])
    if x['disp']:
        value += ('+' if x['disp'] >= 0 else '-') + hex(abs(x['disp']))
    return f"u{x['width']}[{value}]"


def asm(row):
    return row['op'] + (' ' if row['operands'] else '') + ', '.join(map(operand_text, row['operands']))


def parameters(rows):
    """Semantic operands used by the independently written recurrence below."""
    by = {r['va']: r for r in rows}
    try:
        return {'stride': by[0x455187c]['operands'][2]['value'],
                'head_normalization': by[0x4551829]['op'],
                'wrapped_cut': by[0x4551839]['op'],
                'midpoint_reject': [by[a]['op'] for a in (0x4551884, 0x45518f4)],
                'pivot_equal_branch': by[0x4551852]['op'],
                'found_status': by[0x45518a2]['op'],
                'missing_status': by[0x45518c6]['operands'][1]['value']}
    except (KeyError, IndexError) as error:
        raise ValueError('semantic instruction shape changed') from error


PARAMETERS = {'stride': 56, 'head_normalization': 'cmovae', 'wrapped_cut': 'jbe',
              'midpoint_reject': ['cmova', 'cmova'], 'pivot_equal_branch': 'je',
              'found_status': 'xor', 'missing_status': 1}


def search_model(capacity, head, physical_keys, length, needle):
    """Independent rule: choose a physical span, then use Python bisect.

    Returns the complete RAX/RDX result, not an inferred Rust Result layout.
    """
    check_model_input(capacity, head, physical_keys, length, needle)
    if not length:
        return 1, 0
    h = head % capacity
    split = min(length, capacity-h)
    if length > split and needle >= physical_keys[0]:
        if needle == physical_keys[0]:
            return 0, split
        keys, bias = physical_keys[:length-split], split
    else:
        keys, bias = physical_keys[h:h+split], 0
    right = bisect.bisect_right(keys, needle)
    if right and keys[right-1] == needle:
        return 0, bias+right-1
    return 1, bias+right


def check_model_input(capacity, head, keys, length, needle):
    require(type(capacity) is int and 0 < capacity < 1 << 63, 'invalid capacity')
    require(type(head) is int and 0 <= head < 2*capacity, 'invalid head')
    require(type(length) is int and 0 <= length <= capacity, 'invalid length')
    require(len(keys) == capacity and all(type(k) is int and 0 <= k <= U64 for k in keys), 'invalid keys')
    require(type(needle) is int and 0 <= needle <= U64, 'invalid needle')
    h = head % capacity
    logical = [keys[(h+i) % capacity] for i in range(length)]
    require(logical == sorted(logical), 'unsorted logical keys')


def decoded_recurrence(capacity, head, keys, length, needle, p=PARAMETERS):
    """Algebraic projection of the decoded branches; no PC/CPU emulator.

    Separate from search_model: mirrors narrowing and carry-to-index formulas,
    including the early equality return. Inputs satisfy the documented geometry.
    """
    check_model_input(capacity, head, keys, length, needle)
    require(p['stride'] == 56 and p['found_status'] == 'xor', 'unsupported recurrence shape')
    if not length:
        return p['missing_status'], 0
    h = head - (capacity if (head >= capacity if p['head_normalization'] == 'cmovae'
                            else head > capacity) else 0)
    split = capacity-h
    wraps = length > split if p['wrapped_cut'] == 'jbe' else length >= split
    bias, begin, count, which = 0, h, length, 1
    if wraps:
        pivot = keys[0]
        equal = pivot == needle if p['pivot_equal_branch'] == 'je' else pivot != needle
        if equal:
            return 0, split
        if pivot < needle:
            bias, begin, count, which = split, 0, length-split, 0
        else:
            count = split
    if not count:
        return p['missing_status'], 0
    i, n = 0, count
    while n > 1:
        half = n >> 1
        trial = i+half
        reject = keys[begin+trial] > needle if p['midpoint_reject'][which] == 'cmova' else keys[begin+trial] >= needle
        if not reject:
            i = trial
        n -= half
    key = keys[begin+i]
    return (0 if key == needle else p['missing_status'], bias+i+int(key < needle))


def fixtures():
    cases = [([], 3, 0, [0, U64]), ([5], 3, 2, [4, 5, 6]),
             ([1, 3, 5, 7], 6, 1, [0, 1, 2, 5, 7, 8]),
             ([1, 3, 5, 7], 5, 3, [0, 3, 4, 5, 6, 7, 8]),
             ([4, 4, 4, 4], 4, 0, [3, 4, 5]),
             ([4, 4, 4, 4], 4, 2, [3, 4, 5]),
             ([0, 1 << 63, U64], 4, 3, [0, (1 << 63)-1, 1 << 63, U64]),
             ([1, 2, 2, 4, 4], 6, 4, [2, 3, 4, 5])]
    out = []
    for logical, capacity, head, needles in cases:
        keys = [0] * capacity
        for i, key in enumerate(logical):
            keys[(head+i) % capacity] = key
        for raw_head in (head, head+capacity):
            for needle in needles:
                status, index = decoded_recurrence(capacity, raw_head, keys, len(logical), needle)
                out.append({'capacity': capacity, 'head': raw_head, 'physical_keys': keys,
                            'length': len(logical), 'needle': needle, 'rax': status, 'rdx': index})
    return out


def reader(data):
    ss = sections(data)
    require(len({s['name'] for s in ss}) == len(ss), 'duplicate section names')

    def mapping(va, size):
        choices = [s for s in ss if s['type'] != 8 and s['address'] <= va
                   and va+size <= s['address']+s['size']]
        require(len(choices) == 1, 'ambiguous or absent file mapping')
        s = choices[0]
        return s['offset']+va-s['address']

    def read(va, size):
        off = mapping(va, size)
        return bytes(data[off:off+size])

    return ss, mapping, read


def raw_record(va, read, mapping):
    length = struct.unpack('<I', read(va, 4))[0]+4
    raw = read(va, length)
    return {'va': va, 'file_offset': mapping(va, length), 'size': length, 'bytes': raw.hex(), 'sha256': digest(raw)}


def scan_rel32(data, text, destination):
    """Every byte position in .text, including the final possible rel32 start.

    These are byte-scan candidates; this is not a whole-.text instruction map.
    """
    found = []
    begin, end = text['offset'], text['offset']+text['size']
    for opcode in (0xe8, 0xe9):
        pos = begin
        while True:
            pos = data.find(bytes([opcode]), pos, end-4)
            if pos < 0:
                break
            site = text['address']+pos-begin
            target = site+5+struct.unpack_from('<i', data, pos+1)[0]
            if target == destination:
                row = decode(bytes(data[pos:pos+5]), site)[0]
                found.append(row)
            pos += 1
    return sorted(found, key=lambda r: r['va'])


def bind_body(body):
    require(len(body) == END-START, 'window extent changed')
    rows = decode(body, START)
    starts = {r['va'] for r in rows}
    require(all(r.get('target', START) in starts for r in rows), 'branch escapes body or enters instruction interior')
    require(not any(r['op'] == 'call' for r in rows) and rows[-1]['op'] == 'ret', 'leaf closure changed')
    require(parameters(rows) == PARAMETERS, 'semantic parameters changed')
    require(digest(body) == BODY_SHA, 'window bytes changed')
    return rows


def extract(data):
    """Internal structural binder for corruption tests; public generate hashes first."""
    ss, mapping, read = reader(data)
    text = next((s for s in ss if s['name'] == '.text'), None)
    require(text is not None and text['type'] == 1 and text['flags'] == 6 and
            (text['address'], text['address']+text['size']) == (TEXT_START, TEXT_END), 'text mapping changed')
    cies, fdes = eh_frame_records(data, ss)
    overlaps = [f for f in fdes if f['start'] < END and START < f['end']]
    require(overlaps == [FDE], 'FDE identity/extent changed')
    fde = raw_record(FDE['fde'], read, mapping)
    cie = raw_record(FDE['cie'], read, mapping)
    require(fde['bytes'] == FDE_HEX and cie['bytes'] == CIE_HEX, 'FDE/CIE bytes changed')
    next_start = min(f['start'] for f in fdes if f['start'] > START)
    padding = read(END, next_start-END)
    require(next_start == 0x4551930 and padding == b'\xcc' * 5, 'padding changed')
    body = read(START, END-START)
    rows = bind_body(body)
    p = parameters(rows)
    calls = scan_rel32(data, text, START)
    require(tuple(r['va'] for r in calls) == CALL_SITES and all(r['op'] == 'call' for r in calls), 'caller census/target changed')
    ordered = sorted(fdes, key=lambda f: f['start'])
    ordered_starts = [f['start'] for f in ordered]
    caller_rows = []
    for call in calls:
        site = call['va']
        owner = ordered[bisect.bisect_right(ordered_starts, site)-1]
        require(owner['start'] <= site and site+8 <= owner['end'], 'caller outside FDE')
        result_test = decode_one(read(site+5, 3), 0, site+5)
        require(result_test['op'] == 'test' and
                (result_test['operands'] == [reg(0, 8, 0), imm(1)] or
                 result_test['operands'] == [reg(0, 64, 0x48), reg(0, 64, 0x48)]), 'caller result use changed')
        caller_rows.append({'call': call, 'result_test': result_test, 'owner_fde': owner,
                            'owner_body_sha256': digest(read(owner['start'], owner['end']-owner['start']))})
    owner = next(f for f in fdes if f['start'] == SOURCE_OWNER)
    require(owner['start'] < SOURCE_LEA < owner['end'] and owner['start'] < CALL_SITES[0] < owner['end'], 'source owner changed')
    source_insn = decode(read(SOURCE_LEA, 7), SOURCE_LEA)[0]
    require(source_insn['op'] == 'lea' and source_insn['operands'][0]['name'] == 'rsi' and
            source_insn['operands'][1]['target'] == LOCATION, 'source Location reference changed')
    reloc_section = next(s for s in ss if s['name'] == '.rela.dyn')
    require(reloc_section['type'] == 4 and reloc_section['size'] % 24 == 0, 'invalid relocation section')
    relocs = []
    for off in range(reloc_section['offset'], reloc_section['offset']+reloc_section['size'], 24):
        at, info, addend = struct.unpack_from('<QQq', data, off)
        if at == LOCATION:
            relocs.append({'file_offset': off, 'offset_va': at, 'info': info, 'addend': addend,
                           'bytes': bytes(data[off:off+24]).hex()})
    require(len(relocs) == 1 and relocs[0]['info'] == 8 and relocs[0]['addend'] == 0x44e7fd, 'Location relocation changed')
    location_bytes = read(LOCATION, 24)
    pointer, length, line, column = struct.unpack('<QQII', location_bytes)
    require((pointer, length, line, column) == (0, len(SOURCE_PATH), 231, 9), 'Location layout changed')
    path = read(relocs[0]['addend'], length)
    require(path == SOURCE_PATH, 'source path changed')
    vectors = fixtures()
    return {'schema': 1, 'task': 'RE-001', 'component': 'foundation', 'target_sha256': SHA,
            'target_size': SIZE, 'source_base_commit': BASE_COMMIT,
            'window': {'start': START, 'end': END, 'size': len(body), 'file_offset': mapping(START, len(body)),
                       'body_sha256': digest(body), 'bytes': body.hex(), 'fde': FDE, 'fde_record': fde,
                       'cie_record': cie, 'cie_decoded': cies[FDE['cie']],
                       'padding': {'start': END, 'end': next_start, 'size': len(padding), 'bytes': padding.hex()},
                       'instructions': rows, 'callees': []},
            'parameters': p, 'caller_scan': {'section': text, 'start': TEXT_START, 'end': TEXT_END,
                        'method': 'every byte, E8/E9 signed rel32; candidates, not a global instruction-boundary proof',
                        'sites': caller_rows},
            'source_association': {'scope': 'caller contains Location reference; original function ownership/name unproved',
                        'owner_fde': owner, 'instruction': source_insn, 'location_va': LOCATION,
                        'location_file_offset': mapping(LOCATION, 24), 'location_bytes': location_bytes.hex(),
                        'relocation': relocs[0], 'path_va': relocs[0]['addend'], 'path': path.decode('ascii'),
                        'path_sha256': digest(path), 'line': line, 'column': column},
            'vectors': vectors,
            'metrics': {'body_bytes': len(body), 'instructions': len(rows), 'callees': 0,
                        'padding_bytes': len(padding), 'call_sites': len(calls),
                        'caller_fdes': len({c['owner_fde']['start'] for c in caller_rows}),
                        'e8_candidates': sum(c['op'] == 'call' for c in calls),
                        'e9_candidates': sum(c['op'] == 'jmp' for c in calls),
                        'text_scan_bytes': text['size'], 'vectors': len(vectors)}}


def encode_json(record):
    return (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8')


def generate(binary, output):
    # mmap avoids a second in-memory image and allows bounded structural mutants.
    with Path(binary).open('rb') as handle:
        require(handle.seek(0, 2) == SIZE, 'node #115 size/digest mismatch')
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            require(digest(data) == SHA, 'node #115 size/digest mismatch')
            record = extract(data)
    payloads = {'records.json': encode_json(record), 'README.md': render_readme(record).encode('utf-8'),
                'verify.py': (PACKET / 'verify.py').read_bytes()}
    manifest = {name: digest(raw) for name, raw in payloads.items()}
    for relative in ('tools/node115_wrapped_key56_search.py',
                     'tests/test_node115_wrapped_key56_search.py',
                     'tools/elf_index.py', 'tools/fde_extents.py'):
        manifest['../../../' + relative] = digest((ROOT / relative).read_bytes())
    payloads['MANIFEST.sha256'] = ''.join(f'{manifest[name]}  {name}\n'
                                        for name in sorted(manifest)).encode('ascii')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name, raw in payloads.items():
        (output / name).write_bytes(raw)
    return record


def render_readme(r):
    # Kept below the byte/model routines so all reported counts have one origin.
    return _readme(r)


# README renderer is defined below; output has no local paths or clock fields.
def _readme(r):
    m, w, source = r['metrics'], r['window'], r['source_association']
    instructions = '\n'.join(f"{i['va']:08x}  {i['bytes']:<20}  {asm(i)}" for i in w['instructions'])
    callers = '\n'.join(f"| `0x{c['call']['va']:x}` | `0x{c['owner_fde']['start']:x}..0x{c['owner_fde']['end']:x}` | `{asm(c['result_test'])}` |" for c in r['caller_scan']['sites'])
    return f'''# RE-001: node #115 wrapped-key search with its pivot-equality shortcut

- Component: foundation; direct caller associated with `{source['path']}`.
- Target: `artifacts/node/115/hl-node`, SHA-256 `{r['target_sha256']}`.
- Source/reference base: `{r['source_base_commit']}`. Independently authored MIT research code and model; no inferred source copied.
- Bounded question: what status and logical index does `0x{w['start']:x}` compute when searching sorted unsigned keys in a wrapped buffer, including duplicate keys at its wrap boundary?
- Claim status: the instruction/data relations below are observations. Ring geometry and sortedness are explicit preconditions. Original type names, symbol names and ownership are unresolved.

The function searches unsigned qword keys at the start of records with stride
`0x38`. It takes a descriptor through RDI and a needle pointer through RSI.
For the valid sorted geometry below, RAX is zero on a match and one on a miss;
RDX is a logical element index, or the insertion index on a miss. Empty input
returns `(1, 0)`. A match normally selects the last equal key within the physical
span selected for searching. The exception is a wrapped input whose first key at
physical index zero equals the needle: it immediately returns that key's logical
index, even when further equal keys follow. Thus replacing this function with a
uniform last-equal or first-equal search would change its behavior.

## Exact window and evidence denominators

All addresses are original ELF virtual addresses, and intervals are half-open.
No load bias or operand normalization is applied.

| Measurement | Value |
| --- | ---: |
| Function start | `0x{w['start']:x}` |
| Function end | `0x{w['end']:x}` |
| Function file offset | `0x{w['file_offset']:x}` |
| Complete body bytes | {m['body_bytes']} |
| Strictly decoded instructions | {m['instructions']} |
| Callees, including tail calls and indirect dispatch | {m['callees']} |
| INT3 bytes after body | {m['padding_bytes']} |
| Full .text bytes scanned | {m['text_scan_bytes']} |
| E8 rel32 call candidates | {m['e8_candidates']} |
| E9 rel32 tail-jump candidates | {m['e9_candidates']} |
| Total direct-call candidate sites | {m['call_sites']} |
| Distinct containing caller FDEs | {m['caller_fdes']} |
| Instruction-derived fixture vectors | {m['vectors']} |

Body SHA-256: `{w['body_sha256']}`.
The actual FDE is at VA/file offset `0x{w['fde_record']['va']:x}`,
CIE at VA/file offset `0x{w['cie_record']['va']:x}`; raw records, lengths,
CIE interpretation and SHA-256 values are in `records.json`. The FDE has no LSDA.
Its exact range agrees with a complete instruction walk from the entry, internal
branch targets and terminal returns. The bytes from `0x{w['padding']['start']:x}`
to the next FDE start `0x{w['padding']['end']:x}` are INT3 padding, excluded
from the function body. Unwind coverage alone is not the boundary argument.
There are no code/data RIP-relative references, stack writes, memory writes,
opaque calls or external branch destinations in this body. The only RET stack
read is the normal return address; arbitrary pointer faults are outside the rule.

## Input contract and rule

The descriptor's qwords are `C=[RDI+0]`, `B=[RDI+8]`, `H=[RDI+0x10]`,
`L=[RDI+0x18]`. Interpret them as capacity, record base, raw head and length only
under these preconditions: `0<C<2^63`, `0<=H<2*C`, `0<=L<=C`, readable descriptor
and selected record keys, and no address arithmetic overflow or concurrent
mutation. The node body does not check these conditions. The model rejects
out-of-domain geometry rather than claiming the target safely rejects it.
For nonempty input the qword at RSI must also be readable. Payload bytes after
each key are neither read nor written by this function.

Set `h=H-C` if unsigned `H>=C`, otherwise `h=H`. The code subtracts capacity at
most once; it is not a general modulo routine. Under the declared head bound,
`h=H mod C`. Let `K[i]=u64(B+0x38*((h+i) mod C))` for `0<=i<L`, and require
these logical keys to be nondecreasing in unsigned order. Define
`t=min(L,C-h)`, the length of the first physical span.

- If `L=0`, return `(1,0)`. The code reads the descriptor's length and base;
  it does not dereference the needle or any record key on this route.
- If input wraps (`L>t`) and `K[t]==needle`, return `(0,t)` immediately.
- If input wraps and `K[t]<needle`, search logical indices `[t,L)`.
- Otherwise search logical indices `[0,t)`.
- Within the selected span, return `(0,j)` for its last equal key. If none
  equals the needle, return `(1,j)` where `j` is the first greater key's logical
  index, or the span end if every key is smaller. Sortedness makes this the
  insertion index in the full logical sequence.

For example, logical keys `[4,4,4,4]` at capacity four, head zero, needle four
return `(0,3)`. With head two they return `(0,2)` because the wrap pivot equals
the needle. Both examples and their head-plus-capacity forms are in the JSON
fixtures. No Rust enum or container ABI is inferred from the raw result pair.

## Instruction proof

At `0x4551810..0x4551839`, the length-zero test selects the empty path; otherwise
CMP/CMOVAE normalizes H once. SUB computes `C-h` and then `L-(C-h)`.
JBE after the latter subtraction selects the nonwrapped path on borrow or zero.
Under the input bounds these calculations cannot overflow their intended
unsigned ranges. At `0x45518b5`, adding normalized head to length and later
subtracting it restores the nonwrapped length. The empty path zeroes the index
and bypasses every key/needle load.

At `0x4551845`, unsigned CMP followed by SETA and SBB AL,0 maps the pivot
comparison to byte zero for equality, one for pivot greater, and `0xff` for
pivot smaller. SETA preserves CMP's carry. MOVZX clears the upper RAX bits.
The equality jump goes directly to RET at `0x4551916`, leaving RDX=`C-h`.
The greater route rebases RCX to `B+0x38*h` and searches the first span; the
smaller route searches the wrapped span from B and retains `C-h` as its bias.

Each binary-search loop starts with index `i=0` and length `n` of its selected
nonempty span. For `n>1`, it takes `q=floor(n/2)`, tentatively advances to
`i+q`, restores the old index only if the unsigned midpoint key is greater than
the needle (CMOVA), and sets `n=n-q`. Therefore n strictly decreases to one.
For sorted keys, the surviving interval contains the last key <= needle if one
exists; if none exists it retains the span's first key. Equality advances at
midpoints, explaining the last-equal behavior. The IMUL operands bind the key
stride, and the qword CMP operands bind key width and unsigned ordering.

The terminal CMP leaves CF set exactly when the selected key is smaller than
the needle. On inequality ADC index,0 adds that carry, converting the retained
index to the insertion position. On equality there is no increment. The
wrapped search adds its logical bias at `0x45518aa`; the other search returns
the first-span index directly. XOR/MOV plus SETNE produce a full RAX of zero
or one, not merely a partially defined AL. Callee-saved registers are untouched.
This is an all-input argument under the stated preconditions, supported by
boundary vectors; it is not a claim of captured-node execution.

### Complete strict instruction walk

The Python decoder consumes every body byte, including internal NOPs, and
rejects unsupported encodings, truncated instructions and off-boundary branches.
The raw bytes below are unmasked. JSON operands retain widths, registers,
ModRM/SIB addressing, signed displacements and branch targets.

```text
{instructions}
```

## Caller census and first-party association

The producer scans every byte in `.text [0x{TEXT_START:x},0x{TEXT_END:x})` for
E8/E9 with a signed rel32 destination equal to this entry, including the final
possible instruction position. It retains every match, containing actual FDE,
caller body hash, decoded call and following result test. Counts refer to
byte-scan candidates: the scan is not a global instruction-boundary proof, and
cannot discover register calls, relocated function pointers, other executable
sections or jumps into the middle of the body. Exploratory full-FDE GNU
objdump decoding confirmed the listed call starts; reproduction and tests use
only Python and the authenticated image, with no objdump dependency. Caller
control flow and result handling beyond the following tests remain unbound.

| Call site | Containing FDE interval | Following result test |
| --- | --- | --- |
{callers}

Caller `0x{source['owner_fde']['start']:x}` contains a decoded LEA at
`0x{SOURCE_LEA:x}` of Location `0x{LOCATION:x}`. Its actual R_X86_64_RELATIVE
relocation resolves the filename pointer to `{source['path']}`; the length,
line `{source['line']}` and column `{source['column']}` are checked from bytes.
The same FDE contains the direct call at `0x{CALL_SITES[0]:x}`. This is a
first-party caller association, not proof that the leaf originated in that
file, that its key is a particular signature field, or that its source container
was a particular Rust standard-library or private type. No callee identities or
extents are omitted: the fully decoded leaf has no callees.

## Novelty and scope selection

Before implementing this packet, at the recorded source base, these exact
commands each returned exit code one with empty stdout and stderr:

```sh
rg -i 4551810 research/
rg 72685584 research/
rg -i 4551810 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg 72685584 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'wrapped-key56-search|wrapped_key56_search' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The packet directory and tool/test names did not exist. This is a historical
pre-addition check; a current search naturally finds this packet. The chosen
entry lies within the assigned band. No additional function's behavior is bound,
so no callee novelty exception is needed. This work addresses RE-001's concrete
unknown search result and duplicate selection; it requests no catalogue,
progress, component or full-function-map gate change.

## Reproduce and validation

From repository root, materialized authenticated target required. The observed
local interpreter was Python 3.13.5 on Linux x86-64; the code requires Python
3.10+ and standard-library modules only. Exploratory disassembly used GNU
objdump 2.44; it is not invoked or parsed by the producer, verifier or tests.

```sh
python3 tools/node115_wrapped_key56_search.py --out research/work-items/{SLUG}/
python3 -m unittest tests.test_node115_wrapped_key56_search -v
python3 research/work-items/{SLUG}/verify.py
make verify
make catalogue-check
```

`records.json` contains semantic evidence, instruction operands, caller/data
bindings and instruction-derived vectors. `README.md` is rendered from those
records. The generator does not read the retained records as its oracle.
`MANIFEST.sha256` covers the exact whitelisted packet files, producer, tests
and existing ELF/FDE parser dependencies. The verifier rejects missing, extra,
duplicate or changed entries and regenerates all produced evidence into a
temporary directory for byte comparison. It does not execute captured code.

Targeted controls include wrong image digest, mutations throughout the complete
window, shifted FDE range, changed padding, redirected caller target, Location
reference/relocation/path corruption, malformed decoder inputs and a semantic
CMOVA-to-CMOVAE counterexample at an actual midpoint. Public generation rejects
bad identity before creating output; internal structural checks are separately
attacked below that gate with copy-on-write mappings. The independent bisect
model is compared with the decoded narrowing relation across sorted geometry,
wrap boundaries, duplicate pivots and unsigned extremes. Tests check the README
measurement table against JSON and require exact regenerated README equality.

## Non-claims, limitations and next step

This closes a bounded static leaf rule, not an integrated implementation.
Rust reconstruction, compiler flags, Cargo closure, two-build comparison,
normalized or raw compiled-code identity, runtime differential tests and hosted
CI are not implemented/measured here. No node/visor was executed; no public
network, chain action, install, signing, private state or upstream write was used.
There are no normalization masks. Helper closure is local and complete because
there are no calls; indirect incoming references, caller semantics, object/type
layout provenance and whole-ELF equivalence remain open. Invalid geometry,
unsorted keys, invalid memory and concurrent mutation are outside the theorem.

Before this packet, the retained research did not bind this entry. After it,
the full body, its search and duplicate-index rule, and its source-associated
caller edge can be reproduced against the pinned target. All full-scope
acceptance gates remain unchanged. The next question is which caller writes
and sortedness invariants establish this descriptor's key meaning, especially
whether duplicate keys can reach the pivot-equality shortcut in normal use.
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    r = generate(args.binary, args.out)
    print(json.dumps({'target_sha256': SHA, 'start': hex(START), **r['metrics']}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        raise SystemExit('wrapped-key56-search: ' + str(error))

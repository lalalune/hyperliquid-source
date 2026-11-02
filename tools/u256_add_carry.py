#!/usr/bin/env python3
"""Static RE-001 bind of node #94's unsigned four-limb addition leaf.

Python 3.10+ standard library only. No target execution or disassembler process.
The deliberately small decoder rejects instructions outside the retained forms.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-u256-add-carry-94'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
START, END, NEXT = 0x1EB3C40, 0x1EB3CA7, 0x1EB3CB0
BODY_SHA = '28ed2bf420023763fe3224bda9f28d4a47da17f83db9085ea4fc6dc83957d071'
CALLER, CALL_SITE = 0x1F661C0, 0x1F673BC
CONTEXT_START, CONTEXT_END = 0x1F67388, 0x1F67407
CONTEXT_SHA = '5ba99c5f407e561247d0b8a819b6d854fcf2603f51dba595ae83f89471457cf9'
LOCATION_SITE, LOCATION = 0x1F67364, 0x5690288
SOURCE_TAIL = b'l1/src/action/evm_raw_tx.rs'
SOURCE_SHA = 'f56ef638cec993e152a35cc43ca694079f5d6be7ed2c93626971ff1553eac976'
BASE_COMMIT = 'e5c9b6436876b2a4a39daef813171f9879317699'
MASK64, MASK256 = (1 << 64) - 1, (1 << 256) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    require(len(data) == SIZE and digest(data) == SHA256, 'node #94 digest/size mismatch')


def read_va(data, secs, va, size):
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(size >= 0 and len(matches) == 1, 'ambiguous or unmapped VA range')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


@dataclass(frozen=True)
class Operand:
    kind: str
    width: int
    value: int
    displacement: int = 0


@dataclass(frozen=True)
class Instruction:
    va: int
    raw: bytes
    op: str
    operands: tuple


REG64 = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
REG32 = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
         'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d')
REG8 = ('al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
        'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b')


def decode(blob, start):
    """Decode the complete bounded stream, including operands and relative targets.

    Only no-index SIB, base+displacement, register and RIP addressing are
    supported. High byte registers, legacy prefixes and unsupported REX forms are
    refused rather than guessed. These restrictions cover every retained byte.
    """
    result, pos = [], 0

    def take(n):
        nonlocal pos
        require(pos + n <= len(blob), 'truncated instruction')
        out = blob[pos:pos + n]
        pos += n
        return out

    def imm(n, signed=False):
        return int.from_bytes(take(n), 'little', signed=signed)

    while pos < len(blob):
        begin = pos
        rex = imm(1)
        if 0x40 <= rex <= 0x4F:
            opcode = imm(1)
        else:
            opcode, rex = rex, 0
        require(not rex & 2, 'unsupported REX.X')
        width = 64 if rex & 8 else 32

        def modrm(w, xmm=False, group=False):
            byte = imm(1)
            mod, reg, rm = byte >> 6, (byte >> 3) & 7, byte & 7
            require(not group or not rex & 4, 'REX.R on opcode extension')
            require(w != 8 or rex or group or reg < 4, 'high byte register unsupported')
            r = Operand('xmm' if xmm else 'reg', w, reg + (8 if rex & 4 else 0))
            if mod == 3:
                index = rm + (8 if rex & 1 else 0)
                require(w != 8 or rex or ((group or reg < 4) and rm < 4),
                        'high byte register unsupported')
                return reg, r, Operand('xmm' if xmm else 'reg', w, index)
            if rm == 4:
                sib = imm(1)
                require(sib == 0x24, 'unsupported SIB')
                require(not rex & 1, 'unsupported extended SIB base')
            if mod == 0 and rm == 5:
                require(not rex & 1, 'unsupported REX.B on RIP operand')
                operand = Operand('rip', w, imm(4, True))
            else:
                disp = imm(1, True) if mod == 1 else imm(4, True) if mod == 2 else 0
                operand = Operand('mem', w, rm + (8 if rex & 1 else 0), disp)
            return reg, r, operand

        args = ()
        if opcode == 0xC3:
            require(not rex, 'prefixed ret unsupported')
            op = 'ret'
        elif opcode in (0xE8, 0xE9, 0x75):
            require(not rex, 'prefixed branch unsupported')
            displacement = imm(1 if opcode == 0x75 else 4, True)
            op = {0xE8: 'call', 0xE9: 'jmp', 0x75: 'jne'}[opcode]
            args = (Operand('target', 64, start + pos + displacement),)
        elif opcode == 0x04:
            require(not rex, 'prefixed AL immediate unsupported')
            op, args = 'add', (Operand('reg', 8, 0), Operand('imm', 8, imm(1)))
        elif opcode in (0x8B, 0x89, 0x88, 0x01, 0x03, 0x11, 0x08, 0x0B, 0x8D):
            w = 8 if opcode in (0x88, 0x08) else width
            _, reg, rm = modrm(w)
            op = {0x8B: 'mov', 0x89: 'mov', 0x88: 'mov', 0x01: 'add',
                  0x03: 'add', 0x11: 'adc', 0x08: 'or', 0x0B: 'or', 0x8D: 'lea'}[opcode]
            args = (reg, rm) if opcode in (0x8B, 0x03, 0x0B, 0x8D) else (rm, reg)
            require(op != 'lea' or rm.kind in ('mem', 'rip'), 'LEA requires memory encoding')
        elif opcode in (0x80, 0x83, 0xC7):
            w = 8 if opcode == 0x80 else width
            group, _, rm = modrm(w, group=True)
            if opcode == 0xC7:
                require(group == 0, 'unsupported C7 extension')
                op, value = 'mov', imm(4, True)
            else:
                require(group in (2, 4, 7), 'unsupported immediate arithmetic')
                op, value = {2: 'adc', 4: 'and', 7: 'cmp'}[group], imm(1, opcode == 0x83)
            args = (rm, Operand('imm', w, value))
        elif opcode == 0x0F:
            second = imm(1)
            if second in (0x10, 0x11):
                require(not rex, 'extended SIMD unsupported')
                _, reg, rm = modrm(128, xmm=True)
                op, args = 'movups', ((reg, rm) if second == 0x10 else (rm, reg))
            elif second == 0x92:
                group, _, rm = modrm(8, group=True)
                require(group == 0 and not rex & 8, 'unsupported SETB encoding')
                op, args = 'setb', (rm,)
            elif second == 0xB6:
                require(not rex, 'extended MOVZX unsupported')
                _, reg, rm = modrm(8)
                op, args = 'movzx', (Operand('reg', 32, reg.value), rm)
            elif second == 0x45:
                _, reg, rm = modrm(width)
                op, args = 'cmovne', (reg, rm)
            else:
                raise ValueError(f'unsupported 0f opcode {second:02x}')
        else:
            raise ValueError(f'unsupported opcode {opcode:02x} at {start + begin:#x}')
        args = tuple(Operand('absolute', a.width, start + pos + a.value)
                     if a.kind == 'rip' else a for a in args)
        result.append(Instruction(start + begin, blob[begin:pos], op, args))
    return result


def operand_text(a):
    if a.kind == 'reg':
        return {8: REG8, 32: REG32, 64: REG64}[a.width][a.value]
    if a.kind == 'xmm':
        return f'xmm{a.value}'
    if a.kind in ('imm', 'target'):
        return hex(a.value)
    size = {8: 'byte', 32: 'dword', 64: 'qword', 128: 'xmmword'}[a.width]
    if a.kind == 'absolute':
        return f'{size} [rip -> {a.value:#x}]'
    disp = f'{a.displacement:+#x}' if a.displacement else ''
    return f'{size} [{REG64[a.value]}{disp}]'


def assembly(instructions):
    return ''.join((f'{i.va:#x}: {i.raw.hex(" "):<30} {i.op} '
                    + ', '.join(operand_text(a) for a in i.operands)).rstrip() + '\n'
                   for i in instructions)


def add256(left, right):
    """Independent integer model for disjoint readable inputs and writable output."""
    require(type(left) is int and type(right) is int and 0 <= left <= MASK256
            and 0 <= right <= MASK256, 'inputs must be unsigned 256-bit integers')
    total = left + right
    return total & MASK256, int(total > MASK256)


def execute_leaf(instructions, memory, output, left, right):
    """Instruction-level test oracle; simulates bytes, never executes target code.

    Models only the instructions in the leaf, including partial-register writes,
    memory read/write order, 32-bit zero-extension and carry-flag preservation.
    Returns the final registers and a memory-write trace for boundary tests.
    """
    registers, simd = [0] * 16, [0] * 16
    registers[7], registers[6], registers[2] = output, left, right
    carry, writes = 0, []

    def address(a):
        p = registers[a.value] + a.displacement
        require(0 <= p <= len(memory) - a.width // 8, 'test memory access outside fixture')
        return p

    def get(a):
        if a.kind == 'imm':
            return a.value & ((1 << a.width) - 1)
        if a.kind == 'reg':
            return registers[a.value] & ((1 << a.width) - 1)
        if a.kind == 'xmm':
            return simd[a.value]
        require(a.kind == 'mem', 'unsupported oracle read')
        p = address(a)
        return int.from_bytes(memory[p:p + a.width // 8], 'little')

    def put(a, value):
        value &= (1 << a.width) - 1
        if a.kind == 'reg':
            registers[a.value] = (value if a.width >= 32 else
                                  (registers[a.value] & ~255) | value)
        elif a.kind == 'xmm':
            simd[a.value] = value
        else:
            require(a.kind == 'mem', 'unsupported oracle write')
            p = address(a)
            memory[p:p + a.width // 8] = value.to_bytes(a.width // 8, 'little')
            writes.append((p, a.width // 8))

    for index, i in enumerate(instructions):
        if i.op == 'ret':
            require(index == len(instructions) - 1, 'instructions after return')
            return registers, writes
        dst = i.operands[0]
        if i.op == 'setb':
            put(dst, carry)
            continue
        src = i.operands[1]
        if i.op in ('mov', 'movzx', 'movups'):
            put(dst, get(src))
        elif i.op in ('add', 'adc'):
            total = get(dst) + get(src) + (carry if i.op == 'adc' else 0)
            carry = int(total >= 1 << dst.width)
            put(dst, total)
        elif i.op in ('or', 'and'):
            put(dst, get(dst) | get(src) if i.op == 'or' else get(dst) & get(src))
            carry = 0
        else:
            raise ValueError(f'unsupported oracle instruction {i.op}')
    raise ValueError('leaf lacks ret')


def frame_record(data, secs, fdes, start):
    matches = [f for f in fdes if f['start'] == start]
    require(len(matches) == 1, 'FDE start is missing or duplicated')
    f = matches[0]
    frame = next(s for s in secs if s['name'] == '.eh_frame')
    raw_length = struct.unpack('<I', read_va(data, secs, f['fde'], 4))[0]
    raw = read_va(data, secs, f['fde'], raw_length + 4)
    cie_length = struct.unpack('<I', read_va(data, secs, f['cie'], 4))[0]
    cie_raw = read_va(data, secs, f['cie'], cie_length + 4)
    return {'start': hex(start), 'end_exclusive': hex(f['end']), 'bytes': f['end'] - start,
            'body_sha256': digest(read_va(data, secs, start, f['end'] - start)),
            'fde_section_offset': hex(f['fde'] - frame['address']),
            'fde_record_bytes': len(raw), 'fde_raw': raw.hex(),
            'cie_section_offset': hex(f['cie'] - frame['address']),
            'cie_record_bytes': len(cie_raw), 'cie_sha256': digest(cie_raw),
            'lsda': None if f['lsda'] is None else hex(f['lsda'])}


def scan_incoming(data, text, target):
    """Full .text byte-position e8/e9 rel32 census, including unaligned candidates."""
    found = []
    end = text['offset'] + text['size']
    for opcode in (0xE8, 0xE9):
        pos = text['offset']
        while True:
            pos = data.find(bytes([opcode]), pos, end - 4)
            if pos < 0:
                break
            va = text['address'] + pos - text['offset']
            if va + 5 + struct.unpack_from('<i', data, pos + 1)[0] == target:
                found.append({'site': hex(va), 'kind': 'call' if opcode == 0xE8 else 'jmp',
                              'target': hex(target), 'raw': data[pos:pos + 5].hex()})
            pos += 1
    return sorted(found, key=lambda x: int(x['site'], 16))


def vectors():
    cases = [('zero', 0, 0), ('no carry', 0x1234, 0x5678),
             ('all ones plus zero', MASK256, 0), ('full carry chain', MASK256, 1),
             ('high limb overflow', 1 << 255, 1 << 255),
             ('both operands maximal', MASK256, MASK256)]
    for limb in range(1, 4):
        cases.append((f'carry into limb {limb}', (1 << (64 * limb)) - 1, 1))
    # The separate ADD and ADC in limbs 2/3 each have their own carry source.
    for limb in (2, 3):
        shift = 64 * limb
        cases.extend([(f'limb {limb} base-add carry', MASK64 << shift, 1 << shift),
                      (f'limb {limb} carry-in overflow', (1 << (shift + 64)) - 1, 1),
                      (f'limb {limb} base carry with carry-in',
                       (1 << (shift + 64)) - 1, (1 << shift) + 1)])
    return [{'case': name, 'left': hex(a), 'right': hex(b),
             'sum_mod_2_256': hex(add256(a, b)[0]), 'overflow': add256(a, b)[1]}
            for name, a, b in cases]


def decode_context(raw):
    instructions = decode(raw, CONTEXT_START)
    calls = [i for i in instructions if i.op == 'call']
    require(len(calls) == 1 and calls[0].va == CALL_SITE
            and calls[0].operands[0].value == START, 'wrong callee target')
    require(digest(raw) == CONTEXT_SHA, 'caller context mismatch')
    return instructions


def derive(data):
    authenticate(data)  # No command-line digest override or unauthenticated mode.
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    fn = frame_record(data, secs, fdes, START)
    require(fn['end_exclusive'] == hex(END) and fn['body_sha256'] == BODY_SHA,
            'leaf body/extent mismatch')
    require(fn['fde_section_offset'] == '0x438c0' and fn['cie_section_offset'] == '0x0',
            'leaf FDE/CIE association mismatch')
    following = frame_record(data, secs, fdes, NEXT)
    require(min(f['start'] for f in fdes if f['start'] > START) == NEXT,
            'next FDE association mismatch')
    pad = read_va(data, secs, END, NEXT - END)
    require(pad == b'\xcc' * (NEXT - END), 'padding mismatch')
    fn['padding'] = {'start': hex(END), 'end_exclusive': hex(NEXT),
                     'bytes': len(pad), 'raw': pad.hex(),
                     'next_fde_section_offset': following['fde_section_offset']}
    body = read_va(data, secs, START, END - START)
    instructions = decode(body, START)
    require(instructions[-1].op == 'ret' and all(i.op not in ('call', 'jmp', 'jne', 'ret')
            for i in instructions[:-1]), 'leaf control flow mismatch')
    text = next(s for s in secs if s['name'] == '.text')
    incoming = scan_incoming(data, text, START)
    require([(x['site'], x['kind']) for x in incoming] == [(hex(CALL_SITE), 'call')],
            'incoming census mismatch')
    caller = frame_record(data, secs, fdes, CALLER)
    require(int(caller['end_exclusive'], 16) >= CONTEXT_END, 'caller context outside FDE')
    context = read_va(data, secs, CONTEXT_START, CONTEXT_END - CONTEXT_START)
    caller_instructions = decode_context(context)
    loc_code = read_va(data, secs, LOCATION_SITE, 7)
    loc_insns = decode(loc_code, LOCATION_SITE)
    require(len(loc_insns) == 1 and loc_insns[0].op == 'lea'
            and loc_insns[0].operands == (Operand('reg', 64, 1), Operand('absolute', 64, LOCATION)),
            'caller Location reference mismatch')
    rel = next(s for s in secs if s['name'] == '.rela.dyn')
    relocations = []
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot == LOCATION:
            relocations.append((off - rel['offset'], info, addend))
    require(len(relocations) == 1 and relocations[0][1] == 8, 'Location relocation mismatch')
    loc_raw = read_va(data, secs, LOCATION, 24)
    stored, length, line, column = struct.unpack('<QQII', loc_raw)
    path = read_va(data, secs, relocations[0][2], length)
    require(stored == 0 and digest(path) == SOURCE_SHA and path.endswith(SOURCE_TAIL)
            and (line, column) == (158, 53), 'first-party source Location mismatch')
    rule = {'limbs': 4, 'limb_bits': 64, 'integer_bits': 256, 'sum_bytes': 32,
            'overflow_offset': 32, 'overflow_bytes': 1, 'output_bytes': 33,
            'left_register': 'rsi', 'right_register': 'rdx', 'output_register': 'rdi',
            'limb_offsets': [0, 8, 16, 24],
            'equation': 'T = A + B; left = T mod 2^256; output = (left, T >= 2^256)',
            'preconditions': 'valid disjoint input/output regions; little-endian limbs; no concurrent mutation',
            'source_right_unchanged': True, 'input_left_mutated': True,
            'return_register': 'rax contains the final most-significant limb; no source-level return ABI claimed',
            'carry_observations': [
                {'site': '0x1eb3c4a', 'rule': 'ADC propagates limb-0 carry into limb 1'},
                {'site': '0x1eb3c5d', 'rule': 'AL is 0/1; ADD AL,255 converts saved carry back to CF'},
                {'site': '0x1eb3c66', 'rule': 'OR merges limb-2 base-add carry and carry-in overflow'},
                {'site': '0x1eb3c84', 'rule': 'OR merges limb-3 base-add carry and carry-in overflow'},
            ]}
    records = {
        'schema': 're001-u256-add-carry-v1', 'task': 'RE-001', 'component': 'action-wire',
        'target': {'release': '94', 'sha256': SHA256, 'bytes': len(data),
                   'coordinate_system': 'original ELF virtual addresses, before load bias'},
        'baseline_commit': BASE_COMMIT,
        'function': fn, 'callees': [], 'rule': rule,
        'incoming': {'scan': 'every .text byte position: e8/e9 plus signed rel32; no normalization',
                     'text_start': hex(text['address']),
                     'text_end_exclusive': hex(text['address'] + text['size']),
                     'text_bytes': text['size'], 'sites': incoming},
        'caller': {'function': caller,
                   'context': {'start': hex(CONTEXT_START), 'end_exclusive': hex(CONTEXT_END),
                               'bytes': len(context), 'sha256': digest(context)},
                   'interpretation': 'local consumer selects all-ones limbs on overflow, otherwise the sum',
                   'location': {'reference_site': hex(LOCATION_SITE), 'reference_raw': loc_code.hex(),
                                'address': hex(LOCATION), 'raw': loc_raw.hex(),
                                'relocation_section_offset': hex(relocations[0][0]),
                                'relocation_type': 'R_X86_64_RELATIVE',
                                'path_address': hex(relocations[0][2]), 'path_bytes': length,
                                'path_sha256': SOURCE_SHA, 'path_tail': SOURCE_TAIL.decode(),
                                'line': line, 'column': column}},
        'vectors': vectors(),
        'novelty': {'checked_before_packet': True, 'hex_query': f'{START:x}',
                    'decimal_query': str(START), 'research_matches': [], 'pr_title_matches': [],
                    'pr_lists': ['open_prs.txt', 'merged_prs.txt', 'closed_unmerged_prs.txt'],
                    'scope': 'primary start; no behavior-bound callees; baseline plus supplied local PR lists'},
    }
    records['counts'] = {'body_bytes': len(body), 'padding_bytes': len(pad),
                         'instructions': len(instructions), 'callees': len(records['callees']),
                         'direct_calls': sum(x['kind'] == 'call' for x in incoming),
                         'direct_tail_jumps': sum(x['kind'] == 'jmp' for x in incoming),
                         'vectors': len(records['vectors'])}
    return records, instructions, caller_instructions, loc_insns


VERIFY_SOURCE = '''#!/usr/bin/env python3
"""Whitelist and reproduce this packet; static, Python standard library only."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from u256_add_carry import BINARY, verify_packet

if __name__ == '__main__':
    try:
        verify_packet(Path(__file__).resolve().parent, BINARY)
    except (OSError, ValueError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        raise SystemExit(1)
    print('ALL CHECKS PASSED (static evidence; target not executed)')
'''


def readme(r):
    f, c, rule = r['function'], r['counts'], r['rule']
    loc, ctx, caller = r['caller']['location'], r['caller']['context'], r['caller']['function']
    return f'''# RE-001: unsigned addition and carry in node #{r['target']['release']}

Task: RE-001; component allocation: action-wire. Bounded question: what does
`{f['start']}` compute from the regions addressed by `rsi` and `rdx`, what
does it write through `rdi`, and how does it report overflow?

Answer: interpret each input as an unsigned {rule['integer_bits']}-bit integer
in {rule['limbs']} little-endian {rule['limb_bits']}-bit limbs. With valid,
disjoint regions and no concurrent mutation, the function adds the inputs,
replaces the left input with the sum modulo the integer width, copies that
sum to the output, and writes the unsigned overflow bit at output offset
`{rule['overflow_offset']:#x}`. It leaves the right input unchanged. It neither
saturates nor signals overflow through a branch. Its local caller uses the
overflow byte to select all-ones limbs instead of the sum. This binds the
whole leaf; the caller's surrounding transaction policy remains unresolved.

| Evidence metric | Value |
| --- | ---: |
| Body bytes | {c['body_bytes']} |
| Decoded instructions | {c['instructions']} |
| Padding bytes | {c['padding_bytes']} |
| Callees | {c['callees']} |
| Direct call sites | {c['direct_calls']} |
| Direct tail-jump sites | {c['direct_tail_jumps']} |
| Model vectors | {c['vectors']} |

Target SHA-256: `{r['target']['sha256']}`; artifact size:
{r['target']['bytes']} bytes. Baseline source revision: `{r['baseline_commit']}`.
No inferred reference implementation was read or copied. New code is MIT.
The analysis requires Python 3.10+ and was run with Python 3.13.5. Initial
inspection used GNU objdump 2.44; reproduction, verification and tests use
only Python, including the strict decoder in the added tool. No REA provider
was connected and no captured executable was run.

The new extractor is scoped to this previously unbound leaf and its local
caller evidence. It reuses the existing ELF and FDE parsers. Existing bind
tools have no decoder or semantic checks for this window; no general tooling
or infrastructure change is proposed.

## Extent and bytes

All addresses are original ELF virtual addresses before load bias.
Window: `[{f['start']}, {f['end_exclusive']})`.
Body SHA-256: `{f['body_sha256']}`.
The parsed FDE is at `.eh_frame+{f['fde_section_offset']}`, with CIE at
`.eh_frame+{f['cie_section_offset']}`; its complete record is
{f['fde_record_bytes']} bytes and its CIE is {f['cie_record_bytes']} bytes.
The FDE has no LSDA. The next FDE starts at `{f['padding']['end_exclusive']}`
and is recorded at `.eh_frame+{f['padding']['next_fde_section_offset']}`.
The gap is exclusively `cc` padding, excluded from the body hash.
The FDE association is parsed from the actual unwind records, not inferred
from the next unwind-index entry. A complete linear decode from the FDE start
ends in `ret`, with no outgoing calls, branches, stack adjustment or hidden
helper dependence. `window.asm` accounts for every body byte and the padding.

## Instruction-derived rule

`window.asm` is the complete instruction walk generated by our decoder.
The low limbs use `ADD` followed by `ADC`; `MOV` and `SETB` preserve carry.
The next limb first records the carry from its ordinary addition in `r8b`.
`ADD al,0xff` restores the saved lower-limb carry into CF because AL is
restricted to a Boolean; `ADC rcx,0` then incorporates it. The `OR` of the
two saved overflow flags supplies the carry into the most-significant limb.
That limb similarly combines its base-add carry and carry-in overflow.
`AND cl,1` leaves a canonical Boolean, which is stored to the output.
These are unsigned carries, unrelated to the signed overflow flag.

For each limb, write `s = a + b`, `r = s mod B`, and incoming carry `c`,
where `B` is the limb radix. The emitted carry is
`(s >= B) OR (r + c >= B)`, exactly `floor((a + b + c) / B)`.
The two carry terms cannot both be set: an overflowing base addition has
`r <= B - 2`, while `c <= 1`. This establishes the composed integer rule
for every input satisfying the stated memory preconditions, beyond the
finite model test vectors.

The input-left stores occur in increasing limb order at offsets
{', '.join(f'`{n:#x}`' for n in rule['limb_offsets'])}. The output is then
written by `MOVUPS`, followed by the remaining limb stores and finally the
overflow byte. It occupies {rule['output_bytes']} bytes: {rule['sum_bytes']}
sum bytes and {rule['overflow_bytes']} flag byte. The final `rax` contains
the most-significant sum limb; a source-level return ABI is not inferred.
The pure-integer `add256` model is independently authored. A separate
instruction interpreter models decoded operands, CF, partial registers,
zero-extension and memory order. Tests compare both on the retained vectors,
carry boundaries and deterministic broader inputs. These are static model
checks, not differential execution of the captured binary.

## Caller and first-party association

The census scans all {r['incoming']['text_bytes']} bytes of `.text`,
`[{r['incoming']['text_start']}, {r['incoming']['text_end_exclusive']})`,
at every byte position for `e8` and `e9` with signed relative displacements.
The retained call is at `{r['incoming']['sites'][0]['site']}`. `caller.asm`
decodes its argument setup and overflow consumer in
`[{ctx['start']}, {ctx['end_exclusive']})`, a {ctx['bytes']}-byte slice.
The containing FDE is `[{caller['start']}, {caller['end_exclusive']})`,
{caller['bytes']} bytes, at `.eh_frame+{caller['fde_section_offset']}` with
CIE `.eh_frame+{caller['cie_section_offset']}`. Its body digest and unwind
association are retained as identity evidence, not a semantic bind.

In the same FDE, `LEA` at `{loc['reference_site']}` references a panic
Location at `{loc['address']}`. Its `R_X86_64_RELATIVE` pointer resolves
to a {loc['path_bytes']}-byte source path with SHA-256
`{loc['path_sha256']}`, ending in `{loc['path_tail']}` at
line {loc['line']}, column {loc['column']}. The original build-machine prefix
is deliberately omitted. The relocation, slice length, line and column
are re-read from the binary. This proves a direct first-party caller
association; it does not establish that the leaf itself was authored by
Hyperliquid, its crate, or a source-level name.

## Novelty, before packet creation

The following searches were run against the baseline checkout and the
supplied local PR title snapshots. Each produced empty stdout and exit status
`1` (no matches):

```sh
rg -i '{r['novelty']['hex_query']}' research/
rg -i '{r['novelty']['decimal_query']}' research/
rg -i '{r['novelty']['hex_query']}|{r['novelty']['decimal_query']}' ../../hl-re1-base/open_prs.txt ../../hl-re1-base/merged_prs.txt ../../hl-re1-base/closed_unmerged_prs.txt
```

The leaf has no callees to behavior-bind or additionally novelty-check.
These are historical pre-change checks; searching the completed packet
will naturally find its own address. Existing caller evidence is context,
not re-claimed function behavior. The supplied lists are local snapshots;
no live PR lookup or freshness claim is made.

## Reproduce

```sh
python3 tools/u256_add_carry.py --out research/work-items/RE-001-u256-add-carry-94/
python3 -m unittest tests.test_u256_add_carry -v
python3 research/work-items/RE-001-u256-add-carry-94/verify.py
make verify
make catalogue-check
```

`records.json` contains semantic records, extents, xrefs and test vectors;
instruction rows are confined to the assembly files. The generator is
deterministic and fails closed on the hard-coded artifact identity.
`MANIFEST.sha256` has an exact filename whitelist covering the packet,
new tool/tests and existing ELF/FDE parser dependencies. Verification
regenerates evidence and checks the manifest, including this README.
Tests require that the README equals its rendering from JSON, so all
reported evidence counts are checked against the records.

Packet generation, its unit tests and standalone verification pass.
`make doctor` reports analysis readiness. The initial `make verify` stopped
on an LFS pointer; the requested `git lfs pull` restored the captured artifacts.
The subsequent verification authenticates those artifacts and signatures,
then fails because `references/can1357-hl/bin/hl-node-mainnet-new` is absent.
`make reproduce` stops on the same prerequisite. `make catalogue-check`
reports stale `research/catalogue/components.json`, observed before this
packet was written. The broad `make test` was attempted and stopped after
an unrelated `test_abci_state_inventory` setup error for missing
`references/can1357-hl/l1/abci/state.rs`; that suite is incomplete.
No reference checkout, generated catalogue or progress gate was changed to
work around these failures. The bounded packet checks use the authenticated
artifact directly and do not need the absent reference tree.

## Limits and next step

The caller census is a raw byte-position scan, not a whole-text instruction
boundary proof. The retained hit is decoded with contiguous setup and
consumer context, but arbitrary embedded opcode bytes can match such scans.
Indirect calls, pointers, vtables and non-text references are outside it.
Only the leaf is fully decoded: the caller's local slice is not its full CFG.
The Location can come from an inlined source span; it does not name the whole
caller. Caller source names, transaction fields and economic units are unknown.

The arithmetic rule assumes disjoint regions; arbitrary partial overlap can
change subsequent reads. Exact same-buffer cases are tested only as machine
memory controls, not as a claim about Rust aliasing validity. Faults from
invalid pointers, concurrent mutation, source type/layout compatibility and
current-network behavior remain outside the rule. No normalization masks,
compiled Rust comparison, target execution, whole-node equivalence or gate
advancement is claimed. No imported evidence or existing packet was changed.

Next: independently bind the producer feeding this caller's left operand
and determine what the saturated sum means in its transaction checks.
'''


PACKET_FILES = frozenset(('README.md', 'records.json', 'window.asm', 'caller.asm', 'verify.py'))
DEPENDENCIES = ('tools/u256_add_carry.py', 'tests/test_u256_add_carry.py',
                'tools/elf_index.py', 'tools/fde_extents.py')
MANIFEST_NAMES = PACKET_FILES | frozenset('../../../' + n for n in DEPENDENCIES)


def artifact_bytes(data):
    records, instructions, caller, location = derive(data)
    outputs = {
        'records.json': (json.dumps(records, indent=2, sort_keys=True) + '\n').encode(),
        'README.md': readme(records).encode(),
        'window.asm': ('# Original ELF VAs; strict Python decoder; Intel operand order.\n'
                       + assembly(instructions) + f'# Padding [{END:#x}, {NEXT:#x}): '
                       + records['function']['padding']['raw'] + '\n').encode(),
        'caller.asm': ('# Context only; caller body behavior is not bound.\n'
                       + assembly(location) + '# Argument setup and overflow consumer:\n'
                       + assembly(caller)).encode(),
        'verify.py': VERIFY_SOURCE.encode(),
    }
    entries = {name: digest(content) for name, content in outputs.items()}
    for path in DEPENDENCIES:
        entries['../../../' + path] = digest((ROOT / path).read_bytes())
    outputs['MANIFEST.sha256'] = ''.join(f'{entries[name]}  {name}\n'
                                        for name in sorted(entries)).encode()
    return outputs


def verify_manifest(packet):
    lines = (packet / 'MANIFEST.sha256').read_text().splitlines()
    seen = set()
    for line in lines:
        parts = line.split('  ')
        require(len(parts) == 2, 'malformed manifest row')
        sha, name = parts
        require(name in MANIFEST_NAMES and name not in seen, 'manifest whitelist/duplicate violation')
        seen.add(name)
        path = ROOT / name[9:] if name.startswith('../../../') else packet / name
        require(not path.is_symlink() and digest(path.read_bytes()) == sha,
                f'manifest digest mismatch: {name}')
    require(seen == MANIFEST_NAMES, 'manifest omissions')


def verify_packet(packet, binary=BINARY):
    require({p.name for p in packet.iterdir()} == PACKET_FILES | {'MANIFEST.sha256'},
            'packet filename whitelist mismatch')
    verify_manifest(packet)
    with binary.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        expected = artifact_bytes(data)
    for name, content in expected.items():
        require((packet / name).read_bytes() == content, f'regenerated evidence differs: {name}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=BINARY)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--out', type=Path)
    mode.add_argument('--check', type=Path)
    args = parser.parse_args()
    if args.check:
        verify_packet(args.check, args.binary)
    else:
        with args.binary.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            generated = artifact_bytes(data)
        args.out.mkdir(parents=True, exist_ok=True)
        for name, content in generated.items():
            (args.out / name).write_bytes(content)
    print('Static u256 addition evidence verified; target not executed.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""RE-005: static instruction/word-model comparison for node94's kind-5 reader.

Only objdump reads the non-executable input snapshot. The Python evaluator is
bounded to three authenticated FDEs; it never loads or executes target code.
"""
import argparse
import bisect
from collections import Counter
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import platform
import tempfile

import bincode_varint as bv

MASK = (1 << 64) - 1
READER, WRAPPER, ERROR = 0x466dad0, 0x466be70, 0x466dac0
RANGES = {READER: 0x466dc0c, WRAPPER: 0x466bf55, ERROR: 0x466dace}
TABLES = {0x6f6ee8: 16, 0x6f6eb8: 16}
SLOTS = {0x57745d0: READER, 0x57745e8: ERROR}
OUT, STATE, BUFFER, STACK, EXIT = 0x10000, 0x20000, 0x30000, 0x80000, MASK
REGS = {}
for base, short in [('rax', 'a'), ('rbx', 'b'), ('rcx', 'c'), ('rdx', 'd')]:
    for name, width in [(base, 64), ('e' + short + 'x', 32), (short + 'x', 16), (short + 'l', 8)]:
        REGS[name] = (base, width)
for base in ['rsi', 'rdi', 'rsp', 'rbp']:
    for name, width in [(base, 64), ('e' + base[1:], 32), (base[1:], 16), (base[1:] + 'l', 8)]:
        REGS[name] = (base, width)
for i in range(8, 16):
    for suffix, width in [('', 64), ('d', 32), ('w', 16), ('b', 8)]:
        REGS[f'r{i}{suffix}'] = (f'r{i}', width)


def require(condition, message):
    if not condition:
        raise bv.EvidenceError(message)


def affine(text):
    """Parse the restricted Intel address grammar without eval."""
    terms, constant = Counter(), 0
    for term in re.findall(r'[+-]?[^+-]+', text.replace(' ', '')):
        sign = -1 if term.startswith('-') else 1
        term = term.lstrip('+-')
        factors = term.split('*')
        if len(factors) == 2:
            reg = next((x for x in factors if x in REGS), None)
            require(reg is not None, 'unsupported scaled address')
            scale = int(factors[1] if factors[0] == reg else factors[0], 0)
            require(scale in (1, 2, 4, 8), 'unsupported scale')
            terms[reg] += sign * scale
        elif term in REGS or term == 'rip':
            terms[term] += sign
        else:
            constant += sign * int(term, 0)
    return tuple(sorted(terms.items())), constant & MASK


def operand(text, branch=False):
    text = text.strip().lower()
    if text in REGS:
        return ('reg', text)
    if '[' in text:
        prefix, expression = text.split('[', 1)
        width = {'byte ptr': 8, 'word ptr': 16, 'dword ptr': 32, 'qword ptr': 64, '': 0}[prefix.strip()]
        return ('mem', width, *affine(expression.rstrip(']')))
    return ('imm', int(text, 16) if branch else int(text, 0))


@dataclass(frozen=True)
class Instruction:
    pc: int
    raw: bytes
    op: str
    args: tuple


def parse_listing(text, start, end, data, sections, *, semantic=True):
    rows = []
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$', line)
        if not match:
            continue
        pc, raw = int(match[1], 16), bytes.fromhex(match[2])
        if not start <= pc < end:
            continue
        assembly = match[3].split('#', 1)[0].split('<', 1)[0].strip().lower()
        require(bool(assembly), 'incomplete native instruction record')
        parts = assembly.split(None, 1)
        op = parts[0]
        args = tuple(operand(x, op.startswith('j')) for x in parts[1].split(',')) if semantic and len(parts) == 2 else ()
        off = bv.va_to_off(sections, pc)
        require(data[off:off + len(raw)] == raw, 'native instruction bytes disagree with snapshot')
        rows.append(Instruction(pc, raw, op, args))
    require(bool(rows) and rows[0].pc == start, 'native decoder missed FDE start')
    cursor = start
    for row in rows:
        require(row.pc == cursor, 'native decoder gap or overlap')
        cursor += len(row.raw)
    require(cursor == end, 'native decoder did not cover exact FDE')
    return rows


def canonical(row):
    args = []
    for arg in row.args:
        if arg[0] == 'mem':
            _, width, terms, constant = arg
            reduced = []
            for reg, scale in terms:
                if reg == 'rip':
                    constant += scale * (row.pc + len(row.raw))
                else:
                    reduced.append((reg, scale))
            args.append(('mem', width, tuple(reduced), constant & MASK))
        elif arg[0] == 'imm' and row.op in ('mov', 'add', 'sub', 'cmp', 'test', 'xor', 'rol'):
            destination = row.args[0]
            width = REGS[destination[1]][1] if destination[0] == 'reg' else destination[1]
            args.append(('imm', arg[1] % (1 << width)))
        else:
            args.append(arg)
    return row.pc, row.raw.hex(), row.op, args


def native_tools():
    gnu = shutil.which('objdump')
    llvm = os.environ.get('LLVM_OBJDUMP') or shutil.which('llvm-objdump')
    require(gnu is not None and 'GNU' in subprocess.check_output([gnu, '--version'], text=True), 'GNU objdump required')
    require(llvm is not None, 'LLVM_OBJDUMP or llvm-objdump required')
    return gnu, llvm


def native_pair(path, data, sections, start, end, *, semantic=True):
    gnu, llvm = native_tools()
    texts = []
    for exe, options in [(gnu, ['-M', 'intel', '--insn-width=16']),
                         (llvm, ['--x86-asm-syntax=intel', '--print-imm-hex'])]:
        argv = [exe, '-d', *options, f'--start-address={start:#x}', f'--stop-address={end:#x}', str(path)]
        text = subprocess.check_output(argv, text=True)
        texts.append(text.replace(str(path), '<owned-non-executable-snapshot>'))
    a, b = [parse_listing(t, start, end, data, sections, semantic=semantic) for t in texts]
    if semantic:
        require([canonical(x) for x in a] == [canonical(x) for x in b], 'native semantic disagreement')
    else:
        require([(x.pc, x.raw) for x in a] == [(x.pc, x.raw) for x in b], 'native boundary disagreement')
    return a, texts


class Machine:
    """Small fail-closed integer ISA subset, evaluated as Python data."""
    def __init__(self, program, ro, entry, payload, endian, flag=0, limit=MASK, count=0):
        self.program, self.mem = program, dict(ro)
        self.reg = {base: 0 for base, _ in REGS.values()}
        self.reg.update(rdi=OUT, rsi=STATE, rdx=endian, rsp=STACK, rbx=0x12345678abcdef00)
        self.pc, self.zero, self.carry = entry, False, False
        self.visited, self.branches = set(), set()
        self.writable = [(OUT, OUT + 24), (STATE, STATE + 40), (STACK - 256, STACK + 8)]
        for a, b in self.writable:
            self.mem.update({i: 0xa5 for i in range(a, b)})
        self.mem.update({BUFFER + i: value for i, value in enumerate(payload)})
        self.store(STACK, 64, EXIT)
        if entry == READER:
            self.store(STATE, 64, BUFFER)
            self.store(STATE + 8, 64, len(payload))
        else:
            self.store(STATE, 32, flag)
            self.store(STATE + 8, 64, limit)
            self.store(STATE + 16, 64, BUFFER)
            self.store(STATE + 24, 64, len(payload))
            self.store(STATE + 32, 64, count)

    def register(self, name):
        base, width = REGS[name]
        return self.reg[base] & ((1 << width) - 1)

    def address(self, arg, row):
        return (arg[3] + sum(scale * (row.pc + len(row.raw) if reg == 'rip' else self.register(reg))
                             for reg, scale in arg[2])) & MASK

    def load(self, address, width):
        require(all(address + i in self.mem for i in range(width // 8)), 'read outside bounded fixture/data')
        return int.from_bytes(bytes(self.mem[address + i] for i in range(width // 8)), 'little')

    def store(self, address, width, value):
        require(any(a <= address and address + width // 8 <= b for a, b in self.writable), 'write outside owned fixture')
        self.mem.update({address + i: byte for i, byte in enumerate((value % (1 << width)).to_bytes(width // 8, 'little'))})

    def read(self, arg, row):
        if arg[0] == 'reg':
            return self.register(arg[1])
        if arg[0] == 'imm':
            return arg[1]
        return self.load(self.address(arg, row), arg[1])

    def width(self, arg):
        return REGS[arg[1]][1] if arg[0] == 'reg' else arg[1]

    def write(self, arg, value, row):
        if arg[0] == 'mem':
            self.store(self.address(arg, row), arg[1], value)
            return
        require(arg[0] == 'reg', 'invalid destination')
        base, width = REGS[arg[1]]
        mask = (1 << width) - 1
        self.reg[base] = (value & mask) if width >= 32 else ((self.reg[base] & ~mask) | (value & mask))

    def run(self):
        for _ in range(256):
            row = self.program.get(self.pc)
            require(row is not None, f'branch outside validated program: {self.pc:#x}')
            self.visited.add(row.pc)
            op, args = row.op, row.args
            nxt = row.pc + len(row.raw)
            if op in ('mov', 'movzx', 'movsxd'):
                value = self.read(args[1], row)
                if op == 'movsxd' and value & (1 << 31):
                    value -= 1 << 32
                self.write(args[0], value, row)
            elif op == 'lea':
                self.write(args[0], self.address(args[1], row), row)
            elif op in ('add', 'sub', 'cmp', 'test', 'xor'):
                a, b = [self.read(x, row) for x in args]
                width = self.width(args[0])
                mask = (1 << width) - 1
                b &= mask
                value = {'add': lambda: a + b, 'sub': lambda: a - b, 'cmp': lambda: a - b,
                         'test': lambda: a & b, 'xor': lambda: a ^ b}[op]()
                self.carry = a + b > mask if op == 'add' else a < b if op in ('sub', 'cmp') else False
                self.zero = (value & mask) == 0
                if op not in ('cmp', 'test'):
                    self.write(args[0], value, row)
            elif op in ('bswap', 'rol'):
                width = self.width(args[0])
                value = self.read(args[0], row)
                if op == 'bswap':
                    value = int.from_bytes(value.to_bytes(width // 8, 'little'), 'big')
                else:
                    shift = self.read(args[1], row) % width
                    value = (value << shift) | (value >> (width - shift))
                self.write(args[0], value, row)
            elif op in ('cmove', 'cmovne'):
                take = self.zero if op == 'cmove' else not self.zero
                self.branches.add((row.pc, take))
                if take:
                    self.write(args[0], self.read(args[1], row), row)
            elif op in ('je', 'jne', 'ja', 'jae', 'jbe', 'jb'):
                take = {'je': self.zero, 'jne': not self.zero, 'ja': not self.carry and not self.zero,
                        'jae': not self.carry, 'jbe': self.carry or self.zero, 'jb': self.carry}[op]
                self.branches.add((row.pc, take))
                if take:
                    nxt = self.read(args[0], row)
            elif op == 'jmp':
                nxt = self.read(args[0], row)
            elif op in ('push', 'call'):
                self.reg['rsp'] -= 8
                self.store(self.reg['rsp'], 64, nxt if op == 'call' else self.read(args[0], row))
                if op == 'call':
                    nxt = self.read(args[0], row)
                    require(nxt in (READER, ERROR), 'unclosed indirect callee')
            elif op in ('pop', 'ret'):
                value = self.load(self.reg['rsp'], 64)
                self.reg['rsp'] += 8
                if op == 'pop':
                    self.write(args[0], value, row)
                elif value == EXIT:
                    require(self.reg['rax'] == OUT and self.reg['rsp'] == STACK + 8
                            and self.reg['rbx'] == 0x12345678abcdef00, 'return/callee-save contract')
                    return bytes(self.mem[OUT + i] for i in range(24)), bytes(self.mem[STATE + i] for i in range(40))
                else:
                    nxt = value
            else:
                raise bv.EvidenceError(f'unsupported instruction {op}')
            self.pc = nxt
        raise bv.EvidenceError('bounded evaluator step limit')


def word_model(entry, payload, endian, flag=0, limit=MASK, count=0):
    """Independent byte-level cursor/result equations, not instruction dispatch."""
    result, state = bytearray([0xa5] * 24), bytearray([0xa5] * 40)
    def put(offset, value, width=8):
        state[offset:offset + width] = value.to_bytes(width, 'little')
    wrapper = entry == WRAPPER
    at = 16 if wrapper else 0
    put(at, BUFFER)
    put(at + 8, len(payload))
    if wrapper:
        put(0, flag, 4)
        put(8, limit)
        put(32, count)
        if flag == 1:
            if count > MASK - 8:
                result[0] = 2
                return bytes(result), bytes(state)
            put(32, count + 8)
            if count + 8 > limit:
                result[0] = 2
                return bytes(result), bytes(state)
        endian = 0
    fast = wrapper and len(payload) > 8
    consumed = 0
    if not payload:
        result[0] = 0
        result[8:16] = (1).to_bytes(8, 'little')
    else:
        tag = payload[0]
        consumed = 0 if fast else 1
        if tag >= 254:
            result[:3] = bytes([3, 5, 4 if tag == 254 else 12])
        else:
            width = {251: 2, 252: 4, 253: 8}.get(tag, 0)
            if len(payload) < width + 1:
                result[0] = 0
                result[8:16] = (width + 1 - len(payload)).to_bytes(8, 'little')
            else:
                value = int.from_bytes(payload[1:width + 1], 'big' if endian else 'little') if width else tag
                result[0] = 18
                result[8:16] = value.to_bytes(8, 'little')
                consumed = width + 1
    put(at, BUFFER + consumed)
    put(at + 8, len(payload) - consumed)
    return bytes(result), bytes(state)


def fixtures():
    seen = set()
    def fresh(case):
        if case not in seen:
            seen.add(case)
            return case
        return None
    for entry in (READER, WRAPPER):
        for mode in (0, 1, 255) if entry == READER else (0, 1, 2):
            for length in range(19):
                for tag in range(256) if length else (0,):
                    payload = bytes([tag] + [(37 * i + tag * 11 + length * 7) & 255 for i in range(1, length)]) if length else b''
                    case = (entry, payload, mode if entry == READER else 255, mode if entry == WRAPPER else 0, MASK, 0)
                    if (new := fresh(case)) is not None:
                        yield new
    for length in (0, 1, 2, 3, 5, 8, 9, 17):
        for tag in (0, 250, 251, 252, 253, 254, 255):
            payload = bytes([tag] + [0xff] * (length - 1)) if length else b''
            for flag in (0, 1, 2):
                for limit, count in [(0, 0), (7, 0), (8, 0), (8, 1), (MASK, MASK - 8), (MASK, MASK - 7), (35, 32)]:
                    if (new := fresh((WRAPPER, payload, 255, flag, limit, count))) is not None:
                        yield new
    for width, tag in [(2, 251), (4, 252), (8, 253)]:
        for value in sorted({0, 1, 250, 251, 255, 256, (1 << (width * 8 - 1)), (1 << (width * 8)) - 1}):
            for endian in (0, 1, 255):
                encoded = bytes([tag]) + value.to_bytes(width, 'big' if endian else 'little')
                for extra in (b'', b'\x87' * 9):
                    for entry in (READER, WRAPPER):
                        if (new := fresh((entry, encoded + extra, endian, 0, MASK, 0))) is not None:
                            yield new


def collect(data, snapshot, *, identity=True):
    digest = hashlib.sha256(data).hexdigest()
    if identity:
        require(digest == bv.SHA256, 'not authenticated node94')
    sections = bv.sections(data)
    fdes = bv.fde_extents(data, sections)
    relocs = bv.relative_relocs(data, sections)
    for start, end in RANGES.items():
        require(fdes.get(start) == end, 'FDE range changed')
    for slot, target in SLOTS.items():
        require(relocs.get(slot) == target, 'callee RELATIVE binding changed')
    ro = {}
    for start, length in TABLES.items():
        off = bv.va_to_off(sections, start)
        ro.update({start + i: byte for i, byte in enumerate(data[off:off + length])})
    for slot, target in SLOTS.items():
        ro.update({slot + i: byte for i, byte in enumerate(target.to_bytes(8, 'little'))})
    program, native = {}, [[], []]
    for start, end in sorted(RANGES.items()):
        rows, texts = native_pair(snapshot, data, sections, start, end)
        program.update({row.pc: row for row in rows})
        for i, text in enumerate(texts):
            native[i].append(text)
    # Raw rel32 candidates are individually re-decoded from their containing
    # real FDE by both providers. They are not a bare byte-pattern call count.
    text = sections['.text']
    code = data[text['offset']:text['offset'] + text['size']]
    starts, callers, cache = sorted(fdes), [], {}
    for hit in re.finditer(rb'\xff[\x15\x25]', code):
        pc = text['addr'] + hit.start()
        if pc + 6 + struct.unpack_from('<i', code, hit.start() + 2)[0] != 0x57745d0:
            continue
        owner = starts[bisect.bisect_right(starts, pc) - 1]
        require(pc + 6 <= fdes[owner], 'call candidate outside FDE')
        if owner not in cache:
            rows, _ = native_pair(snapshot, data, sections, owner, fdes[owner], semantic=False)
            cache[owner] = {row.pc: row for row in rows}
        row = cache[owner].get(pc)
        require(row is not None and row.op in ('call', 'jmp') and len(row.raw) == 6, 'not a decoded call/tail jump')
        callers.append({'pc': hex(pc), 'fde': [hex(owner), hex(fdes[owner])], 'bytes': row.raw.hex(), 'op': row.op})
    visited, branches, outcomes, ledger = set(), set(), Counter(), []
    count = 0
    for case in fixtures():
        machine = Machine(program, ro, *case)
        observed = machine.run()
        expected = word_model(*case)
        require(observed == expected, f'instruction/model disagreement for {case}')
        visited.update(machine.visited)
        branches.update(machine.branches)
        outcomes[str(observed[0][0])] += 1
        count += 1
        entry, payload, endian, flag, limit, charge = case
        ledger.append('\t'.join([hex(entry), payload.hex(), str(endian), str(flag), hex(limit), hex(charge), observed[0].hex(), observed[1].hex()]))
    branch_sites = {row.pc for row in program.values() if row.op in ('je', 'jne', 'ja', 'jae', 'jbe', 'jb', 'cmove', 'cmovne')}
    report = {
        'schema': 'hyperliquid.kind5-reader.static.v1', 'target_sha256': digest,
        'authenticated_target': identity and digest == bv.SHA256,
        'fde_ranges': {hex(a): hex(b) for a, b in RANGES.items()},
        'instruction_count': len(program), 'instruction_bytes': sum(len(x.raw) for x in program.values()),
        'fixture_count': count, 'mismatches': 0, 'outcome_tag_counts': dict(sorted(outcomes.items())),
        'visited_instructions': len(visited), 'unvisited': [hex(x) for x in sorted(set(program) - visited)],
        'conditional_sites': len(branch_sites), 'covered_conditional_outcomes': len(branches),
        'missing_conditional_outcomes': [[hex(x), take] for x in sorted(branch_sites) for take in (False, True) if (x, take) not in branches],
        'reader_got_slot': '0x57745d0', 'reader_slot_callers': callers,
        'error_got_slot': '0x57745e8', 'error_target': hex(ERROR),
        'jump_tables': {hex(address): {
            'bytes': data[bv.va_to_off(sections, address):bv.va_to_off(sections, address) + length].hex(),
            'targets': [hex(address + struct.unpack_from('<i', data, bv.va_to_off(sections, address) + i)[0])
                        for i in range(0, length, 4)],
        } for address, length in TABLES.items()},
        'relative_slots': {hex(slot): hex(target) for slot, target in SLOTS.items()},
        'normalization': 'no machine-byte masks; native header snapshot pathname replaced; RIP expressions resolved; signed immediate displays represented at their exact destination width',
        'limits': ['finite instruction evaluation, not captured execution or Rust equivalence', 'kind5 type name remains opaque', 'only one wrapper fully evaluated; other caller bodies not interpreted', 'no progress gate requested'],
    }
    return report, ('\n'.join(ledger) + '\n').encode(), ['\n'.join(x) for x in native]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=bv.TARGET)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    require(hashlib.sha256(data).hexdigest() == bv.SHA256, 'not authenticated node94')
    require(not args.output.exists(), 'output already exists; preserve evidence')
    with tempfile.TemporaryDirectory(prefix='kind5-static-') as tmp:
        snapshot = Path(tmp) / 'input.elf'
        snapshot.write_bytes(data)
        snapshot.chmod(0o600)
        report, ledger, native = collect(data, snapshot)
    args.output.mkdir(parents=True)
    (args.output / 'reader.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode='wb', filename='', mtime=0) as output:
        output.write(ledger)
    (args.output / 'cases.tsv.gz').write_bytes(compressed.getvalue())
    for name, text in zip(['gnu.txt', 'llvm.txt'], native):
        (args.output / name).write_text(text)
    gnu, llvm = native_tools()
    versions = {'python': platform.python_version(), 'platform': platform.platform(),
                'gnu': subprocess.check_output([gnu, '--version'], text=True),
                'llvm': subprocess.check_output([llvm, '--version'], text=True)}
    (args.output / 'toolchain.json').write_text(json.dumps(versions, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: report[k] for k in ['fixture_count', 'instruction_count', 'visited_instructions', 'mismatches']}))


if __name__ == '__main__':
    main()

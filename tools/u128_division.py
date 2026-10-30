#!/usr/bin/env python3
"""Static, bounded evaluation of node #94's 198-byte unsigned division helper.

The captured ELF is data. LLVM decodes a fixed FDE window; the evaluator below
implements only the integer instructions found there. No captured code executes.
"""
import argparse
import collections
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import random
import re
import subprocess

from spot_wei_scale import EvidenceError, Fdes, Image, SHA256, check_digest

ROOT = Path(__file__).resolve().parents[1]
ENTRY, END, SLOT = 0x565f5a0, 0x565f666, 0x576e1a8
MASK = (1 << 64) - 1
REGISTERS = {}
for full, half, byte in [('rax', 'eax', 'al'), ('rbx', 'ebx', 'bl'),
                         ('rcx', 'ecx', 'cl'), ('rdx', 'edx', 'dl'),
                         ('rdi', 'edi', 'dil'), ('rsi', 'esi', 'sil')]:
    for name, width in [(full, 64), (half, 32), (byte, 8)]:
        REGISTERS[name] = (full, width)
for i in range(8, 12):
    for suffix, width in [('', 64), ('d', 32), ('b', 8)]:
        REGISTERS[f'r{i}{suffix}'] = (f'r{i}', width)


class DivideError(Exception):
    def __init__(self, pc, width, reason):
        self.pc, self.width, self.reason = pc, width, reason
        super().__init__(f'{reason} at {pc:#x}, width {width}')


@lru_cache(maxsize=None)
def decoder_flags(tool):
    version = subprocess.check_output([tool, '--version'], text=True)
    if 'GNU objdump' in version:
        return ['-M', 'intel']
    if 'LLVM' in version:
        return ['--x86-asm-syntax=intel']
    raise EvidenceError('an identified GNU or LLVM objdump is required')


def disassemble(binary, tool):
    return subprocess.check_output([tool, '-d', *decoder_flags(tool),
                                    f'--start-address={ENTRY:#x}',
                                    f'--stop-address={END:#x}', str(binary)], text=True)


def decode(text, image, *, start=ENTRY, end=END):
    """Bind every decoded byte and internal branch to the fixed ELF window."""
    rows = []
    for line in text.splitlines():
        match = re.fullmatch(
            r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2} )*[0-9a-f]{2})\s+([a-z]+)\s*(.*?)\s*',
            line,
        )
        if not match:
            if re.match(r'\s*[0-9a-f]+:', line):
                raise EvidenceError('unparsed instruction line')
            continue
        address, raw, mnemonic, operands = match.groups()
        pc, raw = int(address, 16), bytes.fromhex(raw)
        operands = operands.split(' #', 1)[0].split(' <', 1)[0]
        args = tuple(part.strip() for part in operands.split(',')) if operands else ()
        if mnemonic.startswith('j') and args and not args[0].startswith('0x'):
            args = (hex(int(args[0], 16)),)
        if mnemonic == 'shr' and len(args) == 1:
            args = (*args, '1')
        # Canonicalize only textual spellings: GNU prints an explicit shift by
        # one and unsigned immediates where LLVM may use implicit one / -0x1.
        width = REGISTERS.get(args[0], ('', 64))[1] if args else 64
        args = tuple(hex(int(arg, 0) & ((1 << width) - 1))
                     if re.fullmatch(r'-?(?:0x[0-9a-f]+|[0-9]+)', arg) else arg
                     for arg in args)
        rows.append((pc, raw, mnemonic, args))
    cursor = start
    for pc, raw, mnemonic, args in rows:
        if pc != cursor or raw != image.read(pc, len(raw)):
            raise EvidenceError('listing does not exactly cover authenticated bytes')
        cursor += len(raw)
    if cursor != end:
        raise EvidenceError('listing does not reach the FDE endpoint')
    starts = {row[0] for row in rows}
    for _, _, mnemonic, args in rows:
        if mnemonic.startswith('j') and int(args[0], 0) not in starts:
            raise EvidenceError('branch is not an instruction start in the helper')
    return rows


class Machine:
    """Only the observed register-only x86 subset, with defined-bit tracking.

    Unknown incoming register bits stay unknown through partial MOVs. A shift
    uses CL only; reading any other unknown arithmetic operand is an error.
    CF/ZF become unavailable after instructions that leave them undefined.
    """
    def __init__(self, rows):
        self.rows = {row[0]: row for row in rows}
        self.visited = set()
        self.decisions = set()

    def get(self, name):
        full, width = REGISTERS[name]
        value, known = self.regs.get(full, (0, 0))
        mask = (1 << width) - 1
        return value & mask, known & mask

    def put(self, name, value, known=None):
        full, width = REGISTERS[name]
        mask = (1 << width) - 1
        known = mask if known is None else known & mask
        if width == 32:
            self.regs[full] = (value & mask, known | (MASK ^ mask))
        elif width == 64:
            self.regs[full] = (value & mask, known)
        else:
            old, old_known = self.regs.get(full, (0, 0))
            self.regs[full] = ((old & ~mask) | (value & mask),
                               (old_known & ~mask) | known)

    def number(self, operand, width):
        mask = (1 << width) - 1
        if operand in REGISTERS:
            value, known = self.get(operand)
            if known != mask:
                raise EvidenceError(f'undefined register bits read: {operand}')
            return value
        return int(operand, 0) & mask

    def flag(self, name):
        value = self.flags[name]
        if value is None:
            raise EvidenceError(f'undefined {name} read')
        return value

    def run(self, numerator, denominator):
        if not (0 <= numerator < 1 << 128 and 0 <= denominator < 1 << 128):
            raise EvidenceError('inputs must be unsigned 128-bit integers')
        self.regs, self.flags, self.stack = {}, {'cf': None, 'zf': None}, []
        for name, value in [('rdi', numerator & MASK), ('rsi', numerator >> 64),
                            ('rdx', denominator & MASK), ('rcx', denominator >> 64)]:
            self.put(name, value)
        pc = ENTRY
        for _ in range(100):
            if pc not in self.rows:
                raise EvidenceError('execution left the bounded instruction graph')
            self.visited.add(pc)
            _, raw, op, args = self.rows[pc]
            next_pc = pc + len(raw)
            if op == 'mov':
                dst, src = args
                if src in REGISTERS:
                    self.put(dst, *self.get(src))
                else:
                    self.put(dst, int(src, 0))
            elif op in {'push', 'pop'}:
                if args != ('rbx',):
                    raise EvidenceError('unexpected stack operation')
                if op == 'push':
                    self.stack.append(self.regs.get('rbx', (0, 0)))
                else:
                    if not self.stack:
                        raise EvidenceError('stack underflow')
                    self.regs['rbx'] = self.stack.pop()
            elif op == 'ret':
                if self.stack or self.regs.get('rbx', (0, 0)) != (0, 0):
                    raise EvidenceError('callee-saved RBX/stack not restored')
                return self.number('rax', 64) | self.number('rdx', 64) << 64, pc
            elif op in {'je', 'jae'}:
                taken = self.flag('zf') if op == 'je' else not self.flag('cf')
                self.decisions.add((pc, taken))
                if taken:
                    next_pc = int(args[0], 0)
            elif op in {'cmove', 'cmovb'}:
                taken = self.flag('zf' if op == 'cmove' else 'cf')
                self.decisions.add((pc, taken))
                if taken:
                    self.put(args[0], *self.get(args[1]))
            elif op == 'bsr':
                value = self.number(args[1], 64)
                self.flags = {'cf': None, 'zf': value == 0}
                self.put(args[0], value.bit_length() - 1 if value else 0,
                         MASK if value else 0)
            elif op == 'div':
                width = REGISTERS[args[0]][1]
                low, high = ('rax', 'rdx') if width == 64 else ('eax', 'edx')
                dividend = self.number(low, width) | self.number(high, width) << width
                divisor = self.number(args[0], width)
                if divisor == 0:
                    raise DivideError(pc, width, 'zero divisor')
                quotient, remainder = divmod(dividend, divisor)
                if quotient >= 1 << width:
                    raise DivideError(pc, width, 'quotient overflow')
                self.put(low, quotient)
                self.put(high, remainder)
                self.flags = {'cf': None, 'zf': None}
            elif op == 'mul':
                product = self.number('rax', 64) * self.number(args[0], 64)
                self.put('rax', product)
                self.put('rdx', product >> 64)
                self.flags = {'cf': product > MASK, 'zf': None}
            elif op in {'shr', 'shld', 'shrd'}:
                dst = args[0]
                width = REGISTERS[dst][1]
                count = 1 if len(args) == 1 else self.number(args[-1], 8)
                count &= 63 if width == 64 else 31
                if count:
                    value = self.number(dst, width)
                    mask = (1 << width) - 1
                    if op == 'shr':
                        result, carry = value >> count, (value >> (count - 1)) & 1
                    else:
                        source = self.number(args[1], width)
                        if op == 'shrd':
                            result = (value >> count) | (source << (width - count))
                            carry = (value >> (count - 1)) & 1
                        else:
                            result = (value << count) | (source >> (width - count))
                            carry = (value >> (width - count)) & 1
                    self.put(dst, result)
                    self.flags = {'cf': bool(carry), 'zf': (result & mask) == 0}
            elif op in {'xor', 'or', 'test', 'sub', 'add', 'sbb', 'cmp', 'imul'}:
                dst, src = args
                width = REGISTERS[dst][1]
                mask = (1 << width) - 1
                if op == 'xor' and dst == src:
                    a = b = 0
                else:
                    a, b = self.number(dst, width), self.number(src, width)
                if op in {'xor', 'or', 'test'}:
                    result = a ^ b if op == 'xor' else a | b if op == 'or' else a & b
                    self.flags = {'cf': False, 'zf': result == 0}
                elif op == 'imul':
                    result = a * b
                    self.flags = {'cf': None, 'zf': None}
                elif op == 'add':
                    result = a + b
                    self.flags = {'cf': result > mask, 'zf': (result & mask) == 0}
                else:
                    borrow = int(self.flag('cf')) if op == 'sbb' else 0
                    result = a - b - borrow
                    self.flags = {'cf': a < b + borrow, 'zf': (result & mask) == 0}
                if op not in {'test', 'cmp'}:
                    self.put(dst, result)
            else:
                raise EvidenceError(f'unsupported instruction: {op}')
            pc = next_pc
        raise EvidenceError('instruction budget exceeded')


def vectors():
    """Deterministic boundaries, quotient/remainder edges, and fixed-seed samples."""
    top = (1 << 128) - 1
    edges = {0, top}
    for bit in range(128):
        edges.update(x for x in [(1 << bit) - 1, 1 << bit, (1 << bit) + 1] if x <= top)
    for n in sorted(edges):
        for d in sorted(edges - {0}):
            yield n, d
    rng = random.Random(940128)
    for _ in range(4096):
        n, d = rng.getrandbits(128), rng.getrandbits(128) or 1
        yield n, d
        d = rng.getrandbits(64) or 1
        yield n, d
    for d in sorted(edges - {0}):
        for q in [1, 2, 3, (1 << 32) - 1, 1 << 32, (1 << 64) - 1]:
            for delta in [-1, 0, 1]:
                n = d * q + delta
                if 0 <= n <= top:
                    yield n, d


def produce(binary, listing):
    data = Path(binary).read_bytes()
    check_digest(data)
    image = Image(data)
    extent = Fdes(image).range_of(ENTRY)
    if (extent['start'], extent['end']) != (ENTRY, END):
        raise EvidenceError('unexpected FDE extent')
    if image.relative_relocs().get(SLOT) != ENTRY:
        raise EvidenceError('call slot no longer targets the helper')
    rows = decode(listing, image)
    machine, counts, digest = Machine(rows), collections.Counter(), hashlib.sha256()
    for numerator, denominator in vectors():
        observed, return_pc = machine.run(numerator, denominator)
        if observed != numerator // denominator:
            raise EvidenceError(f'quotient mismatch for {numerator:#x}/{denominator:#x}')
        digest.update(f'{numerator:032x}/{denominator:032x}={observed:032x}\n'.encode())
        counts[f'{return_pc:#x}'] += 1
    faults = []
    for numerator in [0, 1, (1 << 64) - 1, 1 << 64, 1 << 96, (1 << 128) - 1]:
        try:
            machine.run(numerator, 0)
        except DivideError as error:
            faults.append({'numerator': hex(numerator), 'pc': hex(error.pc),
                           'width': error.width, 'reason': error.reason})
        else:
            raise EvidenceError('zero denominator returned instead of trapping')
    return {'schema': 'node94-u128-division-static-v1', 'target_sha256': SHA256,
            'entry_va': hex(ENTRY), 'end_va': hex(END), 'fde_va': hex(extent['fde']),
            'slot_va': hex(SLOT), 'raw_window_sha256': hashlib.sha256(image.read(ENTRY, END-ENTRY)).hexdigest(),
            'instructions': len(rows), 'visited_instructions': len(machine.visited),
            'vectors': sum(counts.values()), 'mismatches': 0,
            'return_counts': dict(sorted(counts.items())), 'vector_result_sha256': digest.hexdigest(),
            'decisions': [{'va': hex(pc), 'taken': taken} for pc, taken in sorted(machine.decisions)],
            'zero_divisor_controls': faults,
            'captured_code_executed': False,
            'limits': ['Finite static evaluator checks, not a universal proof or native execution.',
                       'Only this #94 helper; no #115, caller reachability, library attribution or component gate.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--objdump', default=os.environ.get('LLVM_OBJDUMP', 'objdump'))
    args = parser.parse_args()
    binary = ROOT / 'artifacts/node/94/hl-node'
    check_digest(binary.read_bytes())
    listing = disassemble(binary, args.objdump)
    result = produce(binary, listing)
    args.out.mkdir(parents=True, exist_ok=True)
    # Keep machine-dependent file paths out of the retained decoder output.
    listing = listing.replace(str(binary), 'artifacts/node/94/hl-node')
    (args.out / 'helper.objdump.txt').write_text(listing)
    (args.out / 'evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Node94 compact-string alias: bounded static integer transfer evaluation.

The target is never loaded as executable code. Native tools only disassemble it;
Python applies the decoded integer equations to synthetic memory. This is finite
static evidence, not a runtime oracle, a general x86 emulator or a Rust recovery.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from artifacts import ROOT, check
from short_string_static import read_va

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RANGES = {'producer': (0x13C6060, 0x13C629E), 'feed': (0x13DAA30, 0x13DAC07)}
MASK = (1 << 64) - 1
IV = (0x736F6D6570736575, 0x646F72616E646F6D,
      0x6C7967656E657261, 0x7465646279746573)
MAGIC = 0x4EC4EC4EC4EC4EC5


def instructions(text):
    """Read native decoder instruction records, retaining bytes and Intel operands."""
    result = {}
    for line in text.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S.*)', line)
        if m:
            va = int(m[1], 16)
            if va in result:
                raise ValueError('Duplicate instruction')
            body = bytes.fromhex(m[2])
            asm = m[3].split('#', 1)[0].split('<', 1)[0].strip().lower()
            result[va] = (body, asm)
    return result


def decode(binary, data):
    frames = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    extents = [(int(a, 16), int(b, 16)) for a, b in
               re.findall(r'FDE[^\n]*pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)', frames)]
    code, raw = {}, {}
    llvm = os.environ.get('LLVM_OBJDUMP', 'llvm-objdump')
    for name, (begin, end) in RANGES.items():
        if extents.count((begin, end)) != 1:
            raise ValueError('Expected exactly one full FDE: ' + name)
        common = [f'--start-address={begin:#x}', f'--stop-address={end:#x}', str(binary)]
        gnu = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                       *common], text=True)
        other = subprocess.check_output([llvm, '--disassemble', '--x86-asm-syntax=intel',
                                         *common], text=True)
        one, two = instructions(gnu), instructions(other)
        if {v: b for v, (b, _) in one.items()} != {v: b for v, (b, _) in two.items()}:
            raise ValueError('GNU/LLVM instruction boundary or byte disagreement')
        cursor = begin
        for va, (body, _) in one.items():
            if va != cursor or read_va(data, va, len(body))[1] != body:
                raise ValueError('Incomplete or non-target decode')
            cursor += len(body)
        if cursor != end:
            raise ValueError('Incomplete FDE decode')
        code.update(one)
        raw[name + '.gnu.txt'] = gnu.replace(str(binary), '<authenticated-node94>')
        raw[name + '.llvm.txt'] = other.replace(str(binary), '<authenticated-node94>')
    raw['frames.txt'] = '\n'.join(line for line in frames.splitlines() if 'FDE' in line
        and any(f'pc={a:016x}..{b:016x}' in line for a, b in RANGES.values())) + '\n'
    return code, raw


REGISTERS = {}
for root, names in {'rax': ('eax', 'ax', 'al'), 'rbx': ('ebx', 'bx', 'bl'),
                    'rcx': ('ecx', 'cx', 'cl'), 'rdx': ('edx', 'dx', 'dl'),
                    'rsi': ('esi', 'si', 'sil'), 'rdi': ('edi', 'di', 'dil'),
                    'rbp': ('ebp', 'bp', 'bpl'), 'rsp': ('esp', 'sp', 'spl')}.items():
    REGISTERS[root] = (root, 64)
    for name, width in zip(names, (32, 16, 8)):
        REGISTERS[name] = (root, width)
for n in range(8, 16):
    for suffix, width in (('', 64), ('d', 32), ('w', 16), ('b', 8)):
        REGISTERS[f'r{n}{suffix}'] = (f'r{n}', width)
REGISTERS['xmm0'] = ('xmm0', 128)


class Transfers:
    """Only the integer/load/store/control equations present in the two FDEs.

    No host pointers, system calls, JIT, executable mapping or external callee.
    Unknown instructions, memory escapes, allocation and step-budget overflow
    are errors. All state is disposable Python integers and bytearrays.
    """
    def __init__(self, code):
        self.code = code
        self.reg = {r: 0xABCDEF0123456789 for r, _ in REGISTERS.values()}
        self.reg['rsp'] = 0x900000
        self.reg['xmm0'] = 0
        self.memory = [(0x8FF000, bytearray(0x2000), True)]
        self.zf = self.cf = self.sf = self.of = False
        self.known_flags = set()
        self.visits, self.edges = Counter(), Counter()
        self.steps = 0
        self.counter_hashes = []

    def map(self, address, content, writable=False):
        if any(address < a + len(b) and a < address + len(content)
               for a, b, _ in self.memory):
            raise ValueError('Overlapping synthetic region')
        self.memory.append((address, bytearray(content), writable))

    def load(self, address, width):
        for a, b, _ in self.memory:
            if a <= address and address + width // 8 <= a + len(b):
                return int.from_bytes(b[address-a:address-a+width//8], 'little')
        raise ValueError(f'Out-of-region read {address:#x}/{width}')

    def store(self, address, width, value):
        for a, b, writable in self.memory:
            if a <= address and address + width // 8 <= a + len(b):
                if not writable:
                    raise ValueError('Write to synthetic read-only input')
                b[address-a:address-a+width//8] = (value & ((1 << width)-1)).to_bytes(width//8, 'little')
                return
        raise ValueError(f'Out-of-region write {address:#x}/{width}')

    def width(self, operand):
        if operand in REGISTERS:
            return REGISTERS[operand][1]
        sizes = {'byte': 8, 'word': 16, 'dword': 32, 'qword': 64, 'xmmword': 128}
        if operand.split()[0] in sizes:
            return sizes[operand.split()[0]]
        raise ValueError('No operand width: ' + operand)

    def address(self, operand):
        expression = operand[operand.index('[')+1:operand.index(']')]
        total = 0
        for term in expression.replace('-', '+-').split('+'):
            term = term.strip()
            sign = -1 if term.startswith('-') else 1
            term = term.lstrip('-')
            factors = term.split('*')
            v = 1
            for factor in factors:
                v *= self.get(factor.strip())
            total += sign*v
        return total & MASK

    def get(self, operand):
        if operand in REGISTERS:
            root, width = REGISTERS[operand]
            return self.reg[root] & ((1 << width)-1)
        if '[' in operand:
            return self.load(self.address(operand), self.width(operand))
        return int(operand, 16)

    def put(self, operand, value):
        width = self.width(operand)
        value &= (1 << width)-1
        if '[' in operand:
            self.store(self.address(operand), width, value)
        else:
            root, _ = REGISTERS[operand]
            self.reg[root] = value if width >= 32 else (self.reg[root] & ~((1 << width)-1)) | value

    def flags(self, a, b, result, width, subtraction=False):
        mask = (1 << width)-1
        value = result & mask
        self.zf, self.sf = value == 0, bool(value & (1 << (width-1)))
        self.cf = a < b if subtraction else result > mask
        self.of = bool(((a ^ b) if subtraction else ~(a ^ b)) &
                       (a ^ value) & (1 << (width-1)))
        self.known_flags = {'cf', 'zf', 'sf', 'of'}

    def require_flags(self, *names):
        if not set(names) <= self.known_flags:
            raise ValueError('A branch consumes unmodeled flags')

    def run(self, entry, budget=200000):
        pc, depth = entry, 0
        preserved = {r: self.get(r) for r in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15', 'rsp')}
        while True:
            self.steps += 1
            if self.steps > budget or pc not in self.code:
                raise ValueError('Static transfer budget/range exceeded')
            body, asm = self.code[pc]
            self.visits[pc] += 1
            if pc == 0x13C6221:
                self.counter_hashes.append((self.get('ebp'), self.get('r14')))
            op, *tail = asm.split(None, 1)
            args = [x.strip() for x in tail[0].split(',')] if tail else []
            nxt = pc + len(body)
            if op in ('mov', 'movabs', 'movzx', 'movups'):
                self.put(args[0], self.get(args[1]))
            elif op == 'lea':
                self.put(args[0], self.address(args[1]))
            elif op in ('xor', 'xorps', 'or', 'and', 'add', 'sub', 'cmp', 'test'):
                a, b = self.get(args[0]), self.get(args[1])
                width = self.width(args[0])
                if op in ('xor', 'xorps'): value = a ^ b
                elif op == 'or': value = a | b
                elif op in ('and', 'test'): value = a & b
                elif op == 'add': value = a + b
                else: value = a - b
                if op in ('add', 'sub', 'cmp'):
                    self.flags(a, b, value, width, op != 'add')
                elif op != 'xorps':
                    self.zf = (value & ((1 << width)-1)) == 0
                    self.sf = bool(value & (1 << (width-1)))
                    self.cf = self.of = False
                    self.known_flags = {'cf', 'zf', 'sf', 'of'}
                if op not in ('cmp', 'test'):
                    self.put(args[0], value)
            elif op in ('rol', 'shr', 'shl'):
                a, width = self.get(args[0]), self.width(args[0])
                shift = self.get(args[1]) & (63 if width == 64 else 31)
                if op == 'rol':
                    shift %= width
                    value = (a << shift) | (a >> ((width-shift) % width))
                else:
                    value = a >> shift if op == 'shr' else a << shift
                self.put(args[0], value)
                # Fail if a later conditional consumes flags we did not model.
                self.known_flags = set()
            elif op == 'inc':
                a, cf, cf_known = self.get(args[0]), self.cf, 'cf' in self.known_flags
                self.flags(a, 1, a+1, self.width(args[0]))
                self.cf = cf
                if not cf_known:
                    self.known_flags.discard('cf')
                self.put(args[0], a+1)
            elif op == 'mul':
                product = self.get('rax') * self.get(args[0])
                self.put('rax', product)
                self.put('rdx', product >> 64)
                self.cf = self.of = bool(product >> 64)
                self.known_flags = {'cf', 'of'}
            elif op == 'cmovb':
                self.require_flags('cf')
                if self.cf:
                    self.put(args[0], self.get(args[1]))
            elif op in ('push', 'pop'):
                if op == 'push':
                    value = self.get(args[0])
                    self.reg['rsp'] -= 8
                    self.store(self.reg['rsp'], 64, value)
                else:
                    self.put(args[0], self.load(self.reg['rsp'], 64))
                    self.reg['rsp'] += 8
            elif op == 'call':
                dest = int(args[0], 16)
                if dest != RANGES['feed'][0]:
                    raise ValueError('Unclosed callee (including output growth)')
                self.reg['rsp'] -= 8
                self.store(self.reg['rsp'], 64, nxt)
                depth += 1
                nxt = dest
            elif op == 'ret':
                if not depth:
                    if any(self.get(r) != value for r, value in preserved.items()):
                        raise ValueError('Nonvolatile register/stack transfer changed')
                    return
                nxt = self.load(self.reg['rsp'], 64)
                self.reg['rsp'] += 8
                depth -= 1
            elif op in ('jmp', 'je', 'jne', 'jb', 'jae', 'jge'):
                self.require_flags(*{'jmp': (), 'je': ('zf',), 'jne': ('zf',),
                                     'jb': ('cf',), 'jae': ('cf',), 'jge': ('sf', 'of')}[op])
                take = {'jmp': True, 'je': self.zf, 'jne': not self.zf,
                        'jb': self.cf, 'jae': not self.cf, 'jge': self.sf == self.of}[op]
                self.edges[(pc, take)] += 1
                if take:
                    nxt = int(args[0], 16)
            elif op != 'nop':
                raise ValueError('Unsupported equation: ' + asm)
            pc = nxt


def rotate(x, bits):
    return ((x << bits) | (x >> (64-bits))) & MASK


def round_words(v):
    """Independent word equations; order is v0,v1,v2,v3, unlike target memory."""
    a, b, c, d = v
    a = (a+b) & MASK
    b = rotate(b, 13) ^ a
    a = rotate(a, 32)
    c = (c+d) & MASK
    d = rotate(d, 16) ^ c
    a = (a+d) & MASK
    d = rotate(d, 21) ^ a
    c = (c+b) & MASK
    b = rotate(b, 17) ^ c
    return [a, b, rotate(c, 32), d]


def compress(v, word):
    v = list(v)
    v[3] ^= word
    v = round_words(v)
    v[0] ^= word
    return v


def stream_state(chunks):
    joined = b''.join(chunks)
    v = list(IV)
    end = len(joined) - len(joined) % 8
    for offset in range(0, end, 8):
        v = compress(v, int.from_bytes(joined[offset:offset+8], 'little'))
    return v, len(joined), int.from_bytes(joined[end:], 'little'), len(joined)-end


def hash_words(message):
    v, length, tail, _ = stream_state([message])
    v = compress(v, tail | ((length & 255) << 56))
    v[2] ^= 255
    for _ in range(3):
        v = round_words(v)
    return v[0] ^ v[1] ^ v[2] ^ v[3]


def alias(message):
    return bytes(65 + hash_words(message+b'\xff'+i.to_bytes(4, 'little')) % 26 for i in range(10))


def alias_transfers(code, message, capacity=10):
    t = Transfers(code)
    t.map(0x10000, message)
    t.map(0x20000, struct.pack('<QQ', 0x10000, len(message)))
    t.map(0x30000, struct.pack('<Qii', 0x20000, 0, 10))
    t.map(0x40000, struct.pack('<QQQ', capacity, 0x50000, 0), True)
    t.map(0x50000, bytes(capacity), True)
    t.put('rdi', 0x30000)
    t.put('rsi', 0x40000)
    t.run(RANGES['producer'][0])
    length = t.load(0x40010, 64)
    if length != 10:
        raise ValueError('Unexpected output length')
    return bytes(t.load(0x50000+i, 8) for i in range(length)), t


def feed_transfers(code, chunks):
    t = Transfers(code)
    # Target layout is v0,v2,v1,v3, two reserved words, length, tail, tail-count.
    t.map(0x10000, struct.pack('<9Q', IV[0], IV[2], IV[1], IV[3], 0, 0, 0, 0, 0), True)
    history = []
    for i, chunk in enumerate(chunks):
        addr = 0x20000 + 0x1000*i
        t.map(addr, chunk)
        t.put('rdi', 0x10000)
        t.put('rsi', addr)
        t.put('rdx', len(chunk))
        t.run(RANGES['feed'][0])
        words = [t.load(0x10000+8*j, 64) for j in range(9)]
        history.append(([words[j] for j in (0, 2, 1, 3)], words[6], words[7], words[8]))
    return history, t


def fixtures():
    # Byte lengths, not character lengths. All fixtures are generated fiction.
    lengths = list(range(65)) + [127, 128, 129, 255, 256, 257, 511, 512, 513]
    return [bytes((i*73+n*19) & 255 for i in range(n)) for n in lengths] + [
        b'A'*17, b'\0'*24, bytes(range(256)), 'fictional-\u03b1-\U0001f30d-identifier'.encode()]


def evaluate(code):
    visits, edges, vectors = Counter(), Counter(), []
    feed_cases = 0
    def record(t):
        visits.update(t.visits)
        edges.update(t.edges)
    for message in fixtures():
        actual, t = alias_transfers(code, message)
        expected_hashes = [(i, hash_words(message+b'\xff'+i.to_bytes(4, 'little'))) for i in range(10)]
        if t.counter_hashes != expected_hashes:
            raise ValueError(f'Counter hash mismatch for {message.hex()}')
        expected = alias(message)
        if actual != expected:
            raise ValueError(f'Alias mismatch for {message.hex()}: {actual!r} != {expected!r}')
        record(t)
        vectors.append({'input_hex': message.hex(), 'bytes': len(message), 'alias_ascii': actual.decode(),
                        'counter_hashes_hex': [f'{h:016x}' for _, h in t.counter_hashes]})
    # Every initial tail residue and each next chunk length across 8-byte bounds;
    # compare after EACH write, not only the final digest.
    for prefix in range(8):
        for size in range(33):
            chunks = [bytes(range(prefix)), bytes((i*37+5) & 255 for i in range(size)), b'\xff', b'\x09\0\0\0']
            history, t = feed_transfers(code, chunks)
            for i, state in enumerate(history):
                if state != stream_state(chunks[:i+1]):
                    raise ValueError(f'Feed state mismatch prefix={prefix}, size={size}, write={i}')
                feed_cases += 1
            record(t)
    qmax = MASK // 26
    if MAGIC*26 - (1 << 67) != 2 or not 2*qmax + 25*MAGIC < (1 << 67):
        raise ValueError('Reciprocal reduction inequality failed')
    return {'alias_vectors': vectors, 'alias_comparisons': len(vectors),
            'distinct_alias_inputs': len({v['input_hex'] for v in vectors}),
            'constructor_long_input_cases': sum(v['bytes'] > 16 for v in vectors),
            'alias_counter_hashes': len(vectors)*10,
            'per_write_state_comparisons': feed_cases, 'feed_sequences': 8*33,
            'instruction_visits': {hex(k): v for k, v in sorted(visits.items())},
            'branch_outcomes': {f'{va:#x}:{"taken" if take else "fallthrough"}': n
                                for (va, take), n in sorted(edges.items())},
            'reciprocal_proof': {'M': hex(MAGIC), '26*M-2^67': 2,
                                  'max_2q_plus_25M': 2*qmax+25*MAGIC,
                                  'upper_bound_exclusive': 1 << 67}}


def generate(binary, output):
    identity = next(x for x in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']
                    if x['path'] == 'artifacts/node/94/hl-node')
    if identity['sha256'] != TARGET:
        raise ValueError('Unexpected pinned target')
    check(binary, identity)
    data = binary.read_bytes()
    code, raw = decode(binary, data)
    result = evaluate(code)
    ranges = {}
    for name, (begin, end) in RANGES.items():
        offset, body = read_va(data, begin, end-begin)
        ranges[name] = {'start_va': hex(begin), 'end_va': hex(end), 'file_offset': hex(offset),
                        'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                        'decoded_instructions': sum(begin <= v < end for v in code)}
    result.update({'target_sha256': TARGET, 'target_bytes': len(data), 'ranges': ranges,
                   'decoded_instructions': len(code), 'visited_instructions': len(result['instruction_visits']),
                   'unvisited_instruction_vas': [hex(v) for v in sorted(code)
                       if hex(v) not in result['instruction_visits']],
                   'captured_executable_launched': False,
                   'scope': 'Finite static integer transfers on synthetic preallocated memory; not runtime equivalence. Growth/cache/locks/whole constructor excluded; no gate change.'})
    output.mkdir(parents=True, exist_ok=True)
    for name, value in raw.items():
        (output/name).write_text(value)
    (output/'records.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT/'work/short-string-alias-94')
    args = parser.parse_args()
    result = generate(args.binary.resolve(), args.output)
    print(json.dumps({k: v for k, v in result.items() if k not in (
        'alias_vectors', 'instruction_visits', 'branch_outcomes')}, indent=2))

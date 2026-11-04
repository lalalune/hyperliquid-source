#!/usr/bin/env python3
"""Digest-bound static expression lifting, not captured-code execution.

Only the four admitted straight-line bodies are supported. Pointer regions are
abstract and disjoint; no host address, target instruction or generated code is
executed. Z3 checks expressions obtained from decoded instructions.
"""
import argparse
import bisect
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
import platform
import struct

import capstone as cs
import elftools
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
import z3 as z

ROOT = Path(__file__).resolve().parents[3]
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES = {
    0x6325530: (513, '2555b1ca425795cd43bc9004425076bde3e268eb1ad3a9bfa251d23210dafdd4'),
    0x6337d80: (523, '82789177474f065482f5f247daf435a66131bc8140ddc5a58e840ccb21ebf994'),
    0x631d630: (259, '3cead16bae6d94fead58e2a6f7544fc470c9049fc267d4a3beb8cf379eeea994'),
    0x632c130: (259, '3cead16bae6d94fead58e2a6f7544fc470c9049fc267d4a3beb8cf379eeea994'),
}
HELPERS = {0x631d630, 0x632c130}
M52, M48, C = (1 << 52) - 1, (1 << 48) - 1, (1 << 32) + 977


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bv(value, bits=64):
    return z.BitVecVal(value, bits)


@dataclass(frozen=True)
class Pointer:
    region: str
    offset: int = 0

    def add(self, offset):
        return Pointer(self.region, self.offset + offset)


# Explicit aliases avoid assumptions about partial-register writes. All
# arithmetic flags except ZF/CF are dead before the only flag consumers here.
ALIASES = {}
for full, low32, low8 in [('rax', 'eax', 'al'), ('rbx', 'ebx', 'bl'),
                         ('rcx', 'ecx', 'cl'), ('rdx', 'edx', 'dl'),
                         ('rsi', 'esi', 'sil'), ('rdi', 'edi', 'dil'),
                         ('rbp', 'ebp', 'bpl'), ('rsp', 'esp', 'spl')]:
    for alias, width in [(full, 64), (low32, 32), (low8, 8)]:
        ALIASES[alias] = (full, width)
for n in range(8, 16):
    for suffix, width in [('', 64), ('d', 32), ('b', 8)]:
        ALIASES[f'r{n}{suffix}'] = (f'r{n}', width)


class Lift:
    """A small static transfer-function model, restricted to admitted opcodes."""
    def __init__(self, decoded, inputs):
        self.decoded = decoded
        self.regs = {r: z.BitVec('initial_' + r, 64) for r, w in ALIASES.values() if w == 64}
        self.regs.update({f'xmm{i}': z.BitVec(f'initial_xmm{i}', 128) for i in range(16)})
        self.initial = dict(self.regs)
        self.regs.update(rsp=Pointer('stack'), rsi=Pointer('input'), rdi=Pointer('output'))
        self.memory = {('input', i * 8): x for i, x in enumerate(inputs)}
        self.memory[('tls', 0x28)] = z.BitVec('tls_canary', 64)
        self.writes = []
        self.loads = []
        self.calls = []
        self.branches = []
        self.zf = self.cf = None

    def readreg(self, name):
        if name.startswith('xmm'):
            return self.regs[name]
        full, width = ALIASES[name]
        value = self.regs[full]
        require(not isinstance(value, Pointer) or width == 64, 'partial pointer read')
        return value if width == 64 else z.Extract(width - 1, 0, value)

    def writereg(self, name, value):
        if name.startswith('xmm'):
            require(value.size() == 128, 'vector width')
            self.regs[name] = value
            return
        full, width = ALIASES[name]
        if isinstance(value, Pointer):
            require(width == 64, 'partial pointer write')
            self.regs[full] = value
            return
        require(value.size() == width, 'register width')
        if width == 32:
            value = z.ZeroExt(32, value)
        elif width == 8:
            require(not isinstance(self.regs[full], Pointer), 'partial pointer overwrite')
            value = z.Concat(z.Extract(63, 8, self.regs[full]), value)
        self.regs[full] = z.simplify(value)

    def address(self, ins, operand):
        m = operand.mem
        require(m.index == 0, 'indexed memory unsupported')
        if m.segment:
            require(ins.reg_name(m.segment) == 'fs' and not m.base, 'segment')
            return Pointer('tls', m.disp)
        require(m.base != 0, 'absolute memory')
        p = self.readreg(ins.reg_name(m.base))
        require(isinstance(p, Pointer), 'symbolic memory address')
        return p.add(m.disp)

    def load(self, p, size):
        require(size in (8, 16), 'memory read width')
        self.loads.append([p.region, p.offset, size])
        require((p.region, p.offset) in self.memory, 'uninitialized memory read')
        lo = self.memory[p.region, p.offset]
        if size == 8:
            return lo
        require(not isinstance(lo, Pointer), 'vector pointer load')
        hi = self.load(p.add(8), 8)
        require(not isinstance(hi, Pointer), 'vector pointer load')
        return z.Concat(hi, lo)

    def store(self, p, size, value):
        require(p.region in ('stack', 'output'), 'write outside stack/output')
        require(size in (8, 16), 'memory write width')
        self.writes.append([p.region, p.offset, size])
        if size == 16:
            self.store(p, 8, z.Extract(63, 0, value))
            self.store(p.add(8), 8, z.Extract(127, 64, value))
        else:
            require(isinstance(value, Pointer) or value.size() == 64, 'store width')
            self.memory[p.region, p.offset] = value

    def read(self, ins, op, width=None):
        if op.type == X86_OP_REG:
            return self.readreg(ins.reg_name(op.reg))
        if op.type == X86_OP_MEM:
            return self.load(self.address(ins, op), op.size)
        require(op.type == X86_OP_IMM, 'operand kind')
        return bv(op.imm, width or op.size * 8)

    def write(self, ins, op, value):
        if op.type == X86_OP_REG:
            self.writereg(ins.reg_name(op.reg), value)
        else:
            require(op.type == X86_OP_MEM, 'destination kind')
            self.store(self.address(ins, op), op.size, value)

    def run(self, entry):
        sequence = self.decoded[entry]
        for index, ins in enumerate(sequence):
            ops, mnemonic = ins.operands, ins.mnemonic
            if mnemonic == 'ret':
                if entry in HELPERS:
                    require(index == len(sequence) - 1, 'helper return extent')
                else:
                    require(index == len(sequence) - 2 and sequence[-1].mnemonic == 'call'
                            and sequence[-1].operands[0].imm == 0x63f0d70, 'caller failure tail')
                return
            if mnemonic in ('push', 'pop'):
                p = self.regs['rsp']
                require(isinstance(p, Pointer) and p.region == 'stack', 'stack pointer')
                if mnemonic == 'push':
                    self.regs['rsp'] = p.add(-8)
                    self.store(p.add(-8), 8, self.read(ins, ops[0]))
                else:
                    self.write(ins, ops[0], self.load(p, 8))
                    self.regs['rsp'] = p.add(8)
            elif mnemonic == 'call':
                require(ops[0].type == X86_OP_IMM and ops[0].imm in HELPERS, 'unsupported call')
                self.calls.append([ins.address, ops[0].imm])
                p = self.regs['rsp']
                self.regs['rsp'] = p.add(-8)
                self.store(p.add(-8), 8, bv(ins.address + ins.size))
                self.run(ops[0].imm)
                require(self.regs['rsp'] == p.add(-8), 'callee stack balance')
                require(z.is_true(z.simplify(self.load(p.add(-8), 8) == bv(ins.address + ins.size))), 'callee return address')
                self.regs['rsp'] = p
            elif mnemonic == 'jne':
                require(self.zf is not None, 'undefined branch flags')
                # Only the stack-canary failure branch is supported. Its
                # unreachable edge is proved below, never silently discarded.
                self.branches.append((ins.address, self.zf))
                require(ops[0].type == X86_OP_IMM, 'branch kind')
                target = next(i for i in self.decoded[entry] if i.address == ops[0].imm)
                require(target.mnemonic == 'call' and target.operands[0].imm == 0x63f0d70, 'failure edge')
            elif mnemonic in ('mov', 'movabs', 'movdqu', 'movaps', 'movdqa', 'movups', 'movzx'):
                value = self.read(ins, ops[1])
                if mnemonic == 'movzx':
                    value = z.ZeroExt(ops[0].size * 8 - value.size(), value)
                self.write(ins, ops[0], value)
            elif mnemonic == 'lea':
                self.write(ins, ops[0], self.address(ins, ops[1]))
            elif mnemonic in ('sete', 'setb'):
                flag = self.zf if mnemonic == 'sete' else self.cf
                require(flag is not None, 'undefined comparison flags')
                self.write(ins, ops[0], z.If(flag, bv(1, 8), bv(0, 8)))
            elif mnemonic in ('add', 'sub', 'and', 'or', 'xor', 'shr', 'shl', 'imul', 'cmp', 'neg'):
                a = self.read(ins, ops[0])
                if mnemonic == 'neg':
                    result = -a
                else:
                    b = self.read(ins, ops[1], ops[0].size * 8)
                    if isinstance(a, Pointer):
                        require(mnemonic in ('add', 'sub') and z.is_bv_value(b), 'pointer arithmetic')
                        result = a.add(b.as_long() * (1 if mnemonic == 'add' else -1))
                        self.write(ins, ops[0], result)
                        self.zf = self.cf = None
                        continue
                    require(not isinstance(b, Pointer), 'pointer as integer')
                    if b.size() < a.size():
                        b = z.ZeroExt(a.size() - b.size(), b)
                    if mnemonic in ('shl', 'shr'):
                        b = b & (63 if a.size() == 64 else 31)
                    result = {'add': lambda: a + b, 'sub': lambda: a - b,
                              'cmp': lambda: a - b, 'and': lambda: a & b,
                              'or': lambda: a | b, 'xor': lambda: a ^ b,
                              'shr': lambda: z.LShR(a, b), 'shl': lambda: a << b,
                              'imul': lambda: a * b}[mnemonic]()
                self.zf = result == 0
                self.cf = z.ULT(a, b) if mnemonic in ('cmp', 'sub') else None
                if mnemonic != 'cmp':
                    self.write(ins, ops[0], result)
            else:
                raise ValueError(f'unsupported instruction {ins.address:x}: {mnemonic}')
        raise ValueError('missing return')


def normalize(a, details=False):
    """Independent numeric specification with explicit u64 bitvector wrapping."""
    t = [None] * 5
    carry = z.LShR(a[4], 48) * C
    for i in range(4):
        total = a[i] + carry
        t[i], carry = total & M52, z.LShR(total, 52)
    t[4] = (a[4] & M48) + carry
    threshold = z.And(t[4] == M48, (t[1] & t[2] & t[3]) == M52, z.UGE(t[0], (1 << 52) - C))
    selector = z.LShR(t[4], 48) | z.If(threshold, bv(1), bv(0))
    carry = (-selector) & C
    out = []
    for i in range(4):
        total = t[i] + carry
        out.append(total & M52)
        carry = z.LShR(total, 52)
    out += [(t[4] + carry) & M48]
    return (out, selector) if details else out


def pack(a):
    return [a[0] | (a[1] << 52), z.LShR(a[1], 12) | (a[2] << 40),
            z.LShR(a[2], 24) | (a[3] << 28), z.LShR(a[3], 36) | (a[4] << 16)]


def check(name, violation, expected='unsat'):
    solver = z.Solver()
    solver.set(timeout=60000)
    solver.add(violation)
    status = str(solver.check())
    require(status == expected, f'{name}: expected {expected}, got {status}')
    record = {'name': name, 'result': status, 'timeout_ms': 60000}
    if status == 'sat':
        m = solver.model()
        record['counterexample'] = {d.name(): str(m[d]) for d in m.decls()}
    return record


def admit(data):
    require(digest(data) == TARGET, 'target digest')
    elf = ELFFile(io.BytesIO(data))
    require(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_X86_64', 'ELF identity')
    fdes = [x for x in elf.get_dwarf_info().EH_CFI_entries() if isinstance(x, FDE)]
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    decoder.detail = True
    decoded, records = {}, []
    for address, (length, expected) in BODIES.items():
        sections = [s for s in elf.iter_sections() if s['sh_addr'] <= address and address + length <= s['sh_addr'] + s['sh_size'] and s['sh_flags'] & 4]
        require(len(sections) == 1, 'unique executable section')
        section = sections[0]
        offset = section['sh_offset'] + address - section['sh_addr']
        body = data[offset:offset + length]
        require(digest(body) == expected, 'body digest')
        matches = [f for f in fdes if f['initial_location'] == address]
        require(len(matches) == 1 and matches[0]['address_range'] == length, 'complete unique FDE')
        instructions = list(decoder.disasm(body, address))
        require(sum(i.size for i in instructions) == length, 'complete decode')
        require(instructions[-1].mnemonic in ('ret', 'call'), 'terminal instruction')
        decoded[address] = instructions
        loads = [p for p in elf.iter_segments() if p['p_type'] == 'PT_LOAD' and p['p_flags'] & 1 and p['p_vaddr'] <= address and address + length <= p['p_vaddr'] + p['p_filesz']]
        require(len(loads) == 1 and loads[0]['p_offset'] + address - loads[0]['p_vaddr'] == offset, 'executable PT_LOAD mapping')
        relocations = []
        for s in elf.iter_sections():
            if s['sh_type'] in ('SHT_RELA', 'SHT_REL'):
                relocations.extend({'section': s.name, 'offset': r['r_offset']} for r in s.iter_relocations() if address <= r['r_offset'] < address + length)
        require(not relocations, 'body relocations')
        next_fde = min(f['initial_location'] for f in fdes if f['initial_location'] >= address + length)
        gap = data[offset + length:offset + length + next_fde - address - length]
        require(gap == b'\xcc' * len(gap), 'INT3 tail')
        records.append({'address': hex(address), 'length': length, 'file_offset': hex(offset), 'sha256': digest(body),
                        'bytes': body.hex(), 'section': section.name, 'fde_offset': matches[0].offset,
                        'fde_bytes': elf.get_section_by_name('.eh_frame').data()[matches[0].offset:matches[0].offset + matches[0]['length'] + 4].hex(),
                        'cie_offset': matches[0].cie.offset,
                        'cie_bytes': elf.get_section_by_name('.eh_frame').data()[matches[0].cie.offset:matches[0].cie.offset + matches[0].cie['length'] + 4].hex(),
                        'next_fde': hex(next_fde), 'int3_padding': len(gap), 'instruction_count': len(instructions),
                        'relocations': relocations,
                        'instructions': [{'address': hex(i.address), 'bytes': bytes(i.bytes).hex(), 'mnemonic': i.mnemonic, 'operands': i.op_str} for i in instructions]})
    # This is an E8/E9 pattern census, with decode confirmation where the
    # enclosing unique FDE gives a bounded complete linear decode. It is not
    # an indirect/short-jump or alternate-entry xref census.
    text = elf.get_section_by_name('.text')
    text_data = text.data()
    starts = sorted(set(f['initial_location'] for f in fdes))
    by_start = {}
    for f in fdes:
        by_start.setdefault(f['initial_location'], []).append(f)
    boundary_cache = {}
    xrefs = []
    for opcode in (0xe8, 0xe9):
        pos = text_data.find(bytes([opcode]))
        while pos >= 0:
            if pos + 5 <= len(text_data):
                site = text['sh_addr'] + pos
                destination = site + 5 + struct.unpack_from('<i', text_data, pos + 1)[0]
                if destination in BODIES:
                    ix = bisect.bisect_right(starts, site) - 1
                    candidates = by_start.get(starts[ix], []) if ix >= 0 else []
                    f = candidates[0] if len(candidates) == 1 else None
                    record = {'site': hex(site), 'destination': hex(destination), 'opcode': hex(opcode), 'boundary_confirmed': False}
                    if f is not None and site + 5 <= f['initial_location'] + f['address_range']:
                        record.update(enclosing_fde=hex(f['initial_location']), fde_length=f['address_range'])
                        if f['address_range'] <= 100000:
                            begin = f['initial_location'] - text['sh_addr']
                            if f['initial_location'] not in boundary_cache:
                                ins = list(decoder.disasm(text_data[begin:begin + f['address_range']], f['initial_location']))
                                boundary_cache[f['initial_location']] = ({i.address for i in ins}, sum(i.size for i in ins) == f['address_range'])
                            boundaries, complete = boundary_cache[f['initial_location']]
                            record['boundary_confirmed'] = complete and site in boundaries
                    xrefs.append(record)
            pos = text_data.find(bytes([opcode]), pos + 1)
    plt = elf.get_section_by_name('.plt')
    plt_bytes = plt.data()[0x63f0d70 - plt['sh_addr']:0x63f0d80 - plt['sh_addr']]
    require(plt_bytes[:2] == b'\xff\x25', 'failure PLT jump')
    got = 0x63f0d76 + struct.unpack_from('<i', plt_bytes, 2)[0]
    rela = elf.get_section_by_name('.rela.plt')
    require(rela is not None, 'PLT relocation section')
    syms = elf.get_section(rela['sh_link'])
    failure_relocs = [r for r in rela.iter_relocations() if r['r_offset'] == got]
    require(len(failure_relocs) == 1, 'failure relocation')
    r = failure_relocs[0]
    symbol = syms.get_symbol(r['r_info_sym']).name
    require(symbol == '__stack_chk_fail' and r['r_info_type'] == 7, 'failure symbol')
    closure = {'text_scan_bytes': len(text_data), 'entry_e8_e9_xrefs': xrefs,
               'failure_plt': {'address': '0x63f0d70', 'bytes': plt_bytes.hex(), 'got': hex(got),
                               'relocation_section': rela.name, 'relocation_type': 'R_X86_64_JUMP_SLOT', 'symbol': symbol}}
    return decoded, records, closure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(cs.__version__ == '5.0.7' and z.get_version_string() == '4.15.4' and elftools.__version__ == '0.32', 'pinned analysis versions')
    data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
    decoded, records, closure = admit(data)
    inputs = [z.BitVec(f'input{i}', 64) for i in range(10)]
    spec = pack(normalize(inputs[:5])) + pack(normalize(inputs[5:]))
    proofs, callers, caller_outputs = [], [], []
    for entry in (0x6325530, 0x6337d80):
        lift = Lift(decoded, inputs)
        lift.run(entry)
        out = [lift.memory['output', i * 8] for i in range(8)]
        caller_outputs.append(out)
        proofs.append(check(f'{entry:x}: output equality for all ten u64 inputs', z.Or(*[a != b for a, b in zip(out, spec)])))
        for site, zf in lift.branches:
            proofs.append(check(f'{site:x}: canary failure unreachable under disjoint stable TLS', z.Not(zf)))
        preserved = []
        for name in ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'):
            proofs.append(check(f'{entry:x}: preserve {name}', lift.regs[name] != lift.initial[name]))
            preserved.append(name)
        require(lift.regs['rsp'] == Pointer('stack'), 'caller stack balance')
        require(all(o + n <= 0 for r, o, n in lift.writes if r == 'stack'), 'write over caller return frame')
        require(sorted(set(o for r, o, n in lift.writes if r == 'output' and n == 8)) == list(range(0, 64, 8)), 'output extent')
        require(all(0 <= o and o + n <= 80 for r, o, n in lift.loads if r == 'input'), 'input extent')
        callers.append({'entry': hex(entry), 'calls': [[hex(a), hex(b)] for a, b in lift.calls],
                        'branch_sites': [hex(a) for a, _ in lift.branches], 'preserved': preserved,
                        'loads': sorted(set(tuple(x) for x in lift.loads)), 'writes': sorted(set(tuple(x) for x in lift.writes))})
    # Packing is a lossless change of radix under the normalized limb bounds.
    limbs = inputs[:5]
    bounded = z.And(*[z.ULE(x, M52 if i < 4 else M48) for i, x in enumerate(limbs)])
    wide = sum(z.ZeroExt(256, x) << (52 * i) for i, x in enumerate(limbs))
    packed = sum(z.ZeroExt(256, x) << (64 * i) for i, x in enumerate(pack(limbs)))
    proofs.append(check('packing preserves the 256-bit integer under radix bounds', z.And(bounded, wide != packed)))
    # A separate width-320 arithmetic theorem supplies the bounded modular
    # interpretation. All possible five-u64 weighted inputs fit in 273 bits.
    prime = (1 << 256) - C
    normalized, selector = normalize(limbs, details=True)
    numeric_input = sum(z.ZeroExt(256, x) << (52 * i) for i, x in enumerate(limbs))
    numeric_output = sum(z.ZeroExt(256, x) << (52 * i) for i, x in enumerate(normalized))
    magnitude64 = z.And(*[z.ULE(x, 64 * (M52 if i < 4 else M48)) for i, x in enumerate(limbs)])
    quotient = z.ZeroExt(256, z.LShR(limbs[4], 48) + selector)
    proofs.append(check('magnitude-64 normalization: exact quotient identity and canonical range',
                        z.And(magnitude64, z.Or(numeric_output != numeric_input - quotient * prime,
                                               z.UGE(numeric_output, prime)))))
    proofs.append(check('all-u64 normalization selector is Boolean', z.And(selector != 0, selector != 1)))
    proofs.append(check('all-u64 normalized output is below the prime', z.UGE(numeric_output, prime)))
    # A finite independent oracle uses Python integers and % p, not normalize().
    # Every single-bit input position exercises a radix-to-qword boundary.
    scalars = sorted(set([0, 1, prime - 1, prime, prime + 1, 2 * prime - 1, 2 * prime,
                          (1 << 256) - 1, 1 << 256] + [1 << bit for bit in range(256)]))
    rows = ['input_limbs_hex\toutput_qwords_hex\tx_mod_p_hex\ty_mod_p_hex']
    for index, x in enumerate(scalars):
        y = scalars[-1 - index]
        def split(n):
            return [(n >> (52 * i)) & M52 for i in range(4)] + [n >> 208]
        fixed = split(x) + split(y)
        substitutions = [(v, bv(n)) for v, n in zip(inputs, fixed)]
        expected = [((n % prime) >> (64 * j)) & ((1 << 64) - 1) for n in (x, y) for j in range(4)]
        for expressions in caller_outputs:
            actual = [z.simplify(z.substitute(v, *substitutions)).as_long() for v in expressions]
            require(actual == expected, 'integer-oracle boundary case')
        rows.append(','.join(f'{n:016x}' for n in fixed) + '\t' + ','.join(f'{n:016x}' for n in expected)
                    + f'\t{x % prime:064x}\t{y % prime:064x}')
    boundary_data = ('\n'.join(rows) + '\n').encode()
    boundary_path = args.output.with_suffix('.boundaries.tsv')
    controls = []
    # Change actual encoded immediates, independently of the specification.
    # These counterfactuals deliberately bypass target admission and earn no
    # authentic-target credit. No mutated bytes are executed.
    for entry, site in [(0x6325530, 0x632566e), (0x6337d80, 0x6337e94)]:
        length = BODIES[entry][0]
        body = bytearray(data[entry - 0x1000:entry - 0x1000 + length])
        original = next(i for i in decoded[entry] if i.address == site)
        require(original.mnemonic == 'shl' and original.operands[1].imm == 52, 'control shift')
        body[site - entry + original.size - 1] += 1
        decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        decoder.detail = True
        changed = list(decoder.disasm(bytes(body), entry))
        require(sum(i.size for i in changed) == length, 'control decode')
        altered = next(i for i in changed if i.address == site)
        require(altered.mnemonic == 'shl' and altered.operands[1].imm == 53, 'control mutation')
        mutant = Lift(decoded | {entry: changed}, inputs)
        mutant.run(entry)
        actual = [mutant.memory['output', i * 8] for i in range(8)]
        fixed = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
        control = check(f'{entry:x}: encoded packing shift +1 detected',
                        z.And(*[v == n for v, n in zip(inputs, fixed)], z.Or(*[a != b for a, b in zip(actual, spec)])), 'sat')
        control.update(body_sha256=digest(body), qualified_target=False,
                       site=hex(site), original_bytes=bytes(original.bytes).hex(), mutated_bytes=bytes(altered.bytes).hex(), inputs=fixed)
        substitutions = [(v, bv(n)) for v, n in zip(inputs, fixed)]
        control['expected_output'] = [z.simplify(z.substitute(v, *substitutions)).as_long() for v in spec]
        control['mutated_output'] = [z.simplify(z.substitute(v, *substitutions)).as_long() for v in actual]
        require(control['expected_output'] != control['mutated_output'], 'control replay')
        controls.append(control)
    off_domain = [(1 << 64) - 1, 0, 0, 0, 1 << 48] + [0] * 5
    substitutions = [(v, bv(n)) for v, n in zip(inputs, off_domain)]
    actual = [z.simplify(z.substitute(v, *substitutions)).as_long() for v in caller_outputs[0]]
    integer_input = sum(n << (52 * i) for i, n in enumerate(off_domain[:5]))
    integer_output = sum(n << (64 * i) for i, n in enumerate(actual[:4]))
    require(integer_output != integer_input % prime, 'off-domain control must violate congruence')
    controls.append({'name': 'all-u64 congruence is false without magnitude bounds', 'result': 'counterexample',
                     'inputs': off_domain, 'native_expression_output': integer_output,
                     'integer_mod_p': integer_input % prime})
    bad = bytearray(data)
    bad[0x6324530] ^= 1
    try:
        admit(bytes(bad))
    except ValueError as e:
        require(str(e) == 'target digest', 'unexpected corruption rejection')
        controls.append({'name': 'full-target byte mutation', 'result': 'rejected', 'sha256': digest(bad), 'reason': str(e)})
    else:
        raise ValueError('mutated target admitted')
    result = {'target_sha256': TARGET, 'target_size': len(data), 'base_commit': '8fd8db680ec4bfef40996e5616bce3d5156d0b86',
              'versions': {'python': platform.python_version(), 'capstone': cs.__version__, 'pyelftools': elftools.__version__, 'z3': z.get_version_string()},
              'scope': 'static symbolic transfer functions; no captured execution; disjoint abstract input/output/stack/TLS',
              'bodies': records, 'closure': closure, 'callers': callers, 'proofs': proofs, 'controls': controls,
              'integer_oracle': {'paired_cases': len(scalars), 'caller_checks': 2 * len(scalars),
                                 'all_256_single_bit_positions': True, 'sha256': digest(boundary_data)}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    boundary_path.write_bytes(boundary_data)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'proofs': len(proofs), 'controls': len(controls)}))


if __name__ == '__main__':
    main()

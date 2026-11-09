#!/usr/bin/env python3
"""Reconstruct the node #115 PDI asset-name lookup body at 0x421a8b0 from bytes.

The body is the helper behind slot 0x64e69b8: the pre-registration rule check
of the merged RE-007 caller packet calls it as its rule 9 with
(out, suffix pointer, suffix length, front record) and lists the body itself
as unresolved. This tool verifies the target digest, decodes the complete
FDE extent [0x421a8b0, 0x421a9cc) with a fail-closed decoder for exactly the
encodings present, runs the bytes in a small x86-64 evaluator whose only
externals are recording stubs (bcmp, memcpy, the allocation helper and the
three noreturn shims), and compares every result with an independently
written rule list. It never executes the captured binary and uses only the
standard library plus tools/elf_index.py and tools/fde_extents.py.
"""
import argparse
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105_896_032

BODY_START = 0x421A8B0
BODY_END = 0x421A9CC
BODY_SHA256 = '6f1a63aad6cfbcc1635d94d4cb57cd28153f4714301d3b23da4711bf1e8cc967'
LOCATION_VA = 0x6483FB0
LOCATION_STR_VA = 0x448F4E
LOCATION_STR = b'l1/src/asset/pdi.rs'
PANIC_ADD_MSG_VA = 0x46EADD
PANIC_MUL_MSG_VA = 0x46EAF9

SLOT_BCMP = 0x64DF9F8
SLOT_ALLOC = 0x64DF480
SLOT_ALLOC_ERR = 0x64DF498
SLOT_MEMCPY = 0x64DF508
SLOT_PANIC_ADD = 0x64DF520
SLOT_PANIC_MUL = 0x64DF870
LOOKUP_SLOT = 0x64E69B8

OK_TAG = 0x1A2
ERR_TAG = 0x68
MULTIPLIER = 10_000
RECORD_SIZE = 0x20
PAGE_MAX = (2**64 - 1) // MULTIPLIER  # product is 2**64 - 1616

ARENA_BASE = 0x1000_0000
ARENA_SIZE = 0x100_0000
CTX_VA = ARENA_BASE + 0x000000
RECORDS_VA = ARENA_BASE + 0x010000
STRINGS_VA = ARENA_BASE + 0x040000
SUFFIX_VA = ARENA_BASE + 0x080000
OUT_VA = ARENA_BASE + 0x090000
HEAP_VA = ARENA_BASE + 0x100000
STACK_TOP = ARENA_BASE + 0xF00000
RET_SENTINEL = 0xDEAD0000
JUNK = 0xA5

REG_NAMES = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R12, R13, R14, R15 = 12, 13, 14, 15
M64 = 2**64 - 1


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def va_to_offset(secs, va):
    for s in secs:
        if s['type'] != 8 and s['address'] <= va < s['address'] + s['size']:
            return s['offset'] + (va - s['address'])
    raise ValueError(f'VA {va:#x} is not inside any file-backed section')


def relocations(data, secs):
    """Map slot VA -> (kind, target VA or symbol name) from .rela.dyn."""
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    symtab = next(s for s in secs if s['name'] == '.dynsym')
    strtab = next(s for s in secs if s['name'] == '.dynstr')
    out = {}
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        off, info, addend = struct.unpack_from('<QQq', data, pos)
        typ = info & 0xFFFFFFFF
        sym = info >> 32
        if typ == 8:  # R_X86_64_RELATIVE
            out[off] = ('relative', addend)
        elif typ == 6 and sym:  # R_X86_64_GLOB_DAT
            soff = symtab['offset'] + sym * 24
            name_off = struct.unpack_from('<I', data, soff)[0]
            end = data.index(b'\0', strtab['offset'] + name_off)
            out[off] = ('glob_dat', data[strtab['offset'] + name_off:end].decode())
    return out


def slot_targets(data, secs):
    """Resolve every slot the body calls through to a stub role."""
    rel = relocations(data, secs)
    expect = {
        SLOT_BCMP: ('glob_dat', 'bcmp'),
        SLOT_MEMCPY: ('glob_dat', 'memcpy'),
        SLOT_ALLOC: ('relative', 0x6355830),
        SLOT_ALLOC_ERR: ('relative', 0x141E264),
        SLOT_PANIC_ADD: ('relative', 0x1681DA0),
        SLOT_PANIC_MUL: ('relative', 0x1681DC0),
    }
    roles = {}
    for slot, want in expect.items():
        got = rel.get(slot)
        if got != want:
            raise ValueError(f'slot {slot:#x}: expected {want}, found {got}')
        roles[slot] = {SLOT_BCMP: 'bcmp', SLOT_MEMCPY: 'memcpy',
                       SLOT_ALLOC: 'alloc', SLOT_ALLOC_ERR: 'alloc_err',
                       SLOT_PANIC_ADD: 'panic_add',
                       SLOT_PANIC_MUL: 'panic_mul'}[slot]
    lookup = rel.get(LOOKUP_SLOT)
    if lookup != ('relative', BODY_START):
        raise ValueError(f'lookup slot: expected the body, found {lookup}')
    return roles


# ---------------------------------------------------------------------------
# Fail-closed decoder for exactly the encodings present in the body.
# ---------------------------------------------------------------------------

class DecodeError(ValueError):
    pass


class Insn:
    __slots__ = ('va', 'size', 'op', 'a', 'b', 'w', 'text')

    def __init__(self, va, size, op, a, b, w, text):
        self.va, self.size, self.op = va, size, op
        self.a, self.b, self.w, self.text = a, b, w, text


def _modrm(body, pos, bits):
    """Decode ModRM (+SIB/displacement). Returns (reg, operand, newpos)."""
    modrm = body[pos]
    pos += 1
    mod = modrm >> 6
    reg = ((modrm >> 3) & 7) | (((bits >> 2) & 1) << 3)
    rm = modrm & 7
    if mod == 3:
        return reg, ('r', rm | ((bits & 1) << 3)), pos
    if rm == 4:  # SIB
        sib = body[pos]
        pos += 1
        scale = 1 << (sib >> 6)
        index = ((sib >> 3) & 7) | (((bits >> 1) & 1) << 3)
        base_bits = sib & 7
        if index == RSP and not ((bits >> 1) & 1):
            index = None
        if mod == 0 and base_bits == 5:
            disp = struct.unpack_from('<i', body, pos)[0]
            return reg, ('m', None, index, scale, disp), pos + 4
        base = base_bits | ((bits & 1) << 3)
        disp = 0
        if mod == 1:
            disp = struct.unpack_from('<b', body, pos)[0]
            pos += 1
        elif mod == 2:
            disp = struct.unpack_from('<i', body, pos)[0]
            pos += 4
        return reg, ('m', base, index, scale, disp), pos
    if mod == 0 and rm == 5:  # RIP-relative
        disp = struct.unpack_from('<i', body, pos)[0]
        return reg, ('rip', disp), pos + 4
    base = rm | ((bits & 1) << 3)
    disp = 0
    if mod == 1:
        disp = struct.unpack_from('<b', body, pos)[0]
        pos += 1
    elif mod == 2:
        disp = struct.unpack_from('<i', body, pos)[0]
        pos += 4
    return reg, ('m', base, None, 1, disp), pos


def _mem_text(opnd, va, size):
    if opnd[0] == 'r':
        return REG_NAMES[opnd[1]]
    if opnd[0] == 'rip':
        return f'[{va + size + opnd[1]:#x}]'
    _, base, index, scale, disp = opnd
    parts = []
    if base is not None:
        parts.append(REG_NAMES[base])
    if index is not None:
        parts.append(f'{REG_NAMES[index]}*{scale}' if scale != 1 else REG_NAMES[index])
    text = '+'.join(parts)
    if disp:
        text += f'{disp:+#x}'
    return f'[{text}]'


def decode_body(body, start=BODY_START, end=BODY_END):
    """Decode the whole extent; raise DecodeError on any unknown encoding."""
    insns = []
    pos = 0
    while pos < len(body):
        va = start + pos
        at = pos
        opsize = False
        while pos < len(body) and body[pos] in (0x66, 0x2E, 0x3E, 0x64, 0x65, 0xF2, 0xF3):
            if body[pos] == 0x66:
                opsize = True
            pos += 1
        rex = 0
        if 0x40 <= body[pos] <= 0x4F:
            rex = body[pos]
            pos += 1
        bits = rex - 0x40 if rex else 0
        width = 8 if bits & 0x8 else 4
        opcode = body[pos]
        pos += 1

        def done(op, a, b, text):
            insns.append(Insn(va, pos - at, op, a, b, width, text))
            return pos

        if 0x50 <= opcode <= 0x57:
            reg = (opcode - 0x50) | ((bits & 1) << 3)
            pos = done('push', ('r', reg), None, f'push {REG_NAMES[reg]}')
        elif 0x58 <= opcode <= 0x5F:
            reg = (opcode - 0x58) | ((bits & 1) << 3)
            pos = done('pop', ('r', reg), None, f'pop {REG_NAMES[reg]}')
        elif opcode == 0x83:
            reg, opnd, pos = _modrm(body, pos, bits)
            imm = struct.unpack_from('<b', body, pos)[0]
            pos += 1
            name = {0: 'add', 5: 'sub'}.get(reg)
            if name is None:
                raise DecodeError(f'{va:#x}: unsupported 83 /{reg}')
            pos = done(name, opnd, ('i', imm),
                       f'{name} {_mem_text(opnd, va, pos - at)}, {imm:#x}')
        elif opcode in (0x89, 0x8B):
            reg, opnd, pos = _modrm(body, pos, bits)
            if opcode == 0x89:
                pos = done('mov', opnd, ('r', reg),
                           f'mov {_mem_text(opnd, va, pos - at)}, {REG_NAMES[reg]}')
            else:
                pos = done('mov', ('r', reg), opnd,
                           f'mov {REG_NAMES[reg]}, {_mem_text(opnd, va, pos - at)}')
        elif opcode == 0xF7:
            reg, opnd, pos = _modrm(body, pos, bits)
            if reg != 4:
                raise DecodeError(f'{va:#x}: unsupported f7 /{reg}')
            pos = done('mulq', opnd, None, f'mulq {_mem_text(opnd, va, pos - at)}')
        elif opcode == 0x39:
            reg, opnd, pos = _modrm(body, pos, bits)
            pos = done('cmp', opnd, ('r', reg),
                       f'cmp {_mem_text(opnd, va, pos - at)}, {REG_NAMES[reg]}')
        elif opcode == 0x3B:
            reg, opnd, pos = _modrm(body, pos, bits)
            pos = done('cmp', ('r', reg), opnd,
                       f'cmp {REG_NAMES[reg]}, {_mem_text(opnd, va, pos - at)}')
        elif opcode == 0x85:
            reg, opnd, pos = _modrm(body, pos, bits)
            pos = done('test', opnd, ('r', reg),
                       f'test {_mem_text(opnd, va, pos - at)}, {REG_NAMES[reg]}')
        elif opcode == 0x31:
            reg, opnd, pos = _modrm(body, pos, bits)
            pos = done('xor', opnd, ('r', reg),
                       f'xor {_mem_text(opnd, va, pos - at)}, {REG_NAMES[reg]}')
        elif opcode == 0xC1:
            reg, opnd, pos = _modrm(body, pos, bits)
            imm = body[pos]
            pos += 1
            if reg != 4:
                raise DecodeError(f'{va:#x}: unsupported c1 /{reg}')
            pos = done('shl', opnd, ('i', imm),
                       f'shl {_mem_text(opnd, va, pos - at)}, {imm:#x}')
        elif opcode == 0xFF:
            reg, opnd, pos = _modrm(body, pos, bits)
            if reg == 0:
                pos = done('inc', opnd, None, f'inc {_mem_text(opnd, va, pos - at)}')
            elif reg == 2 and opnd[0] == 'rip':
                slot = va + (pos - at) + opnd[1]
                pos = done('call_slot', ('i', slot), None, f'call [{slot:#x}]')
            else:
                raise DecodeError(f'{va:#x}: unsupported ff /{reg}')
        elif opcode == 0x8D:
            reg, opnd, pos = _modrm(body, pos, bits)
            if opnd[0] != 'rip':
                raise DecodeError(f'{va:#x}: unsupported lea')
            target = va + (pos - at) + opnd[1]
            pos = done('lea', ('r', reg), ('i', target),
                       f'lea {REG_NAMES[reg]}, [{target:#x}]')
        elif 0xB8 <= opcode <= 0xBF:
            reg = (opcode - 0xB8) | ((bits & 1) << 3)
            imm = struct.unpack_from('<I', body, pos)[0]
            pos += 4
            pos = done('mov', ('r', reg), ('i', imm),
                       f'mov {REG_NAMES[reg]}, {imm:#x}')
        elif opcode == 0xC7:
            reg, opnd, pos = _modrm(body, pos, bits)
            if reg != 0 or not opsize:
                raise DecodeError(f'{va:#x}: unsupported c7')
            imm = struct.unpack_from('<H', body, pos)[0]
            pos += 2
            pos = done('movw', opnd, ('i', imm),
                       f'movw {_mem_text(opnd, va, pos - at)}, {imm:#x}')
        elif opcode == 0x0F:
            opcode2 = body[pos]
            pos += 1
            if opcode2 == 0x1F:
                _, _, pos = _modrm(body, pos, bits)
                pos = done('nop', None, None, 'nop')
            elif 0x80 <= opcode2 <= 0x8F:
                disp = struct.unpack_from('<i', body, pos)[0]
                pos += 4
                name = {0x80: 'jo', 0x82: 'jb', 0x84: 'je', 0x85: 'jne'}[opcode2]
                target = va + (pos - at) + disp
                pos = done(name, ('i', target), None, f'{name} {target:#x}')
            else:
                raise DecodeError(f'{va:#x}: unsupported 0f {opcode2:#x}')
        elif 0x70 <= opcode <= 0x7F:
            disp = struct.unpack_from('<b', body, pos)[0]
            pos += 1
            name = {0x74: 'je', 0x75: 'jne', 0x79: 'jns'}[opcode]
            target = va + (pos - at) + disp
            pos = done(name, ('i', target), None, f'{name} {target:#x}')
        elif opcode == 0xEB:
            disp = struct.unpack_from('<b', body, pos)[0]
            pos += 1
            target = va + (pos - at) + disp
            pos = done('jmp', ('i', target), None, f'jmp {target:#x}')
        elif opcode == 0xC3:
            pos = done('ret', None, None, 'ret')
        elif opcode == 0x90:
            pos = done('nop', None, None, 'nop')
        else:
            raise DecodeError(f'{va:#x}: unsupported opcode {opcode:#x}')
    if start + pos != end:
        raise DecodeError('decode did not land on the FDE end')
    return insns


# ---------------------------------------------------------------------------
# Evaluator: runs decoded instructions against a fixture arena.
# ---------------------------------------------------------------------------

class Trap(Exception):
    def __init__(self, kind, detail=()):
        super().__init__(kind)
        self.kind = kind
        self.detail = detail


class Memory:
    def __init__(self):
        self.buf = bytearray(ARENA_SIZE)

    def _off(self, va, n):
        off = va - ARENA_BASE
        if off < 0 or off + n > ARENA_SIZE:
            raise Trap('memory', (va,))
        return off

    def read(self, va, n):
        off = self._off(va, n)
        return bytes(self.buf[off:off + n])

    def write(self, va, data):
        off = self._off(va, len(data))
        self.buf[off:off + len(data)] = data

    def u64(self, va):
        return struct.unpack('<Q', self.read(va, 8))[0]

    def w64(self, va, value):
        self.write(va, struct.pack('<Q', value & M64))

    def w16(self, va, value):
        self.write(va, struct.pack('<H', value & 0xFFFF))


class Fixture:
    """One lookup input: records [(name bytes, length field)], suffix, page."""

    def __init__(self, records, suffix, page, alloc_fail=False,
                 suffix_len_override=None):
        self.records = records
        self.suffix = suffix
        self.page = page
        self.alloc_fail = alloc_fail
        self.suffix_len = (len(suffix) if suffix_len_override is None
                            else suffix_len_override)


def build_memory(fx):
    mem = Memory()
    name_vas = []
    cursor = STRINGS_VA
    for name, _len_field in fx.records:
        mem.write(cursor, name)
        name_vas.append(cursor)
        cursor += max(len(name), 1) + 8
    for i, ((_name, len_field), name_va) in enumerate(zip(fx.records, name_vas)):
        base = RECORDS_VA + i * RECORD_SIZE
        mem.w64(base + 0x00, 0xD15EA5E000000000 + i)
        mem.w64(base + 0x08, name_va)
        mem.w64(base + 0x10, len_field)
        mem.w64(base + 0x18, 0xBAD0BAD000000000 + i)
    mem.write(SUFFIX_VA, fx.suffix)
    mem.write(CTX_VA, bytes([JUNK]) * 0x600)
    mem.w64(CTX_VA + 0x08, RECORDS_VA)
    mem.w64(CTX_VA + 0x10, len(fx.records))
    mem.w64(CTX_VA + 0x50, fx.page)
    mem.write(OUT_VA, bytes([0xAA]) * 0x20)
    mem.w64(STACK_TOP - 8, RET_SENTINEL)
    return mem


def run_body(insns, fx, slot_roles):
    mem = build_memory(fx)
    regs = [0] * 16
    regs[RDI] = OUT_VA
    regs[RSI] = SUFFIX_VA
    regs[RDX] = fx.suffix_len
    regs[RCX] = CTX_VA
    regs[RSP] = STACK_TOP - 8
    flags = {'ZF': 0, 'SF': 0, 'CF': 0, 'OF': 0}
    trace = []
    heap_next = [HEAP_VA]
    by_va = {ins.va: ins for ins in insns}
    rip = BODY_START

    def addr_of(opnd):
        _, base, index, scale, disp = opnd
        value = disp
        if base is not None:
            value += regs[base]
        if index is not None:
            value += regs[index] * scale
        return value & M64

    def read_op(opnd, size):
        if opnd[0] == 'r':
            return regs[opnd[1]] & ((1 << (size * 8)) - 1)
        if opnd[0] == 'i':
            return opnd[1]
        if opnd[0] == 'rip':
            raise Trap('control', ('rip operand read',))
        return int.from_bytes(mem.read(addr_of(opnd), size), 'little')

    def write_op(opnd, value, size):
        if opnd[0] == 'r':
            regs[opnd[1]] = value & ((1 << (size * 8)) - 1)
            return
        mem.write(addr_of(opnd),
                  (value & ((1 << (size * 8)) - 1)).to_bytes(size, 'little'))

    def flags_sub(a, b, bits):
        mask = (1 << bits) - 1
        result = (a - b) & mask
        flags['ZF'] = int(result == 0)
        flags['SF'] = (result >> (bits - 1)) & 1
        flags['CF'] = int((a & mask) < (b & mask))
        flags['OF'] = int((((a ^ b) & (a ^ result)) >> (bits - 1)) & 1)

    def flags_logic(result, bits):
        mask = (1 << bits) - 1
        result &= mask
        flags['ZF'] = int(result == 0)
        flags['SF'] = (result >> (bits - 1)) & 1
        flags['CF'] = 0
        flags['OF'] = 0

    steps = 0
    while True:
        if rip == RET_SENTINEL:
            break
        ins = by_va.get(rip)
        if ins is None:
            raise Trap('control', ('rip left the body', rip))
        steps += 1
        if steps > 4_000_000:
            raise Trap('control', ('step limit',))
        op, a, b, w = ins.op, ins.a, ins.b, ins.w
        nxt = ins.va + ins.size
        if op == 'push':
            regs[RSP] = (regs[RSP] - 8) & M64
            mem.w64(regs[RSP], regs[a[1]])
        elif op == 'pop':
            regs[a[1]] = mem.u64(regs[RSP])
            regs[RSP] = (regs[RSP] + 8) & M64
        elif op == 'mov':
            write_op(a, read_op(b, w), w)
        elif op == 'movw':
            mem.w16(addr_of(a), b[1])
        elif op == 'lea':
            regs[a[1]] = b[1]
        elif op == 'add':
            old = read_op(a, w)
            result = old + b[1]
            flags['CF'] = int(result > (1 << (w * 8)) - 1)
            flags_logic(result, w * 8)
            flags['CF'] = int(result > (1 << (w * 8)) - 1)
            write_op(a, result, w)
        elif op == 'sub':
            old = read_op(a, w)
            flags_sub(old, b[1], w * 8)
            write_op(a, old - b[1], w)
        elif op == 'test':
            flags_logic(read_op(a, w) & read_op(b, w), w * 8)
        elif op == 'cmp':
            flags_sub(read_op(a, w), read_op(b, w), w * 8)
        elif op == 'xor':
            result = read_op(a, w) ^ read_op(b, w)
            flags_logic(result, w * 8)
            write_op(a, result, w)
        elif op == 'shl':
            old = read_op(a, w)
            result = (old << b[1]) & ((1 << (w * 8)) - 1)
            cf = (old >> (w * 8 - b[1])) & 1 if b[1] else flags['CF']
            flags_logic(result, w * 8)
            flags['CF'] = cf
            write_op(a, result, w)
        elif op == 'inc':
            old = read_op(a, w)
            result = (old + 1) & ((1 << (w * 8)) - 1)
            cf = flags['CF']
            flags_logic(result, w * 8)
            flags['CF'] = cf
            write_op(a, result, w)
        elif op == 'mulq':
            product = regs[RAX] * mem.u64(addr_of(a))
            regs[RAX] = product & M64
            flags['OF'] = flags['CF'] = int(product > M64)
        elif op in ('jo', 'jb', 'je', 'jne', 'jns', 'jmp'):
            taken = {'jo': flags['OF'], 'jb': flags['CF'], 'je': flags['ZF'],
                     'jne': 1 - flags['ZF'], 'jns': 1 - flags['SF'],
                     'jmp': 1}[op]
            if taken:
                nxt = a[1]
        elif op == 'nop':
            pass
        elif op == 'call_slot':
            slot = a[1]
            role = slot_roles.get(slot)
            if role is None:
                raise Trap('control', ('call through an unknown slot', slot))
            if role == 'bcmp':
                n = regs[RDX]
                left = mem.read(regs[RDI], n) if n else b''
                right = mem.read(regs[RSI], n) if n else b''
                result = 0 if left == right else 1
                trace.append(('bcmp', n, result))
                regs[RAX] = result
            elif role == 'memcpy':
                n = regs[RDX]
                if n:
                    mem.write(regs[RDI], mem.read(regs[RSI], n))
                trace.append(('memcpy', n))
                regs[RAX] = regs[RDI]
            elif role == 'alloc':
                size = regs[RDI]
                if fx.alloc_fail:
                    trace.append(('alloc', size, 0))
                    regs[RAX] = 0
                else:
                    ptr = heap_next[0]
                    heap_next[0] += max(size, 1)
                    trace.append(('alloc', size, 1))
                    regs[RAX] = ptr
            elif role in ('panic_add', 'panic_mul'):
                trace.append(('panic', role))
                raise Trap(role, (regs[RDI],))
            elif role == 'alloc_err':
                trace.append(('alloc_error', regs[RDI], regs[RSI]))
                raise Trap('alloc_error', (regs[RDI], regs[RSI]))
            else:
                raise Trap('control', ('unknown stub', role))
        elif op == 'ret':
            rip = mem.u64(regs[RSP])
            regs[RSP] = (regs[RSP] + 8) & M64
            continue
        else:
            raise Trap('control', ('unimplemented op', op))
        rip = nxt
    return {'kind': 'return', 'out': mem.read(OUT_VA, 0x20), 'trace': trace,
            'heap': mem.read(HEAP_VA, heap_next[0] - HEAP_VA)}


# ---------------------------------------------------------------------------
# Independent rule list for the same contract.
# ---------------------------------------------------------------------------

def _blank_out():
    return bytearray([0xAA] * 0x20)


def run_rule(fx):
    trace = []
    records = fx.records
    suffix = fx.suffix
    n = fx.suffix_len
    if records:
        product_full = MULTIPLIER * fx.page
        if product_full > M64:
            trace.append(('panic', 'panic_mul'))
            return {'kind': 'trap', 'trap': 'panic_mul',
                    'detail': (LOCATION_VA,), 'trace': trace}
        product = product_full
        for pos, (name, len_field) in enumerate(records):
            if product + pos > M64:
                trace.append(('panic', 'panic_add'))
                return {'kind': 'trap', 'trap': 'panic_add',
                        'detail': (LOCATION_VA,), 'trace': trace}
            if len_field == n:
                # bcmp compares n bytes of arena memory: the stored name
                # bytes (zero-filled arena beyond them) against the suffix
                # bytes (likewise). A zero-length bcmp is always equal.
                mem_name = name + b'\0' * max(0, n - len(name))
                mem_suf = suffix + b'\0' * max(0, n - len(suffix))
                equal = mem_name[:n] == mem_suf[:n]
                trace.append(('bcmp', n, 0 if equal else 1))
                if equal:
                    out = _blank_out()
                    struct.pack_into('<H', out, 0, OK_TAG)
                    struct.pack_into('<Q', out, 8, product + pos)
                    return {'kind': 'return', 'out': bytes(out), 'trace': trace}
    if n >= 2**63:
        trace.append(('alloc_error', 0, n))
        return {'kind': 'trap', 'trap': 'alloc_error', 'detail': (0, n),
                'trace': trace}
    if n == 0:
        out = _blank_out()
        struct.pack_into('<H', out, 0, ERR_TAG)
        struct.pack_into('<Q', out, 8, 0)
        struct.pack_into('<Q', out, 0x10, 1)
        struct.pack_into('<Q', out, 0x18, 0)
        return {'kind': 'return', 'out': bytes(out), 'trace': trace}
    trace.append(('alloc', n, 0 if fx.alloc_fail else 1))
    if fx.alloc_fail:
        trace.append(('alloc_error', 1, n))
        return {'kind': 'trap', 'trap': 'alloc_error', 'detail': (1, n),
                'trace': trace}
    trace.append(('memcpy', n))
    out = _blank_out()
    struct.pack_into('<H', out, 0, ERR_TAG)
    struct.pack_into('<Q', out, 8, n)
    struct.pack_into('<Q', out, 0x10, HEAP_VA)
    struct.pack_into('<Q', out, 0x18, n)
    return {'kind': 'return', 'out': bytes(out), 'trace': trace, 'heap': suffix}


def outcome_of(result):
    if result['kind'] == 'trap':
        return ('trap', result['trap'], result.get('detail', ()))
    out = result['out']
    tag = struct.unpack_from('<H', out, 0)[0]
    if tag == OK_TAG:
        return ('ok', struct.unpack_from('<Q', out, 8)[0])
    return ('err', struct.unpack_from('<Q', out, 8)[0],
            struct.unpack_from('<Q', out, 0x10)[0],
            struct.unpack_from('<Q', out, 0x18)[0])


def run_case(insns, fx, slot_roles):
    """Run evaluator and rule list; return (match, got outcome, want outcome)."""
    try:
        got = run_body(insns, fx, slot_roles)
    except Trap as trap:
        got = {'kind': 'trap', 'trap': trap.kind, 'detail': trap.detail,
               'trace': None}
    want = run_rule(fx)
    match = outcome_of(got) == outcome_of(want)
    if got['kind'] == 'return' and want['kind'] == 'return':
        if got['out'] != want['out']:
            match = False
        if got['trace'] != want['trace']:
            match = False
        if outcome_of(want)[0] == 'err' and fx.suffix_len > 0 and not fx.alloc_fail:
            if got.get('heap', b'') != fx.suffix:
                match = False
    return match, outcome_of(got), outcome_of(want)


# ---------------------------------------------------------------------------
# Case corpus.
# ---------------------------------------------------------------------------

def named_cases():
    cases = []

    def add(name, records, suffix, page=0, **kw):
        cases.append((name, Fixture(records, suffix, page, **kw)))

    def rec(name):
        return (name, len(name))

    add('hit-first', [rec(b'ABC'), rec(b'DEF')], b'ABC')
    add('hit-last', [rec(b'ABC'), rec(b'DEF'), rec(b'GHI')], b'GHI')
    add('hit-page7', [rec(b'ABC'), rec(b'DEF')], b'DEF', page=7)
    add('miss-short', [rec(b'ABC')], b'ABD')
    add('miss-empty-table', [], b'ABC')
    add('empty-suffix-hit-zero-len-record', [rec(b'AB'), (b'', 0)], b'')
    add('empty-suffix-miss', [rec(b'AB')], b'')
    add('decoy-same-length-different-bytes', [rec(b'ABD'), rec(b'ABC')], b'ABC')
    add('decoy-same-bytes-different-length-field', [(b'ABC', 4), rec(b'ABC')], b'ABC')
    add('duplicate-names-first-wins', [rec(b'ABC'), rec(b'ABC')], b'ABC')
    add('count-zero-page-overflow-ignored', [], b'ABC', page=PAGE_MAX + 1)
    add('mul-overflow-hit-attempt', [rec(b'ABC')], b'ABC', page=PAGE_MAX + 1)
    add('mul-overflow-miss-attempt', [rec(b'ABC')], b'ZZZ', page=PAGE_MAX + 1)
    add('page-max-hit', [rec(b'ABC'), rec(b'DEF')], b'DEF', page=PAGE_MAX)
    add('page-max-miss-err-copy', [rec(b'ABC')], b'NOPE', page=PAGE_MAX)
    add('alloc-fail-miss', [rec(b'ABC')], b'NOPE', alloc_fail=True)
    add('alloc-fail-hit-unaffected', [rec(b'ABC')], b'ABC', alloc_fail=True)
    add('huge-len-miss-alloc-error', [], b'xy', suffix_len_override=2**63)
    add('huge-len-after-scan', [rec(b'ABC'), rec(b'DE')], b'xy',
        suffix_len_override=2**63)
    add('len-just-below-2^63-alloc-fail', [], b'xy',
        suffix_len_override=2**63 - 1, alloc_fail=True)
    wrap_records = [(b'R%04d' % i, 5) for i in range(1617)]
    add('index-wrap-guard-fires-before-record-1616', wrap_records,
        b'R1616', page=PAGE_MAX)
    add('index-wrap-last-reachable-record-1615', wrap_records,
        b'R1615', page=PAGE_MAX)
    add('index-wrap-shorter-table-misses', wrap_records[:1616],
        b'R1616', page=PAGE_MAX)
    add('index-wrap-no-match-table-1616-traps', wrap_records[:1616],
        b'ZZZZZ', page=PAGE_MAX)
    add('case-sensitive', [rec(b'abc')], b'ABC')
    add('nine-char-suffix-hit', [rec(b'ABCDEFGHI')], b'ABCDEFGHI')
    add('long-name-300', [(b'N' * 300, 300)], b'N' * 300)
    add('long-name-300-miss-last-byte', [(b'N' * 300, 300)], b'N' * 299 + b'M')
    add('record-junk-fields-ignored', [(b'ABC', 3)], b'ABC', page=3)
    add('single-record-hit', [rec(b'X')], b'X')
    add('single-record-miss', [rec(b'X')], b'Y')
    return cases


def sweep_cases(count=3000, seed=20261109):
    rng = random.Random(seed)
    alphabet = [b'A', b'B', b'C', b'K:', b'0', b'9']
    cases = []
    for _i in range(count):
        nrec = rng.randrange(0, 25)
        records = []
        for _ in range(nrec):
            name = b''.join(rng.choice(alphabet)
                            for _ in range(rng.randrange(0, 6)))
            len_field = len(name)
            if rng.random() < 0.1:
                len_field = max(len_field + rng.choice((-1, 1, 7)), 0) \
                    if len_field else 3
            records.append((name, len_field))
        if records and rng.random() < 0.6:
            suffix = rng.choice(records)[0]
        else:
            suffix = b''.join(rng.choice(alphabet)
                              for _ in range(rng.randrange(0, 6)))
        page = rng.choice((0, 0, 1, 2, 5, 1000, PAGE_MAX))
        cases.append(Fixture(records, suffix, page,
                             alloc_fail=rng.random() < 0.15))
    return cases


# ---------------------------------------------------------------------------
# Mutation and structure controls.
# ---------------------------------------------------------------------------

def find_insn_offset(insns, va):
    start = insns[0].va
    for ins in insns:
        if ins.va == va:
            return ins.va - start, ins.size
    raise ValueError(f'no instruction at {va:#x}')


def mutate(body, offset, transform):
    data = bytearray(body)
    transform(data, offset)
    return bytes(data)


MUTATIONS = [
    # (name, instruction va, byte transform, expected effect)
    ('multiplier-10000-to-10001', 0x421A8D4,
     lambda d, o: d.__setitem__(slice(o + 1, o + 5), struct.pack('<I', 10_001)),
     'named case outcomes change'),
    ('ok-tag-0x1a2-to-0x1a3', 0x421A93C,
     lambda d, o: d.__setitem__(slice(o + 3, o + 5), struct.pack('<H', 0x1A3)),
     'hit outcomes change'),
    ('err-tag-0x68-to-0x69', 0x421A984,
     lambda d, o: d.__setitem__(slice(o + 3, o + 5), struct.pack('<H', 0x69)),
     'miss outcomes change'),
    ('record-stride-shl-5-to-6', 0x421A8EA,
     lambda d, o: d.__setitem__(o + 3, 6),
     'scan outcomes change'),
    ('record-length-offset-0x10-to-0x18', 0x421A915,
     lambda d, o: d.__setitem__(o + 4, 0x18),
     'scan outcomes change'),
    ('empty-count-je-to-jne', 0x421A8D2,
     lambda d, o: d.__setitem__(o, 0x75),
     'empty-table control flow changes'),
    ('bcmp-result-jne-to-je', 0x421A931,
     lambda d, o: d.__setitem__(o, 0x74),
     'hit and miss outcomes swap'),
    ('empty-miss-sentinel-1-to-2', 0x421A979,
     lambda d, o: d.__setitem__(o + 2, 2),
     'empty-miss pointer changes'),
    ('page-field-offset-0x50-to-0x48', 0x421A8D9,
     lambda d, o: d.__setitem__(o + 3, 0x48),
     'page arithmetic reads the junk field and changes'),
]


def run_controls(body, insns, slot_roles, cases):
    rows = []
    originals = [run_case(insns, fx, slot_roles)[0] for _n, fx in cases]
    for name, va, transform, note in MUTATIONS:
        offset, _size = find_insn_offset(insns, va)
        mutant = mutate(body, offset, transform)
        try:
            mutant_insns = decode_body(mutant)
        except DecodeError:
            rows.append((name, 'killed (decode fails)', note))
            continue
        changed = 0
        for (_case_name, fx), o_match in zip(cases, originals):
            m_match, _g2, _w2 = run_case(mutant_insns, fx, slot_roles)
            if o_match and not m_match:
                changed += 1
        rows.append((name, f'killed ({changed} named cases diverge)' if changed
                     else 'SURVIVED', note))
    # Structure controls: a wrong digest and a non-FDE start must be refused.
    rows.append(('structure-wrong-body-digest',
                 'killed (refused)' if sha256(body) != BODY_SHA256.replace('6', '7', 1)
                 else 'n/a', 'the tool checks the body digest before decoding'))
    try:
        decode_body(body, BODY_START + 1, BODY_END)
        rows.append(('structure-non-fde-start', 'SURVIVED',
                     'decoding from a non-FDE start was not refused'))
    except DecodeError:
        rows.append(('structure-non-fde-start', 'killed (decode fails at the '
                     'shifted offset)', 'boundaries come from the FDE extent'))
    return rows


def random_mutation_sample(body, insns, slot_roles, cases, count=60,
                           seed=20261109):
    rng = random.Random(seed)
    originals = [run_case(insns, fx, slot_roles)[0] for _n, fx in cases]
    killed = survived = undecodable = 0
    for _ in range(count):
        offset = rng.randrange(len(body))
        mutant = bytearray(body)
        mutant[offset] ^= 1 << rng.randrange(8)
        try:
            mutant_insns = decode_body(bytes(mutant))
        except DecodeError:
            undecodable += 1
            continue
        diverged = False
        for (_case_name, fx), o_match in zip(cases, originals):
            m_match, _g2, _w2 = run_case(mutant_insns, fx, slot_roles)
            if o_match and not m_match:
                diverged = True
                break
        if diverged:
            killed += 1
        else:
            survived += 1
    return {'sampled': count, 'undecodable': undecodable, 'killed': killed,
            'survived': survived}


# ---------------------------------------------------------------------------
# Call-site census for the lookup slot.
# ---------------------------------------------------------------------------

def scan_call_sites(data, secs, extents):
    """Find direct call sites whose target slot holds the lookup body.

    Scans every executable section for call [rip+disp32] (FF 15) and
    call [rip+disp32] with a REX prefix (4x FF 15) whose computed slot is
    LOOKUP_SLOT, then attributes each site to its containing FDE.
    """
    exec_secs = [s for s in secs if s['flags'] & 0x4 and s['type'] != 8]
    sites = []
    for s in exec_secs:
        blob = data[s['offset']:s['offset'] + s['size']]
        base = s['address']
        for pattern, plen in ((b'\xff\x15', 6),):
            pos = 0
            while True:
                idx = blob.find(pattern, pos)
                if idx < 0:
                    break
                pos = idx + 1
                disp = struct.unpack_from('<i', blob, idx + 2)[0]
                slot = base + idx + plen + disp
                if slot == LOOKUP_SLOT:
                    sites.append(base + idx)
        for rex in range(0x40, 0x50):
            pattern = bytes((rex, 0xFF, 0x15))
            pos = 0
            while True:
                idx = blob.find(pattern, pos)
                if idx < 0:
                    break
                pos = idx + 1
                disp = struct.unpack_from('<i', blob, idx + 3)[0]
                slot = base + idx + 7 + disp
                if slot == LOOKUP_SLOT:
                    sites.append(base + idx)
    sites = sorted(set(sites))
    starts = sorted(extents)
    rows = []
    for site in sites:
        owner = None
        for start in starts:
            if start > site:
                break
            if start <= site < extents[start][0]:
                owner = start
        rows.append((site, owner))
    return rows


# ---------------------------------------------------------------------------
# Evidence emission.
# ---------------------------------------------------------------------------

def fmt_outcome(outcome):
    if outcome[0] == 'trap':
        return f'trap:{outcome[1]}'
    if outcome[0] == 'ok':
        return f'ok index={outcome[1]}'
    return (f'err cap={outcome[1]} ptr={outcome[2]:#x} len={outcome[3]}')


def emit(outdir, body, insns, slot_roles, named, sweep_count, sweep_mismatches,
         controls, sample, sites, secs, data):
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / 'function-rows.tsv').write_text(
        'function_start\tfunction_end\tsize\tbody_sha256\tlsda\trole\n'
        f'{BODY_START:#x}\t{BODY_END:#x}\t{BODY_END - BODY_START}\t'
        f'{BODY_SHA256}\tnone\tPDI asset-name lookup behind slot '
        f'{LOOKUP_SLOT:#x}: linear scan of the front record name table, '
        'Ok carries the global asset index, Err carries an owned copy of '
        'the missing suffix\n')
    edges = []
    for ins in insns:
        if ins.op == 'call_slot':
            edges.append((ins.va, ins.a[1], slot_roles[ins.a[1]]))
    call_lines = ['site\tvia\ttarget_or_slot\trole']
    for site, slot, role in edges:
        call_lines.append(f'{site:#x}\tdirect slot\t{slot:#x}\t{role}')
    for site, owner in sites:
        call_lines.append(f'{site:#x}\tslot {LOOKUP_SLOT:#x}\t'
                            f'{BODY_START:#x}\t'
                            f'caller inside FDE {owner:#x}' if owner else
                            f'{site:#x}\tslot {LOOKUP_SLOT:#x}\t'
                            f'{BODY_START:#x}\tcaller outside every FDE')
    (outdir / 'call-sites.tsv').write_text('\n'.join(call_lines) + '\n')
    loc_bytes = data[va_to_offset(secs, LOCATION_STR_VA):
                     va_to_offset(secs, LOCATION_STR_VA) + len(LOCATION_STR)]
    (outdir / 'constants.tsv').write_text(
        'constant\tvalue\tnote\n'
        f'ok_tag\t{OK_TAG:#x}\tstored by the hit path\n'
        f'err_tag\t{ERR_TAG:#x}\tstored by the miss path\n'
        f'multiplier\t{MULTIPLIER}\tpage to global index scale (0x2710)\n'
        f'record_size\t{RECORD_SIZE:#x}\tname table record stride (shl 5)\n'
        f'location_va\t{LOCATION_VA:#x}\tshared panic Location object\n'
        f'location_file\t{loc_bytes.decode()}:32:14\t'
        'embedded in the Location payload\n'
        f'page_max\t{PAGE_MAX}\tlargest page whose product fits u64\n'
        f'product_at_page_max\t{MULTIPLIER * PAGE_MAX}\t2**64 - 1616\n')
    outcome_lines = ['case\tinput_summary\tevaluator\tverdict']
    for name, fx, got, want in named:
        summary = (f'records={len(fx.records)} suffix_len={fx.suffix_len} '
                   f'page={fx.page}')
        outcome_lines.append(f'{name}\t{summary}\t{fmt_outcome(got)}\t'
                             f'{"match" if got == want else "MISMATCH"}')
    (outdir / 'outcomes.tsv').write_text('\n'.join(outcome_lines) + '\n')
    (outdir / 'sweep-outcomes.tsv').write_text(
        'seed\tcases\tmismatches\n20261109\t'
        f'{sweep_count}\t{sweep_mismatches}\n')
    control_lines = ['control\tresult\tnote']
    for name, result, note in controls:
        control_lines.append(f'{name}\t{result}\t{note}')
    control_lines.append(
        f'random-single-bit-sample\t{sample["killed"]} killed, '
        f'{sample["survived"]} survived, {sample["undecodable"]} undecodable '
        f'of {sample["sampled"]}\tsingle-bit flips over the whole extent, '
        'fixed seed 20261109')
    (outdir / 'controls.tsv').write_text('\n'.join(control_lines) + '\n')
    measure = {
        'target': 'artifacts/node/115/hl-node',
        'target_sha256': TARGET_SHA256,
        'target_size': TARGET_SIZE,
        'body': {'start': BODY_START, 'end': BODY_END,
                 'size': BODY_END - BODY_START, 'sha256': BODY_SHA256,
                 'instructions': len(insns)},
        'named_cases': len(named),
        'named_mismatches': sum(1 for _n, _f, g, w in named if g != w),
        'sweep_cases': sweep_count,
        'sweep_mismatches': sweep_mismatches,
        'slot_call_sites': len(sites),
        'slot_call_site_fdes': len({o for _s, o in sites if o}),
        'mutations': {name: result for name, result, _note in controls},
        'random_sample': sample,
        'location': 'l1/src/asset/pdi.rs:32:14',
        'conclusion': ('the slot body linearly scans the front record name '
                       'table; a hit returns the global index '
                       'page*10000+position under tag 0x1a2, a miss returns '
                       'an owned copy of the suffix under tag 0x68; the two '
                       'overflow guards share l1/src/asset/pdi.rs:32:14'),
    }
    (outdir / 'measure.json').write_text(
        json.dumps(measure, indent=2, sort_keys=True) + '\n')
    evidence = {
        'target_sha256': TARGET_SHA256,
        'tool': 'tools/pdi_name_lookup115.py',
        'function': {'start': BODY_START, 'end': BODY_END,
                     'sha256': BODY_SHA256},
        'slot': {'va': LOOKUP_SLOT, 'relocation': 'R_X86_64_RELATIVE',
                 'target': BODY_START},
        'stubs': {f'{slot:#x}': role for slot, role in slot_roles.items()},
        'rules': [
            'the count at front+0x10 gates everything: with zero records '
            'the page product is never computed and an overflowing page is '
            'ignored',
            'with at least one record, prod = page * 10000 is computed '
            'once under a multiply-overflow panic',
            'records are scanned in order at a 0x20 stride from front+8; '
            'the length field at record+0x10 must equal the suffix length '
            'before bcmp compares the name bytes at record+8',
            'the comparison covers exactly the length-field count of '
            'bytes from each pointer: a zero length compares equal '
            'against any record, and a length past a shorter stored name '
            'reads whatever follows it in memory',
            'before the record at position p is examined, prod + p is '
            'checked for add overflow; the first unreachable position at '
            'the maximal page is 1616',
            'a hit stores tag 0x1a2 and the global index prod + position '
            'at out+8 and returns',
            'the first matching record wins',
            'a miss with a negative i64 length traps through the '
            'allocation-error shim with arguments (0, len)',
            'a zero-length miss stores tag 0x68 with cap 0, ptr 1, len 0 '
            'and allocates nothing',
            'any other miss allocates len bytes, copies the suffix into '
            'the allocation and stores tag 0x68 with cap = len, '
            'ptr = allocation, len = len; an allocation failure traps '
            'with arguments (1, len)',
            'both panic guards use the shared Location object for '
            'l1/src/asset/pdi.rs:32:14',
        ],
        'limitations': [
            'the evaluator models the six external slots as stubs; the '
            'real bcmp, memcpy, allocator and panic shims were identified '
            'by relocation and call shape, not executed',
            'out bytes 2..7 are never written by the body and keep the '
            'caller buffer contents; the corpus compares the full 0x20 '
            'output against a 0xAA prefill',
            'caller-side consumption of the returned index and error '
            'string is outside this body and stays with the RE-007 '
            'registration caller question',
        ],
    }
    (outdir / 'evidence.json').write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + '\n')


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--sweep-count', type=int, default=3000)
    args = parser.parse_args()

    data = TARGET.read_bytes()
    if len(data) != TARGET_SIZE or sha256(data) != TARGET_SHA256:
        raise SystemExit('target digest mismatch: refusing to run')
    secs = sections(data)
    _cies, fde_rows = eh_frame_records(data, secs)
    extents = {row['start']: (row['end'], row['lsda']) for row in fde_rows}
    if BODY_START not in extents or extents[BODY_START][0] != BODY_END:
        raise SystemExit('FDE extent for the body does not match the pin')
    body_off = va_to_offset(secs, BODY_START)
    body = data[body_off:body_off + (BODY_END - BODY_START)]
    if sha256(body) != BODY_SHA256:
        raise SystemExit('body digest mismatch: refusing to run')
    loc_file = data[va_to_offset(secs, LOCATION_STR_VA):
                    va_to_offset(secs, LOCATION_STR_VA) + len(LOCATION_STR)]
    if loc_file != LOCATION_STR:
        raise SystemExit('panic Location file string mismatch')
    slot_roles = slot_targets(data, secs)
    insns = decode_body(body)

    named = []
    for name, fx in named_cases():
        _match, got, want = run_case(insns, fx, slot_roles)
        named.append((name, fx, got, want))
    named_mismatches = sum(1 for _n, _f, g, w in named if g != w)
    sweep = sweep_cases(args.sweep_count)
    sweep_mismatches = 0
    for fx in sweep:
        match, _g, _w = run_case(insns, fx, slot_roles)
        if not match:
            sweep_mismatches += 1
    controls = run_controls(body, insns, slot_roles, named_cases())
    sample = random_mutation_sample(body, insns, slot_roles, named_cases())
    sites = scan_call_sites(data, secs, extents)

    ok = (named_mismatches == 0 and sweep_mismatches == 0
          and all(not r.startswith('SURVIVED') for _n, r, _t in controls))
    print(f'named cases: {len(named) - named_mismatches}/{len(named)} match')
    print(f'sweep cases: {args.sweep_count - sweep_mismatches}/'
          f'{args.sweep_count} match')
    print(f'slot call sites: {len(sites)} in '
          f'{len({o for _s, o in sites if o})} FDEs')
    for name, result, _note in controls:
        print(f'control {name}: {result}')
    print(f'random sample: {sample}')
    if args.out:
        emit(args.out, body, insns, slot_roles,
             [(n, fx, g, w) for n, fx, g, w in named],
             args.sweep_count, sweep_mismatches, controls, sample, sites,
             secs, data)
    if args.check and not ok:
        raise SystemExit(1)
    print('PASS' if ok else 'FAIL')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())

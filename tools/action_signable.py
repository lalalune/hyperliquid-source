#!/usr/bin/env python3
"""RE-005: the L1 action signing payload in node #94 (static, no execution of the target).

Three functions own the only panic ``Location`` records that name
``l1/src/action/rmp_signable.rs`` (line 14, column 55).  Each serializes an action
with rmp-serde, appends a signing suffix to the encoded bytes, hashes the result with
Keccak-256 and builds a signable payload:

    preimage = encoded_action
             ++ nonce as 8 big-endian bytes
             ++ (0x01 ++ vault_address[20]  |  0x00)
             ++ (0x00 ++ expires_after as 8 big-endian bytes  |  nothing)
    connection_id = keccak256(preimage)

Two copies return ``{source: "a" if chain == 3 else "b", connection_id, chain_id 1337,
verifying_contract 0}``; the third returns ``{signature_chain_id, connection_id, nonce,
chain}``.

The tool reads the pinned ELF, binds the three functions through relocations, FDEs and
RIP-relative ``lea`` sites, disassembles them with ``objdump`` (GNU binutils or LLVM; set
``OBJDUMP`` to choose) and interprets the real instructions in a small x86-64 evaluator.
The action serializer is the only callee replaced by an oracle: it stores caller-chosen
encoded bytes into the ``Vec`` it was handed and returns ``Ok``.  Growth, allocation,
hashing and deallocation callees are modelled by their observed interfaces; the hash
model is a pure-Python Keccak-256.  The evaluator stops on any unmodelled instruction,
register byte, flag, memory byte or call target.  Nothing from the binary runs natively.

    python3 tools/action_signable.py --out <dir>

writes ``evidence.json``, ``functions.tsv``, ``vectors.tsv``, one normalized listing per
function and ``MANIFEST.sha256``.  Only the Python standard library and objdump are used.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FIRST_PARTY = b'/home/ubuntu/hl/code_Mainnet/'
SOURCE_PATH = b'l1/src/action/rmp_signable.rs'
SEED = b'RE-005-action-signable-94'
MASK = (1 << 64) - 1

UNWRAP_MESSAGE = b'called `Result::unwrap()` on an `Err` value'
OK_NICHE = 0x8000000000000004          # the serializer's Ok tag in its niche-encoded result
KECCAK_RATE = 136                      # 200 - 256 / 4
KECCAK_DELIM = 0x01                    # Keccak (not SHA-3) padding byte
KECCAK_STATE_SIZE = 0xE0               # bytes copied when the hasher state is cloned
RMP_CONFIG_DWORD = 0x01000400          # depth 1024, is_human_readable 0, is_named 1
CHAIN_ID = 1337
MAINNET_CHAIN = 3
KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
KECCAK_RHO = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
CRATE_PATHS = (b'rmp-serde-1.3.0/src/encode.rs', b'tiny-keccak-2.0.2/src/')

# Production vector from the public Python SDK test-suite
# (hyperliquid-dex/hyperliquid-python-sdk, tests/signing_test.py,
# test_phantom_agent_creation_matches_production): one IOC limit order, nonce
# 1677777606040, no vault address, no expiry, mainnet source.
SDK_ACTION = {
    'type': 'order',
    'orders': [{'a': 4, 'b': True, 'p': '1670.1', 's': '0.0147', 'r': False,
                't': {'limit': {'tif': 'Ioc'}}}],
    'grouping': 'na',
}
SDK_NONCE = 1677777606040
SDK_CONNECTION_ID = '0fcbeda5ae3c4950a548021552a4fea2226858c4453571bf3f24ba017eac2908'

LEA_RE = re.compile(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
CALLER_SAVED = ('rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11')
TERMINAL_ROLES = ('unwind', 'alloc-error', 'unwrap-failed')


class EvidenceError(ValueError):
    pass


# --------------------------------------------------------------------------- models

def keccak256(message: bytes) -> bytes:
    """Keccak-256 (pad10*1 with the 0x01 delimiter), the Ethereum hash."""
    rot = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
           [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]

    def rol(x, n):
        n %= 64
        return ((x << n) | (x >> (64 - n))) & MASK if n else x

    def permute(a):
        for rc in KECCAK_RC:
            c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
            a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    b[y][(2 * x + 3 * y) % 5] = rol(a[x][y], rot[x][y])
            a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
                 for x in range(5)]
            a[0][0] ^= rc
        return a

    padded = bytearray(message) + bytes([KECCAK_DELIM])
    while len(padded) % KECCAK_RATE:
        padded.append(0)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), KECCAK_RATE):
        for i in range(KECCAK_RATE // 8):
            state[i % 5][i // 5] ^= int.from_bytes(padded[off + 8 * i:off + 8 * i + 8], 'little')
        state = permute(state)
    return b''.join(state[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))


def signing_suffix(nonce: int, vault, expires) -> bytes:
    """The suffix the public SDK appends before hashing (``action_hash``)."""
    out = nonce.to_bytes(8, 'big')
    out += b'\x01' + vault if vault is not None else b'\x00'
    if expires is not None:
        out += b'\x00' + expires.to_bytes(8, 'big')
    return out


def expected_payload(encoded: bytes, nonce: int, vault, expires, chain: int):
    preimage = encoded + signing_suffix(nonce, vault, expires)
    return preimage, keccak256(preimage), b'a' if chain == MAINNET_CHAIN else b'b'


def msgpack(value) -> bytes:
    """Minimal MessagePack encoder for the SDK vector (maps keep insertion order)."""
    if value is True or value is False:
        return b'\xc3' if value else b'\xc2'
    if value is None:
        return b'\xc0'
    if isinstance(value, int):
        if 0 <= value < 0x80:
            return bytes([value])
        if 0 <= value < 0x100:
            return b'\xcc' + bytes([value])
        if 0 <= value < 0x10000:
            return b'\xcd' + value.to_bytes(2, 'big')
        if 0 <= value < 0x100000000:
            return b'\xce' + value.to_bytes(4, 'big')
        if 0 <= value < 1 << 64:
            return b'\xcf' + value.to_bytes(8, 'big')
        raise ValueError('unsupported integer')
    if isinstance(value, str):
        raw = value.encode('utf-8')
        if len(raw) < 32:
            return bytes([0xA0 | len(raw)]) + raw
        if len(raw) < 0x100:
            return b'\xd9' + bytes([len(raw)]) + raw
        raise ValueError('unsupported string length')
    if isinstance(value, list):
        if len(value) >= 16:
            raise ValueError('unsupported array length')
        return bytes([0x90 | len(value)]) + b''.join(msgpack(v) for v in value)
    if isinstance(value, dict):
        if len(value) >= 16:
            raise ValueError('unsupported map length')
        return bytes([0x80 | len(value)]) + b''.join(msgpack(k) + msgpack(v) for k, v in value.items())
    raise ValueError(f'unsupported value {value!r}')


# --------------------------------------------------------------------------- ELF

class Elf:
    def __init__(self, data: bytes):
        if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
            raise EvidenceError('not an ELF64 little-endian file')
        self.data = data
        phoff, = struct.unpack_from('<Q', data, 0x20)
        shoff, = struct.unpack_from('<Q', data, 0x28)
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from('<HHHHH', data, 0x36)
        self.loads = []
        for i in range(phnum):
            p_type, _f, p_off, p_va, _pa, p_filesz, _m, _a = struct.unpack_from(
                '<IIQQQQQQ', data, phoff + i * phentsize)
            if p_type == 1:
                self.loads.append((p_va, p_off, p_filesz))
        secs = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
        stro = secs[shstrndx][4]
        self.sections = {}
        for s in secs:
            name = data[stro + s[0]:data.index(b'\0', stro + s[0])].decode()
            self.sections[name] = (s[3], s[4], s[5])      # (addr, offset, size)
        for required in ('.text', '.rodata', '.data.rel.ro', '.rela.dyn', '.eh_frame_hdr',
                         '.dynsym', '.dynstr'):
            if required not in self.sections:
                raise EvidenceError(f'missing section {required}')

    def off(self, va):
        for v, o, s in self.loads:
            if v <= va < v + s:
                return o + va - v
        return None

    def read(self, va, n):
        o = self.off(va)
        if o is None or o + n > len(self.data):
            raise EvidenceError(f'{va:#x} is not file-backed')
        return self.data[o:o + n]

    def rodata_hits(self, needle: bytes):
        ro_va, ro_off, ro_size = self.sections['.rodata']
        return [ro_va + m.start() - ro_off for m in re.finditer(re.escape(needle), self.data)
                if ro_off <= m.start() < ro_off + ro_size]


def fde_index(elf: Elf):
    addr, off, _size = elf.sections['.eh_frame_hdr']
    d = elf.data
    if tuple(d[off:off + 4]) != (1, 0x1B, 0x03, 0x3B):
        raise EvidenceError('unexpected .eh_frame_hdr encodings')
    count = struct.unpack_from('<I', d, off + 8)[0]
    starts, ends = [], []
    for i in range(count):
        pos = off + 12 + 8 * i
        pc = addr + struct.unpack_from('<i', d, pos)[0]
        fde_va = addr + struct.unpack_from('<i', d, pos + 4)[0]
        fo = elf.off(fde_va)
        pc_begin = fde_va + 8 + struct.unpack_from('<i', d, fo + 8)[0]
        if pc_begin != pc:
            raise EvidenceError(f'FDE pc_begin mismatch at {fde_va:#x}')
        starts.append(pc)
        ends.append(pc + struct.unpack_from('<I', d, fo + 12)[0])
    if starts != sorted(starts):
        raise EvidenceError('.eh_frame_hdr table is not sorted')
    return starts, ends


def containing(starts, ends, va):
    j = bisect.bisect_right(starts, va) - 1
    if j >= 0 and va < ends[j]:
        return starts[j], ends[j]
    return None


def relocations(elf: Elf):
    """RELATIVE slots (slot -> target) and GLOB_DAT/JUMP_SLOT names (slot -> symbol)."""
    relative, named = {}, {}
    dynsym, dynstr = elf.sections['.dynsym'], elf.sections['.dynstr']
    for name in ('.rela.dyn', '.rela.plt'):
        if name not in elf.sections:
            continue
        _a, off, size = elf.sections[name]
        for o in range(off, off + size, 24):
            r_off, info, add = struct.unpack_from('<QQq', elf.data, o)
            kind, sym = info & 0xFFFFFFFF, info >> 32
            if kind == 8:
                relative[r_off] = add
            elif kind in (6, 7):
                st_name = struct.unpack_from('<I', elf.data, dynsym[1] + 24 * sym)[0]
                so = dynstr[1] + st_name
                named[r_off] = elf.data[so:elf.data.index(b'\0', so)].decode()
    return relative, named


def lea_targets(elf: Elf):
    t_va, t_off, t_size = elf.sections['.text']
    text = elf.data[t_off:t_off + t_size]
    out = {}
    for m in LEA_RE.finditer(text):
        i = m.start()
        if i + 7 > len(text):
            continue
        tgt = t_va + i + 7 + struct.unpack_from('<i', text, i + 3)[0]
        out.setdefault(tgt, []).append(t_va + i)
    return out


def direct_callers(elf: Elf, target: int):
    """Sites of ``e8 rel32`` byte patterns landing on ``target`` (a byte scan, not a decode)."""
    t_va, t_off, t_size = elf.sections['.text']
    text = elf.data[t_off:t_off + t_size]
    out = []
    for m in re.finditer(rb'\xe8', text):
        i = m.start()
        if i + 5 <= len(text) and t_va + i + 5 + struct.unpack_from('<i', text, i + 1)[0] == target:
            out.append(t_va + i)
    return out


def source_bindings(elf: Elf, relative: dict):
    """The path string, its Location records (slot, line, col)."""
    path = FIRST_PARTY + SOURCE_PATH
    hits = elf.rodata_hits(path)
    if len(hits) != 1:
        raise EvidenceError(f'expected one .rodata copy of the source path, found {len(hits)}')
    path_va = hits[0]
    drr_va, _o, drr_size = elf.sections['.data.rel.ro']
    records = []
    for slot, target in relative.items():
        if target != path_va or not drr_va <= slot < drr_va + drr_size:
            continue
        length, line, col = struct.unpack_from('<QII', elf.read(slot + 8, 16))
        if length == len(path):
            records.append({'location_va': slot, 'line': line, 'col': col})
    if not records:
        raise EvidenceError('no Location record names the source path')
    return path_va, sorted(records, key=lambda r: r['location_va'])


# --------------------------------------------------------------------------- disassembly

REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
REGS = {}
for _i, _n in enumerate(REG64):
    REGS[_n] = (_i, 8, 0)
for _i, _n in enumerate(['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
                         'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']):
    REGS[_n] = (_i, 4, 0)
for _i, _n in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
                         'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']):
    REGS[_n] = (_i, 2, 0)
for _i, _n in enumerate(['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
                         'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']):
    REGS[_n] = (_i, 1, 0)
for _i, _n in enumerate(['ah', 'ch', 'dh', 'bh']):
    REGS[_n] = (_i, 1, 1)
XMM = {f'xmm{i}': i for i in range(16)}
SIZES = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8, 'xmmword': 16}
SIZE_NAMES = {v: k for k, v in SIZES.items()}
SIZE_RE = re.compile(r'\b(byte|word|dword|qword|xmmword)\s+ptr\b')
LINE_RE = re.compile(r'^\s*([0-9a-f]+):\s*([a-z][a-z0-9]*)\s*(.*?)\s*$')


def objdump_command():
    tool = os.environ.get('OBJDUMP') or shutil.which('objdump')
    if not tool:
        raise EvidenceError('objdump is required (set OBJDUMP to a GNU or LLVM objdump)')
    return tool


def disassemble(binary: Path, start: int, end: int) -> str:
    cmd = [objdump_command(), '-d', '-M', 'intel', '--no-show-raw-insn',
           f'--start-address={start:#x}', f'--stop-address={end:#x}', str(binary)]
    return subprocess.check_output(cmd, text=True)


class Mem:
    __slots__ = ('size', 'base', 'index', 'scale', 'disp', 'rip')

    def __init__(self, size, base, index, scale, disp, rip):
        self.size, self.base, self.index, self.scale, self.disp, self.rip = size, base, index, scale, disp, rip

    def text(self):
        inner = f'rip -> {self.disp:#x}' if self.rip else (self.base or '')
        if self.index:
            inner += f'+{self.index}*{self.scale}'
        if self.disp and not self.rip:
            inner += f'+{self.disp:#x}' if self.disp > 0 else f'-{-self.disp:#x}'
        return f'{SIZE_NAMES.get(self.size, "")} [{inner}]'.strip()


def parse_operand(text: str, next_va: int):
    text = text.strip()
    if text in REGS:
        return ('reg', text)
    if text in XMM:
        return ('xmm', text)
    size = None
    m = SIZE_RE.search(text)
    if m:
        size = SIZES[m.group(1)]
        text = SIZE_RE.sub('', text).strip()
    if text.startswith('[') and text.endswith(']'):
        inner = text[1:-1].replace(' ', '')
        base = index = None
        scale, disp, rip = 1, 0, False
        for sign, term in re.findall(r'([+-]?)([^+-]+)', inner):
            neg = sign == '-'
            if '*' in term:
                left, right = term.split('*')          # GNU: reg*scale; LLVM: scale*reg
                r, s = (left, right) if left in REGS else (right, left)
                index, scale = r, int(s, 0)
            elif term == 'rip':
                rip = True
            elif term in REGS:
                if base is None:
                    base = term
                else:
                    index, scale = term, 1
            else:
                v = int(term, 0)
                if v >= 1 << 63:                      # GNU prints negative displacements as u64
                    v -= 1 << 64
                disp += -v if neg else v
        if rip:
            return ('mem', Mem(size, None, None, 1, next_va + disp, True))
        return ('mem', Mem(size, base, index, scale, disp, False))
    if re.fullmatch(r'-?0x[0-9a-f]+|-?[0-9]+', text):
        return ('imm', int(text, 0))
    raise EvidenceError(f'unparsed operand {text!r}')


def parse_listing(listing: str, start: int, end: int):
    """objdump text (GNU or LLVM intel syntax) -> list of (va, size, mnemonic, operands)."""
    rows = []
    for line in listing.splitlines():
        line = line.split('#', 1)[0]
        line = re.sub(r'<[^>]*>', '', line).rstrip()
        m = LINE_RE.match(line.lower())
        if not m:
            continue
        va = int(m.group(1), 16)
        mn, ops = m.group(2), m.group(3)
        while mn in ('cs', 'ds', 'es', 'ss', 'data16', 'rep', 'repz', 'repnz', 'lock', 'notrack', 'bnd') and ops:
            head, _sep, ops = ops.partition(' ')
            mn = head
        if mn == 'nop':
            ops = ''
        ops = re.sub(r'\b[cdefgs]s:', '', ops)
        if start <= va < end:
            rows.append((va, mn, ops))
    if not rows or rows[0][0] != start:
        raise EvidenceError(f'listing does not start at {start:#x}')
    insns = []
    for i, (va, mn, ops) in enumerate(rows):
        next_va = rows[i + 1][0] if i + 1 < len(rows) else end
        if next_va <= va:
            raise EvidenceError(f'non-monotonic listing at {va:#x}')
        parts, depth, cur = [], 0, ''
        for ch in ops:
            depth += (ch == '[') - (ch == ']')
            if ch == ',' and depth == 0:
                parts.append(cur)
                cur = ''
            else:
                cur += ch
        if ops:
            parts.append(cur)
        if (mn.startswith('j') or mn == 'call') and parts and re.fullmatch(r'\s*(0x)?[0-9a-f]+\s*', parts[0]):
            insns.append((va, next_va - va, mn, [('target', int(parts[0].strip(), 16))]))
            continue
        operands = [parse_operand(p, next_va) for p in parts]
        if mn == 'movabs' and operands[1][0] == 'imm':
            operands[1] = ('imm', operands[1][1] & MASK)
        if mn in ('rol', 'ror', 'shl', 'shr', 'sal', 'sar', 'rcl', 'rcr') and len(operands) == 1:
            operands.append(('imm', 1))                   # LLVM prints the shift-by-one form bare
        insns.append((va, next_va - va, mn, operands))
    return insns


def operand_text(op):
    kind, v = op
    if kind in ('reg', 'xmm'):
        return v
    if kind == 'imm':
        return f'{v:#x}' if v >= 0 else f'-{-v:#x}'
    if kind == 'target':
        return f'{v:#x}'
    return v.text()


def normalized_listing(insns) -> str:
    return ''.join(f'{va:#x} {size:2d} {mn} {", ".join(operand_text(o) for o in ops)}'.rstrip() + '\n'
                   for va, size, mn, ops in insns)


def imm_stores(insns):
    return {v for _va, _s, mn, ops in insns if mn in ('mov', 'movabs') for k, v in ops[1:] if k == 'imm'}


# --------------------------------------------------------------------------- evaluator

class Stop(Exception):
    def __init__(self, kind, detail=None):
        super().__init__(f'{kind} {detail}' if detail is not None else kind)
        self.kind, self.detail = kind, detail


class Machine:
    """Interprets the parsed instructions of one function over byte-granular state.

    Registers are tracked per byte; reading an undefined byte stops the run.  Calls are
    dispatched by the role assigned to their resolved target.
    """

    def __init__(self, insns, relative: dict, named: dict, roles: dict, oracle):
        self.insns = {va: (size, mn, ops) for va, size, mn, ops in insns}
        self.relative, self.named, self.roles, self.oracle = relative, named, roles, oracle
        self.regs = {}            # index -> (value, defined byte mask)
        self.xmm = {}
        self.flags = {}
        self.mem = {}
        self.absorbers = {}       # hasher state address -> absorbed bytes
        self.heap = 0x10000000
        self.log = []
        self.steps = 0
        self.freed = []
        self.panic = None

    # --- registers and memory
    def reg(self, name):
        idx, size, shift = REGS[name]
        value, defined = self.regs.get(idx, (0, 0))
        need = ((1 << size) - 1) << shift
        if defined & need != need:
            raise Stop('undefined-register', name)
        return (value >> (8 * shift)) & ((1 << (8 * size)) - 1)

    def set_reg(self, name, value):
        idx, size, shift = REGS[name]
        old, defined = self.regs.get(idx, (0, 0))
        if size >= 4:
            self.regs[idx] = (value & ((1 << (8 * size)) - 1), 0xFF)
            return
        mask = ((1 << (8 * size)) - 1) << (8 * shift)
        self.regs[idx] = ((old & ~mask) | ((value << (8 * shift)) & mask), defined | (((1 << size) - 1) << shift))

    def read(self, addr, n):
        out = 0
        for i in range(n):
            b = self.mem.get(addr + i)
            if b is None:
                raise Stop('undefined-memory', f'{addr + i:#x}')
            out |= b << (8 * i)
        return out

    def read_bytes(self, addr, n):
        return bytes(self.read(addr + i, 1) for i in range(n))

    def write(self, addr, n, value):
        for i in range(n):
            self.mem[addr + i] = (value >> (8 * i)) & 0xFF

    def write_bytes(self, addr, data):
        for i, b in enumerate(data):
            self.mem[addr + i] = b

    def alloc(self, n):
        addr = self.heap
        self.heap += max((n + 0xFFF) & ~0xFFF, 0x1000)
        return addr

    def address(self, m: Mem):
        if m.rip:
            return m.disp
        addr = m.disp
        if m.base:
            addr += self.reg(m.base)
        if m.index:
            addr += self.reg(m.index) * m.scale
        return addr & MASK

    def value(self, op, size=None):
        kind, v = op
        if kind == 'reg':
            return self.reg(v)
        if kind == 'xmm':
            if v not in self.xmm:
                raise Stop('undefined-register', v)
            return self.xmm[v]
        if kind == 'imm':
            return v & ((1 << (8 * size)) - 1) if size else v
        if kind == 'mem':
            size = v.size or size
            if size is None:
                raise Stop('unsized-memory')
            return self.read(self.address(v), size)
        raise Stop('bad-operand', kind)

    def store(self, op, value, size):
        kind, v = op
        if kind == 'reg':
            self.set_reg(v, value)
        elif kind == 'xmm':
            self.xmm[v] = value & ((1 << 128) - 1)
        elif kind == 'mem':
            self.write(self.address(v), v.size or size, value)
        else:
            raise Stop('bad-store', kind)

    @staticmethod
    def size_of(ops):
        for kind, v in ops:
            if kind == 'reg':
                return REGS[v][1]
            if kind == 'xmm':
                return 16
            if kind == 'mem' and v.size:
                return v.size
        raise Stop('unsized-operands')

    # --- flags
    def arith_flags(self, a, b, size, sub):
        bits = 8 * size
        m = (1 << bits) - 1
        full = a - b if sub else a + b
        r = full & m
        of = ((a ^ b) if sub else ~(a ^ b)) & (a ^ r)
        self.flags = {'zf': r == 0, 'sf': bool(r >> (bits - 1)),
                      'cf': (a < b) if sub else (full > m), 'of': bool((of >> (bits - 1)) & 1)}
        return r

    def logic_flags(self, result, size):
        bits = 8 * size
        r = result & ((1 << bits) - 1)
        self.flags = {'zf': r == 0, 'sf': bool(r >> (bits - 1)), 'cf': False, 'of': False}
        return r

    def flag(self, name):
        if name not in self.flags:
            raise Stop('undefined-flag', name)
        return self.flags[name]

    def condition(self, cc):
        f = self.flag
        table = {
            'e': lambda: f('zf'), 'z': lambda: f('zf'),
            'ne': lambda: not f('zf'), 'nz': lambda: not f('zf'),
            'b': lambda: f('cf'), 'c': lambda: f('cf'), 'nae': lambda: f('cf'),
            'ae': lambda: not f('cf'), 'nb': lambda: not f('cf'), 'nc': lambda: not f('cf'),
            'be': lambda: f('cf') or f('zf'), 'na': lambda: f('cf') or f('zf'),
            'a': lambda: not f('cf') and not f('zf'), 'nbe': lambda: not f('cf') and not f('zf'),
            's': lambda: f('sf'), 'ns': lambda: not f('sf'),
            'l': lambda: f('sf') != f('of'), 'nge': lambda: f('sf') != f('of'),
            'ge': lambda: f('sf') == f('of'), 'nl': lambda: f('sf') == f('of'),
            'le': lambda: f('zf') or f('sf') != f('of'), 'ng': lambda: f('zf') or f('sf') != f('of'),
            'g': lambda: not f('zf') and f('sf') == f('of'), 'nle': lambda: not f('zf') and f('sf') == f('of'),
        }
        if cc not in table:
            raise Stop('unknown-condition', cc)
        return table[cc]()

    # --- calls
    def clobber(self):
        for name in CALLER_SAVED:
            self.regs.pop(REGS[name][0], None)
        self.xmm.clear()
        self.flags = {}

    def vec(self, p):
        return self.read(p, 8), self.read(p + 8, 8), self.read(p + 16, 8)       # cap, ptr, len

    def grow(self, p, additional):
        cap, ptr, length = self.vec(p)
        required = length + additional
        if required <= cap:
            raise Stop('needless-grow', f'cap {cap} len {length} +{additional}')
        new_cap = max(2 * cap, required, 8)
        new_ptr = self.alloc(new_cap)
        self.write_bytes(new_ptr, self.read_bytes(ptr, length))
        self.write(p, 8, new_cap)
        self.write(p + 8, 8, new_ptr)
        self.log.append(('grew', cap, new_cap))
        self.clobber()

    def call_grow(self):            # (vec*, len, additional, align, elem_size)
        p, length, additional = self.reg('rdi'), self.reg('rsi'), self.reg('rdx')
        if (self.reg('rcx'), self.reg('r8')) != (1, 1):
            raise Stop('grow-layout', (self.reg('rcx'), self.reg('r8')))
        if length != self.read(p + 16, 8):
            raise Stop('grow-length-mismatch')
        self.grow(p, additional)

    def call_grow_one(self):        # (vec*)
        self.grow(self.reg('rdi'), 1)

    def call_absorb(self):          # (state*, data*, len)
        state, data, n = self.reg('rdi'), self.reg('rsi'), self.reg('rdx')
        if state not in self.absorbers:
            init = self.read_bytes(state, 218)       # buffer[200], offset, rate, delim, mode
            self.log.append(('absorb-init', {
                'buffer_zero': init[:200] == bytes(200),
                'offset': int.from_bytes(init[200:208], 'little'),
                'rate': int.from_bytes(init[208:216], 'little'),
                'delim': init[216], 'mode': init[217]}))
            self.absorbers[state] = bytearray()
        self.absorbers[state] += self.read_bytes(data, n)
        self.clobber()

    def call_memcpy(self):          # (dst, src, n) -> dst
        dst, src, n = self.reg('rdi'), self.reg('rsi'), self.reg('rdx')
        for i in range(n):                            # undefined bytes (struct padding) stay undefined
            b = self.mem.get(src + i)
            if b is None:
                self.mem.pop(dst + i, None)
            else:
                self.mem[dst + i] = b
        if src in self.absorbers and n == KECCAK_STATE_SIZE:
            self.absorbers[dst] = bytearray(self.absorbers[src])
        self.clobber()
        self.set_reg('rax', dst)

    def call_finalize(self):        # (state*, out*, len)
        state, out, n = self.reg('rdi'), self.reg('rsi'), self.reg('rdx')
        if state not in self.absorbers or n != 32:
            raise Stop('finalize-shape', n)
        self.write_bytes(out, keccak256(bytes(self.absorbers[state])))
        self.log.append(('finalized', bytes(self.absorbers[state])))
        self.clobber()

    def call_dealloc(self):         # (ptr, size, align)
        self.freed.append((self.reg('rdi'), self.reg('rsi'), self.reg('rdx')))
        self.clobber()

    def call_alloc(self):           # (size, ...) -> ptr
        n = self.reg('rdi')
        self.log.append(('alloc', n))
        p = self.alloc(max(n, 1))
        self.clobber()
        self.set_reg('rax', p)

    def call_unwrap_failed(self):   # (msg*, msg_len, err*, vtable*, location*)
        self.panic = {'message_va': self.reg('rdi'), 'message_len': self.reg('rsi'),
                      'vtable_va': self.reg('rcx'), 'location_va': self.reg('r8')}
        raise Stop('unwrap-failed')

    def call_target(self, op):
        kind, v = op
        if kind == 'target':
            return v
        if kind == 'mem' and v.rip:
            if v.disp in self.named:
                return ('import', self.named[v.disp])
            if v.disp not in self.relative:
                raise Stop('unrelocated-call-slot', f'{v.disp:#x}')
            return self.relative[v.disp]
        raise Stop('indirect-call', kind)

    def do_call(self, target):
        role = self.roles.get(target)
        if role is None:
            raise Stop('unknown-call', f'{target:#x}' if isinstance(target, int) else target[1])
        self.log.append((role, target))
        if role == 'oracle':
            self.oracle(self)
        elif role in TERMINAL_ROLES and role != 'unwrap-failed':
            raise Stop(role)
        else:
            getattr(self, 'call_' + role.replace('-', '_'))()

    # --- execution
    def run(self, va, limit=20000):
        while True:
            if va not in self.insns:
                raise Stop('outside-function', f'{va:#x}')
            size, mn, ops = self.insns[va]
            self.steps += 1
            if self.steps > limit:
                raise Stop('step-limit')
            nxt = va + size
            if mn == 'ret':
                self.read(self.reg('rsp'), 8)        # the return address must be defined
                self.set_reg('rsp', self.reg('rsp') + 8)
                return
            if mn == 'ud2':
                raise Stop('ud2')
            if mn in ('nop', 'endbr64'):
                pass
            elif mn == 'push':
                v = self.value(ops[0], 8)
                self.set_reg('rsp', self.reg('rsp') - 8)
                self.write(self.reg('rsp'), 8, v)
            elif mn == 'pop':
                self.store(ops[0], self.read(self.reg('rsp'), 8), 8)
                self.set_reg('rsp', self.reg('rsp') + 8)
            elif mn in ('mov', 'movabs', 'movups', 'movaps', 'movdqu', 'movdqa'):
                size_ = self.size_of(ops)
                self.store(ops[0], self.value(ops[1], size_) & ((1 << (8 * size_)) - 1), size_)
            elif mn == 'lea':
                self.store(ops[0], self.address(ops[1][1]), 8)
            elif mn in ('add', 'sub', 'cmp'):
                size_ = self.size_of(ops)
                a, b = self.value(ops[0], size_), self.value(ops[1], size_)
                r = self.arith_flags(a, b, size_, mn != 'add')
                if mn != 'cmp':
                    self.store(ops[0], r, size_)
            elif mn in ('inc', 'dec'):
                size_ = self.size_of(ops)
                cf = self.flags.get('cf')
                r = self.arith_flags(self.value(ops[0], size_), 1, size_, mn == 'dec')
                self.flags['cf'] = cf
                self.store(ops[0], r, size_)
            elif mn in ('test', 'and', 'or', 'xor'):
                size_ = self.size_of(ops)
                if mn == 'xor' and ops[0] == ops[1]:
                    a = b = 0                                   # zeroing idiom, no read
                else:
                    a, b = self.value(ops[0], size_), self.value(ops[1], size_)
                r = self.logic_flags({'test': a & b, 'and': a & b, 'or': a | b, 'xor': a ^ b}[mn], size_)
                if mn != 'test':
                    self.store(ops[0], r, size_)
            elif mn in ('xorps', 'pxor'):
                r = 0 if ops[0] == ops[1] else self.value(ops[0]) ^ self.value(ops[1])
                self.store(ops[0], r, 16)
            elif mn == 'bswap':
                size_ = self.size_of(ops)
                v = self.value(ops[0], size_)
                self.store(ops[0], int.from_bytes(v.to_bytes(size_, 'little'), 'big'), size_)
            elif mn.startswith('set'):
                self.store(ops[0], 1 if self.condition(mn[3:]) else 0, 1)
            elif mn == 'jmp':
                if ops[0][0] != 'target':
                    raise Stop('indirect-jump')
                nxt = ops[0][1]
            elif mn.startswith('j'):
                if self.condition(mn[1:]):
                    nxt = ops[0][1]
            elif mn == 'call':
                self.do_call(self.call_target(ops[0]))
            else:
                raise Stop('unmodelled-mnemonic', mn)
            va = nxt


# --------------------------------------------------------------------------- binding

def call_sites(insns, relative, named):
    """(site, target_key, kind) for every call; slots resolve through relocations."""
    out = []
    for va, _size, mn, ops in insns:
        if mn != 'call':
            continue
        kind, v = ops[0]
        if kind == 'target':
            out.append((va, v, 'direct'))
        elif kind == 'mem' and v.rip:
            if v.disp in named:
                out.append((va, ('import', named[v.disp]), 'import'))
            elif v.disp in relative:
                out.append((va, relative[v.disp], 'slot'))
            else:
                raise EvidenceError(f'call through unrelocated slot {v.disp:#x} at {va:#x}')
        else:
            raise EvidenceError(f'indirect call at {va:#x}')
    return out


def preceding(insns, site, count=6):
    idx = next(i for i, ins in enumerate(insns) if ins[0] == site)
    return insns[max(0, idx - count):idx]


def classify_site(insns, site, kind, elf: Elf, location_vas, ok_check_va):
    """Assign a role to one call from the instructions that set up its arguments."""
    pre = preceding(insns, site)
    loads = {}
    for _va, _s, mn, ops in pre:
        if mn == 'mov' and ops[0][0] == 'reg' and ops[1][0] == 'imm':
            loads[ops[0][1]] = ops[1][1]
        if mn == 'lea' and ops[0][0] == 'reg' and ops[1][1].rip:
            loads[ops[0][1]] = ('lea', ops[1][1].disp)
    if site < ok_check_va:
        return 'oracle'
    if kind == 'direct' and loads.get('ecx') == 1 and loads.get('r8d') == 1 and 'edx' in loads:
        return 'grow'
    if kind == 'import':
        return 'memcpy'
    if kind == 'slot':
        if loads.get('esi') == len(UNWRAP_MESSAGE) and isinstance(loads.get('rdi'), tuple) \
                and elf.read(loads['rdi'][1], len(UNWRAP_MESSAGE)) == UNWRAP_MESSAGE \
                and isinstance(loads.get('r8'), tuple) and loads['r8'][1] in location_vas:
            return 'unwrap-failed'
        if loads.get('edi') == 1 and loads.get('esi') == 1:
            return 'alloc-error'
        if loads.get('edi') == 1:
            return 'alloc'
        if any(mn == 'mov' and ops == [('reg', 'rdi'), ('reg', 'rsp')] for _v, _s, mn, ops in pre):
            return 'grow-one'
        if loads.get('edx') == 0x20:
            return 'finalize'
        if any(mn == 'xor' and ops == [('reg', 'edx'), ('reg', 'edx')] for _v, _s, mn, ops in pre):
            return 'dealloc'
        # absorb: rdi is the hasher state whose rate slot (state + 0xd0) was stored as 136
        rate_slots = [ops[0][1].disp - 0xD0 for v, _s, mn, ops in insns
                      if v < site and mn == 'mov' and ops[0][0] == 'mem' and ops[0][1].base == 'rsp'
                      and ops[0][1].size == 8 and ops[1] == ('imm', KECCAK_RATE)]
        for _v, _s, mn, ops in pre:
            if mn == 'lea' and ops[0] == ('reg', 'rdi') and ops[1][0] == 'mem' \
                    and ops[1][1].base == 'rsp' and ops[1][1].disp in rate_slots:
                return 'absorb'
    return 'unwind'


def bind_function(elf, relative, named, starts, ends, binary, start, end, location_vas):
    listing = disassemble(binary, start, end)
    insns = parse_listing(listing, start, end)
    stores = imm_stores(insns)
    ok_checks = [va for va, _s, mn, ops in insns if mn == 'movabs' and ops[1] == ('imm', OK_NICHE)]
    if len(ok_checks) != 1:
        raise EvidenceError(f'{start:#x}: expected one Ok-niche compare, found {len(ok_checks)}')
    sites = call_sites(insns, relative, named)
    roles = {}
    site_roles = []
    for site, target, kind in sites:
        role = classify_site(insns, site, kind, elf, location_vas, ok_checks[0])
        if roles.get(target, role) != role:
            raise EvidenceError(f'{start:#x}: target {target} classified as both {roles[target]} and {role}')
        roles[target] = role
        site_roles.append({'site': site, 'target': target, 'kind': kind, 'role': role})
    oracle_targets = [t for t, r in roles.items() if r == 'oracle']
    if len(oracle_targets) != 1:
        raise EvidenceError(f'{start:#x}: expected one serializer call, found {len(oracle_targets)}')
    fn = {
        'start': start, 'end': end, 'size': end - start, 'instructions': len(insns),
        'serializer': oracle_targets[0],
        'serializer_fde': containing(starts, ends, oracle_targets[0]),
        'serializer_style': 'inline' if RMP_CONFIG_DWORD in stores else 'wrapper',
        'payload': 'agent' if CHAIN_ID in stores else 'embedded',
        'roles': roles, 'sites': site_roles, 'insns': insns,
        'mnemonics': sorted({mn for _v, _s, mn, _o in insns}),
        'callers': direct_callers(elf, start),
    }
    fn['caller_fdes'] = sorted({containing(starts, ends, c) for c in fn['callers']} - {None})
    return fn


def callees(insns, relative):
    """Direct call targets plus targets of calls through RELATIVE-relocated slots."""
    out = set()
    for _va, _s, mn, ops in insns:
        if mn != 'call':
            continue
        kind, v = ops[0]
        if kind == 'target':
            out.add(v)
        elif kind == 'mem' and v.rip and v.disp in relative:
            out.add(relative[v.disp])
    return sorted(out)


def keccak_structure(elf: Elf, leas, starts, ends, binary, roles_by_target, relative):
    """Bind the absorb/finalize targets to the keccak-f permutation and its constants."""
    table = b''.join(struct.pack('<Q', c) for c in KECCAK_RC)
    hits = elf.rodata_hits(table)
    if len(hits) != 1:
        raise EvidenceError(f'expected one Keccak round-constant table, found {len(hits)}')
    rc_va = hits[0]
    kf_sites = leas.get(rc_va, [])
    kf = sorted({containing(starts, ends, s) for s in kf_sites} - {None})
    if len(kf) != 1:
        raise EvidenceError(f'round-constant table referenced from {len(kf)} functions')
    kf_start, kf_end = kf[0]
    kf_insns = parse_listing(disassemble(binary, kf_start, kf_end), kf_start, kf_end)
    rotations = sorted({ops[1][1] for _va, _s, mn, ops in kf_insns if mn in ('rol', 'ror') and ops[1][0] == 'imm'})
    rho_seen = set(rotations) | {64 - r for r in rotations}
    kf_calls = callees(kf_insns, relative)
    hashers = {}
    for target, role in roles_by_target.items():
        if role in ('absorb', 'finalize'):
            fde = containing(starts, ends, target)
            if fde is None or fde[0] != target:
                raise EvidenceError(f'{role} target {target:#x} is not an FDE start')
            insns = parse_listing(disassemble(binary, *fde), *fde)
            called = callees(insns, relative)
            hashers[role] = {'start': fde[0], 'end': fde[1], 'size': fde[1] - fde[0],
                             'callees': called, 'calls_keccak_f': kf_start in called}
    if set(hashers) != {'absorb', 'finalize'} or not all(h['calls_keccak_f'] for h in hashers.values()):
        raise EvidenceError(f'absorb/finalize do not both call the keccak-f function {kf_start:#x}: '
                            + json.dumps(hexify(hashers)))
    return {
        'round_constant_table_va': rc_va,
        'round_constants': len(KECCAK_RC),
        'keccak_f': {'start': kf_start, 'end': kf_end, 'size': kf_end - kf_start,
                     'lea_sites': kf_sites, 'callees': kf_calls,
                     'direct_callers': direct_callers(elf, kf_start),
                     'relocated_slots': sorted(s for s, t in relative.items() if t == kf_start),
                     'rotate_immediates': rotations,
                     'rho_offsets_covered': len(KECCAK_RHO & rho_seen), 'rho_offsets': len(KECCAK_RHO)},
        'hashers': hashers,
    }


# --------------------------------------------------------------------------- evaluation

def deterministic_bytes(label: bytes, n: int) -> bytes:
    out = b''
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(SEED + b'|' + label + b'|' + counter.to_bytes(4, 'big')).digest()
        counter += 1
    return out[:n]


def vectors():
    """Deterministic (encoded, nonce, vault, expires, chain, slack) tuples."""
    nonces = [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFFFFFF, 0x100000000, SDK_NONCE,
              0x7FFFFFFFFFFFFFFF, 0x8000000000000000, MASK]
    vaults = [None, bytes(20), bytes([0xFF] * 20), deterministic_bytes(b'vault', 20)]
    expiries = [None, 0, 1, MASK, SDK_NONCE + 60_000]
    lengths = [0, 1, 7, 8, 9, 31, 32, 127, 128, 255, 256, 300]
    chains = [0, 1, 2, 3, 4, 0x7F, 0x80, 0xFF]
    out = []
    i = 0
    for length in lengths:
        encoded = deterministic_bytes(b'encoded%d' % length, length)
        for vault in vaults:
            for expires in expiries:
                out.append((encoded, nonces[i % len(nonces)], vault, expires, chains[i % len(chains)], i % 2 == 1))
                i += 1
    for nonce in nonces:
        for chain in chains:
            out.append((deterministic_bytes(b'n%d' % nonce, 40), nonce, None, None, chain, False))
    return out


def run_vector(fn, encoded, nonce, vault, expires, chain, slack, relative, named, ok=True, insns=None):
    """Evaluate one call of a signing function; return the observed payload and preimage."""
    insns = fn['insns'] if insns is None else insns
    cap = len(encoded) + (64 if slack else 0)

    def oracle(m: Machine):
        # The serializer writes `encoded` into the Vec it was handed and returns Ok.
        if fn['serializer_style'] == 'wrapper':
            result, vec = m.reg('rdi'), m.reg('rsi')
        else:
            result, vec = m.reg('rdi'), m.read(m.reg('rdx'), 8)
            m.log.append(('serializer-config', (m.read(m.reg('rdx') + 8, 4), m.read(m.reg('rdx') + 12, 1))))
        ptr = m.alloc(cap) if cap else 1
        m.write_bytes(ptr, encoded)
        m.write(vec, 8, cap)
        m.write(vec + 8, 8, ptr)
        m.write(vec + 16, 8, len(encoded))
        m.write(result, 8, OK_NICHE if ok else 0)
        m.write_bytes(result + 8, bytes(24))
        m.clobber()

    m = Machine(insns, relative, named, fn['roles'], oracle)
    stack_top = 0x7FFF0000
    out, ctx, action = 0x20000000, 0x30000000, 0x40000000
    m.write_bytes(ctx, bytes(0x30))
    m.write(ctx, 4, 1 if expires is not None else 0)
    m.write(ctx + 8, 8, expires or 0)
    m.write(ctx + 0x10, 8, nonce)
    m.write(ctx + 0x18, 1, 1 if vault is not None else 0)
    m.write_bytes(ctx + 0x19, vault or bytes(20))
    sig_chain_id = deterministic_bytes(b'sigchain%d' % nonce, 32)
    m.write_bytes(action, bytes(0x48) + sig_chain_id)
    m.write_bytes(out, b'\xAA' * 0x60)
    m.write(stack_top, 8, 0xDEAD0000)
    saved = {name: 0x5A5A000000000000 | (i << 8) for i, name in enumerate(('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'))}
    for name, value in saved.items():
        m.set_reg(name, value)
    m.set_reg('rsp', stack_top)
    m.set_reg('rdi', out)
    m.set_reg('rsi', action)
    m.set_reg('rdx', chain)
    m.set_reg('rcx', ctx)
    try:
        m.run(fn['start'])
    except Stop as stop:
        if stop.kind == 'unwrap-failed' and not ok:
            return {'stopped': stop.kind, 'panic': m.panic, 'log': m.log, 'steps': m.steps, 'freed': m.freed}
        raise EvidenceError(f'{fn["start"]:#x}: evaluator stopped: {stop}') from None
    if m.reg('rsp') != stack_top + 8:
        raise EvidenceError('unbalanced stack')
    if any(m.reg(name) != value for name, value in saved.items()):
        raise EvidenceError('callee-saved register not restored')
    preimage = next(entry[1] for entry in m.log if entry[0] == 'finalized')
    observed = {'preimage': preimage, 'log': m.log, 'steps': m.steps, 'freed': m.freed, 'cap': cap}
    if fn['payload'] == 'agent':
        scap, sptr, slen = m.vec(out)
        observed.update({
            'source': m.read_bytes(sptr, slen) if slen == 1 else None, 'string_cap': scap,
            'connection_id': m.read_bytes(out + 0x18, 32),
            'chain_id': m.read(out + 0x38, 8),
            'verifying_contract': m.read_bytes(out + 0x40, 24),
        })
    else:
        observed.update({
            'signature_chain_id': m.read_bytes(out, 32), 'expected_signature_chain_id': sig_chain_id,
            'connection_id': m.read_bytes(out + 0x20, 32),
            'nonce': m.read(out + 0x40, 8), 'chain': m.read(out + 0x48, 1),
        })
    return observed


def compare(fn, observed, encoded, nonce, vault, expires, chain):
    """Names of the checks that differ between the evaluated function and the model."""
    preimage, digest, source = expected_payload(encoded, nonce, vault, expires, chain)
    bad = []
    if observed['preimage'] != preimage:
        bad.append('preimage')
    if observed['connection_id'] != digest:
        bad.append('connection_id')
    if fn['payload'] == 'agent':
        if observed['source'] != source:
            bad.append('source')
        if observed['chain_id'] != CHAIN_ID:
            bad.append('chain_id')
        if observed['verifying_contract'] != bytes(24):
            bad.append('verifying_contract')
        if observed['string_cap'] != 1:
            bad.append('string_cap')
    else:
        if observed['signature_chain_id'] != observed['expected_signature_chain_id']:
            bad.append('signature_chain_id')
        if observed['nonce'] != nonce:
            bad.append('nonce')
        if observed['chain'] != chain:
            bad.append('chain')
    log = observed['log']
    inits = [e[1] for e in log if e[0] == 'absorb-init']
    if inits != [{'buffer_zero': True, 'offset': 0, 'rate': KECCAK_RATE, 'delim': KECCAK_DELIM, 'mode': 0}]:
        bad.append('hasher_init')
    if sum(1 for e in log if e[0] == 'finalized') != 1:
        bad.append('finalize_count')
    if fn['serializer_style'] == 'inline' and [e[1] for e in log if e[0] == 'serializer-config'] != [(RMP_CONFIG_DWORD, 0)]:
        bad.append('serializer_config')
    grows = [e for e in log if e[0] == 'grew']
    if grows and observed['cap'] != len(encoded):
        bad.append('grow_with_slack')
    final_cap = grows[-1][2] if grows else observed['cap']
    freed = observed['freed']
    if final_cap == 0:
        if freed:
            bad.append('dealloc_empty')
    elif len(freed) != 1 or freed[0][1] != final_cap:
        bad.append('dealloc')
    return bad


# --------------------------------------------------------------------------- driver

def check_digest(binary: Path) -> bytes:
    data = binary.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise EvidenceError(f'{binary} does not have SHA-256 {SHA256}')
    return data


def analyse(binary: Path, data: bytes | None = None):
    data = check_digest(binary) if data is None else data
    elf = Elf(data)
    starts, ends = fde_index(elf)
    relative, named = relocations(elf)
    leas = lea_targets(elf)
    path_va, records = source_bindings(elf, relative)
    location_vas = {r['location_va'] for r in records}
    owners = {}
    for rec in records:
        sites = leas.get(rec['location_va'], [])
        rec['lea_sites'] = sites
        fdes = sorted({containing(starts, ends, s) for s in sites} - {None})
        rec['fdes'] = fdes
        for fde in fdes:
            owners.setdefault(fde, []).append(rec['location_va'])
    functions = [bind_function(elf, relative, named, starts, ends, binary, s, e, location_vas)
                 for (s, e) in sorted(owners)]
    for fn, (fde, locs) in zip(functions, sorted(owners.items())):
        fn['locations'] = locs
    roles_by_target = {}
    for fn in functions:
        for target, role in fn['roles'].items():
            if role not in ('oracle', 'unwind') and roles_by_target.get(target, role) != role:
                raise EvidenceError(f'target {target} has roles {roles_by_target[target]} and {role}')
            if role not in ('oracle', 'unwind'):
                roles_by_target[target] = role
    for role in ('grow', 'grow-one', 'absorb', 'finalize', 'memcpy', 'dealloc', 'alloc', 'unwrap-failed', 'alloc-error'):
        targets = [t for t, r in roles_by_target.items() if r == role]
        if len(targets) != 1:
            detail = ', '.join(f'{t:#x}' if isinstance(t, int) else t[1] for t in targets)
            raise EvidenceError(f'role {role} bound to {len(targets)} targets: {detail}')
    keccak = keccak_structure(elf, leas, starts, ends, binary, roles_by_target, relative)
    wrappers = {}
    for fn in functions:
        if fn['serializer_style'] == 'wrapper':
            fde = fn['serializer_fde']
            insns = parse_listing(disassemble(binary, *fde), *fde)
            wrappers[fn['start']] = {
                'wrapper': fde[0], 'wrapper_size': fde[1] - fde[0],
                'stores_config': RMP_CONFIG_DWORD in imm_stores(insns),
                'callees': callees(insns, relative),
            }
    inline_serializers = {fn['serializer'] for fn in functions if fn['serializer_style'] == 'inline' and fn['payload'] == 'agent'}

    # evaluation
    sdk_encoded = msgpack(SDK_ACTION)
    sdk_preimage, sdk_digest, _ = expected_payload(sdk_encoded, SDK_NONCE, None, None, MAINNET_CHAIN)
    if sdk_digest.hex() != SDK_CONNECTION_ID:
        raise EvidenceError('the Keccak/suffix model does not reproduce the SDK production vector')
    grid = vectors()
    rows, summary = [], {}
    for fn in functions:
        mismatches, steps = 0, 0
        grows = 0
        dealloc_args = set()
        for encoded, nonce, vault, expires, chain, slack in grid:
            obs = run_vector(fn, encoded, nonce, vault, expires, chain, slack, relative, named)
            bad = compare(fn, obs, encoded, nonce, vault, expires, chain)
            mismatches += bool(bad)
            steps += obs['steps']
            grows += sum(1 for g in obs['log'] if g[0] == 'grew')
            dealloc_args |= {f[2] for f in obs['freed']}
            rows.append((fn['start'], len(encoded), nonce, vault, expires, chain, slack, obs['connection_id'].hex(), ','.join(bad) or '-'))
        sdk = run_vector(fn, sdk_encoded, SDK_NONCE, None, None, MAINNET_CHAIN, False, relative, named)
        err = run_vector(fn, b'\x81\xa1x\x01', 7, None, None, MAINNET_CHAIN, False, relative, named, ok=False)
        panic = err['panic']
        summary[fn['start']] = {
            'vectors': len(grid), 'mismatches': mismatches, 'instructions_executed': steps, 'grow_calls': grows,
            'dealloc_third_args': sorted(dealloc_args),
            'sdk_vector_connection_id': sdk['connection_id'].hex(),
            'sdk_vector_matches': sdk['connection_id'].hex() == SDK_CONNECTION_ID and sdk['preimage'] == sdk_preimage,
            'error_path': {
                'message_is_unwrap': elf.read(panic['message_va'], panic['message_len']) == UNWRAP_MESSAGE,
                'message_va': panic['message_va'], 'location_va': panic['location_va'],
                'location_is_bound': panic['location_va'] in fn['locations'],
                'buffer_freed_before_panic': len(err['freed']) == 1,
            },
        }
    crates = {p.decode(): len(elf.rodata_hits(p)) for p in CRATE_PATHS}
    return {
        'elf': elf, 'relative': relative, 'named': named, 'starts': starts, 'ends': ends,
        'path_va': path_va, 'records': records, 'functions': functions, 'roles': roles_by_target,
        'keccak': keccak, 'wrappers': wrappers, 'inline_serializers': sorted(inline_serializers),
        'summary': summary, 'rows': rows, 'crates': crates,
        'sdk': {'encoded_hex': sdk_encoded.hex(), 'nonce': SDK_NONCE, 'connection_id': sdk_digest.hex()},
        'fde_count': len(starts),
    }


HEX_KEYS = {'start', 'end', 'site', 'target', 'slot', 'wrapper', 'callers', 'lea_sites', 'fdes', 'serializer',
            'serializer_fde', 'caller_fdes', 'locations', 'callees', 'direct_callers', 'relocated_slots',
            'location_va', 'message_va', 'source_path_va', 'round_constant_table_va', 'ok_niche',
            'rmp_config_dword', 'inline_serializers'}


def hexify(value, key=None):
    """Render address-like fields as hex strings; counts stay decimal."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return f'{value:#x}' if key in HEX_KEYS else value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {(f'{k:#x}' if isinstance(k, int) else k): hexify(v, k if isinstance(k, str) else key)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [hexify(v, key) for v in value]
    return value


def evidence_document(result):
    fns = []
    for fn in result['functions']:
        fns.append({
            'start': fn['start'], 'end': fn['end'], 'size': fn['size'], 'instructions': fn['instructions'],
            'locations': fn['locations'], 'payload': fn['payload'], 'serializer_style': fn['serializer_style'],
            'serializer': fn['serializer'], 'serializer_fde': fn['serializer_fde'],
            'calls': [{'site': s['site'], 'target': s['target'] if not isinstance(s['target'], tuple) else s['target'][1],
                       'kind': s['kind'], 'role': s['role']} for s in fn['sites']],
            'mnemonics': fn['mnemonics'], 'callers': fn['callers'], 'caller_fdes': fn['caller_fdes'],
            'evaluation': result['summary'][fn['start']],
        })
    doc = {
        'target': {'path': BINARY, 'sha256': SHA256, 'fde_count': result['fde_count']},
        'source_path': (FIRST_PARTY + SOURCE_PATH).decode(), 'source_path_va': result['path_va'],
        'locations': result['records'],
        'functions': fns,
        'roles': {f'{t:#x}' if isinstance(t, int) else t[1]: r for t, r in result['roles'].items()},
        'keccak': result['keccak'],
        'wrappers': result['wrappers'],
        'inline_serializers': result['inline_serializers'],
        'crate_paths': result['crates'],
        'constants': {'ok_niche': OK_NICHE, 'rmp_config_dword': RMP_CONFIG_DWORD, 'keccak_rate': KECCAK_RATE,
                      'keccak_delim': KECCAK_DELIM, 'chain_id': CHAIN_ID, 'mainnet_chain': MAINNET_CHAIN},
        'sdk_vector': result['sdk'],
        'summary': {
            'functions': len(fns),
            'total_mismatches': sum(s['mismatches'] for s in result['summary'].values()),
            'all_sdk_vectors_match': all(s['sdk_vector_matches'] for s in result['summary'].values()),
            'all_error_paths_bound': all(s['error_path']['location_is_bound'] and s['error_path']['message_is_unwrap']
                                         for s in result['summary'].values()),
        },
    }
    return hexify(doc)


def write_packet(result, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    written = []

    def emit(name, text):
        (out / name).write_text(text, encoding='utf-8', newline='\n')
        written.append(name)

    emit('evidence.json', json.dumps(evidence_document(result), indent=2, sort_keys=False) + '\n')
    lines = ['start\tend\tsize\tinstructions\tpayload\tserializer_style\tserializer\tlocation_va\tcallers\tvectors\tmismatches']
    for fn in result['functions']:
        s = result['summary'][fn['start']]
        lines.append('\t'.join(str(x) for x in (f'{fn["start"]:#x}', f'{fn["end"]:#x}', fn['size'], fn['instructions'],
                                                 fn['payload'], fn['serializer_style'], f'{fn["serializer"]:#x}',
                                                 ','.join(f'{l:#x}' for l in fn['locations']), len(fn['callers']),
                                                 s['vectors'], s['mismatches'])))
    emit('functions.tsv', '\n'.join(lines) + '\n')
    lines = ['function\tencoded_len\tnonce\tvault\texpires\tchain\tslack\tconnection_id\tmismatches']
    for fn, n, nonce, vault, expires, chain, slack, cid, bad in result['rows']:
        lines.append('\t'.join(str(x) for x in (f'{fn:#x}', n, nonce, vault.hex() if vault is not None else '-',
                                                 expires if expires is not None else '-', chain, int(slack), cid, bad)))
    emit('vectors.tsv', '\n'.join(lines) + '\n')
    for fn in result['functions']:
        emit(f'listing-{fn["start"]:#x}.txt', normalized_listing(fn['insns']))
    manifest = ''.join(f'{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n' for n in sorted(written))
    (out / 'MANIFEST.sha256').write_text(manifest, encoding='utf-8', newline='\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--binary', default=str(ROOT / BINARY))
    parser.add_argument('--out', required=True)
    args = parser.parse_args(argv)
    result = analyse(Path(args.binary))
    write_packet(result, Path(args.out))
    doc = evidence_document(result)
    print(json.dumps({'functions': doc['summary']['functions'],
                      'total_mismatches': doc['summary']['total_mismatches'],
                      'sdk_vector': doc['summary']['all_sdk_vectors_match'],
                      'error_paths_bound': doc['summary']['all_error_paths_bound']}, indent=2))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except EvidenceError as error:
        print(f'error: {error}', file=sys.stderr)
        sys.exit(1)

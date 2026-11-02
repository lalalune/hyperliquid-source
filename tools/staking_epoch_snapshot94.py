#!/usr/bin/env python3
"""Byte-backed node 94 epoch snapshot, insertion and pruning study.

Uses file-backed ELF sections, decoded FDEs and a restricted instruction-length
recognizer. It does not execute the target and it does not invoke external tools.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = (
    (0x33e71c0, 'clone_validator_tree'),
    (0x33ed230, 'clone_delegation_tree'),
    (0x33a7690, 'epoch_map_replace_or_insert'),
    (0x2f91900, 'epoch_map_insert_and_split'),
    (0x2fd8bc0, 'epoch_map_remove_cursor'),
    (0x2fc6430, 'epoch_map_remove_leaf_repair'),
    (0x33b64d0, 'consume_snapshot_tree'),
    (0x2fa3300, 'borrow_left'),
    (0x2fa7e00, 'borrow_right'),
)

# Fixed, manually reviewed instruction patterns; values, displacements, targets,
# and body extents reported by the tool are read from the authenticated ELF.
PINS = (
    ('context_clone_call', 0x3369889, 'e832d90700', 'caller passes root and height to clone'),
    ('context_insert_call', 0x3369906, 'e885dd0300', 'caller passes epoch and snapshot to map'),
    ('context_remove_call', 0x3369bad, 'e80ef0c6ff', 'caller removes oldest epoch after its guard'),
    ('guard_epoch_count', 0x3369a1b, '48817b40e9030000', 'pruning starts when count is at least 1001'),
    ('guard_active_compare', 0x3369af0, '483b5348', 'oldest key compared to active epoch'),
    ('guard_active_stop', 0x3369af4, '0f8348020000', 'oldest key at or above active epoch stops'),
    ('guard_dispose_date', 0x3369c1a, '837c247000', 'zero date suppresses old snapshot disposal'),
    ('clone_outer_height_test', 0x33e71d7, '4885d2', 'zero height selects leaf'),
    ('clone_outer_height_branch', 0x33e71da, '0f84f6020000', 'leaf branch'),
    ('clone_outer_child', 0x33e71e3, '498bb630040000', 'first child pointer'),
    ('clone_outer_recursive', 0x33e71f5, 'e8c6ffffff', 'recursive first child'),
    ('clone_outer_inner_size', 0x33e720d, 'bf90040000', 'inner allocation size'),
    ('clone_outer_leaf_size', 0x33e74d6, 'bf30040000', 'leaf allocation size'),
    ('clone_outer_nested_count', 0x33e72c2, '4b837c7e1000', 'nested map length controls cloning'),
    ('clone_outer_nested_null', 0x33e72ce, '4885f6', 'nonempty nested map requires a root'),
    ('clone_outer_nested_call', 0x33e72e4, 'e8475f0000', 'clone nested map'),
    ('clone_outer_next_child', 0x33e7379, 'e842feffff', 'recursive next child'),
    ('clone_outer_max', 0x33e73f1, '4883f90b', 'capacity check'),
    ('clone_outer_parent', 0x33e7471, '4c89a020040000', 'write child parent'),
    ('clone_outer_parent_index', 0x33e7478, '66899028040000', 'write child parent index'),
    ('clone_nested_height_test', 0x33ed244, '4885d2', 'zero height selects leaf'),
    ('clone_nested_height_branch', 0x33ed24c, '0f84ec010000', 'leaf branch'),
    ('clone_nested_recursive', 0x33ed265, 'e8c6ffffff', 'recursive first child'),
    ('clone_nested_inner_size', 0x33ed27c, 'bfa0010000', 'inner allocation size'),
    ('clone_nested_leaf_size', 0x33ed43e, 'bf40010000', 'leaf allocation size'),
    ('clone_nested_next_child', 0x33ed33c, 'e8effeffff', 'recursive next child'),
    ('clone_nested_max', 0x33ed3af, '4883f90b', 'capacity check'),
    ('clone_nested_parent', 0x33ed3f1, '4c8920', 'write child parent'),
    ('clone_nested_parent_index', 0x33ed3f4, '6689903c010000', 'write child parent index'),
    ('map_root_test', 0x33a76a4, '4885c0', 'empty root allocation'),
    ('map_count', 0x33a76b1, '440fb7881a020000', 'u16 count in node'),
    ('map_search_cmp', 0x33a76d5, '483b54f810', 'unsigned key compare'),
    ('map_search_relation', 0x33a76da, '410f97c3', 'set above'),
    ('map_existing_out', 0x33a7717, '4a8b4c0058', 'existing value tail loaded'),
    ('map_empty_leaf_size', 0x33a7765, 'bf20020000', 'new leaf allocation'),
    ('map_empty_leaf_capacity', 0x33a779d, '4883fa0b', 'u16 node count below capacity'),
    ('map_key_store', 0x33a77b4, '4c897cd008', 'write u64 key'),
    ('map_count_increment', 0x33a77da, '48ff4110', 'increase map length on new key'),
    ('map_insert_call', 0x33a7842, 'e8b9a0beff', 'insert into nonempty leaf'),
    ('insert_full_limit', 0x2f91923, '4883fb0b', 'full leaf at eleven'),
    ('insert_not_full', 0x2f91927, '722f', 'nonfull branch'),
    ('insert_pivot_cmp5', 0x2f91932, '4983ff05', 'compare insertion index to five'),
    ('insert_pivot_branch5', 0x2f91943, '7350', 'index at least five'),
    ('insert_pivot4', 0x2f9194a, '41bf04000000', 'old pivot four'),
    ('insert_pivot_cmp6', 0x2f9199b, '4983ff06', 'compare insertion index to six'),
    ('insert_pivot_branch6', 0x2f9199f, '0f85ef000000', 'index other than six'),
    ('insert_pivot5', 0x2f919a5, '41bf05000000', 'old pivot five'),
    ('insert_pivot6', 0x2f91a9d, '41bf06000000', 'old pivot six'),
    ('insert_leaf_alloc', 0x2f91aaa, 'bf20020000', 'split leaf allocation size'),
    ('insert_leaf_alloc_test', 0x2f91ab5, '4885c0', 'allocation check'),
    ('insert_leaf_alloc_failure', 0x2f91ab8, '0f84e00a0000', 'allocation failure branch'),
    ('insert_promote_key', 0x2f91af9, '4b8b44fc08', 'read promoted key'),
    ('insert_left_count', 0x2f91b8d, '664589bc241a020000', 'set left count to pivot index'),
    ('remove_leaf_call_a', 0x2fd8ce3, 'e848d7feff', 'remove replacement leaf entry'),
    ('remove_leaf_call_b', 0x2fd8dfd, 'e82ed6feff', 'remove direct leaf entry'),
    ('remove_key_base', 0x2fc6463, '498d7cdf08', 'u64 key array'),
    ('remove_value_base', 0x2fc649c, '498d3cc7', '40-byte value slot calculation'),
    ('remove_count_store', 0x2fc64e5, '664189bf1a020000', 'decrement count'),
    ('remove_underfull_cmp', 0x2fc64fe, '6683ff04', 'compare remaining count to four'),
    ('remove_underfull_branch', 0x2fc6502, '0f8705050000', 'more than four skips repair'),
    ('remove_root_test', 0x2fc650b, '4885db', 'parent pointer check'),
    ('remove_root_branch', 0x2fc650e, '0f84f9040000', 'root skips repair'),
    ('remove_sibling_edge', 0x2fc6521, '4885f6', 'parent edge index check'),
    ('remove_sibling_branch', 0x2fc6529, '0f84f7030000', 'zero edge uses other sibling'),
    ('remove_merge_sum', 0x2fc657e, '4501c5', 'old count plus sibling count'),
    ('remove_merge_cmp', 0x2fc6581, '4183fd0c', 'compare sum to twelve'),
    ('remove_merge_branch', 0x2fc6585, '0f833f040000', 'sum at least twelve selects alternative'),
)

class Image:
    def __init__(self, data):
        if hashlib.sha256(data).hexdigest() != DIGEST:
            raise ValueError('Target SHA-256 mismatch')
        self.data = data
        self.blob = data
        self.sections = sections(data)
        _, records = eh_frame_records(data, self.sections)
        self.fdes = {}
        for row in records:
            if row['start'] in dict(FUNCTIONS):
                if row['start'] in self.fdes:
                    raise ValueError('Duplicate selected FDE')
                self.fdes[row['start']] = row
        if len(self.fdes) != len(FUNCTIONS):
            raise ValueError('Missing selected FDE')
        for start, _ in FUNCTIONS:
            self.read(start, self.fdes[start]['end'] - start, executable=True)

    def offset(self, address, size=1, executable=False):
        if size <= 0 or address < 0:
            raise ValueError('Invalid address range')
        candidates = [s['offset'] + address - s['address'] for s in self.sections
                      if s['type'] != 8 and s['flags'] & 2 and
                      (not executable or s['flags'] & 4) and
                      s['address'] <= address and address + size <= s['address'] + s['size']]
        if len(candidates) != 1:
            raise ValueError('Address range is not in one file-backed section')
        return candidates[0]

    def read(self, address, size, executable=False):
        off = self.offset(address, size, executable)
        return self.data[off:off + size]

    def integer(self, address, size, signed=False):
        return int.from_bytes(self.read(address, size), 'little', signed=signed)


def validate_pins(image):
    for name, va, expected, _ in PINS:
        if image.read(va, len(bytes.fromhex(expected)), executable=True).hex() != expected:
            raise ValueError('Instruction pin mismatch: ' + name)

def decode_one(data, offset, va):
    """Restricted x86-64 opcode-pattern length/transfer decoder for this packet.

    This does not assign source semantics. Unsupported opcodes fail closed.
    Instruction bytes are retained; internal transfer targets must be starts.
    """
    start, pos, rex, operand16, address32 = offset, offset, 0, False, False
    def need(n):
        if pos + n > len(data):
            raise ValueError('Truncated instruction')
    while True:
        need(1)
        op = data[pos]
        if op in (0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x3e, 0x26, 0x36, 0x64, 0x65) or 0x40 <= op <= 0x4f:
            operand16 |= op == 0x66
            address32 |= op == 0x67
            if 0x40 <= op <= 0x4f:
                rex = op
            pos += 1
            if pos - start >= 15:
                raise ValueError('Too many instruction prefixes')
        else:
            break
    pos += 1
    imm, modrm, kind, relative = 0, False, 'plain', False
    slot_disp = None
    opwidth = 2 if operand16 and not rex & 8 else 4
    if 0x70 <= op <= 0x7f:
        imm, kind, relative = 1, 'conditional', True
    elif op in (0xe8, 0xe9, 0xeb):
        imm, kind, relative = (1 if op == 0xeb else 4), ('call' if op == 0xe8 else 'jump'), True
    elif op == 0x0f:
        need(1)
        second = data[pos]
        pos += 1
        if 0x80 <= second <= 0x8f:
            imm, kind, relative = 4, 'conditional', True
        elif second == 0x0b:
            kind = 'trap'
        elif second in (0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x1f, 0x28, 0x29, 0x2a, 0x2c, 0x2d,
                        0x2e, 0x2f, 0x51, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
                        0x5e, 0x5f, 0x6e, 0x6f, 0x7e, 0x7f, 0xaf, 0xb0, 0xb1, 0xb6, 0xb7, 0xb8,
                        0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xd6, 0xef) or 0x40 <= second <= 0x4f or 0x90 <= second <= 0x9f:
            modrm = True
        elif second in (0x70, 0x71, 0x72, 0x73, 0xba, 0xc2, 0xc4, 0xc5, 0xc6):
            modrm, imm = True, 1
        else:
            raise ValueError('Unsupported 0f opcode at ' + hex(va))
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0x9c, 0x9d, 0xc9):
        pass
    elif op in (0xc3, 0xc2):
        kind, imm = 'return', 2 if op == 0xc2 else 0
    elif op == 0xcc:
        kind = 'trap'
    elif 0xb0 <= op <= 0xb7:
        imm = 1
    elif 0xb8 <= op <= 0xbf:
        imm = 8 if rex & 8 else opwidth
    elif op in (0x04, 0x0c, 0x14, 0x1c, 0x24, 0x2c, 0x34, 0x3c, 0x6a, 0xa8):
        imm = 1
    elif op in (0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d, 0x68, 0xa9):
        imm = opwidth
    elif (op < 0x40 and op & 7 <= 3) or op in (0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85,
             0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f, 0xc0, 0xc1, 0xc6, 0xc7,
             0xd0, 0xd1, 0xd2, 0xd3, 0xf6, 0xf7, 0xfe, 0xff):
        modrm = True
        imm = 1 if op in (0x6b, 0x80, 0x83, 0xc0, 0xc1, 0xc6) else opwidth if op in (0x69, 0x81, 0xc7) else 0
    else:
        raise ValueError('Unsupported opcode at ' + hex(va))
    if modrm:
        need(1)
        m = data[pos]
        pos += 1
        mode, group, rm = m >> 6, (m >> 3) & 7, m & 7
        if op in (0xf6, 0xf7) and group in (0, 1):
            imm = 1 if op == 0xf6 else opwidth
        if op == 0xff and group in (2, 4):
            kind = 'indirect_call' if group == 2 else 'indirect_jump'
        if mode != 3:
            disp = 1 if mode == 1 else 4 if mode == 2 else 0
            if rm == 4:
                need(1)
                sib = data[pos]
                pos += 1
                if mode == 0 and sib & 7 == 5:
                    disp = 4
            elif mode == 0 and rm == 5:
                disp = 4
                if op == 0xff and group in (2, 4) and not address32:
                    slot_disp = pos
            need(disp)
            pos += disp
    need(imm)
    delta_pos = pos
    pos += imm
    if pos - start > 15:
        raise ValueError('Instruction exceeds architectural length')
    target = va + pos - start + int.from_bytes(data[delta_pos:pos], 'little', signed=True) if relative else None
    slot = va + pos - start + int.from_bytes(data[slot_disp:slot_disp + 4], 'little', signed=True) if slot_disp is not None else None
    return dict(address=va, size=pos-start, bytes=data[start:pos].hex(), kind=kind, target=target, slot=slot)


def decode_function(image, start):
    end = image.fdes[start]['end']
    raw, result, pos = image.read(start, end-start), [], 0
    while pos < len(raw):
        row = decode_one(raw, pos, start + pos)
        result.append(row)
        pos += row['size']
    starts = {r['address'] for r in result}
    for row in result:
        target = row['target']
        if target is not None and start <= target < end and target not in starts:
            raise ValueError('Internal transfer targets an instruction interior')
    return result


# The following restricted x86 interpreter is adapted from the MIT-licensed
# tools/staking_stake_accounting.py family. Copyright (c) 2026 Hyperliquid Source
# contributors. Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including without
# limitation the rights to use, copy, modify, merge, publish, distribute,
# sublicense, and/or sell copies of the Software, and to permit persons to whom
# the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS
# IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xff, 2: 0xffff, 4: 0xffffffff, 8: 0xffffffffffffffff}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xa5
STACK_TOP = 0x7ff000000
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x400000
RETURN_SENTINEL = 0xdead0000
POISON = 0xa5a5a5a5a5a5a5a5
STEP_LIMIT = 200000

class EvidenceError(Exception):
    pass

class Halt(Exception):
    pass

def fdiv(left, right):
    return left / right


def to_float(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & MASK[8]))[0]


def to_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at", "data")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {0: "rol", 1: "ror", 4: "shl", 5: "shr", 7: "sar"}


def decode(read, va):
    """Decode one instruction at va; read(va, n) returns n code bytes."""
    window = read(va, 16)
    pos, rex, opsize, rep, repne = 0, 0, False, False, False
    while True:
        byte = window[pos]
        if byte == 0x66:
            opsize = True
        elif byte == 0xF3:
            rep = True
        elif byte == 0xF2:
            repne = True
        elif byte == 0xF0:
            pass
        elif byte != 0x2E:
            break
        pos += 1
    if 0x40 <= window[pos] <= 0x4F:
        rex = window[pos]
        pos += 1
    wide = bool(rex & 8)
    width = 8 if wide else (2 if opsize else 4)
    byte = window[pos]
    pos += 1
    imm = None
    rip_at = None

    def modrm(vector=False):
        nonlocal pos, rip_at
        mod_rm = window[pos]
        pos += 1
        mod, reg, rm = mod_rm >> 6, ((mod_rm >> 3) & 7) | ((rex & 4) << 1), mod_rm & 7
        if mod == 3:
            return reg, ("x" if vector else "r", rm | ((rex & 1) << 3))
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = window[pos]
            pos += 1
            scale = 1 << (sib >> 6)
            index = ((sib >> 3) & 7) | ((rex & 2) << 2)
            if index == 4:
                index = None
            base = (sib & 7) | ((rex & 1) << 3)
            if sib & 7 == 5 and mod == 0:
                base = None
                disp = struct.unpack_from("<i", window, pos)[0]
                pos += 4
                return reg, ("m", base, index, scale, disp, False)
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | ((rex & 1) << 3)
        disp = 0
        if mod == 1:
            disp = struct.unpack_from("<b", window, pos)[0]
            pos += 1
        elif mod == 2 or rip:
            if rip:
                rip_at = pos
            disp = struct.unpack_from("<i", window, pos)[0]
            pos += 4
        return reg, ("m", base, index, scale, disp, rip)

    def immediate(size):
        nonlocal pos, imm
        value = struct.unpack_from({1: "<b", 2: "<h", 4: "<i", 8: "<q"}[size], window, pos)[0]
        imm = (pos, size)
        pos += size
        return value

    def finish(op, a=None, b=None, w=None, cc=None, target=None):
        size = pos
        if (width if w is None else w) == 1 and not rex:
            if op != "mov" and any(operand and operand[0] == "r" and 4 <= operand[1] <= 7 for operand in (a, b)):
                raise EvidenceError("high byte register at %#x" % va)
            if a and a[0] == "r" and 4 <= a[1] <= 7:
                a = ("h", a[1] - 4)
            if b and b[0] == "r" and 4 <= b[1] <= 7:
                b = ("h", b[1] - 4)

        def fix(operand):
            if operand and operand[0] == "m" and operand[5]:
                return ("m", None, None, 1, va + size + operand[4], False)
            return operand
        return Insn(va, size, op, fix(a), fix(b), width if w is None else w, cc, target, imm, rip_at)

    if 0x50 <= byte <= 0x57:
        return finish("push", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if 0x58 <= byte <= 0x5F:
        return finish("pop", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if byte < 0x40 and byte & 7 < 4:
        name = GROUP1[byte >> 3]
        w = 1 if not byte & 1 else width
        reg, rm = modrm()
        if byte & 2:
            return finish(name, ("r", reg), rm, w)
        return finish(name, rm, ("r", reg), w)
    if byte < 0x40 and byte & 7 in (4, 5):
        w = 1 if byte & 7 == 4 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish(GROUP1[byte >> 3], ("r", RAX), ("i", value), w)
    if byte == 0x63 and wide:
        reg, rm = modrm()
        return finish("movsxd", ("r", reg), rm, 8)
    if 0x70 <= byte <= 0x7F:
        rel = immediate(1)
        return finish("jcc", cc=byte & 15, target=va + pos + rel)
    if byte in (0x80, 0x81, 0x83):
        reg, rm = modrm()
        w = 1 if byte == 0x80 else width
        value = immediate(4 if byte == 0x81 and w != 2 else 2 if byte == 0x81 else 1)
        return finish(GROUP1[reg & 7], rm, ("i", value), w)
    if byte in (0x84, 0x85):
        reg, rm = modrm()
        return finish("test", rm, ("r", reg), 1 if byte == 0x84 else width)
    if byte in (0x88, 0x89, 0x8A, 0x8B):
        reg, rm = modrm()
        w = 1 if not byte & 1 else width
        if byte & 2:
            return finish("mov", ("r", reg), rm, w)
        return finish("mov", rm, ("r", reg), w)
    if byte == 0x8D:
        reg, rm = modrm()
        return finish("lea", ("r", reg), rm, width)
    if byte == 0x90:
        return finish("nop")
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
    if byte == 0x98:
        return finish("cdqe" if wide else "cwde")
    if byte == 0xA9:
        value = immediate(4)
        return finish("test", ("r", RAX), ("i", value), width)
    if byte == 0xA8:
        value = immediate(1)
        return finish("test", ("r", RAX), ("i", value), 1)
    if 0xB0 <= byte <= 0xB7:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(1)
        return finish("mov", ("r", reg), ("i", value & 0xFF), 1)
    if 0xB8 <= byte <= 0xBF:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(8 if wide else 2 if opsize else 4)
        return finish("mov", ("r", reg), ("i", value & MASK[width]), width)
    if byte == 0x69:
        reg, rm = modrm()
        value = immediate(4)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0x6B:
        reg, rm = modrm()
        value = immediate(1)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0xD3:
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("r", RCX), width)
    if byte in (0xD1, 0xD0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("i", 1), 1 if byte == 0xD0 else width)
    if byte in (0xC1, 0xC0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        value = immediate(1) & 0xFF
        return finish(SHIFTS[reg & 7], rm, ("i", value), 1 if byte == 0xC0 else width)
    if byte == 0xC3:
        return finish("ret")
    if byte == 0xCC:
        return finish("int3")
    if byte in (0xC6, 0xC7):
        reg, rm = modrm()
        w = 1 if byte == 0xC6 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish("mov", rm, ("i", value & MASK[w]), w)
    if byte == 0xE8:
        rel = immediate(4)
        return finish("call", target=va + pos + rel)
    if byte == 0xE9:
        rel = immediate(4)
        return finish("jmp", target=va + pos + rel)
    if byte == 0xEB:
        rel = immediate(1)
        return finish("jmp", target=va + pos + rel)
    if byte in (0xF6, 0xF7):
        reg, rm = modrm()
        w = 1 if byte == 0xF6 else width
        kind = reg & 7
        if kind == 0:
            value = immediate(1 if w == 1 else 4)
            return finish("test", rm, ("i", value), w)
        if kind in (2, 3, 4, 5, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 5: "imul1", 6: "div"}[kind], rm, w=w)
        raise EvidenceError("unsupported group 3 opcode at %#x" % va)
    if byte in (0xFE, 0xFF):
        reg, rm = modrm()
        kind = reg & 7
        w = 1 if byte == 0xFE else width
        if kind in (0, 1):
            return finish("inc" if kind == 0 else "dec", rm, w=w)
        if byte == 0xFF and kind == 2:
            return finish("calli", rm, w=8)
        if byte == 0xFF and kind == 4:
            return finish("jmpi", rm, w=8)
        if byte == 0xFF and kind == 6:
            return finish("pushm", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x87:
        reg, rm = modrm()
        return finish("xchg", rm, ("r", reg), width)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if 0xC8 <= two <= 0xCF:
            return finish("bswap", ("r", (two & 7) | ((rex & 1) << 3)), w=width)
        if two == 0xC6 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("shufpd", ("x", reg), rm, 16, target=value)
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmppd", ("x", reg), rm, 16, target=value)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x72 and opsize:
            reg, rm = modrm(True)
            if reg & 7 not in (4, 6):
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrad" if reg & 7 == 4 else "pslld", rm, ("i", value), 16)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xAB:
            reg, rm = modrm()
            return finish("btsr", rm, ("r", reg), width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("btr", rm, ("r", reg), width)
        if two in (0xBE, 0xBF):
            reg, rm = modrm()
            return finish("movsx", ("r", reg), rm, width, cc=1 if two == 0xBE else 2)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two == 0x13:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and rep:
            reg, rm = modrm(True)
            if rm[0] == "x":
                raise EvidenceError("movss between registers at %#x" % va)
            if two == 0x10:
                return finish("movss", ("x", reg), rm, 4)
            return finish("movss", rm, ("x", reg), 4)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0xDF, True): "pandn", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x6C, True): "punpcklqdq",
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, 8)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
        if two == 0x70 and (opsize or repne):
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("pshufd" if opsize else "pshuflw", ("x", reg), rm, 16, target=value)
        if two == 0xD7 and opsize:
            reg, rm = modrm(True)
            return finish("pmovmskb", ("r", reg), rm, 4)
        if two == 0xBC and rep:
            reg, rm = modrm()
            return finish("tzcnt", ("r", reg), rm, width)
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two == 0x16 and not opsize:
            reg, rm = modrm(True)
            return finish("movhps", ("x", reg), rm, 8)
        if two == 0x12 and not opsize and not rep and not repne:
            reg, rm = modrm(True)
            return finish("movlps", ("x", reg), rm, 8)
        if two == 0x7E and opsize and not wide:
            reg, rm = modrm()
            return finish("movdout", rm, ("x", reg), 4)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x6E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x7E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", rm, ("x", reg), 8)
        if 0x40 <= two <= 0x4F:
            reg, rm = modrm()
            return finish("cmov", ("r", reg), rm, width, cc=two & 15)
        if 0x80 <= two <= 0x8F:
            rel = immediate(4)
            return finish("jcc", cc=two & 15, target=va + pos + rel)
        if 0x90 <= two <= 0x9F:
            _, rm = modrm()
            return finish("set", rm, w=1, cc=two & 15)
        if two == 0xAF:
            reg, rm = modrm()
            return finish("imul2", ("r", reg), rm, width)
        if two == 0xBD:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAC:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shrd", rm, ("r", reg), width, target=value)
        if two == 0xB1:
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), width)
        if two == 0xAD:
            reg, rm = modrm()
            return finish("shrd", rm, ("r", reg), width)
        if two in (0xB6, 0xB7):
            reg, rm = modrm()
            return finish("movzx", ("r", reg), rm, width, cc=1 if two == 0xB6 else 2)
    raise EvidenceError("undecodable opcode %#x at %#x" % (byte, va))


def decode_range(image, start, end):
    """Decode [start, end) linearly; the last instruction must end exactly at end."""
    base = image.offset(start)
    code = image.blob[base:base + (end - start) + 16]

    def read(va, count):
        return code[va - start:va - start + count]

    rows = []
    va = start
    while va < end:
        row = decode(read, va)
        row.data = bytes(read(va, row.size))
        rows.append(row)
        va = row.next
    if va != end:
        raise EvidenceError("decoder overran FDE end at %#x" % end)
    return rows


class Memory:
    def __init__(self, image):
        self.image = image
        self.stack = bytearray(STACK_SIZE)
        self.heap = bytearray(HEAP_SIZE)
        self.stack_base = STACK_TOP - STACK_SIZE
        self.fresh = (bytes([STACK_MARK]) * STACK_SIZE, bytes([STACK_MARK]) * HEAP_SIZE)
        self.statics = {}

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
        return None, 0

    def read(self, addr, count):
        return int.from_bytes(self.bytes_at(addr, count), "little")

    def write(self, addr, count, value):
        buffer, at = self.locate(addr, count)
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + count] = (value & MASK.get(count, (1 << (8 * count)) - 1)).to_bytes(count, "little")

    def put_bytes(self, addr, data):
        buffer, at = self.locate(addr, len(data))
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + len(data)] = data

    def bytes_at(self, addr, count):
        buffer, at = self.locate(addr, count)
        if buffer is not None:
            return bytes(buffer[at:at + count])
        if addr in self.statics:
            return self.statics[addr].to_bytes(count, "little")
        try:
            offset = self.image.offset(addr, count)
        except (EvidenceError, ValueError):
            raise Halt("read outside every mapping: %#x" % addr)
        return bytes(self.image.blob[offset:offset + count])

    def copy(self, dst, src, count):
        self.put_bytes(dst, self.bytes_at(src, count))

class Machine:
    def __init__(self, image, patches=None):
        self.image = image
        self.patches = patches or {}
        self.memory = Memory(image)
        self.cache = {}
        self.calls = {}
        self.real = frozenset()
        self.slots = {}
        self.regs = [0] * 16
        self.xmm = [POISON | POISON << 64] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.seen = set()
        self.steps = 0
        self.keep_rdx = False
        self.step_limit = STEP_LIMIT
        self.xmm_result = None

    def read_code(self, va, count):
        offset = self.image.offset(va, count)
        data = bytearray(self.image.blob[offset:offset + count])
        for index in range(count):
            if va + index in self.patches:
                data[index] = self.patches[va + index]
        return data

    def address(self, operand):
        _, base, index, scale, disp, _ = operand
        value = disp
        if base is not None:
            value += self.regs[base]
        if index is not None:
            value += self.regs[index] * scale
        return value & MASK[8]

    def get(self, operand, width):
        kind = operand[0]
        if kind == "r":
            return self.regs[operand[1]] & MASK[width]
        if kind == "h":
            return self.regs[operand[1]] >> 8 & 0xFF
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "h":
            self.regs[operand[1]] = (self.regs[operand[1]] & ~0xFF00) | value << 8
            return
        if operand[0] == "r":
            reg = operand[1]
            if width >= 4:
                self.regs[reg] = value
            else:
                self.regs[reg] = (self.regs[reg] & ~MASK[width]) | value
        else:
            self.memory.write(self.address(operand), width, value)

    def condition(self, code):
        result = {
            0: self.of, 1: self.cf, 2: self.zf, 3: self.cf or self.zf, 4: self.sf,
            5: self.pf, 6: self.sf != self.of, 7: self.zf or self.sf != self.of,
        }[code >> 1]
        return bool(result) != bool(code & 1)

    def set_logic(self, result, width):
        self.cf = self.of = False
        self.zf = result & MASK[width] == 0
        self.sf = bool(result & SIGN[width])

    def add_sub(self, left, right, carry, width, subtract):
        mask = MASK[width]
        if subtract:
            result = (left - right - carry) & mask
            self.cf = left < right + carry
            self.of = bool((left ^ right) & (left ^ result) & SIGN[width])
        else:
            total = left + right + carry
            result = total & mask
            self.cf = total > mask
            self.of = bool(~(left ^ right) & (left ^ result) & SIGN[width])
        self.zf = result == 0
        self.sf = bool(result & SIGN[width])
        return result

    def push(self, value):
        self.regs[RSP] -= 8
        self.memory.write(self.regs[RSP], 8, value)

    def pop(self):
        value = self.memory.read(self.regs[RSP], 8)
        self.regs[RSP] += 8
        return value

    def stub(self, hook):
        self.keep_rdx = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        self.xmm = [POISON | POISON << 64] * 16

    def run(self, entry, args, stack=()):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        for value in reversed(stack):
            self.push(value)
        self.push(RETURN_SENTINEL)
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL:
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                row = decode(self.read_code, pc)
                cache[pc] = row
            self.seen.add(pc)
            self.steps += 1
            pc = self.step(row)
        if self.regs[RSP] != top + 8:
            raise Halt("unbalanced stack")
        for reg, value in saved.items():
            if self.regs[reg] != value:
                raise Halt("callee-saved register changed")
        return self.regs[RAX]

    def step(self, row):
        op = row.op
        width = row.width
        if op == "mov":
            self.put(row.a, width, self.get(row.b, width))
        elif op == "jcc":
            return row.target if self.condition(row.cc) else row.next
        elif op == "lea":
            self.put(row.a, width, self.address(row.b))
        elif op == "push":
            self.push(self.regs[row.a[1]])
        elif op == "pop":
            self.regs[row.a[1]] = self.pop()
        elif op in ("add", "adc", "sub", "sbb", "cmp"):
            carry = int(self.cf) if op in ("adc", "sbb") else 0
            result = self.add_sub(self.get(row.a, width), self.get(row.b, width), carry, width, op not in ("add", "adc"))
            if op != "cmp":
                self.put(row.a, width, result)
        elif op in ("and", "or", "xor", "test"):
            left, right = self.get(row.a, width), self.get(row.b, width)
            result = left & right if op in ("and", "test") else left | right if op == "or" else left ^ right
            self.set_logic(result, width)
            if op != "test":
                self.put(row.a, width, result)
        elif op == "cmpxchg":
            current = self.get(row.a, width)
            wanted = self.regs[RAX] & MASK[width]
            self.add_sub(wanted, current, 0, width, True)
            if wanted == current:
                self.put(row.a, width, self.get(row.b, width))
            else:
                self.put(("r", RAX), width, current)
        elif op == "xchg":
            first, second = self.get(row.a, width), self.get(row.b, width)
            self.put(row.a, width, second)
            self.put(row.b, width, first)
        elif op == "call":
            self.push(row.next)
            if row.target in self.real:
                return row.target
            hook = self.calls.get(row.target)
            if not hook:
                raise Halt("unmodelled call to %#x at %#x" % (row.target, row.va))
            self.stub(hook)
            return self.pop()
        elif op == "jmp":
            return row.target
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            return target
        elif op == "pushm":
            self.push(self.get(row.a, 8))
        elif op == "pushi":
            self.push(row.a[1] & MASK[8])
        elif op == "btsr":
            bit = self.get(row.b, width) & (8 * width - 1)
            value = self.get(row.a, width)
            self.cf = bool(value >> bit & 1)
            self.put(row.a, width, value | 1 << bit)
        elif op == "btr":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
        elif op == "movsx":
            value = self.get(row.b, row.cc)
            self.put(row.a, width, value - (1 << (8 * row.cc)) if value & SIGN[row.cc] else value)
        elif op == "ror":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) & MASK[width])
        elif op == "rol":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value << count | value >> (bits - count)) & MASK[width])
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (row.b[1] & (8 * width - 1)) & 1)
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.xmm_result = None
            self.stub(hook)
            if self.xmm_result is not None:
                self.xmm[0] = self.xmm_result
        elif op == "ret":
            return self.pop()
        elif op == "movzx":
            self.put(row.a, width, self.get(row.b, row.cc))
        elif op == "set":
            self.put(row.a, 1, int(self.condition(row.cc)))
        elif op == "cmov":
            value = self.get(row.b, width)
            self.put(row.a, width, value if self.condition(row.cc) else self.get(row.a, width))
        elif op in ("inc", "dec"):
            carry = self.cf
            value = self.add_sub(self.get(row.a, width), 1, 0, width, op == "dec")
            self.cf = carry
            self.put(row.a, width, value)
        elif op == "neg":
            value = self.add_sub(0, self.get(row.a, width), 0, width, True)
            self.put(row.a, width, value)
        elif op == "not":
            self.put(row.a, width, ~self.get(row.a, width))
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            left -= (left >> 63) << 64
            right -= (right >> 63) << 64
            product = left * right
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            bits = 8 * width
            left, right = self.get(row.b, width), row.target & MASK[width]
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op in ("shl", "shr", "sar"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "shl":
                result = value << count
            elif op == "shr":
                result = value >> count
            else:
                result = (value - (1 << (8 * width)) if value & SIGN[width] else value) >> count
            if count:
                self.set_logic(result, width)
            self.put(row.a, width, result)
        elif op == "movx":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.vector(row.b)
            elif row.b[0] == "x":
                self.memory.write(self.address(row.a), 16, self.xmm[row.b[1]])
            else:
                raise Halt("unmodelled vector move")
        elif op == "xorps":
            self.xmm[row.a[1]] ^= self.vector(row.b)
        elif op == "int3":
            raise Halt("int3 at %#x" % row.va)
        elif op == "cwde":
            self.regs[RAX] = ((self.regs[RAX] & 0xFFFF) ^ 0x8000) - 0x8000 & MASK[4]
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            bits = 8 * width
            left, right = self.get(row.a, width), self.get(row.b, width)
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd"):
            count = (row.target if row.target is not None else self.regs[RCX]) & 63
            high, low = self.get(row.a, 8), self.get(row.b, 8)
            if op == "shld":
                value = (high << count | low >> (64 - count)) if count else high
            else:
                value = (high >> count | low << (64 - count)) if count else high
            self.put(row.a, 8, value)
        elif op == "div":
            divisor = self.get(row.a, width)
            if divisor == 0:
                raise Halt("division by zero at %#x" % row.va)
            dividend = (self.regs[RDX] & MASK[width]) << (8 * width) | (self.regs[RAX] & MASK[width])
            quotient, remainder = divmod(dividend, divisor)
            if quotient > MASK[width]:
                raise Halt("division overflow at %#x" % row.va)
            self.regs[RAX], self.regs[RDX] = quotient, remainder
        elif op == "movsxd":
            value = self.get(row.b, 4)
            self.put(row.a, 8, value - (1 << 32) if value & SIGN[4] else value)
        else:
            self.step_vector(row, op)
        return row.next

    def low(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]] & MASK[8]
        return self.memory.read(self.address(operand), 8)

    def set_low(self, register, bits):
        self.xmm[register] = (self.xmm[register] & ~MASK[8]) | bits

    def step_vector(self, row, op):
        if op == "movss":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.memory.read(self.address(row.b), 4)
            else:
                self.memory.write(self.address(row.a), 4, self.xmm[row.b[1]] & MASK[4])
            return
        if op == "movsd":
            if row.a[0] == "x":
                if row.b[0] == "x":
                    self.set_low(row.a[1], self.low(row.b))
                else:
                    self.xmm[row.a[1]] = self.low(row.b)
            else:
                self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "movq":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "divsd":
                result = fdiv(left, right)
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "minsd":
                result = left if left < right else right
            else:
                result = left if left > right else right
            self.set_low(row.a[1], to_bits(result))
        elif op == "ucomisd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            unordered = left != left or right != right
            self.of = self.sf = False
            self.pf = unordered
            self.zf = unordered or left == right
            self.cf = unordered or left < right
        elif op == "cvttsd2si":
            value = to_float(self.low(row.b))
            if value != value or not -9223372036854775808.0 <= value < 9223372036854775808.0:
                self.put(row.a, 8, 1 << 63)
            else:
                self.put(row.a, 8, int(value))
        elif op == "cvtsi2sd":
            value = self.get(row.b, 8)
            self.set_low(row.a[1], to_bits(float(value - (1 << 64) if value & SIGN[8] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            self.xmm[row.a[1]] = int.from_bytes(bytes(byte for pair in zip(left[:8], right[:8]) for byte in pair), "little")
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = [(source >> (16 * index)) & 0xFFFF for index in range(4)]
            low = sum(words[(row.target >> (2 * index)) & 3] << (16 * index) for index in range(4))
            self.xmm[row.a[1]] = source >> 64 << 64 | low
        elif op == "pshufd":
            source = self.vector(row.b)
            words = [(source >> (32 * index)) & MASK[4] for index in range(4)]
            self.xmm[row.a[1]] = sum(words[(row.target >> (2 * index)) & 3] << (32 * index) for index in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            lanes = (b"\xff" * size if left[at:at + size] == right[at:at + size] else bytes(size) for at in range(0, 16, size))
            self.xmm[row.a[1]] = int.from_bytes(b"".join(lanes), "little")
        elif op == "pmovmskb":
            data = self.xmm[row.b[1]].to_bytes(16, "little")
            self.put(row.a, 4, sum((byte >> 7) << index for index, byte in enumerate(data)))
        elif op == "tzcnt":
            source = self.get(row.b, row.width)
            count = (source & -source).bit_length() - 1 if source else row.width * 8
            self.cf = source == 0
            self.zf = count == 0
            self.put(row.a, row.width, count)
        elif op == "movhps":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | self.get(row.b, 8) << 64
        elif op == "movlps":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 << 64 | self.get(row.b, 8)
        elif op == "movdout":
            self.put(row.a, 4, self.xmm[row.b[1]] & MASK[4])
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op in ("pslld", "psrad"):
            value, lanes = self.xmm[row.a[1]], 0
            for shift in (0, 32, 64, 96):
                lane = (value >> shift) & MASK[4]
                if op == "pslld":
                    lane = (lane << row.b[1]) & MASK[4]
                else:
                    lane = ((lane - (1 << 32) if lane & SIGN[4] else lane) >> row.b[1]) & MASK[4]
                lanes |= lane << shift
            self.xmm[row.a[1]] = lanes
        elif op == "pandn":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] ^ ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "psrlq":
            value = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = ((value & MASK[8]) >> row.b[1]) | (((value >> 64) >> row.b[1]) << 64)
        elif op in ("addpd", "divpd"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            lanes = []
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                lanes.append(to_bits(one + two if op == "addpd" else fdiv(one, two)))
            self.xmm[row.a[1]] = lanes[0] | lanes[1] << 64
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            first = (left >> (64 * (row.target & 1))) & MASK[8]
            second = (right >> (64 * ((row.target >> 1) & 1))) & MASK[8]
            self.xmm[row.a[1]] = first | second << 64
        elif op == "cmppd":
            if row.target != 5:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                if not to_float((left >> shift) & MASK[8]) < to_float((right >> shift) & MASK[8]):
                    value |= MASK[8] << shift
            self.xmm[row.a[1]] = value
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")




class TraceMachine(Machine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.edges = set()
        self.last_va = None

    def step(self, row):
        self.last_va = row.va
        if row.op == 'jcc':
            self.edges.add((row.va, bool(self.condition(row.cc))))
        return super().step(row)


COVERAGE = set()
EDGES = set()

def record_coverage(machine):
    COVERAGE.update(machine.seen)
    EDGES.update(machine.edges)


SLOT_ALLOC = 0x576dfd8
SLOT_COPY = 0x576dfe0
SLOT_MOVE = 0x576e0e0
SLOT_FREE = 0x576e010
SLOT_FAILURES = (0x576e020, 0x576e108, 0x576e470, 0x576e128)

class Fixture:
    """Bounded memory and allocator for evaluating only selected bytes."""
    def __init__(self, image, patches=None):
        self.machine = TraceMachine(image, patches)
        self.machine.real = {start for start, _ in FUNCTIONS}
        self.input_next = HEAP_BASE + 0x1000
        self.alloc_next = HEAP_BASE + 0x20000
        self.allocations = []
        self.frees = []
        self.blocks = {}
        self.released = set()
        self.fail_after = None
        self.machine.memory.statics.update({slot: slot for slot in
            (SLOT_ALLOC, SLOT_COPY, SLOT_MOVE, SLOT_FREE) + SLOT_FAILURES})
        self.machine.slots = {SLOT_ALLOC: self.alloc_hook, SLOT_COPY: self.copy_hook,
                              SLOT_MOVE: self.copy_hook, SLOT_FREE: self.free_hook}
        for slot in SLOT_FAILURES:
            self.machine.slots[slot] = self.failure_hook

    def reserve(self, size):
        addr = self.input_next
        self.input_next = (addr + size + 15) & ~15
        if self.input_next >= HEAP_BASE + 0x1e000:
            raise ValueError('Fixture input overflow')
        self.machine.memory.put_bytes(addr, bytes(size))
        self.blocks[addr] = size
        return addr

    def alloc_hook(self, machine):
        size = machine.regs[RDI]
        if self.fail_after is not None and len(self.allocations) == self.fail_after:
            machine.regs[RAX] = 0
            return
        addr = self.alloc_next
        self.alloc_next = (addr + size + 15) & ~15
        if self.alloc_next > HEAP_BASE + HEAP_SIZE:
            raise Halt('Fixture allocator overflow')
        self.allocations.append((addr, size))
        self.blocks[addr] = size
        machine.regs[RAX] = addr

    def copy_hook(self, machine):
        dest, src, count = (machine.regs[x] for x in (RDI, RSI, RDX))
        machine.memory.copy(dest, src, count)
        machine.regs[RAX] = dest

    def free_hook(self, machine):
        address, size = machine.regs[RDI], machine.regs[RSI]
        if address not in self.blocks or self.blocks[address] != size or address in self.released:
            raise Halt('invalid modeled deallocation')
        self.released.add(address)
        self.frees.append((address, size))
        machine.regs[RAX] = 0

    def failure_hook(self, machine):
        self.failure_site = machine.last_va
        raise Halt('failure boundary')

    def write(self, address, size, value):
        self.machine.memory.write(address, size, value)

    def bytes(self, address, size):
        return self.machine.memory.bytes_at(address, size)

    def integer(self, address, size):
        return self.machine.memory.read(address, size)

    def nested(self, spec, parent=0, edge=0):
        # spec is ([(20-byte key, u64 value), ...], [child specs]).
        rows, children = spec
        if len(rows) > 11 or (children and len(children) != len(rows) + 1):
            raise ValueError('Bad nested fixture')
        addr = self.reserve(0x1a0 if children else 0x140)
        self.write(addr, 8, parent)
        self.write(addr + 0x13c, 2, edge)
        self.write(addr + 0x13e, 2, len(rows))
        total = len(rows)
        for index, (key, value) in enumerate(rows):
            if len(key) != 20:
                raise ValueError('Bad key width')
            self.machine.memory.put_bytes(addr + 0x60 + 20 * index, key)
            self.write(addr + 8 + 8 * index, 8, value)
        for index, child in enumerate(children):
            child_addr, height, child_count = self.nested(child, addr, index)
            self.write(addr + 0x140 + 8 * index, 8, child_addr)
            if index and height != child_height:
                raise ValueError('Unbalanced nested fixture')
            child_height = height
            total += child_count
        return addr, 1 + child_height if children else 0, total

    def outer(self, spec, parent=0, edge=0):
        # spec is ([(32-byte key, nested spec or None, hot, cold), ...], children).
        rows, children = spec
        if len(rows) > 11 or (children and len(children) != len(rows) + 1):
            raise ValueError('Bad outer fixture')
        addr = self.reserve(0x490 if children else 0x430)
        self.write(addr + 0x420, 8, parent)
        self.write(addr + 0x428, 2, edge)
        self.write(addr + 0x42a, 2, len(rows))
        total = len(rows)
        for index, (key, nested, hot, cold) in enumerate(rows):
            if len(key) != 32 or len(hot) != 20 or len(cold) != 20:
                raise ValueError('Bad outer key or value width')
            self.machine.memory.put_bytes(addr + 0x2c0 + 32 * index, key)
            value = addr + 64 * index
            if nested is not None:
                root, height, count = self.nested(nested)
                for offset, word in ((0, root), (8, height), (16, count)):
                    self.write(value + offset, 8, word)
            self.machine.memory.put_bytes(value + 0x18, hot)
            self.machine.memory.put_bytes(value + 0x2c, cold)
        for index, child in enumerate(children):
            child_addr, height, child_count = self.outer(child, addr, index)
            self.write(addr + 0x430 + 8 * index, 8, child_addr)
            if index and height != child_height:
                raise ValueError('Unbalanced outer fixture')
            child_height = height
            total += child_count
        return addr, 1 + child_height if children else 0, total

    def collect_nested(self, root, height, parent=0, edge=0):
        if not root or self.integer(root, 8) != parent or (parent and self.integer(root + 0x13c, 2) != edge):
            raise AssertionError('Nested parent mismatch')
        count = self.integer(root + 0x13e, 2)
        if count > 11:
            raise AssertionError('Nested node overfull')
        rows, nodes = [], {root}
        for index in range(count + 1):
            if height:
                child = self.integer(root + 0x140 + 8 * index, 8)
                part, visited = self.collect_nested(child, height - 1, root, index)
                rows.extend(part); nodes.update(visited)
            if index < count:
                rows.append((self.bytes(root + 0x60 + 20 * index, 20).hex(),
                             self.integer(root + 8 + 8 * index, 8)))
        return rows, nodes

    def collect_outer(self, root, height, parent=0, edge=0):
        if not root or self.integer(root + 0x420, 8) != parent or (parent and self.integer(root + 0x428, 2) != edge):
            raise AssertionError('Outer parent mismatch')
        count = self.integer(root + 0x42a, 2)
        if count > 11:
            raise AssertionError('Outer node overfull')
        rows, nodes = [], {root}
        for index in range(count + 1):
            if height:
                child = self.integer(root + 0x430 + 8 * index, 8)
                part, visited = self.collect_outer(child, height - 1, root, index)
                rows.extend(part); nodes.update(visited)
            if index < count:
                value = root + 64 * index
                nested_root = self.integer(value, 8)
                nested_height, nested_count = self.integer(value + 8, 8), self.integer(value + 16, 8)
                if nested_count:
                    nested, visited = self.collect_nested(nested_root, nested_height)
                    if len(nested) != nested_count:
                        raise AssertionError('Nested length mismatch')
                    nodes.update(visited)
                else:
                    if nested_root:
                        raise AssertionError('Non-null empty fixture')
                    nested = []
                rows.append((self.bytes(root + 0x2c0 + 32 * index, 32).hex(), nested,
                             self.bytes(value + 0x18, 20).hex(), self.bytes(value + 0x2c, 20).hex()))
        return rows, nodes


def key(width, value):
    return value.to_bytes(width, 'big')


def sample_outer_row(value, nested):
    return (key(32, value), nested, key(20, 0x1000 + value), key(20, 0x2000 + value))


def clone_case(image, spec, label, patches=None):
    f = Fixture(image, patches)
    root, height, total = f.outer(spec)
    before, source_nodes = f.collect_outer(root, height)
    out = f.reserve(24)
    f.machine.run(0x33e71c0, {RDI: out, RSI: root, RDX: height})
    result_root, result_height, result_len = (f.integer(out + off, 8) for off in (0, 8, 16))
    after, result_nodes = f.collect_outer(result_root, result_height)
    record_coverage(f.machine)
    if (before != after or result_len != total or result_height != height or
            source_nodes.intersection(result_nodes) or len(f.allocations) != len(result_nodes)):
        raise AssertionError('Clone mismatch: ' + label)
    return {'case': label, 'height': height, 'validator_rows': total,
            'nested_rows': sum(len(row[1]) for row in after),
            'source_nodes': len(source_nodes), 'copied_nodes': len(result_nodes),
            'allocation_sizes': ','.join(hex(size) for _, size in f.allocations),
            'visited_instructions': len(f.machine.seen)}


def clone_cases(image):
    nested_leaf = lambda count: ([(key(20, i + 1), 11 + i) for i in range(count)], [])
    nested_inner = ([(key(20, 3), 13)], [nested_leaf(2), ([(key(20, 4), 14), (key(20, 5), 15)], [])])
    cases = [([], []), ([sample_outer_row(2, None)], []),
             ([sample_outer_row(2, nested_leaf(1))], []),
             ([sample_outer_row(2, nested_leaf(11))], []),
             ([sample_outer_row(2, nested_inner)], []),
             ([sample_outer_row(i + 1, nested_leaf(i % 3) if i % 3 else None) for i in range(11)], []),
             ([sample_outer_row(20, nested_leaf(1))],
              [([sample_outer_row(10, nested_inner)], []),
               ([sample_outer_row(30, nested_leaf(2))], [])])]
    return [clone_case(image, case, 'clone_%02d' % i) for i, case in enumerate(cases)]


def epoch_value(number):
    # Opaque 40-byte row; word at +0x18 is nonzero so replacement is observable.
    return struct.pack('<QQQQQ', number + 10, number + 20, number + 30, number + 40, number + 50)


def build_epoch_leaf(f, rows):
    if len(rows) > 11:
        raise ValueError('Fixture over capacity')
    root = f.reserve(0x220)
    f.write(root + 0x21a, 2, len(rows))
    for index, (k, value) in enumerate(rows):
        f.write(root + 8 + index * 8, 8, k)
        f.machine.memory.put_bytes(root + 0x60 + index * 40, value)
    return root


def collect_epoch(f, root, height, parent=0, edge=0):
    if f.integer(root, 8) != parent or (parent and f.integer(root + 0x218, 2) != edge):
        raise AssertionError('Epoch parent mismatch')
    count = f.integer(root + 0x21a, 2)
    if count > 11 or (parent and count < 5):
        raise AssertionError('Epoch occupancy outside bounds')
    rows = []
    for index in range(count + 1):
        if height:
            child = f.integer(root + 0x220 + 8 * index, 8)
            rows.extend(collect_epoch(f, child, height - 1, root, index))
        if index < count:
            rows.append((f.integer(root + 8 + 8 * index, 8), f.bytes(root + 0x60 + 40 * index, 40)))
    if any(a[0] >= b[0] for a, b in zip(rows, rows[1:])):
        raise AssertionError('Epoch keys are not strictly ordered')
    return rows


def insert_case(image, count, position, replacement=False, fail_after=None, patches=None):
    if not 0 <= count <= 11 or not 0 <= position <= count or (replacement and position == count):
        raise ValueError('Bad insertion fixture')
    f = Fixture(image, patches)
    rows = [(2 * i + 2, epoch_value(i + 1)) for i in range(count)]
    root = build_epoch_leaf(f, rows) if count else 0
    tree = f.reserve(24)
    for off, val in ((0, root), (8, 0), (16, count)):
        f.write(tree + off, 8, val)
    number = rows[position][0] if replacement else 2 * position + 1
    value = epoch_value(1000 + position)
    value_ptr, out = f.reserve(40), f.reserve(40)
    f.machine.memory.put_bytes(value_ptr, value)
    f.fail_after = fail_after
    f.machine.run(0x33a7690, {RDI: out, RSI: tree, RDX: number, RCX: value_ptr})
    root, height, length = (f.integer(tree + off, 8) for off in (0, 8, 16))
    result = collect_epoch(f, root, height)
    record_coverage(f.machine)
    expected = dict(rows)
    expected[number] = value
    if result != sorted(expected.items()) or length != len(expected):
        raise AssertionError('Insert/replace tree mismatch')
    if replacement:
        if f.bytes(out, 40) != rows[position][1]:
            raise AssertionError('Old value mismatch')
    elif f.integer(out + 0x18, 4) != 0:
        raise AssertionError('New value must report absence')
    pivot = ''
    if height:
        if height != 1 or count != 11 or replacement:
            raise AssertionError('Unexpected height change')
        pivot = f.integer(root + 8, 8)
        left = f.integer(root + 0x220, 8)
        right = f.integer(root + 0x228, 8)
        left_count, right_count = f.integer(left + 0x21a, 2), f.integer(right + 0x21a, 2)
        expected_pivot_index = 4 if position < 5 else 5 if position <= 6 else 6
        if pivot != rows[expected_pivot_index][0] or left_count + right_count != 11:
            raise AssertionError('Split pivot mismatch')
    else:
        left_count = right_count = ''
    return {'old_count': count, 'position': position, 'replaced': int(replacement),
            'height': height, 'new_count': length, 'pivot_key': pivot,
            'left_count': left_count, 'right_count': right_count,
            'allocations': len(f.allocations), 'visited_instructions': len(f.machine.seen)}


def insert_cases(image):
    rows = []
    for count in range(12):
        for index in range(count + 1):
            rows.append(insert_case(image, count, index))
        for index in range(count):
            rows.append(insert_case(image, count, index, replacement=True))
    return rows


def remove_case(image, leaf_count, index, sibling_count=None, edge=0, patches=None):
    if not 1 <= leaf_count <= 11 or not 0 <= index < leaf_count:
        raise ValueError('Bad leaf fixture')
    if sibling_count is not None and (not 5 <= sibling_count <= 11 or edge not in (0, 1)):
        raise ValueError('Bad sibling fixture')
    f = Fixture(image, patches)
    count = leaf_count + (0 if sibling_count is None else sibling_count + 1)
    rows = [(2 * i + 2, epoch_value(i + 1)) for i in range(count)]
    if sibling_count is None:
        root = leaf = build_epoch_leaf(f, rows)
        height, removed_index = 0, index
    else:
        left_count = leaf_count if edge == 0 else sibling_count
        root = f.reserve(0x280)
        left = build_epoch_leaf(f, rows[:left_count])
        right = build_epoch_leaf(f, rows[left_count + 1:])
        f.write(root + 0x21a, 2, 1)
        f.write(root + 8, 8, rows[left_count][0])
        f.machine.memory.put_bytes(root + 0x60, rows[left_count][1])
        for i, child in enumerate((left, right)):
            f.write(root + 0x220 + 8 * i, 8, child)
            f.write(child, 8, root)
            f.write(child + 0x218, 2, i)
        height, leaf = 1, left if edge == 0 else right
        removed_index = index if edge == 0 else left_count + 1 + index
    out, cursor, collapsed = f.reserve(0x48), f.reserve(0x20), f.reserve(1)
    f.write(cursor, 8, leaf)
    f.write(cursor + 8, 8, 0)
    f.write(cursor + 16, 8, index)
    f.write(collapsed, 1, 0)
    f.machine.run(0x2fd8bc0, {RDI: out, RSI: cursor, RDX: collapsed})
    removed = (f.integer(out, 8), f.bytes(out + 8, 40))
    flag = f.integer(collapsed, 1)
    if removed != rows[removed_index] or flag not in (0, 1):
        raise AssertionError('Removed row or root flag mismatch')
    if flag:
        if height != 1 or f.integer(root + 0x21a, 2) != 0:
            raise AssertionError('Unexpected root collapse flag')
        # The caller performs this root promotion, not the selected remover.
        root = f.integer(root + 0x220, 8)
        f.write(root, 8, 0)
        height -= 1
    result = collect_epoch(f, root, height)
    record_coverage(f.machine)
    expected = rows[:removed_index] + rows[removed_index + 1:]
    if result != expected:
        raise AssertionError('Removal content mismatch')
    if sibling_count is None:
        choice = 'root_leaf'
    elif leaf_count > 5:
        choice = 'no_repair'
    else:
        choice = ('borrow_' if leaf_count + sibling_count >= 12 else 'merge_') + ('right' if edge == 0 else 'left')
    return {'leaf_count': leaf_count, 'index': index,
            'sibling_count': '' if sibling_count is None else sibling_count,
            'edge': '' if sibling_count is None else edge, 'choice': choice,
            'root_collapsed': flag, 'remaining': len(result), 'height': height,
            'visited_instructions': len(f.machine.seen)}


def remove_cases(image):
    cases = []
    for n in range(1, 12):
        for index in range(n):
            cases.append(remove_case(image, n, index))
    for n in range(5, 12):
        for sibling in range(5, 12):
            for edge in (0, 1):
                for index in range(n):
                    cases.append(remove_case(image, n, index, sibling, edge))
    return cases




def unsigned_key_cases(image):
    cases = []
    high = (1 << 64) - 1
    base = [0, 1 << 63, high]
    for number in (0, 1, (1 << 63) - 1, 1 << 63, (1 << 63) + 1, high - 1, high):
        f = Fixture(image)
        rows = [(k, epoch_value(i)) for i, k in enumerate(base)]
        root = build_epoch_leaf(f, rows)
        tree, out, value_ptr = f.reserve(24), f.reserve(40), f.reserve(40)
        for off, val in ((0, root), (8, 0), (16, len(rows))):
            f.write(tree + off, 8, val)
        replacement = epoch_value(999)
        f.machine.memory.put_bytes(value_ptr, replacement)
        f.machine.run(0x33a7690, {RDI: out, RSI: tree, RDX: number, RCX: value_ptr})
        result = collect_epoch(f, f.integer(tree, 8), f.integer(tree + 8, 8))
        expected = dict(rows); expected[number] = replacement
        if result != sorted(expected.items()) or f.integer(tree + 16, 8) != len(expected):
            raise AssertionError('Unsigned key comparison mismatch')
        old = dict(rows).get(number)
        if old is not None and f.bytes(out, 40) != old:
            raise AssertionError('Unsigned replacement mismatch')
        if old is None and f.integer(out + 0x18, 4) != 0:
            raise AssertionError('Unsigned insertion did not report absence')
        record_coverage(f.machine)
        cases.append({'key': hex(number), 'replaced': int(old is not None), 'result_count': len(result),
                      'visited_instructions': len(f.machine.seen)})
    return cases


def internal_remove_case(image, left_count, right_count):
    if not (5 <= left_count <= 11 and 5 <= right_count <= 11):
        raise ValueError('Bad internal fixture')
    f = Fixture(image)
    rows = [(2 * i + 2, epoch_value(i + 1)) for i in range(left_count + right_count + 1)]
    root = f.reserve(0x280)
    left = build_epoch_leaf(f, rows[:left_count])
    right = build_epoch_leaf(f, rows[left_count + 1:])
    f.write(root + 0x21a, 2, 1)
    f.write(root + 8, 8, rows[left_count][0])
    f.machine.memory.put_bytes(root + 0x60, rows[left_count][1])
    for i, child in enumerate((left, right)):
        f.write(root + 0x220 + i * 8, 8, child)
        f.write(child, 8, root)
        f.write(child + 0x218, 2, i)
    out, cursor, flag_addr = f.reserve(0x48), f.reserve(0x20), f.reserve(1)
    f.write(cursor, 8, root)
    f.write(cursor + 8, 8, 1)
    f.write(cursor + 16, 8, 0)
    f.write(flag_addr, 1, 0)
    f.machine.run(0x2fd8bc0, {RDI: out, RSI: cursor, RDX: flag_addr})
    if (f.integer(out, 8), f.bytes(out + 8, 40)) != rows[left_count]:
        raise AssertionError('Internal removed row mismatch')
    flag = f.integer(flag_addr, 1)
    if flag:
        if f.integer(root + 0x21a, 2) != 0:
            raise AssertionError('Unexpected internal collapse')
        root = f.integer(root + 0x220, 8)
        f.write(root, 8, 0)
    result = collect_epoch(f, root, 0 if flag else 1)
    if result != rows[:left_count] + rows[left_count + 1:]:
        raise AssertionError('Internal remove tree mismatch')
    record_coverage(f.machine)
    return {'left_count': left_count, 'right_count': right_count,
            'collapsed': flag, 'remaining': len(result),
            'visited_instructions': len(f.machine.seen)}


def internal_remove_cases(image):
    return [internal_remove_case(image, left, right) for left in range(5, 12) for right in range(5, 12)]



def cascade_remove_case(image, active_edge, sibling_inner_count, leaf_index):
    if active_edge not in (0, 1) or sibling_inner_count not in (5, 6, 7, 11) or not 0 <= leaf_index < 5:
        raise ValueError('Bad cascade fixture')
    f = Fixture(image)
    next_key = 0
    leaves = []
    def build(height, node_count, parent, edge):
        nonlocal next_key
        node = f.reserve(0x280 if height else 0x220)
        f.write(node, 8, parent)
        f.write(node + 0x218, 2, edge)
        f.write(node + 0x21a, 2, node_count)
        for i in range(node_count + 1):
            if height:
                if height == 2:
                    child_count = 5 if i == active_edge else sibling_inner_count
                else:
                    child_count = 5
                child = build(height - 1, child_count, node, i)
                f.write(node + 0x220 + 8 * i, 8, child)
            if i < node_count:
                next_key += 2
                f.write(node + 8 + 8 * i, 8, next_key)
                f.machine.memory.put_bytes(node + 0x60 + 40 * i, epoch_value(next_key))
        if height == 0:
            leaves.append(node)
        return node
    root = build(2, 1, 0, 0)
    original = collect_epoch(f, root, 2)
    active_child = f.integer(root + 0x220 + active_edge * 8, 8)
    leaf = f.integer(active_child + 0x220, 8)
    removed_key = f.integer(leaf + 8 + leaf_index * 8, 8)
    removed_value = f.bytes(leaf + 0x60 + leaf_index * 40, 40)
    out, cursor, flag_addr = f.reserve(0x48), f.reserve(0x20), f.reserve(1)
    f.write(cursor, 8, leaf); f.write(cursor + 8, 8, 0); f.write(cursor + 16, 8, leaf_index)
    f.write(flag_addr, 1, 0)
    f.machine.run(0x2fd8bc0, {RDI: out, RSI: cursor, RDX: flag_addr})
    if (f.integer(out, 8), f.bytes(out + 8, 40)) != (removed_key, removed_value):
        raise AssertionError('Cascade removed value mismatch')
    flag = f.integer(flag_addr, 1)
    if flag:
        if f.integer(root + 0x21a, 2) != 0:
            raise AssertionError('Unexpected cascade collapse')
        root = f.integer(root + 0x220, 8)
        f.write(root, 8, 0)
    result = collect_epoch(f, root, 1 if flag else 2)
    if result != [r for r in original if r[0] != removed_key]:
        raise AssertionError('Cascade output mismatch')
    if flag != (sibling_inner_count < 7):
        raise AssertionError('Unexpected upper-level repair')
    record_coverage(f.machine)
    return {'active_edge': active_edge, 'sibling_inner_count': sibling_inner_count,
            'leaf_index': leaf_index, 'collapsed': flag, 'remaining': len(result),
            'freed_nodes': len(f.frees), 'visited_instructions': len(f.machine.seen)}


def cascade_remove_cases(image):
    return [cascade_remove_case(image, edge, sibling, index) for edge in (0, 1)
            for sibling in (5, 6, 7, 11) for index in range(5)]


def insert_deep_case(image, child_index, position):
    if not 0 <= child_index <= 11 or not 0 <= position <= 11:
        raise ValueError('Bad deep split fixture')
    f = Fixture(image)
    root = f.reserve(0x280)
    f.write(root + 0x21a, 2, 11)
    expected = {}
    for i in range(11):
        separator = (i + 1) * 1000
        value = epoch_value(separator)
        expected[separator] = value
        f.write(root + 8 + i * 8, 8, separator)
        f.machine.memory.put_bytes(root + 0x60 + 40 * i, value)
    for i in range(12):
        rows = [(i * 1000 + 2 * j + 2, epoch_value(i * 1000 + 2 * j + 2)) for j in range(11)]
        expected.update(rows)
        leaf = build_epoch_leaf(f, rows)
        f.write(root + 0x220 + i * 8, 8, leaf)
        f.write(leaf, 8, root)
        f.write(leaf + 0x218, 2, i)
    tree = f.reserve(24)
    for off, val in ((0, root), (8, 1), (16, len(expected))):
        f.write(tree + off, 8, val)
    number = child_index * 1000 + 2 * position + 1
    value = epoch_value(number + 30000)
    value_ptr, out = f.reserve(40), f.reserve(40)
    f.machine.memory.put_bytes(value_ptr, value)
    f.machine.run(0x33a7690, {RDI: out, RSI: tree, RDX: number, RCX: value_ptr})
    new_root, height, length = (f.integer(tree + off, 8) for off in (0, 8, 16))
    expected[number] = value
    result = collect_epoch(f, new_root, height)
    record_coverage(f.machine)
    expected_pivot = (4 if child_index < 5 else 5 if child_index <= 6 else 6) + 1
    if (result != sorted(expected.items()) or length != len(expected) or height != 2 or
            f.integer(new_root + 8, 8) != expected_pivot * 1000 or f.integer(out + 0x18, 4)):
        raise AssertionError('Deep split mismatch')
    return {'child_index': child_index, 'leaf_position': position, 'height': height,
            'new_count': length, 'root_pivot': expected_pivot * 1000,
            'allocations': len(f.allocations), 'visited_instructions': len(f.machine.seen)}


def deep_cases(image):
    return [insert_deep_case(image, child, index) for child in range(12) for index in range(12)]


def iterator_case(image, spec, label):
    f = Fixture(image)
    root, height, count = f.outer(spec)
    expected, source_nodes = f.collect_outer(root, height)
    state, out = f.reserve(0x48), f.reserve(0x18)
    # State initialization follows the parent call-site's two-ended iterator.
    for off, val in ((0, 1), (8, 0), (16, root), (24, height),
                     (32, 1), (40, 0), (48, root), (56, height), (64, count)):
        f.write(state + off, 8, val)
    keys = []
    for _ in range(count + 1):
        f.machine.run(0x33b64d0, {RDI: out, RSI: state})
        node = f.integer(out, 8)
        if not node:
            break
        index = f.integer(out + 16, 8)
        keys.append(f.bytes(node + 0x2c0 + 32 * index, 32).hex())
    if keys != [r[0] for r in expected] or f.integer(state + 0x40, 8) != 0:
        raise AssertionError('Iterator order or count mismatch')
    record_coverage(f.machine)
    freed = {address for address, _ in f.frees}
    if freed != source_nodes or len(f.frees) != len(source_nodes):
        raise AssertionError('Iterator freed unexpected node')
    return {'case': label, 'height': height, 'yielded': len(keys), 'tree_nodes_freed': len(f.frees),
            'visited_instructions': len(f.machine.seen)}


def iterator_cases(image):
    cases = [([], []), ([sample_outer_row(1, None)], []),
             ([sample_outer_row(i + 1, None) for i in range(11)], []),
             ([sample_outer_row(20, None)],
              [([sample_outer_row(10, None)], []), ([sample_outer_row(30, None)], [])])]
    return [iterator_case(image, spec, 'iterator_%02d' % i) for i, spec in enumerate(cases)]


def fault_cases(image):
    records = []
    nested = ([(key(20, 1), 10)], [])
    spec = ([sample_outer_row(2, nested)], [])
    for label, failure_after, missing_nested, expected_site in (
        ('clone_outer_allocation', 0, False, 0x33e776c),
        ('clone_nested_allocation', 1, False, 0x33ed5b1),
        ('nested_nonempty_null_root', None, True, 0x33e7718),
    ):
        f = Fixture(image)
        root, height, _ = f.outer(spec)
        out = f.reserve(24)
        f.fail_after = failure_after
        if missing_nested:
            f.write(root, 8, 0)
        try:
            f.machine.run(0x33e71c0, {RDI: out, RSI: root, RDX: height})
        except Halt as error:
            if str(error) != 'failure boundary' or f.failure_site != expected_site:
                raise AssertionError('Unexpected failure boundary: ' + label) from error
        else:
            raise AssertionError('Expected failure was not reached: ' + label)
        records.append({'case': label, 'boundary_site': hex(f.failure_site),
                        'allocations_before_failure': len(f.allocations)})
    for label, count, fail_after, expected_site in (
        ('insert_empty_allocation', 0, 0, 0x33a7858),
        ('insert_split_leaf_allocation', 11, 0, 0x2f925a8),
        ('insert_split_root_allocation', 11, 1, 0x2f925d1),
    ):
        f = Fixture(image)
        rows = [(2 * i + 2, epoch_value(i)) for i in range(count)]
        root = build_epoch_leaf(f, rows) if count else 0
        tree, out, value = f.reserve(24), f.reserve(40), f.reserve(40)
        for off, word in ((0, root), (8, 0), (16, count)):
            f.write(tree + off, 8, word)
        f.machine.memory.put_bytes(value, epoch_value(50))
        f.fail_after = fail_after
        try:
            f.machine.run(0x33a7690, {RDI: out, RSI: tree, RDX: 1, RCX: value})
        except Halt as error:
            if str(error) != 'failure boundary' or f.failure_site != expected_site:
                raise AssertionError('Unexpected insertion failure: ' + label) from error
        else:
            raise AssertionError('Expected insertion failure was not reached: ' + label)
        records.append({'case': label, 'boundary_site': hex(f.failure_site),
                        'allocations_before_failure': len(f.allocations)})
    return records


def mutation_cases(image):
    records = []
    spec = ([sample_outer_row(1, None)], [])
    tests = (
        ('clone_height_branch', {0x33e71db: 0x85}, lambda patches: clone_case(image, spec, 'mutant', patches)),
        ('insert_pivot_compare', {0x2f91935: 0x04}, lambda patches: insert_case(image, 11, 5, patches=patches)),
        ('insert_pivot_value', {0x2f9194c: 0x03}, lambda patches: insert_case(image, 11, 1, patches=patches)),
        ('insert_capacity', {0x2f91926: 0x0a}, lambda patches: insert_case(image, 10, 1, patches=patches)),
        ('remove_underfull', {0x2fc6501: 0x03}, lambda patches: remove_case(image, 5, 0, 5, 0, patches)),
    )
    for name, patches, case in tests:
        try:
            case(patches)
        except AssertionError:
            detected = True
        else:
            detected = False
        if not detected:
            raise AssertionError('Surviving selected mutation: ' + name)
        address, replacement = next(iter(patches.items()))
        records.append({'case': name, 'address': hex(address), 'original': image.read(address, 1).hex(),
                        'replacement': '%02x' % replacement, 'detected': int(detected)})
    return records



def lifecycle_case(image, active_epoch, replace=False):
    if active_epoch not in (1, 2, 1003) or (replace and active_epoch != 1):
        raise ValueError('Unknown lifecycle fixture')
    f = Fixture(image)
    previous_spec = ([sample_outer_row(7, None)], [])
    prior_root, prior_height, prior_count = f.outer(previous_spec)
    current_spec = ([sample_outer_row(19, ([(key(20, 3), 25)], []))], [])
    current_root, current_height, current_count = f.outer(current_spec)
    current_rows, current_nodes = f.collect_outer(current_root, current_height)
    tree, oldout, value = f.reserve(24), f.reserve(40), f.reserve(40)
    for i in range(1, 1002):
        # Nonzero date is part of the opaque snapshot, with a nonempty old tree only at key 1.
        raw = struct.pack('<QQQQQ', prior_root if i == 1 else 0,
                          prior_height if i == 1 else 0, prior_count if i == 1 else 0, i + 1, 0)
        f.machine.memory.put_bytes(value, raw)
        f.machine.run(0x33a7690, {RDI: oldout, RSI: tree, RDX: i, RCX: value})
        if f.integer(oldout + 0x18, 4):
            raise AssertionError('Setup unexpectedly replaced a snapshot')
    if f.integer(tree + 16, 8) != 1001:
        raise AssertionError('Lifecycle setup length')
    cloned = f.reserve(24)
    f.machine.run(0x33e71c0, {RDI: cloned, RSI: current_root, RDX: current_height})
    cloned_root, cloned_height, cloned_count = (f.integer(cloned + off, 8) for off in (0, 8, 16))
    copied_rows, copied_nodes = f.collect_outer(cloned_root, cloned_height)
    if copied_rows != current_rows or current_nodes & copied_nodes or cloned_count != current_count:
        raise AssertionError('Lifecycle clone mismatch')
    f.machine.memory.put_bytes(value, struct.pack('<QQQQQ', cloned_root, cloned_height, cloned_count, 1003, 0))
    target_epoch = 1 if replace else 1002
    f.machine.run(0x33a7690, {RDI: oldout, RSI: tree, RDX: target_epoch, RCX: value})
    if bool(f.integer(oldout + 0x18, 4)) != replace:
        raise AssertionError('Lifecycle replacement flag mismatch')
    # Parent guard, root promotion, and value destructor are modeled boundaries.
    # These iterator calls traverse and free tree nodes; nested-value drops are not run.
    deleted, disposed = [], []
    def consume_snapshot(snapshot_root, snapshot_height, snapshot_len):
        if snapshot_len:
            state, item = f.reserve(0x48), f.reserve(0x18)
            for off, word in ((0, 1), (8, 0), (16, snapshot_root), (24, snapshot_height),
                              (32, 1), (40, 0), (48, snapshot_root), (56, snapshot_height), (64, snapshot_len)):
                f.write(state + off, 8, word)
            for _ in range(snapshot_len + 1):
                f.machine.run(0x33b64d0, {RDI: item, RSI: state})
                node = f.integer(item, 8)
                if not node:
                    break
                idx = f.integer(item + 16, 8)
                disposed.append(f.bytes(node + 0x2c0 + idx * 32, 32).hex())
    if replace:
        old_root, old_height, old_length = (f.integer(oldout + off, 8) for off in (0, 8, 16))
        if (old_root, old_height, old_length) != (prior_root, prior_height, prior_count):
            raise AssertionError('Replacement did not return the old snapshot')
        consume_snapshot(old_root, old_height, old_length)
    while f.integer(tree + 16, 8) > 1000:
        root, height = f.integer(tree, 8), f.integer(tree + 8, 8)
        leaf = root
        for _ in range(height):
            leaf = f.integer(leaf + 0x220, 8)
        if not f.integer(leaf + 0x21a, 2):
            break
        smallest = f.integer(leaf + 8, 8)
        if smallest >= active_epoch:
            break
        cursor, out, flag_addr = f.reserve(0x20), f.reserve(0x48), f.reserve(1)
        f.write(cursor, 8, leaf); f.write(cursor + 8, 8, 0); f.write(cursor + 16, 8, 0)
        f.write(flag_addr, 1, 0)
        f.machine.run(0x2fd8bc0, {RDI: out, RSI: cursor, RDX: flag_addr})
        if f.integer(out, 8) != smallest:
            raise AssertionError('Lifecycle oldest key mismatch')
        f.write(tree + 16, 8, f.integer(tree + 16, 8) - 1)
        if f.integer(flag_addr, 1):
            newroot = f.integer(root + 0x220, 8)
            f.write(newroot, 8, 0)
            f.write(tree, 8, newroot)
            f.write(tree + 8, 8, height - 1)
        snapshot_root, snapshot_height, snapshot_len = (f.integer(out + 8 + off, 8) for off in (0, 8, 16))
        consume_snapshot(snapshot_root, snapshot_height, snapshot_len)
        deleted.append(smallest)
    final = collect_epoch(f, f.integer(tree, 8), f.integer(tree + 8, 8))
    expected_removed = [i for i in (1, 2) if i < active_epoch][:1 if replace else 2]
    end_epoch = 1002 if replace else 1003
    if deleted != expected_removed or [k for k, _ in final] != list(range(1 + len(deleted), end_epoch)):
        raise AssertionError('Lifecycle pruning mismatch')
    if disposed != ([key(32, 7).hex()] if deleted or replace else []):
        raise AssertionError('Lifecycle old-snapshot iteration mismatch')
    retained = dict(final)[target_epoch]
    if int.from_bytes(retained[:8], 'little') != cloned_root:
        raise AssertionError('Cloned snapshot root was not retained')
    retained_rows, retained_nodes = f.collect_outer(cloned_root, cloned_height)
    if retained_rows != current_rows or retained_nodes & current_nodes:
        raise AssertionError('Retained snapshot changed')
    record_coverage(f.machine)
    return {'active_epoch': active_epoch, 'initial_epochs': 1001, 'inserted_epoch': target_epoch,
            'replaced': int(replace), 'removed_epochs': ','.join(str(i) for i in deleted),
            'final_epochs': len(final), 'disposed_validator_rows': len(disposed),
            'final_height': f.integer(tree + 8, 8), 'visited_instructions': len(f.machine.seen)}



def lifecycle_cases(image):
    return [lifecycle_case(image, active) for active in (1, 2, 1003)] + [lifecycle_case(image, 1, True)]


def relocation_index(image):
    by_name = {s['name']: s for s in image.sections}
    rela, syms, strings = (by_name[x] for x in ('.rela.dyn', '.dynsym', '.dynstr'))
    if any(s['type'] == 8 for s in (rela, syms, strings)) or rela['size'] % 24 or syms['size'] % 24:
        raise ValueError('Invalid dynamic tables')
    string_data = image.data[strings['offset']:strings['offset'] + strings['size']]
    result = {}
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, off)
        kind, sym = info & 0xffffffff, info >> 32
        if slot in result:
            raise ValueError('Duplicate dynamic relocation slot')
        symbol = ''
        if sym:
            if sym * 24 + 24 > syms['size']:
                raise ValueError('Symbol outside dynamic symbol table')
            nameoff = struct.unpack_from('<I', image.data, syms['offset'] + sym * 24)[0]
            if nameoff >= len(string_data):
                raise ValueError('Symbol name outside string table')
            end = string_data.find(b'\0', nameoff)
            if end < 0:
                raise ValueError('Unterminated dynamic symbol')
            symbol = string_data[nameoff:end].decode('ascii')
        result[slot] = (kind, addend, symbol)
    return result


def as_hex(value):
    return '' if value is None else hex(value)


def table(path, fields, rows):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=fields, delimiter='\t', lineterminator='\n', extrasaction='raise')
        writer.writeheader()
        writer.writerows(rows)


def generate(image, out):
    validate_pins(image)
    out.mkdir(parents=True, exist_ok=True)
    COVERAGE.clear(); EDGES.clear()
    clones = clone_cases(image)
    insertions = insert_cases(image)
    unsigned_keys = unsigned_key_cases(image)
    deep = deep_cases(image)
    removals = remove_cases(image)
    iterators = iterator_cases(image)
    internal_removals = internal_remove_cases(image)
    cascades = cascade_remove_cases(image)
    lifecycle = lifecycle_cases(image)
    # Save coverage before running mutation controls, which deliberately alter code.
    reached, edge_outcomes = set(COVERAGE), set(EDGES)
    faults, mutations = fault_cases(image), mutation_cases(image)
    relocation = relocation_index(image)
    functions, instructions, branches, transfers = [], [], [], []
    for start, name in FUNCTIONS:
        fde = image.fdes[start]
        data = image.read(start, fde['end'] - start, executable=True)
        decoded = decode_function(image, start)
        executable = decode_range(image, start, fde['end'])
        if [(r['address'], r['size']) for r in decoded] != [(r.va, r.size) for r in executable]:
            raise ValueError('Independent opcode decoders disagree')
        functions.append({'name': name, 'start_va': hex(start), 'end_va_exclusive': hex(fde['end']),
                          'fde_va': hex(fde['fde']), 'file_offset': hex(image.offset(start, len(data), True)),
                          'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                          'instructions': len(decoded), 'reached': sum(r['address'] in reached for r in decoded)})
        for row in decoded:
            va, kind = row['address'], row['kind']
            instructions.append({'function': name, 'address': hex(va), 'bytes': row['bytes'],
                                 'kind': kind, 'target': as_hex(row['target']), 'slot': as_hex(row['slot']),
                                 'reached': int(va in reached)})
            if kind == 'conditional':
                branches.append({'function': name, 'address': hex(va), 'bytes': row['bytes'],
                                 'taken_target': as_hex(row['target']),
                                 'fallthrough': hex(va + row['size']),
                                 'seen_taken': int((va, True) in edge_outcomes),
                                 'seen_fallthrough': int((va, False) in edge_outcomes)})
            if kind in ('call', 'indirect_call', 'jump', 'indirect_jump'):
                slot = row['slot']
                reltype, addend, symbol = relocation.get(slot, (None, None, ''))
                transfers.append({'function': name, 'address': hex(va), 'bytes': row['bytes'], 'kind': kind,
                                  'target': as_hex(row['target']), 'slot': as_hex(slot),
                                  'relocation_type': as_hex(reltype),
                                  'relative_addend': as_hex(addend) if reltype == 8 else '', 'symbol': symbol})
    pins = []
    for name, va, expected, meaning in PINS:
        raw = image.read(va, len(bytes.fromhex(expected)), executable=True)
        pins.append({'name': name, 'address': hex(va), 'file_offset': hex(image.offset(va, len(raw), True)),
                     'bytes': raw.hex(), 'meaning': meaning})
    incoming = []
    for name, address, expected, meaning in PINS:
        if name.startswith('context_'):
            raw = image.read(address, len(bytes.fromhex(expected)), executable=True)
            decoded = decode_one(raw, 0, address)
            incoming.append({'name': name, 'address': hex(address), 'bytes': raw.hex(),
                             'target': as_hex(decoded['target']), 'meaning': meaning})
    if [r['target'] for r in incoming] != [hex(0x33e71c0), hex(0x33a7690), hex(0x2fd8bc0)]:
        raise ValueError('Caller context does not reach selected functions')
    datasets = (
        ('functions.tsv', ('name','start_va','end_va_exclusive','fde_va','file_offset','bytes','sha256','instructions','reached'), functions),
        ('instructions.tsv', ('function','address','bytes','kind','target','slot','reached'), instructions),
        ('branches.tsv', ('function','address','bytes','taken_target','fallthrough','seen_taken','seen_fallthrough'), branches),
        ('transfers.tsv', ('function','address','bytes','kind','target','slot','relocation_type','relative_addend','symbol'), transfers),
        ('pins.tsv', ('name','address','file_offset','bytes','meaning'), pins),
        ('incoming.tsv', ('name','address','bytes','target','meaning'), incoming),
        ('lifecycle-cases.tsv', ('active_epoch','initial_epochs','inserted_epoch','replaced','removed_epochs','final_epochs','disposed_validator_rows','final_height','visited_instructions'), lifecycle),
        ('clone-cases.tsv', ('case','height','validator_rows','nested_rows','source_nodes','copied_nodes','allocation_sizes','visited_instructions'), clones),
        ('insert-cases.tsv', ('old_count','position','replaced','height','new_count','pivot_key','left_count','right_count','allocations','visited_instructions'), insertions),
        ('unsigned-keys.tsv', ('key','replaced','result_count','visited_instructions'), unsigned_keys),
        ('deep-cases.tsv', ('child_index','leaf_position','height','new_count','root_pivot','allocations','visited_instructions'), deep),
        ('remove-cases.tsv', ('leaf_count','index','sibling_count','edge','choice','root_collapsed','remaining','height','visited_instructions'), removals),
        ('cascade-cases.tsv', ('active_edge','sibling_inner_count','leaf_index','collapsed','remaining','freed_nodes','visited_instructions'), cascades),
        ('internal-remove-cases.tsv', ('left_count','right_count','collapsed','remaining','visited_instructions'), internal_removals),
        ('iterator-cases.tsv', ('case','height','yielded','tree_nodes_freed','visited_instructions'), iterators),
        ('fault-cases.tsv', ('case','boundary_site','allocations_before_failure'), faults),
        ('mutation-cases.tsv', ('case','address','original','replacement','detected'), mutations),
    )
    for filename, fields, rows in datasets:
        table(out / filename, fields, rows)
    counts = {key: sum(1 for row in removals if row['choice'] == key)
              for key in ('root_leaf','no_repair','merge_left','merge_right','borrow_left','borrow_right')}
    summary = {'target_sha256': DIGEST, 'coordinate_system': 'ELF virtual addresses; exclusive FDE ends',
               'selected_functions': len(functions), 'fde_bytes': sum(f['bytes'] for f in functions),
               'decoded_instructions': len(instructions),
               'fixture_reached_instructions': sum(r['reached'] for r in instructions),
               'conditional_branches': len(branches),
               'branches_both_sides_seen': sum(r['seen_taken'] and r['seen_fallthrough'] for r in branches),
               'clone_cases': len(clones), 'insert_cases': len(insertions), 'unsigned_key_cases': len(unsigned_keys), 'deep_split_cases': len(deep),
               'remove_cases': len(removals), 'internal_remove_cases': len(internal_removals), 'cascade_remove_cases': len(cascades), 'removal_choices': counts, 'iterator_cases': len(iterators),
               'lifecycle_cases': len(lifecycle), 'failure_boundary_cases': len(faults), 'selected_mutations_detected': len(mutations),
               'limits': 'FDE ranges and bounded interpreted fixtures only; no target execution, runtime effects, Rust equivalence or whole-node denominator.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    image = Image(BINARY.read_bytes())
    print(json.dumps(generate(image, args.out), indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error, AssertionError, Halt, EvidenceError) as error:
        print('staking_epoch_snapshot94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)

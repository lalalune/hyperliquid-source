#!/usr/bin/env python3
"""Static node 94 evidence for pending-total B-tree leaf removal and repair.

No external programs or captured code are executed. The restricted instruction
length decoder is adapted from the MIT-licensed staking_validator_vote_prune94
research tool; it accepts opcode patterns, not disassembler output.
"""
import argparse
import csv
import hashlib
import io
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = ((0x2fc7e30, 'remove_leaf_repair'), (0x2fa4900, 'borrow_left'),
             (0x2fa8ed0, 'borrow_right'), (0x2fae7a0, 'merge_and_track'))
# Curated exact instruction witnesses: address, bytes, observed operation.
PINS = (
('cursor_node',0x2fc7e4c,'4c8b3e','load cursor node'),
('cursor_slot',0x2fc7e4f,'488b6e10','load cursor slot'),
('leaf_count',0x2fc7e53,'410fb79796010000','read occupied count'),
('key_times_five',0x2fc7e60,'488d44ad00','form five times slot'),
('key_base_scale',0x2fc7e65,'498dbc87b8000000','key base and scale four'),
('key_next',0x2fc7e91,'4881c6cc000000','key source at next element'),
('remaining',0x2fc7e98,'4989ed49f7d54901d5','old count minus slot minus one'),
('memmove_slot',0x2fc7ead,'488b1d2c627a02','load overlapping copy slot'),
('move_keys',0x2fc7eb4,'ffd3','move following keys left'),
('value_shift',0x2fc7ebe,'48c1e004','sixteen-byte value stride'),
('value_next',0x2fc7ed7,'4883c610','value source at next element'),
('value_count',0x2fc7edb,'49c1e504','remaining values times stride'),
('move_values',0x2fc7ee2,'ffd3','move following values left'),
('subtract_one',0x2fc7eec,'418d40ff','subtract one occupied row'),
('store_leaf_count',0x2fc7ef0,'6641898796010000','store occupied count'),
('leaf_minimum_cmp',0x2fc7efd,'6683f804','compare remaining to four'),
('leaf_minimum_branch',0x2fc7f01,'0f879c000000','above four bypasses repair'),
('parent_load',0x2fc7f07,'488b86b0000000','load parent'),
('parent_absent',0x2fc7f16,'0f8491000000','root bypasses sibling repair'),
('parent_edge',0x2fc7f22,'0fb79694010000','read parent edge'),
('edge_test',0x2fc7f29,'4885d2','test parent edge'),
('choose_right',0x2fc7f2c,'0f848a000000','edge zero selects right sibling'),
('left_length',0x2fc7f78,'0fb78696010000','read left sibling count'),
('left_sum',0x2fc7f7f,'4101c0','add pre-removal and sibling counts'),
('left_merge_limit',0x2fc7f82,'4183f80c','compare to twelve'),
('left_borrow_branch',0x2fc7f86,'0f83ac000000','at least twelve borrows from left'),
('right_merge_limit',0x2fc8017,'4183f80c','compare to twelve'),
('right_borrow_branch',0x2fc801b,'734c','at least twelve borrows from right'),
('merge_call',0x2fc8031,'e86a67feff','merge and preserve cursor'),
('left_one',0x2fc8043,'be01000000','initial left transfer count'),
('left_borrow_call',0x2fc804b,'e8b0c8fdff','borrow left'),
('right_one',0x2fc8077,'be01000000','initial right transfer count'),
('right_borrow_call',0x2fc807f,'e84c0efeff','borrow right'),
('repair_parent',0x2fc80a7,'4c8bb6b0000000','load next parent'),
('repair_minimum_cmp',0x2fc80ca,'6683f804','compare parent count to four'),
('repair_repeat_branch',0x2fc80ce,'7657','at most four repeats repair'),
('repair_top',0x2fc816f,'0f8488040000','no grandparent checks root'),
('repair_edge_zero',0x2fc818c,'0f848e000000','zero edge chooses right'),
('repair_left_sum',0x2fc81dd,'428d1438','sum parent and left sibling'),
('repair_left_sep',0x2fc81e1,'ffc2','include separator'),
('repair_left_cmp',0x2fc81e3,'83fa0c','compare merged size to twelve'),
('repair_left_borrow',0x2fc81e6,'0f8327040000','large combined row borrows left'),
('empty_internal',0x2fc822b,'0f842f040000','empty internal parent failure'),
('repair_right_sum',0x2fc827c,'4a8d3400','sum parent and right sibling'),
('repair_right_sep',0x2fc8280,'48ffc6','include separator'),
('repair_right_cmp',0x2fc8283,'4883fe0c','compare merged size to twelve'),
('repair_right_borrow',0x2fc8287,'0f83a0030000','large combined row borrows right'),
('merge_parent_count',0x2fc84ba,'6641ff8e96010000','decrement parent count'),
('free_leaf_bytes',0x2fc84c2,'be98010000','leaf node free size'),
('free_internal_branch',0x2fc84d0,'0f826afcffff','height decides node free size'),
('free_internal_bytes',0x2fc8558,'bef8010000','internal node free size'),
('nonempty_root',0x2fc8600,'0f85cafaffff','nonempty root returns'),
('root_empty_flag',0x2fc860b,'c60001','set caller flag for empty root'),
('up_left_target',0x2fc8613,'be05000000','target five occupied rows'),
('up_left_need',0x2fc8618,'4829c6','subtract current row count'),
('up_left_call',0x2fc8623,'e8d8c2fdff','borrow enough from left'),
('up_right_target',0x2fc862d,'be05000000','target five occupied rows'),
('up_right_need',0x2fc8632,'4829c6','subtract current row count'),
('up_right_call',0x2fc863d,'e88e08feff','borrow enough from right'),
('left_dest_len',0x2fa4912,'0fb7ab96010000','left borrow destination count'),
('left_dest_add',0x2fa4919,'488d042e','destination plus count'),
('left_dest_cmp',0x2fa491d,'4883f80c','destination capacity threshold'),
('left_dest_fail',0x2fa4921,'0f83d6020000','capacity violation panics'),
('left_source_sub',0x2fa4933,'4d89f44929f4','source subtracts count'),
('left_source_fail',0x2fa4939,'0f82d7020000','source underflow panics'),
('left_source_store',0x2fa4944,'664589a596010000','store source count'),
('left_dest_store',0x2fa4951,'66898396010000','store destination count'),
('left_height',0x2fa4aa2,'4983782000','test left child height'),
('left_height_zero',0x2fa4aab,'746e','height zero path'),
('left_height_mismatch',0x2fa4ab0,'7472','one zero child height and one nonzero fails'),
('right_dest_len',0x2fa8ee2,'450fb78e96010000','right borrow destination count'),
('right_dest_add',0x2fa8eea,'4a8d040e','destination plus count'),
('right_dest_cmp',0x2fa8eee,'4883f80c','destination capacity threshold'),
('right_dest_fail',0x2fa8ef2,'0f8345030000','capacity violation panics'),
('right_source_sub',0x2fa8f07,'4929f0','source subtracts count'),
('right_source_fail',0x2fa8f0a,'0f8246030000','source underflow panics'),
('right_dest_store',0x2fa8f10,'6641898696010000','store destination count'),
('right_source_store',0x2fa8f18,'6644898396010000','store source count'),
('right_height',0x2fa9056,'49837f2000','test right child height'),
('right_height_zero',0x2fa905f,'0f84ff000000','height zero path'),
('right_height_mismatch',0x2fa9068,'0f84ff000000','one zero child height and one nonzero fails'),
('merge_left_count',0x2fae7b5,'410fb7ae96010000','read left count'),
('merge_flag',0x2fae7c0,'f6c201','select tracked edge side'),
('merge_flag_branch',0x2fae7c3,'740b','select left bound on zero bit'),
('merge_cursor_cmp',0x2fae7d0,'4839c1','compare tracked edge and selected length'),
('merge_cursor_fail',0x2fae7d3,'0f87c4030000','out-of-bounds cursor panics'),
('merge_sum',0x2fae7e4,'4c8d042b','left plus right count'),
('merge_separator',0x2fae7e8,'49ffc0','add one separator'),
('merge_cmp',0x2fae7eb,'4983f80c','merged capacity threshold'),
('merge_capacity_fail',0x2fae7ef,'0f83c1030000','over capacity panics'),
('merge_count_store',0x2fae83e,'6645898696010000','store merged count'),
('merge_parent_dec',0x2faea3a,'6641ff8c2496010000','decrement parent count'),
('merge_leaf_size',0x2faea43,'be98010000','leaf node free size'),
('merge_inner_size',0x2faeae1,'bef8010000','internal node free size'),
('merge_cursor_flag',0x2faeb68,'f644244801','select right tracked edge'),
('merge_cursor_bias',0x2faeb6d,'490f45dc','use left count plus one on right'),
('merge_cursor_add',0x2faeb71,'48035c2450','add tracked edge index'),
('left_source_value',0x2fa4a2d,'430f10442500','load left source value'),
('left_source_key',0x2fa4a53,'410f108c85b8000000','load left source key'),
('left_key_to_parent',0x2fa4a5c,'0f118cb1b8000000','write left source key to parent'),
('left_value_to_parent',0x2fa4a81,'0f110411','write left source value to parent'),
('left_parent_to_dest',0x2fa4a98,'410f11040f','write old parent key to destination'),
('right_source_value',0x2fa8f3f,'420f104423f0','load right source value'),
('right_source_key',0x2fa8f68,'0f108c2ba4000000','load right source key'),
('right_key_to_parent',0x2fa8f77,'0f118c90b8000000','write right source key to parent'),
('right_value_to_parent',0x2fa8fb3,'420f110410','write right source value to parent'),
('right_parent_to_dest',0x2fa8fd3,'410f118486b8000000','write old parent key to destination'),
('merge_separator_key',0x2fae8a5,'410f118486b8000000','append parent separator key to left node'),
('merge_append_keys',0x2fae8e8,'ff15f2f67b02','copy right node keys after separator'),
('merge_separator_value',0x2fae925,'410f11042e','append parent separator value to left node'),
('merge_child_parent',0x2faeac4,'4c89b2b0000000','write child parent pointer'),
('merge_child_index',0x2faeacf,'6689b294010000','write child parent edge'),
('left_shift_edges',0x2fa4ad9,'ff1501967c02','shift right child edge array'),
('left_copy_edges',0x2fa4afa,'ff15e0947c02','copy left child edges to right'),
('left_write_parent',0x2fa4b58,'48899eb0000000','write right child parent'),
('left_write_index',0x2fa4b61,'66898e94010000','write right child edge index'),
('right_copy_edges',0x2fa9095,'ff15454f7c02','copy right child edges to left'),
('right_shift_edges',0x2fa90b1,'ff1529507c02','compact right child edges'),
('right_write_parent',0x2fa90c4,'4c89b0b0000000','write moved child parent'),
('right_write_index',0x2fa90cb,'6689a894010000','write moved child edge index'),
('right_reindex_parent',0x2fa9198,'48899eb0000000','write right child parent'),
('right_reindex_edge',0x2fa91a1,'66898e94010000','write right child edge index'),
('merge_append_edges',0x2faea96,'ff1544f57b02','copy right edges after left edges'),
('caller_predecessor_args',0x2fd8fc1,'4889e7488d742478','predecessor path sets result and cursor arguments'),
('caller_leaf_args',0x2fd90c5,'488d7424604889df','leaf path sets result and cursor arguments'),
('caller_predecessor',0x2fd8fc9,'e862eefeff','predecessor leaf invokes repair'),
('caller_leaf',0x2fd90cd,'e85eedfeff','leaf cursor invokes repair'),
)

class Image:
    def __init__(self, data, authenticate=True):
        if authenticate and hashlib.sha256(data).hexdigest() != DIGEST:
            raise ValueError('node 94 SHA-256 mismatch')
        self.data = data
        self.sections = sections(data)
        _, fdes = eh_frame_records(data, self.sections)
        self.fdes = {}
        for f in fdes:
            if f['start'] in self.fdes:
                raise ValueError('duplicate FDE start')
            self.fdes[f['start']] = f

    def offset(self, va, size=1):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
            raise ValueError('invalid address range')
        found = [s['offset'] + va - s['address'] for s in self.sections
                 if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(found) != 1 or found[0] + size > len(self.data):
            raise ValueError('range lacks one file-backed section')
        return found[0]

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def integer(self, va, size, signed=False):
        return int.from_bytes(self.read(va, size), 'little', signed=signed)

    def rip(self, va, prefix):
        p = bytes.fromhex(prefix)
        if self.read(va, len(p)) != p:
            raise ValueError('unexpected RIP-relative operand')
        return va + len(p) + 4 + self.integer(va + len(p), 4, True)

    def validate(self):
        for name, va, expected, _ in PINS:
            if self.read(va, len(bytes.fromhex(expected))).hex() != expected:
                raise ValueError('byte witness mismatch: ' + name)
        for va, _ in FUNCTIONS:
            if va not in self.fdes or self.fdes[va]['end'] <= va:
                raise ValueError('missing FDE')
            end = self.fdes[va]['end']
            matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 4
                       and s['address'] <= va < end <= s['address'] + s['size']]
            if len(matches) != 1:
                raise ValueError('FDE is not fully file-backed executable')
            self.offset(va, end-va)

class Overlay(Image):
    def __init__(self, image, va, replacement):
        image.offset(va, len(replacement))
        self.__dict__.update(image.__dict__)
        self.original, self.va, self.replacement = image, va, bytes(replacement)

    def read(self, va, size):
        out = bytearray(self.original.read(va, size))
        lo, hi = max(va, self.va), min(va+size, self.va+len(self.replacement))
        if lo < hi:
            out[lo-va:hi-va] = self.replacement[lo-self.va:hi-self.va]
        return bytes(out)


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



def layout(image):
    """Derive the node layout only after the exact witness patterns match."""
    for name, va, expected, _ in PINS:
        if image.read(va, len(bytes.fromhex(expected))).hex() != expected:
            raise ValueError('byte witness mismatch: ' + name)
    return {
        'keys_offset': image.integer(0x2fc7e69, 4),
        'key_stride': 5 * 4,  # witnessed index*5 followed by address scale 4
        'value_offset': 0,
        'value_stride': 1 << image.integer(0x2fc7ec1, 1),
        'parent_offset': image.integer(0x2fc7f0a, 4),
        'parent_edge_offset': image.integer(0x2fc7f25, 4),
        'count_offset': image.integer(0x2fc7e57, 4),
        'child_offset': image.integer(0x2fa4ab5, 4),
        'capacity': image.integer(0x2fc7f85, 1) - 1,
        'minimum_nonroot': image.integer(0x2fc7f00, 1) + 1,
        'leaf_allocation': image.integer(0x2fc84c3, 4),
        'inner_allocation': image.integer(0x2fc8559, 4),
    }


def branch_kind(image, site):
    """Only the x86 unsigned above/above-or-equal/below-or-equal cases used here."""
    first = image.integer(site, 1)
    cc = image.integer(site+1, 1) if first == 0x0f else first
    if first == 0x0f and not 0x80 <= cc <= 0x8f:
        raise ValueError('unsupported conditional')
    if first != 0x0f and not 0x70 <= cc <= 0x7f:
        raise ValueError('unsupported conditional')
    cc &= 0xf
    if cc not in (3, 6, 7):
        raise ValueError('unsupported condition code')
    return cc


def taken(cc, a, b):
    return {3: a >= b, 6: a <= b, 7: a > b}[cc]


def choose_repair(image, old, sibling, edge, parent):
    # Compare the captured condition codes, then independently compare the
    # results to a direct occupancy model in the generated cases.
    threshold = image.integer(0x2fc7f00, 1)
    maximum = image.integer(0x2fc7f85, 1) - 1
    if not 1 <= old <= maximum or not 0 <= sibling <= maximum or edge not in (0, 1) or type(parent) is not bool:
        raise ValueError('invalid fixture')
    if taken(branch_kind(image, 0x2fc7f01), old-1, threshold):
        return 'no_repair'
    if not parent:
        return 'root'
    branch = 0x2fc801b if edge == 0 else 0x2fc7f86
    limit = image.integer(0x2fc801a if edge == 0 else 0x2fc7f85, 1)
    direction = 'right' if edge == 0 else 'left'
    return ('borrow_' if taken(branch_kind(image, branch), old+sibling, limit) else 'merge_') + direction


def upward_repair(image, current, sibling, edge, parent):
    limit = image.integer(0x2fc81e5, 1)
    minimum = image.integer(0x2fc8614, 4)
    if not (0 <= current < minimum and 0 <= sibling < limit and edge in (0, 1) and type(parent) is bool):
        raise ValueError('invalid upward fixture')
    if not parent:
        return ('empty_root' if current == 0 else 'nonempty_root', 0)
    site = 0x2fc8287 if edge == 0 else 0x2fc81e6
    direction = 'right' if edge == 0 else 'left'
    if taken(branch_kind(image, site), current + sibling + 1, limit):
        return ('borrow_' + direction, minimum-current)
    return ('merge_' + direction, 0)


def leaf_projection(image, node, slot):
    geom = layout(image)
    ks, vs = geom['key_stride'], geom['value_stride']
    kb, vb, no = geom['keys_offset'], geom['value_offset'], geom['count_offset']
    if len(node) != geom['leaf_allocation']:
        raise ValueError('invalid leaf allocation')
    n = struct.unpack_from('<H', node, no)[0]
    if not 1 <= n <= geom['capacity'] or not 0 <= slot < n:
        raise ValueError('invalid occupied slot')
    out = bytearray(node)
    key, value = bytes(node[kb+slot*ks:kb+(slot+1)*ks]), bytes(node[vb+slot*vs:vb+(slot+1)*vs])
    for base, size in ((kb, ks), (vb, vs)):
        out[base+slot*size:base+(n-1)*size] = node[base+(slot+1)*size:base+n*size]
    struct.pack_into('<H', out, no, n-1)
    return bytes(out), key, value


def merge_cursor(image, left, right, side, cursor):
    capacity = image.integer(0x2fae7ee, 1)-1
    if not (0 <= left <= capacity and 0 <= right <= capacity and type(side) is int and 0 <= side <= 255 and cursor >= 0):
        raise ValueError('invalid fixture')
    bound = right if side & 1 else left
    if taken(branch_kind(image, 0x2fae7d3), cursor, bound):
        return 'cursor_failure', None
    if taken(branch_kind(image, 0x2fae7ef), left+1+right, capacity+1):
        return 'capacity_failure', None
    # The conditional move at merge_cursor_bias is validated by layout().
    layout(image)
    return 'merged', cursor + (left+1 if side & 1 else 0)


def borrow_guard(image, dest, source, count, side):
    cap = image.integer(0x2fa4920 if side == 'left' else 0x2fa8ef1, 1)-1
    if side not in ('left', 'right') or not all(0 <= x <= cap for x in (dest, source, count)):
        raise ValueError('invalid fixture')
    dest_branch = 0x2fa4921 if side == 'left' else 0x2fa8ef2
    source_branch = 0x2fa4939 if side == 'left' else 0x2fa8f0a
    if taken(branch_kind(image, dest_branch), dest+count, cap+1):
        return 'capacity_failure'
    # borrow check is unsigned below; decode the actual condition nibble.
    raw = image.read(source_branch, 2)
    if raw != b'\x0f\x82':
        raise ValueError('unexpected unsigned borrow branch')
    if source < count:
        return 'source_failure'
    return 'guards_pass'


def fixture_node(geometry, rows):
    """Deterministic synthetic leaf; keys and values remain unique by row ID."""
    if len(rows) > geometry['capacity']:
        raise ValueError('fixture node over capacity')
    node = bytearray((i*37+9) & 255 for i in range(geometry['leaf_allocation']))
    for i, row in enumerate(rows):
        k = row.to_bytes(geometry['key_stride'], 'big')
        v = struct.pack('<QQ', row, row ^ 0xffffffffffffffff)
        base = geometry['keys_offset'] + i*geometry['key_stride']
        node[base:base+geometry['key_stride']] = k
        base = geometry['value_offset'] + i*geometry['value_stride']
        node[base:base+geometry['value_stride']] = v
    struct.pack_into('<H', node, geometry['count_offset'], len(rows))
    return bytes(node)


def pairs(geometry, node):
    if len(node) != geometry['leaf_allocation']:
        raise ValueError('invalid synthetic node')
    n = struct.unpack_from('<H', node, geometry['count_offset'])[0]
    if n > geometry['capacity']:
        raise ValueError('invalid synthetic count')
    k, ks, v, vs = (geometry[x] for x in ('keys_offset','key_stride','value_offset','value_stride'))
    return [(bytes(node[k+i*ks:k+(i+1)*ks]), bytes(node[v+i*vs:v+(i+1)*vs])) for i in range(n)]


def write_pairs(geometry, node, rows):
    out = bytearray(node)
    if len(rows) > geometry['capacity']:
        raise ValueError('too many projected rows')
    for i, (key, val) in enumerate(rows):
        if len(key) != geometry['key_stride'] or len(val) != geometry['value_stride']:
            raise ValueError('invalid row widths')
        k = geometry['keys_offset'] + i*geometry['key_stride']
        v = geometry['value_offset'] + i*geometry['value_stride']
        out[k:k+len(key)] = key
        out[v:v+len(val)] = val
    struct.pack_into('<H', out, geometry['count_offset'], len(rows))
    return bytes(out)


def transfer_projection(image, left, parent, right, operation, count=1):
    """Project paired key/value rows only; no child edges or target execution."""
    geometry = layout(image)
    left_rows, parent_rows, right_rows = (pairs(geometry, n) for n in (left,parent,right))
    if len(parent_rows) != 1:
        raise ValueError('fixture requires one separator')
    if operation == 'merge':
        if len(left_rows) + len(right_rows) + 1 > geometry['capacity']:
            raise ValueError('merge capacity')
        new_l = left_rows + parent_rows + right_rows
        new_p, new_r, freed = [], right_rows, True
    elif operation == 'borrow_left':
        if count <= 0 or borrow_guard(image, len(right_rows), len(left_rows), count, 'left') != 'guards_pass':
            raise ValueError('left borrow guards')
        split = len(left_rows)-count
        new_l, new_p = left_rows[:split], [left_rows[split]]
        new_r = left_rows[split+1:] + parent_rows + right_rows
        freed = False
    elif operation == 'borrow_right':
        if count <= 0 or borrow_guard(image, len(left_rows), len(right_rows), count, 'right') != 'guards_pass':
            raise ValueError('right borrow guards')
        new_l = left_rows + parent_rows + right_rows[:count-1]
        new_p, new_r, freed = [right_rows[count-1]], right_rows[count:], False
    else:
        raise ValueError('unknown operation')
    return (write_pairs(geometry,left,new_l), write_pairs(geometry,parent,new_p),
            write_pairs(geometry,right,new_r), freed)


def child_projection(image, left, right, operation, count=1):
    """Project child IDs and parent-edge indices, not target pointer execution."""
    geom = layout(image)
    if not left or not right or len(left) > geom['capacity']+1 or len(right) > geom['capacity']+1:
        raise ValueError('invalid child arrays')
    if len(set(left+right)) != len(left)+len(right):
        raise ValueError('duplicate child IDs')
    nl, nr = len(left)-1, len(right)-1
    if operation == 'merge':
        if nl+nr+1 > geom['capacity']:
            raise ValueError('merge capacity')
        new_l, new_r = left+right, []
    elif operation == 'borrow_left':
        if count <= 0 or borrow_guard(image,nr,nl,count,'left') != 'guards_pass':
            raise ValueError('left borrow guards')
        new_l, new_r = left[:-count], left[-count:]+right
    elif operation == 'borrow_right':
        if count <= 0 or borrow_guard(image,nl,nr,count,'right') != 'guards_pass':
            raise ValueError('right borrow guards')
        new_l, new_r = left+right[:count], right[count:]
    else:
        raise ValueError('unknown operation')
    links = [(child, 'left', i) for i,child in enumerate(new_l)]
    links += [(child, 'right', i) for i,child in enumerate(new_r)]
    return new_l, new_r, links


def relocs(image):
    ss = [s for s in image.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(ss) != 1 or ss[0]['size'] % 24:
        raise ValueError('bad RELA table')
    section = ss[0]
    out = {}
    for pos in range(section['offset'], section['offset'] + section['size'], 24):
        va, info, addend = struct.unpack_from('<QQq', image.data, pos)
        if info == 8:
            if va in out:
                raise ValueError('duplicate relative relocation')
            out[va] = addend
    return out


def scan_raw_e8(image, destinations):
    """Report raw rel32 byte-pattern candidates, not a call-site census."""
    rows = [s for s in image.sections if s['name'] == '.text' and s['type'] != 8 and s['flags'] & 4]
    if len(rows) != 1:
        raise ValueError('missing unique executable text')
    sec = rows[0]
    raw = image.read(sec['address'], sec['size'])
    targets = set(destinations)
    found = []
    pos = 0
    while True:
        pos = raw.find(b'\xe8', pos)
        if pos < 0:
            break
        if pos + 5 <= len(raw):
            va = sec['address']+pos
            target = va+5+struct.unpack_from('<i',raw,pos+1)[0]
            if target in targets:
                found.append(dict(site=hex(va), file_offset=hex(image.offset(va)),
                                  bytes=raw[pos:pos+5].hex(), target=hex(target)))
        pos += 1
    return found


def import_symbols(image):
    selected = {}
    for name in ('.rela.dyn', '.dynsym', '.dynstr'):
        rows = [s for s in image.sections if s['name'] == name and s['type'] != 8]
        if len(rows) != 1:
            raise ValueError('missing dynamic section')
        selected[name] = rows[0]
    rela, sym, strings = (selected[n] for n in ('.rela.dyn', '.dynsym', '.dynstr'))
    if rela['size'] % 24 or sym['size'] % 24:
        raise ValueError('invalid dynamic records')
    table = image.read(strings['address'], strings['size'])
    result = {}
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, _ = struct.unpack_from('<QQq', image.data, pos)
        if info & 0xffffffff != 6:
            continue
        index = info >> 32
        if (index+1)*24 > sym['size']:
            raise ValueError('symbol index outside table')
        name_offset = image.integer(sym['address'] + index*24, 4)
        if name_offset >= len(table):
            raise ValueError('name outside dynamic string table')
        end = table.find(b'\0', name_offset)
        if end < 0 or slot in result:
            raise ValueError('invalid dynamic symbol')
        result[slot] = table[name_offset:end].decode('ascii')
    return result

REGISTER_CALLS = (
    (0x2fc7ead, '488b1d', 'ffd3', (0x2fc7eb4, 0x2fc7ee2)),
    (0x2fc8309, '488b05', 'ffd0', (0x2fc8310,)),
    (0x2fa497b, '4c8b3d', '41ffd7', (0x2fa498a, 0x2fa49a6)),
    (0x2fa9032, '488b2d', 'ffd5', (0x2fa9043, 0x2fa9054)),
)


def tsv(rows, fields):
    result = io.StringIO(newline='')
    w = csv.DictWriter(result, fields, delimiter='\t', lineterminator='\n')
    w.writeheader()
    w.writerows(rows)
    return result.getvalue().encode()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


FAILURES = (
    ('repair_child_count', 0x2fc8647, 0x2fc8656, False),
    ('empty_internal', 0x2fc8660, 0x2fc866f, True),
    ('borrow_left_child_height', 0x2fa4b24, 0x2fa4b33, False),
    ('borrow_left_capacity', 0x2fa4bfd, 0x2fa4c0c, False),
    ('borrow_left_count', 0x2fa4c16, 0x2fa4c25, False),
    ('borrow_left_copy_length', 0x2fa4c2f, 0x2fa4c3e, False),
    ('borrow_right_child_height', 0x2fa916d, 0x2fa917c, False),
    ('borrow_right_capacity', 0x2fa923d, 0x2fa924c, False),
    ('borrow_right_count', 0x2fa9256, 0x2fa9265, False),
    ('merge_cursor', 0x2faeb9d, 0x2faebac, False),
    ('merge_capacity', 0x2faebb6, 0x2faebc5, False),
    ('merge_child_count', 0x2faebcf, 0x2faebde, False),
)


def failure_rows(image):
    result = []
    for name, site, length, packed in FAILURES:
        text_va = image.rip(site, '488d3d')
        if image.integer(length-1, 1) != 0xbe:
            raise ValueError('unexpected failure length operand')
        arg = image.integer(length, 4)
        if packed and not arg & 1:
            raise ValueError('bad packed literal')
        n = arg >> 1 if packed else arg
        text = image.read(text_va, n).decode('ascii')
        result.append(dict(name=name, site=hex(site), text_va=hex(text_va), raw_argument=arg,
                           encoding='packed_literal' if packed else 'length', text=text))
    return result


def generate(image):
    image.validate()
    geom = layout(image)
    rel = relocs(image)
    imports = import_symbols(image)
    funcs, instructions, transfers, pins = [], [], [], []
    for start, name in FUNCTIONS:
        f = image.fdes[start]
        raw = image.read(start, f['end']-start)
        rows = decode_function(image, start)
        funcs.append(dict(name=name, start=hex(start), end=hex(f['end']), fde=hex(f['fde']),
                          file_offset=hex(image.offset(start)), size=len(raw),
                          sha256=hashlib.sha256(raw).hexdigest(), instruction_count=len(rows)))
        for row in rows:
            target = row['target']
            slot = row['slot']
            r = dict(function=name, address=hex(row['address']), size=row['size'], bytes=row['bytes'],
                     kind=row['kind'], target='' if target is None else hex(target),
                     slot='' if slot is None else hex(slot),
                     relative_target='' if slot not in rel else hex(rel[slot]),
                     import_symbol=imports.get(slot, ''))
            instructions.append(r)
            if row['kind'] != 'plain':
                transfers.append(r)
    for name, va, expected, note in PINS:
        actual = image.read(va, len(bytes.fromhex(expected))).hex()
        pins.append(dict(name=name, va=hex(va), file_offset=hex(image.offset(va)), bytes=actual, observation=note))
    candidates = scan_raw_e8(image, [va for va, _ in FUNCTIONS])
    in_window_calls = {r['address'] for r in transfers if r['kind'] == 'call' and
                       r['target'] in {hex(va) for va, _ in FUNCTIONS}}
    expected_candidates = in_window_calls | {hex(0x2fd8fc9), hex(0x2fd90cd)}
    if {r['site'] for r in candidates} != expected_candidates:
        raise ValueError('raw call candidates do not match reviewed call sites')
    calls = []
    for site in (0x2fd8fc9, 0x2fd90cd):
        raw = image.read(site, 5)
        if raw[0] != 0xe8:
            raise ValueError('caller is not a rel32 call')
        target = site + 5 + struct.unpack_from('<i', raw, 1)[0]
        if target != FUNCTIONS[0][0]:
            raise ValueError('caller target changed')
        calls.append(dict(call_site=hex(site), file_offset=hex(image.offset(site)), bytes=raw.hex(), target=hex(target)))
    register_calls = []
    for load, prefix, call_bytes, sites in REGISTER_CALLS:
        slot = image.rip(load, prefix)
        for site in sites:
            insn = next((r for r in instructions if r['address'] == hex(site)), None)
            if insn is None or insn['kind'] != 'indirect_call' or insn['bytes'] != call_bytes:
                raise ValueError('register call differs from reviewed data flow')
            if imports.get(slot) != 'memmove':
                raise ValueError('unexpected register call slot symbol')
            register_calls.append(dict(load=hex(load), call=hex(site), slot=hex(slot), symbol=imports.get(slot, '')))
    choices = []
    for old in range(1, geom['capacity']+1):
        for sibling, edge, parent in [(0, 0, False)] + [(n,e,True) for n in range(geom['capacity']+1) for e in (0,1)]:
            actual = choose_repair(image, old, sibling, edge, parent)
            expected = ('no_repair' if old-1 >= geom['minimum_nonroot'] else 'root' if not parent
                        else ('borrow_' if old+sibling >= geom['capacity']+1 else 'merge_') + ('right' if edge == 0 else 'left'))
            if actual != expected:
                raise ValueError('initial repair rule mismatch')
            choices.append(dict(old_length=old, sibling_length=sibling, parent_edge=edge, has_parent=int(parent), decision=actual))
    upwards = []
    for current in range(geom['minimum_nonroot']):
        for sibling, edge, parent in [(0,0,False)] + [(n,e,True) for n in range(geom['capacity']+1) for e in (0,1)]:
            decision, amount = upward_repair(image, current, sibling, edge, parent)
            expected = ('empty_root' if current == 0 else 'nonempty_root') if not parent else (('borrow_' if current+sibling+1 >= geom['capacity']+1 else 'merge_') + ('right' if edge == 0 else 'left'))
            if decision != expected or amount != (geom['minimum_nonroot']-current if decision.startswith('borrow_') else 0):
                raise ValueError('upward repair rule mismatch')
            upwards.append(dict(current_length=current, sibling_length=sibling, parent_edge=edge, has_parent=int(parent), decision=decision, count=amount))
    leaves = []
    for n in range(1, geom['capacity']+1):
        for slot in range(n):
            node = bytearray((i*29+17) & 0xff for i in range(geom['leaf_allocation']))
            struct.pack_into('<H', node, geom['count_offset'], n)
            out, key, value = leaf_projection(image, node, slot)
            leaves.append(dict(length=n, slot=slot, removed_key=key.hex(), removed_value=value.hex(),
                               input_sha256=hashlib.sha256(node).hexdigest(), output_sha256=hashlib.sha256(out).hexdigest()))
    cursors = []
    cap = geom['capacity']
    for left in range(cap+1):
        for right in range(cap+1):
            for side in (0,1):
                for cursor in range((right if side else left)+2):
                    outcome, index = merge_cursor(image, left, right, side, cursor)
                    cursors.append(dict(left_length=left, right_length=right, side=side, input_edge=cursor,
                                        outcome=outcome, output_edge='' if index is None else index))
    transfers_cases = []
    children_cases = []
    for left_n in range(cap+1):
        for right_n in range(cap+1):
            left = fixture_node(geom, range(left_n))
            parent = fixture_node(geom, (left_n,))
            right = fixture_node(geom, range(left_n+1, left_n+1+right_n))
            before = pairs(geom,left) + pairs(geom,parent) + pairs(geom,right)
            operations = []
            if left_n + right_n + 1 <= cap:
                operations.append(('merge',1))
            for count in range(1,cap+1):
                if left_n >= count and right_n + count <= cap:
                    operations.append(('borrow_left',count))
                if right_n >= count and left_n + count <= cap:
                    operations.append(('borrow_right',count))
            for operation, count in operations:
                a, b, c, freed = transfer_projection(image,left,parent,right,operation,count)
                after = pairs(geom,a) + pairs(geom,b) + ([] if freed else pairs(geom,c))
                if after != before:
                    raise ValueError('paired row order not preserved')
                digest = hashlib.sha256(a+b+(b'' if freed else c)).hexdigest()
                left_edges = list(range(left_n+1))
                right_edges = list(range(left_n+1,left_n+right_n+2))
                l_edges, r_edges, links = child_projection(image,left_edges,right_edges,operation,count)
                if l_edges+r_edges != left_edges+right_edges or len(links) != len(left_edges)+len(right_edges):
                    raise ValueError('child order not preserved')
                children_cases.append(dict(operation=operation,left_length=left_n,right_length=right_n,
                                           count=count,left_children=len(l_edges),right_children=len(r_edges),
                                           links_sha256=hashlib.sha256(json_bytes(links)).hexdigest()))
                transfers_cases.append(dict(operation=operation,left_length=left_n,right_length=right_n,
                                            count=count,freed_right=int(freed),output_sha256=digest))
    guards = []
    for side in ('left','right'):
        for dest in range(cap+1):
            for source in range(cap+1):
                for count in range(1,cap+1):
                    guards.append(dict(direction=side, destination=dest, source=source, count=count,
                                       outcome=borrow_guard(image,dest,source,count,side)))
    files = {
        'functions.tsv': tsv(funcs, ('name','start','end','fde','file_offset','size','sha256','instruction_count')),
        'instructions.tsv': tsv(instructions, ('function','address','size','bytes','kind','target','slot','relative_target','import_symbol')),
        'transfers.tsv': tsv(transfers, ('function','address','size','bytes','kind','target','slot','relative_target','import_symbol')),
        'witnesses.tsv': tsv(pins, ('name','va','file_offset','bytes','observation')),
        'register-calls.tsv': tsv(register_calls, ('load','call','slot','symbol')),
        'direct-candidates.tsv': tsv(candidates, ('site','file_offset','bytes','target')),
        'incoming.tsv': tsv(calls, ('call_site','file_offset','bytes','target')),
        'failures.tsv': tsv(failure_rows(image), ('name','site','text_va','raw_argument','encoding','text')),
        'repair-cases.tsv': tsv(choices, ('old_length','sibling_length','parent_edge','has_parent','decision')),
        'upward-cases.tsv': tsv(upwards, ('current_length','sibling_length','parent_edge','has_parent','decision','count')),
        'leaf-cases.tsv': tsv(leaves, ('length','slot','removed_key','removed_value','input_sha256','output_sha256')),
        'merge-cursors.tsv': tsv(cursors, ('left_length','right_length','side','input_edge','outcome','output_edge')),
        'child-cases.tsv': tsv(children_cases, ('operation','left_length','right_length','count','left_children','right_children','links_sha256')),
        'transfer-cases.tsv': tsv(transfers_cases, ('operation','left_length','right_length','count','freed_right','output_sha256')),
        'borrow-guards.tsv': tsv(guards, ('direction','destination','source','count','outcome')),
    }
    summary = dict(target_sha256=DIGEST, coordinate_system='ELF virtual address', layout=geom,
                   function_count=len(funcs), instruction_count=len(instructions), transfer_count=len(transfers),
                   witnesses=len(pins), raw_e8_candidates=len(candidates), register_calls=len(register_calls), incoming_calls=len(calls), failure_sites=len(FAILURES),
                   transfer_cases=len(transfers_cases), child_cases=len(children_cases), repair_cases=len(choices), upward_cases=len(upwards), leaf_cases=len(leaves), merge_cursor_cases=len(cursors), borrow_guard_cases=len(guards),
                   scope='Static witnesses and local projections only; no node execution, no full B-tree evaluator.')
    files['summary.json'] = json_bytes(summary)
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    image = Image(BINARY.read_bytes())
    files = generate(image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (args.out / name).write_bytes(data)
    print('Generated %d evidence files.' % len(files))

if __name__ == '__main__':
    main()

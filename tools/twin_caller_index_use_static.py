#!/usr/bin/env python3
"""Static trace of what the four node-115 insert-order callers do with
the slab slot index the RE-006 ring-append twins return.

The twins 0x5911890 / 0x5911b30 (RE-006 book ring append, packet
RE-006-node115-book-ring-append) return the result of the shared
insert routines 0x58df360 / 0x58df790: the pre-insert slab head, i.e.
the index of the slab slot that received the order copy (packet
RE-006-node115-shared-insert-return).  A whole-.text census finds
exactly four direct E8 call sites into the twins, in four distinct
insert-order FDE bodies.  This packet traces, for each caller, every
use of the returned value from the call site to the capture
register's first reassignment:

- the value is captured into a callee-saved register (r15 in the
  A-side callers, r12 in the B-side callers);
- it is forwarded as the rcx (fourth) argument of a direct call to
  0x4eeed90, from the rax copy, before that register is clobbered;
- it is forwarded again as the rsi (second) argument of a direct
  call to 0x51d1b00, whose first argument is a lookup result plus
  0x40;
- it is never stored to memory -- neither to a heap structure nor
  to a frame slot -- and never pushed, anywhere in that window;
- the capture register is then reassigned and holds other values
  for the rest of the body.

In the two B-side callers one further read of the capture register
exists in address order inside the window: a test plus a guarded
call through slot 0x64df4a0 in a block whose only direct branch
predecessor precedes the twin call site, so the register there
holds that arm's own value, not the returned index; the block is
pinned and the exclusion is checked, not assumed.

So at this level the forwarded index is insert-path-local: the
callers turn it into no durable handle themselves.  Any durable
use would have to be created inside the two boundary callees.
This tool authenticates the whole capture, pins those facts in
bytes, and regenerates the packet.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-006-node115-twin-caller-index-use'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

TWINS = {
    'ring_append_a': {
        'range': (0x5911890, 0x5911B27),
        'sha256': '08e8b4239e731ee50d74c945e5fe6ae3f8e18d12a5ee8c6ab8725363260558b6',
    },
    'ring_append_b': {
        'range': (0x5911B30, 0x5911DC7),
        'sha256': 'cecc9282e700d4433aa077e63b65b50eaa287b16d6de32964b7bbb743f5b3223',
    },
}

FWD1_TARGET = 0x4EEED90
FWD2_TARGET = 0x51D1B00
EXCLUDED_SLOT = 0x64DF4A0
EXCLUDED_SLOT_TARGET = 0x635DE30

# Per-caller pinned sites.  'exact' maps a site name to its exact
# instruction bytes; 'calls' maps a site name to the callee a direct
# E8 at that site must resolve to.  Every site is additionally
# required to be a native instruction start in the decoded body.
CALLERS = {
    'caller_1': {
        'range': (0x5901DD0, 0x5905CE9),
        'sha256': '69712a6423044cdfd8b9a5ddf17ffa1a7c6346381471234df8aa587d04e4b2c6',
        'twin': 'ring_append_a',
        'capture_register': 'r15',
        'exact': {
            'capture': (0x5903FB0, '4989c7'),
            'fwd1_rdi': (0x5903FB6, '488dbc2400030000'),
            'fwd1_rsi': (0x5903FBE, '4c89e6'),
            'fwd1_rdx': (0x5903FC1, '488b942490000000'),
            'fwd1_mov': (0x5903FC9, '4889c1'),
            'lookup_add': (0x590407E, '4883c040'),
            'fwd2_rdi': (0x5904085, '4889c7'),
            'fwd2_mov': (0x5904088, '4c89fe'),
            'reassign': (0x59041A2, '4c8bbc24c8000000'),
        },
        'calls': {
            'twin_call': (0x5903FAB, 0x5911890),
            'fwd1_call': (0x5903FCC, FWD1_TARGET),
            'prep_call': (0x5904069, 0x4DC5EB0),
            'lookup_call': (0x5904079, 0x4DA81B0),
            'fwd2_call': (0x590408B, FWD2_TARGET),
        },
        'reassign_text': 'mov r15, QWORD PTR [rsp+0xc8]',
        'fwd1_arguments': {
            'rdi': 'lea rdi, [rsp+0x300] (frame record)',
            'rsi': 'r12',
            'rdx': 'the qword at [rsp+0x90]',
            'rcx': 'the returned index (mov rcx, rax)',
        },
        'windows': {
            'window_1': (0x5903FAB, 0x5903FD1),
            'window_2': (0x5904051, 0x5904090),
        },
        'excluded': None,
    },
    'caller_2': {
        'range': (0x5905CF0, 0x5909B21),
        'sha256': '41b6ea3b11ca2a035f22bfa7703cb11ca5a623eb0a3970740b0193580a649e84',
        'twin': 'ring_append_b',
        'capture_register': 'r12',
        'exact': {
            'capture': (0x590821B, '4989c4'),
            'fwd1_rdi': (0x5908221, '488dbc2440020000'),
            'fwd1_rsi': (0x5908229, '4889de'),
            'fwd1_rdx': (0x590822C, '488b9424a8000000'),
            'fwd1_mov': (0x5908234, '4889c1'),
            'lookup_add': (0x59082E4, '4883c040'),
            'fwd2_rdi': (0x59082EB, '4889c7'),
            'fwd2_mov': (0x59082EE, '4c89e6'),
            'reassign': (0x59085AA, '4d89ec'),
        },
        'calls': {
            'twin_call': (0x5908216, 0x5911B30),
            'fwd1_call': (0x5908237, FWD1_TARGET),
            'prep_call': (0x59082CF, 0x4DC18A0),
            'lookup_call': (0x59082DF, 0x4DA7880),
            'fwd2_call': (0x59082F1, FWD2_TARGET),
        },
        'reassign_text': 'mov r12, r13',
        'fwd1_arguments': {
            'rdi': 'lea rdi, [rsp+0x240] (frame record)',
            'rsi': 'rbx',
            'rdx': 'the qword at [rsp+0xa8]',
            'rcx': 'the returned index (mov rcx, rax)',
        },
        'windows': {
            'window_1': (0x5908216, 0x590823C),
            'window_2': (0x59082BC, 0x59082F6),
            'window_3': (0x590840E, 0x590847C),
        },
        'excluded': {
            'block': (0x590840E, 0x590847C),
            'pred': (0x5907E88, '0f8580050000'),
            'preceding_jmp': (0x5908409, 'e9d8120000', 0x59096E6),
            'in_block_je': (0x5908455, '7412'),
            'exact': {
                'test': (0x5908469, '4d85e4'),
                'jle': (0x590846C, '7e0e'),
                'mov_rdi': (0x590846E, '4c89ef'),
                'mov_rsi': (0x5908471, '4c89e6'),
                'xor_edx': (0x5908474, '31d2'),
            },
            'slot_call': (0x5908476, 'ff152470bd00'),
        },
    },
    'caller_3': {
        'range': (0x5909B30, 0x590DA49),
        'sha256': '368701b152fa985ad4852bfa862db2edefb73b7c15f5c425be49a1e259f6ecc4',
        'twin': 'ring_append_a',
        'capture_register': 'r15',
        'exact': {
            'capture': (0x590BD10, '4989c7'),
            'fwd1_rdi': (0x590BD16, '488dbc2400030000'),
            'fwd1_rsi': (0x590BD1E, '4c89e6'),
            'fwd1_rdx': (0x590BD21, '488b942490000000'),
            'fwd1_mov': (0x590BD29, '4889c1'),
            'lookup_add': (0x590BDDE, '4883c040'),
            'fwd2_rdi': (0x590BDE5, '4889c7'),
            'fwd2_mov': (0x590BDE8, '4c89fe'),
            'reassign': (0x590BF02, '4c8bbc24c8000000'),
        },
        'calls': {
            'twin_call': (0x590BD0B, 0x5911890),
            'fwd1_call': (0x590BD2C, FWD1_TARGET),
            'prep_call': (0x590BDC9, 0x4DC5EB0),
            'lookup_call': (0x590BDD9, 0x4DA81B0),
            'fwd2_call': (0x590BDEB, FWD2_TARGET),
        },
        'reassign_text': 'mov r15, QWORD PTR [rsp+0xc8]',
        'fwd1_arguments': {
            'rdi': 'lea rdi, [rsp+0x300] (frame record)',
            'rsi': 'r12',
            'rdx': 'the qword at [rsp+0x90]',
            'rcx': 'the returned index (mov rcx, rax)',
        },
        'windows': {
            'window_1': (0x590BD0B, 0x590BD31),
            'window_2': (0x590BDB1, 0x590BDF0),
        },
        'excluded': None,
    },
    'caller_4': {
        'range': (0x590DA50, 0x5911881),
        'sha256': '17d3fe719c2fc2a12be204c26a182231920e632f81aabf26844f48acf6374bd2',
        'twin': 'ring_append_b',
        'capture_register': 'r12',
        'exact': {
            'capture': (0x590FF7B, '4989c4'),
            'fwd1_rdi': (0x590FF81, '488dbc2440020000'),
            'fwd1_rsi': (0x590FF89, '4889de'),
            'fwd1_rdx': (0x590FF8C, '488b9424a8000000'),
            'fwd1_mov': (0x590FF94, '4889c1'),
            'lookup_add': (0x5910044, '4883c040'),
            'fwd2_rdi': (0x591004B, '4889c7'),
            'fwd2_mov': (0x591004E, '4c89e6'),
            'reassign': (0x591030A, '4d89ec'),
        },
        'calls': {
            'twin_call': (0x590FF76, 0x5911B30),
            'fwd1_call': (0x590FF97, FWD1_TARGET),
            'prep_call': (0x591002F, 0x4DC18A0),
            'lookup_call': (0x591003F, 0x4DA7880),
            'fwd2_call': (0x5910051, FWD2_TARGET),
        },
        'reassign_text': 'mov r12, r13',
        'fwd1_arguments': {
            'rdi': 'lea rdi, [rsp+0x240] (frame record)',
            'rsi': 'rbx',
            'rdx': 'the qword at [rsp+0xa8]',
            'rcx': 'the returned index (mov rcx, rax)',
        },
        'windows': {
            'window_1': (0x590FF76, 0x590FF9C),
            'window_2': (0x591001C, 0x5910056),
            'window_3': (0x591016E, 0x59101DC),
        },
        'excluded': {
            'block': (0x591016E, 0x59101DC),
            'pred': (0x590FBE8, '0f8580050000'),
            'preceding_jmp': (0x5910169, 'e9d8120000', 0x5911446),
            'in_block_je': (0x59101B5, '7412'),
            'exact': {
                'test': (0x59101C9, '4d85e4'),
                'jle': (0x59101CC, '7e0e'),
                'mov_rdi': (0x59101CE, '4c89ef'),
                'mov_rsi': (0x59101D1, '4c89e6'),
                'xor_edx': (0x59101D4, '31d2'),
            },
            'slot_call': (0x59101D6, 'ff15c4f2bc00'),
        },
    },
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hx(value):
    return f'0x{value:x}'


def sha(body):
    return hashlib.sha256(body).hexdigest()


def relative_relocations(data):
    result = {}
    for section in sections(data):
        if section['name'] == '.rela.dyn':
            blob = data[section['offset']:section['offset'] + section['size']]
            for cursor in range(0, len(blob), 24):
                offset, info, addend = struct.unpack_from('<QQq', blob, cursor)
                if info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
                    result[offset] = addend
    return result


def read(data, section_list, va, size):
    matches = [
        section for section in section_list
        if section['type'] != 8
        and section['address'] <= va
        and va + size <= section['address'] + section['size']
    ]
    require(len(matches) == 1, f'Address not uniquely mapped: {hx(va)}')
    section = matches[0]
    offset = section['offset'] + va - section['address']
    return offset, data[offset:offset + size]


def resolve_e8(body, base, va):
    offset = va - base
    disp = struct.unpack_from('<i', body, offset + 1)[0]
    return va + 5 + disp


def resolve_slot(body, base, va, length):
    offset = va - base
    disp = struct.unpack_from('<i', body, offset + length - 4)[0]
    return va + length + disp


# --- operand-level scan helpers -------------------------------------

_REG64 = {
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
}


def base_reg(token):
    token = token.strip().lower()
    if token in _REG64:
        return token
    if re.fullmatch(r'r\d{1,2}[dwb]', token):
        return token[:-1]
    if re.fullmatch(r'e[a-z]{2}', token) and token[1:] in (
            'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'):
        return 'r' + token[1:]
    if token in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'):
        return 'r' + token
    if token in ('al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh'):
        return 'r' + token[0] + 'x'
    if token in ('sil', 'dil', 'bpl', 'spl'):
        return 'r' + token[:2]
    return None


def expr_regs(expr):
    regs = set()
    for token in re.split(r'[^a-z0-9]', expr.lower()):
        reg = base_reg(token)
        if reg:
            regs.add(reg)
    return regs


def split_ops(ops):
    out, depth, cur = [], 0, ''
    for ch in ops:
        if ch == '[':
            depth += 1
        if ch == ']':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parse_asm(asm):
    insns = []
    for line in asm.splitlines():
        parts = line.split('\t')
        if len(parts) < 3 or not parts[0].strip().endswith(':'):
            continue
        try:
            va = int(parts[0].strip()[:-1], 16)
        except ValueError:
            continue
        text = parts[2].strip()
        mnemonic = text.split(' ')[0]
        ops = text[len(mnemonic):].strip()
        insns.append((va, mnemonic, ops))
    return insns


def reads_reg(mnemonic, ops, reg):
    """Whether the instruction reads register `reg` (as a source
    operand register or as a memory base/index register).  A pure
    destination register of a mov/lea does not count."""
    opl = split_ops(ops) if ops else []
    if not opl:
        return False
    if mnemonic in ('mov', 'movzx', 'movsx', 'movq', 'movdqa', 'movdqu',
                    'movups', 'movaps', 'lea'):
        return len(opl) >= 2 and reg in expr_regs(opl[1])
    if mnemonic in ('call', 'ret') or mnemonic.startswith('j'):
        return False
    if mnemonic == 'push':
        return reg in expr_regs(opl[0])
    # Comparisons read both operands; read-modify-write instructions
    # read their destination as well as their source.
    return any(reg in expr_regs(op) for op in opl)


_WRITE_MNEMONICS = {
    'mov', 'movzx', 'movsx', 'movq', 'lea', 'xor', 'add', 'sub', 'and',
    'or', 'inc', 'dec', 'shl', 'shr', 'sar', 'rol', 'ror', 'imul',
    'neg', 'not', 'pop', 'movdqa', 'movdqu', 'movups', 'movaps',
}


def writes_reg(mnemonic, ops, reg):
    opl = split_ops(ops) if ops else []
    if not opl or mnemonic not in _WRITE_MNEMONICS:
        return False
    dest = opl[0]
    if 'ptr' in dest.lower():  # a store: destination is memory
        return False
    tokens = re.split(r'[^a-z0-9]', dest.lower())
    return bool(tokens) and base_reg(tokens[0]) == reg


def store_source_reg(mnemonic, ops):
    """For a store instruction, the register its value comes from."""
    opl = split_ops(ops) if ops else []
    if len(opl) != 2 or mnemonic not in ('mov', 'movq'):
        return None
    if 'ptr' not in opl[0].lower():
        return None
    tokens = re.split(r'[^a-z0-9]', opl[1].lower())
    return base_reg(tokens[0]) if tokens else None


def branch_target(mnemonic, ops):
    if not (mnemonic.startswith('j') or mnemonic == 'call'):
        return None
    match = re.search(r'(?<![0-9a-f])([0-9a-f]+)(?![0-9a-f])', ops)
    return int(match.group(1), 16) if match else None


def flow_verdict(forward_count, store_sites, capture_reassigned):
    """The pinned classification of a caller's use of the returned
    index: it is insert-path-local when the caller forwards it only
    as call arguments, stores it nowhere, and reassigns the capture
    register afterwards."""
    if store_sites:
        return 'stored in the caller'
    if not capture_reassigned:
        return 'capture register never reassigned'
    if forward_count != 2:
        return 'unexpected forward count'
    return ('insert-path-local: register-only, forwarded as call '
            'arguments, never stored in the caller')


def caller_scan(insns, spec):
    """Run the window scans for one caller over its decoded body and
    return the flow record.  Raises ValueError on any divergence."""
    name_cap = spec['capture_register']
    twin_call = spec['calls']['twin_call'][0]
    fwd1_call = spec['calls']['fwd1_call'][0]
    fwd2_mov = spec['exact']['fwd2_mov'][0]
    reassign = spec['exact']['reassign'][0]
    by_va = {va: (mnemonic, ops) for va, mnemonic, ops in insns}

    # (a) rax reads from the twin call to the first forward's call:
    # exactly the capture move and the forward move.
    rax_reads = [
        va for va, mnemonic, ops in insns
        if twin_call < va <= fwd1_call and reads_reg(mnemonic, ops, 'rax')
    ]
    require(rax_reads == [spec['exact']['capture'][0],
                          spec['exact']['fwd1_mov'][0]],
            f'{spec["twin"]} caller rax read set changed')

    # (b) capture-register reads from the twin call to its first
    # reassignment: the second forward's move, plus -- in the
    # B-side callers -- the two reads inside the excluded block.
    cap_reads = [
        va for va, mnemonic, ops in insns
        if twin_call < va < reassign and reads_reg(mnemonic, ops, name_cap)
    ]
    want_reads = [fwd2_mov]
    if spec['excluded'] is not None:
        want_reads += [spec['excluded']['exact']['test'][0],
                       spec['excluded']['exact']['mov_rsi'][0]]
    require(cap_reads == want_reads,
            'Capture register read set changed')

    # (c) the value is never stored: no store in the window takes
    # its source from rax (before the first forward) or from the
    # capture register, and neither register is ever pushed.
    stores = []
    for va, mnemonic, ops in insns:
        if not (twin_call < va < reassign):
            continue
        source = store_source_reg(mnemonic, ops)
        if source == name_cap or (source == 'rax' and va <= fwd1_call):
            stores.append(va)
        if mnemonic == 'push' and (
                reads_reg(mnemonic, ops, name_cap)
                or (va <= fwd1_call and reads_reg(mnemonic, ops, 'rax'))):
            stores.append(va)
    require(not stores, 'Returned index is stored in the caller')

    # (d) the reassignment site is the first write to the capture
    # register after the capture move.
    capture = spec['exact']['capture'][0]
    writes = [
        va for va, mnemonic, ops in insns
        if capture < va <= reassign and writes_reg(mnemonic, ops, name_cap)
    ]
    require(writes == [reassign],
            'Capture register first reassignment changed')

    excluded_record = None
    excluded = spec['excluded']
    if excluded is not None:
        block_start, block_end = excluded['block']
        # (e) the excluded block's direct branch/call predecessors
        # inside the body are exactly the pinned pre-call branch and
        # the block-internal conditional jump to its test; the
        # instruction immediately before the block is an unrelated
        # unconditional jump, so there is no fall-through entry.
        into = sorted(
            (va, branch_target(mnemonic, ops))
            for va, mnemonic, ops in insns
            if branch_target(mnemonic, ops) is not None
            and block_start <= branch_target(mnemonic, ops) < block_end
        )
        require(into == [(excluded['pred'][0], block_start),
                         (excluded['in_block_je'][0],
                          excluded['exact']['test'][0])],
                'Excluded block predecessor set changed')
        require(excluded['pred'][0] < twin_call,
                'Excluded block predecessor is not before the twin call')
        previous = max(va for va, _, _ in insns if va < block_start)
        require(previous == excluded['preceding_jmp'][0],
                'Excluded block preceding instruction changed')
        mnemonic, ops = by_va[previous]
        require(mnemonic == 'jmp'
                and branch_target(mnemonic, ops)
                == excluded['preceding_jmp'][2],
                'Excluded block preceding jump target changed')
        excluded_record = {
            'block': [hx(block_start), hx(block_end)],
            'sole_direct_predecessor': hx(excluded['pred'][0]),
            'predecessor_precedes_twin_call': True,
            'fall_through_entry': (
                'none: the preceding instruction is an unconditional '
                'jump to ' + hx(excluded['preceding_jmp'][2])
            ),
            'guard': {
                'test_site': hx(excluded['exact']['test'][0]),
                'form': (
                    'test <capture>, <capture>; jle past the call; '
                    'the call runs through slot ' + hx(EXCLUDED_SLOT)
                    + ' (bound to ' + hx(EXCLUDED_SLOT_TARGET) + ') '
                    'with rdi = r13, rsi = <capture>, rdx = 0'
                ),
            },
            'reason_excluded': (
                'the block is entered only from a branch that '
                'precedes the twin call site, on an arm that never '
                'executes the twin call; the capture register there '
                'holds that arm\'s own value (a size-like guard '
                'operand for the slot call), not the returned index'
            ),
        }
    return {
        'rax_reads_to_first_forward': [hx(va) for va in rax_reads],
        'capture_register_reads_before_reassignment':
            [hx(va) for va in cap_reads],
        'stores_of_value': [],
        'excluded_block': excluded_record,
    }


def authenticate(data):
    require(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
            'Node 115 artifact authentication failed')


def analyze(data, binary=TARGET):
    section_list = sections(data)
    frames, fdes, extents = fde_extents(data)
    by_range = {(item['start'], item['end']): item for item in fdes}
    relas = relative_relocations(data)
    specs = dict(TWINS)
    specs.update(CALLERS)
    for name in specs:
        start, end = specs[name]['range']
        require((start, end) in by_range, f'{name} is not an exact FDE body')
    body_refs = [
        hx(offset) for offset in sorted(relas)
        if any(spec['range'][0] <= offset < spec['range'][1]
               for spec in specs.values())
    ]
    addend_refs = [
        hx(value) for value in sorted(set(relas.values()))
        if any(value == spec['range'][0] for spec in specs.values())
    ]
    require(not body_refs,
            'A caller or twin body holds a relocation slot')
    require(not addend_refs,
            'A caller or twin body is reached through a relocation')
    require(relas.get(EXCLUDED_SLOT) == EXCLUDED_SLOT_TARGET,
            'Excluded block slot binding changed')
    text = next(section for section in section_list if section['name'] == '.text')
    text_body = data[text['offset']:text['offset'] + text['size']]

    def census(opcode):
        hits = {spec['range'][0]: [] for spec in TWINS.values()}
        cursor = text_body.find(bytes([opcode]))
        while cursor != -1:
            site = text['address'] + cursor
            target = site + 5 + struct.unpack_from('<i', text_body,
                                                    cursor + 1)[0]
            if target in hits:
                hits[target].append(site)
            cursor = text_body.find(bytes([opcode]), cursor + 1)
        return hits

    call_census = census(0xE8)
    jump_census = census(0xE9)
    for twin_name, twin_spec in TWINS.items():
        want = sorted(
            spec['calls']['twin_call'][0]
            for spec in CALLERS.values() if spec['twin'] == twin_name
        )
        require(sorted(call_census[twin_spec['range'][0]]) == want,
                f'{twin_name} direct caller census changed')
        require(not jump_census[twin_spec['range'][0]],
                f'{twin_name} gained a direct jump reference')
    frame_records = {}
    bodies = {}
    for name, spec in specs.items():
        start, end = spec['range']
        offset, body = read(data, section_list, start, end - start)
        bodies[name] = body
        record = by_range[(start, end)]
        frame_records[name] = {
            'fde': hx(record['fde']),
            'cie': hx(record['cie']),
            'lsda': hx(record['lsda']),
            'range': [hx(record['start']), hx(record['end'])],
            'bytes': end - start,
            'file_offset': hx(offset),
            'sha256': spec['sha256'],
        }
    traces = {}
    callers_record = {}
    for name, spec in CALLERS.items():
        start, end = spec['range']
        body = bodies[name]
        # Exact byte pins and resolved call targets are checked
        # against the supplied bytes first; the disassembly-based
        # checks (instruction starts, window scans) run afterwards,
        # so a mutated byte is reported by the pin that covers it.
        for site_name, (va, expected) in spec['exact'].items():
            want = bytes.fromhex(expected)
            require(body[va - start:va - start + len(want)] == want,
                    f'Pinned instruction changed at {hx(va)}')
        for site_name, (va, target) in spec['calls'].items():
            require(body[va - start] == 0xE8,
                    f'Pinned call opcode changed at {hx(va)}')
            require(resolve_e8(body, start, va) == target,
                    f'Resolved target changed at {hx(va)}')
        if spec['excluded'] is not None:
            excluded = spec['excluded']
            for key in ('pred', 'preceding_jmp', 'in_block_je'):
                va, expected = excluded[key][0], excluded[key][1]
                want = bytes.fromhex(expected)
                require(body[va - start:va - start + len(want)] == want,
                        f'Pinned instruction changed at {hx(va)}')
            for site_name, (va, expected) in excluded['exact'].items():
                want = bytes.fromhex(expected)
                require(body[va - start:va - start + len(want)] == want,
                        f'Pinned instruction changed at {hx(va)}')
            va, expected = excluded['slot_call']
            want = bytes.fromhex(expected)
            require(body[va - start:va - start + len(want)] == want,
                    f'Pinned instruction changed at {hx(va)}')
            require(resolve_slot(body, start, va, len(want))
                    == EXCLUDED_SLOT,
                    f'Excluded slot call target changed at {hx(va)}')
            pred_va, _ = excluded['pred']
            require(body[pred_va - start] == 0x0F
                    and body[pred_va - start + 1] == 0x85,
                    'Excluded block predecessor opcode changed')
            pred_disp = struct.unpack_from('<i', body,
                                           pred_va - start + 2)[0]
            require(pred_va + 6 + pred_disp == excluded['block'][0],
                    'Excluded block predecessor target changed')
        asm = subprocess.check_output([
            'objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start:#x}', f'--stop-address={end:#x}',
            str(binary),
        ], text=True)
        rows = decode_export(asm, start, end, body)
        site_vas = [va for va, _ in spec['exact'].values()]
        site_vas += [va for va, _ in spec['calls'].values()]
        if spec['excluded'] is not None:
            excluded = spec['excluded']
            site_vas += [excluded['pred'][0], excluded['preceding_jmp'][0],
                         excluded['in_block_je'][0], excluded['slot_call'][0]]
            site_vas += [va for va, _ in excluded['exact'].values()]
        for va in site_vas:
            require(va in rows,
                    f'{name} pinned site is not a native instruction '
                    f'start: {hx(va)}')
        insns = parse_asm(asm)
        scan = caller_scan(insns, spec)
        twin_spec = TWINS[spec['twin']]
        traces[name] = {
            'twin': spec['twin'],
            'twin_call_site': hx(spec['calls']['twin_call'][0]),
            'returned_value': (
                'the shared insert routine result forwarded by the '
                'twin: the pre-insert slab head (the slab slot index)'
            ),
            'capture': {
                'site': hx(spec['exact']['capture'][0]),
                'register': spec['capture_register'],
                'instruction': f'mov {spec["capture_register"]}, rax',
            },
            'forward_1': {
                'callee': hx(FWD1_TARGET),
                'argument': 'rcx (fourth argument)',
                'mov_site': hx(spec['exact']['fwd1_mov'][0]),
                'call_site': hx(spec['calls']['fwd1_call'][0]),
                'other_arguments': spec['fwd1_arguments'],
            },
            'forward_2': {
                'callee': hx(FWD2_TARGET),
                'argument': 'rsi (second argument)',
                'mov_site': hx(spec['exact']['fwd2_mov'][0]),
                'call_site': hx(spec['calls']['fwd2_call'][0]),
                'first_argument': (
                    'the result of the lookup call at '
                    + hx(spec['calls']['lookup_call'][0]) + ' to '
                    + hx(spec['calls']['lookup_call'][1]) + ', plus 0x40'
                ),
                'prep_call': {
                    'site': hx(spec['calls']['prep_call'][0]),
                    'target': hx(spec['calls']['prep_call'][1]),
                    'note': ('runs between the two forwards and '
                             'receives no index argument'),
                },
            },
            'scan': scan,
            'capture_reassignment': {
                'site': hx(spec['exact']['reassign'][0]),
                'instruction': spec['reassign_text'],
            },
            'verdict': flow_verdict(2, scan['stores_of_value'], True),
        }
        callers_record[name] = {
            'range': [hx(start), hx(end)],
            'bytes': end - start,
            'sha256': spec['sha256'],
            'calls': spec['twin'],
            'twin_call_site': hx(spec['calls']['twin_call'][0]),
            'capture_register': spec['capture_register'],
        }
    # Body digests are verified after the pin and scan checks so a
    # mutated byte inside a body is reported by the check that pins
    # it; the digest remains the integrity net for unpinned bytes.
    for name, spec in specs.items():
        require(sha(bodies[name]) == spec['sha256'],
                f'{name} body changed')
    twins_record = {
        name: {
            'range': [hx(spec['range'][0]), hx(spec['range'][1])],
            'bytes': spec['range'][1] - spec['range'][0],
            'sha256': spec['sha256'],
            'direct_e8_call_sites': [
                hx(spec2['calls']['twin_call'][0])
                for spec2 in CALLERS.values() if spec2['twin'] == name
            ],
            'direct_callers': [
                caller_name for caller_name, spec2 in CALLERS.items()
                if spec2['twin'] == name
            ],
        }
        for name, spec in TWINS.items()
    }
    return {
        'schema': 1,
        'target': {
            'release': 115,
            'bytes': TARGET_SIZE,
            'sha256': TARGET_SHA256,
        },
        'relocation_diagnostics': {
            'relative_relocation_count': len(relas),
            'body_slot_references': body_refs,
            'body_addend_references': addend_refs,
            'excluded_slot_binding': {
                hx(EXCLUDED_SLOT): hx(EXCLUDED_SLOT_TARGET),
            },
        },
        'capture': {
            'fde_count': len(fdes),
            'cie_records': frames['cie_records'],
            'fde_records': frames['fde_records'],
            'unique_fde_starts': frames['unique_fde_starts'],
            'gap_extents_outside_fdes': len(extents),
        },
        'scope': {
            'instruction': (
                'Trace what the four insert-order callers of the '
                'RE-006 ring-append twins do with the forwarded '
                'slab slot index: its capture register, its two '
                'argument forwards, the absence of any store, and '
                'the capture register reassignment, with the twins '
                'and the two forward callees as the boundary.'
            ),
            'measured_denominator_bytes': sum(
                spec['range'][1] - spec['range'][0]
                for spec in CALLERS.values()
            ),
            'owners': list(CALLERS),
            'complete_fdes': len(CALLERS),
            'owner_body_bytes': sum(
                spec['range'][1] - spec['range'][0]
                for spec in CALLERS.values()
            ),
        },
        'frames': frame_records,
        'owners': callers_record,
        'boundaries': twins_record,
        'trace': traces,
    }


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    report = analyze(data, binary)
    output.mkdir(parents=True, exist_ok=True)
    raw = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    ranges = [
        (spec['range'][0], spec['range'][1])
        for spec in list(CALLERS.values()) + list(TWINS.values())
    ]
    lines = [
        line.replace(str(binary), '<authenticated-node115>')
        for line in raw.splitlines()
        if any(f'pc={start:016x}..{end:016x}' in line for start, end in ranges)
    ]
    require(len(lines) == len(report['frames']),
            'Retained readelf frame changed')
    (output / 'frames.txt').write_text('\n'.join(lines) + '\n')
    exports = {}
    for name, spec in CALLERS.items():
        caller_exports = {}
        for window_name, (win_start, win_end) in spec['windows'].items():
            asm = subprocess.check_output([
                'objdump', '-d', '-M', 'intel', '--insn-width=16',
                f'--start-address={win_start:#x}',
                f'--stop-address={win_end:#x}',
                str(binary),
            ], text=True)
            safe_name = f'{name}_{window_name}_{win_start:x}_{win_end:x}_objdump.txt'
            rendered = asm.replace(str(binary), '<authenticated-node115>')
            (output / safe_name).write_text(rendered)
            caller_exports[window_name] = {
                'file': safe_name,
                'sha256': sha(rendered.encode()),
                'range': [hx(win_start), hx(win_end)],
            }
        exports[name] = caller_exports
    report['source_exports'] = exports
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else TARGET
    output = Path(sys.argv[2]) if len(sys.argv) > 2 else PACKET
    generate(binary, output)
    print(output / 'records.json')


if __name__ == '__main__':
    main()

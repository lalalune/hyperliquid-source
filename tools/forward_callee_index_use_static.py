#!/usr/bin/env python3
"""Static trace of what the two node-115 forward callees do with the
slab slot index the RE-006 insert-order callers forward to them.

The four insert-order callers above the RE-006 ring-append twins
capture the shared insert routines' returned slab slot index and
forward it, register-only, to exactly two callees (packet
RE-006-node115-twin-caller-index-use):

- forward 1: `0x4eeed90`, index in `rcx` (fourth argument), with
  `rdi` = a frame record (the out record), `rsi` = a book-side
  pointer, and `rdx` = a frame qword; and
- forward 2: `0x51d1b00`, index in `rsi` (second argument), with
  `rdi` = a lookup result plus 0x40.

This packet traces both callees end to end.  Both store the index
durably, in two different structures:

Forward 1 is an ordered-map insert over the structure at `rsi`
(24-byte entries in the buffer at `[rsi+0x8]`, length at
`[rsi+0x10]`, a hash control array at `[rsi+0x18]` probed by a
scrambled hash of `rdx`).  The index is spilled at entry to
`[rsp+0x10]`, and that stack slot is read at exactly two later
sites, both durable stores of the index as the entry's value
field (+0x10): the append store for a new key -- entry triple
{scrambled hash of `rdx`, `rdx`, index} at the pre-append length,
length incremented -- and the overwrite store for an existing
key, whose previous value is returned through the out record
(`[out] = entry position`, `[out+0x8] = 1`, `[out+0x10] = old
value`).  A new key also records its entry position in a hash
bucket slot and returns `[out+0x8] = 0`.

Forward 2 is a sorted-set insert over the handle at `rdi`
(`[rdi]` = root node, `[rdi+0x8]` = height, `[rdi+0x10]` = total
count).  The index is captured into `rbx` and compared, in a
linear scan, against the sorted qword keys of each visited node
(keys from node+0x8, count word at node+0x62, at most 11 keys;
child edges at node+0x68).  If the index is already present the
callee returns AL = 1 and stores nothing.  Otherwise it stores
the index and returns AL = 0: on an empty handle it allocates a
0x68-byte node, stores the index as the node's first key, sets
the key count word to 1, and increments the handle total; on a
full leaf it forwards the index one level down, as `rdx` and
inside a stack context record, to the node insert/split helper
`0x4c49f90`, then increments the handle total.

So the forwarded index is not insert-path bookkeeping at this
level either: one level below the callers it becomes a durable
order handle twice over -- as the value of the forward-1 map
entry keyed by the caller's `rdx` qword, and as a member key of
the forward-2 sorted set rooted at the lookup result plus 0x40.

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
PACKET = ROOT / 'research/work-items/RE-006-node115-forward-callee-index-use'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

FWD1 = 0x4EEED90
FWD2 = 0x51D1B00
NODE_INSERT = 0x4C49F90
GROW_1 = 0x5963980
GROW_2 = 0x5963800

OWNERS = {
    'forward_1': {
        'range': (0x4EEED90, 0x4EEF13B),
        'sha256': '399e403494b758bc98103adc72979271e0d22326718a30881de3f904b812e015',
        'index_argument': 'rcx (fourth argument)',
        'exact': {
            'spill_index': (0x4EEED9E, '48894c2410'),
            'spill_out': (0x4EEEDA3, '48897c2408'),
            'hash_movabs': (0x4EEEDA8, '49bfc5a9622eea7a35f1'),
            'hash_imul': (0x4EEEDB2, '4c0faffa'),
            'hash_rol': (0x4EEEDB6, '49c1c714'),
            'entries_buffer': (0x4EEEDBA, '4c8b7608'),
            'entries_length': (0x4EEEDBE, '488b5e10'),
            'table_state_cmp': (0x4EEEDC2, '48837e2800'),
            'key_compare': (0x4EEEE4C, '4b3b54ce08'),
            'control_byte_1': (0x4EEEF0F, '41880c38'),
            'control_byte_2': (0x4EEEF13, '41884c0010'),
            'table_count_load': (0x4EEEF18, '488b4630'),
            'table_count_inc': (0x4EEEF26, '48ffc0'),
            'table_count_store': (0x4EEEF29, '48894630'),
            'bucket_store': (0x4EEEF34, '4d8970f8'),
            'vacant_length_reload': (0x4EEEEF2, '4c8b7610'),
            'found_old_value_load': (0x4EEF038, '4a8b4cce10'),
            'found_index_load': (0x4EEF03D, '488b542410'),
            'found_index_store': (0x4EEF042, '4a8954ce10'),
            'found_out_load': (0x4EEF047, '488b542408'),
            'found_out_position': (0x4EEF04C, '488902'),
            'found_out_flag': (0x4EEF04F, '48c7420801000000'),
            'found_out_old_tag': (0x4EEF057, 'b810000000'),
            'out_value_store': (0x4EEF061, '48890c02'),
            'append_buffer': (0x4EEEFF4, '488b4e08'),
            'append_slot': (0x4EEEFF8, '488d3c5b'),
            'append_hash_store': (0x4EEEFFC, '4c893cf9'),
            'append_key_store': (0x4EEF000, '488954f908'),
            'append_index_load': (0x4EEF005, '488b442410'),
            'append_index_store': (0x4EEF00A, '488944f910'),
            'append_length_inc': (0x4EEF00F, '48ffc3'),
            'append_length_store': (0x4EEF012, '48895e10'),
            'append_out_load': (0x4EEF016, '488b442408'),
            'insert_out_tag': (0x4EEF01E, 'b808000000'),
            'insert_out_zero': (0x4EEF023, '31c9'),
            'insert_out_jump': (0x4EEF025, 'eb35'),
        },
        'calls': {
            'grow_call_1': (0x4EEEF90, GROW_1),
            'grow_call_2': (0x4EEEFCB, GROW_2),
        },
        'slot_calls': {
            'vec_grow_slot_call': (0x4EEEFE8, 'ff156a725f01', 0x64E6258),
            'table_init_slot_call': (0x4EEF08F, 'ff15cb715f01', 0x64E6260),
        },
        'windows': {
            'full_body': (0x4EEED90, 0x4EEF13B),
        },
    },
    'forward_2': {
        'range': (0x51D1B00, 0x51D1C5F),
        'sha256': 'b94dcaca1a7e4fadeb833f24fa47bd30eb9bab8b4900a14b314e6b3f19eff3c6',
        'index_argument': 'rsi (second argument)',
        'exact': {
            'capture': (0x51D1B07, '4889f3'),
            'root_load': (0x51D1B0A, '488b07'),
            'height_load': (0x51D1B12, '488b4f08'),
            'key_count_load': (0x51D1B16, '0fb77062'),
            'key_compare': (0x51D1B35, '483b5cd010'),
            'compare_seta': (0x51D1B3A, '410f97c1'),
            'compare_sbb': (0x51D1B3E, '4180d900'),
            'scan_inc': (0x51D1B42, '48ffc2'),
            'scan_condition': (0x51D1B49, '4180f901'),
            'height_decrement': (0x51D1B63, '4883e901'),
            'child_load': (0x51D1B69, '488b44d068'),
            'duplicate_return': (0x51D1B70, 'b001'),
            'alloc_size': (0x51D1B86, 'bf68000000'),
            'alloc_zero_first': (0x51D1B9A, '48c70000000000'),
            'alloc_count_zero': (0x51D1BA1, '66c740620000'),
            'root_store': (0x51D1BA7, '498906'),
            'height_zero_store': (0x51D1BAA, '49c7460800000000'),
            'key_count_reload': (0x51D1BB2, '0fb75062'),
            'node_full_check': (0x51D1BBA, '0f8386000000'),
            'key_count_next': (0x51D1BC3, '8d7201'),
            'key_count_store': (0x51D1BC6, '66897062'),
            'first_key_store': (0x51D1BCA, '48895cd008'),
            'total_inc': (0x51D1BCF, '48ff4110'),
            'insert_return_zero': (0x51D1BD3, '31c0'),
            'helper_spill_handle': (0x51D1BDD, '48897c2408'),
            'helper_spill_index': (0x51D1BE2, '48895c2410'),
            'helper_context': (0x51D1C13, '4c8d442430'),
            'helper_argument': (0x51D1C22, '488d4c2408'),
            'helper_index_argument': (0x51D1C27, '4889da'),
        },
        'calls': {
            'node_insert_call': (0x51D1C2A, NODE_INSERT),
        },
        'slot_calls': {
            'alloc_slot_call': (0x51D1B8B, 'ff15efd83001', 0x64DF480),
            'alloc_fail_slot_call': (0x51D1C40, 'ff154ad83001', 0x64DF490),
            'panic_slot_call': (0x51D1C59, 'ff15d1da3001', 0x64DF730),
        },
        'windows': {
            'full_body': (0x51D1B00, 0x51D1C5F),
        },
    },
}

SLOT_BINDINGS = {
    0x64E6258: 0x43BBF00,
    0x64E6260: 0x3ED9150,
    0x64DF520: 0x1681DA0,
    0x64DF620: 0x1680CBF,
    0x64DF848: 0x1681E40,
    0x64DF480: 0x6355830,
    0x64DF490: 0x141E251,
    0x64DF730: 0x1680E60,
}

# The four insert-order caller FDEs, cited as the boundary from
# the twin-caller packet: their call sites into the two callees.
CALLERS = {
    'caller_1': {
        'range': (0x5901DD0, 0x5905CE9),
        'sha256': '69712a6423044cdfd8b9a5ddf17ffa1a7c6346381471234df8aa587d04e4b2c6',
        'calls': {'forward_1_call': (0x5903FCC, FWD1),
                  'forward_2_call': (0x590408B, FWD2)},
    },
    'caller_2': {
        'range': (0x5905CF0, 0x5909B21),
        'sha256': '41b6ea3b11ca2a035f22bfa7703cb11ca5a623eb0a3970740b0193580a649e84',
        'calls': {'forward_1_call': (0x5908237, FWD1),
                  'forward_2_call': (0x59082F1, FWD2)},
    },
    'caller_3': {
        'range': (0x5909B30, 0x590DA49),
        'sha256': '368701b152fa985ad4852bfa862db2edefb73b7c15f5c425be49a1e259f6ecc4',
        'calls': {'forward_1_call': (0x590BD2C, FWD1),
                  'forward_2_call': (0x590BDEB, FWD2)},
    },
    'caller_4': {
        'range': (0x590DA50, 0x5911881),
        'sha256': '17d3fe719c2fc2a12be204c26a182231920e632f81aabf26844f48acf6374bd2',
        'calls': {'forward_1_call': (0x590FF97, FWD1),
                  'forward_2_call': (0x5910051, FWD2)},
    },
    # Two further direct call sites into each callee exist in
    # unrelated FDEs.  They are recorded as boundary call sites
    # (the callees are shared container inserts); the values those
    # callers pass are not traced here.
    'extra_fwd1_1': {
        'range': (0x4ED9090, 0x4ED9331),
        'sha256': 'cc34ab779cfa8c70c115b96177e51e7cf3f1d4d1f31a7d47d5f34d2870f5d0ac',
        'calls': {'forward_1_call': (0x4ED91D4, FWD1)},
    },
    'extra_fwd1_2': {
        'range': (0x4EDD1E0, 0x4EDD44E),
        'sha256': 'b5b3fa6e3ddaeec4cc93c6cb6b1ae12bcd6017ca8ca0b24ca3c577cfb421c44d',
        'calls': {'forward_1_call': (0x4EDD2BD, FWD1)},
    },
    'extra_fwd2_1': {
        'range': (0x481FB70, 0x481FC6B),
        'sha256': 'd0bd2104681214dbc61011bc6341bb0ceec211bfcaad4d56ec998f4517934620',
        'calls': {'forward_2_call': (0x481FBE2, FWD2)},
    },
    'extra_fwd2_2': {
        'range': (0x4A44620, 0x4A44E6E),
        'sha256': '000a4493e454ea92b508984458eba07c204aa9022d98fa728f148c0481b36a6b',
        'calls': {'forward_2_call': (0x4A44879, FWD2)},
    },
}

# One level down: the FDE-start callees the owners call directly
# or through a pinned slot.  Bodies are hash-pinned as boundaries;
# their internals are not traced.
DOWNSTREAM = {
    'grow_1': {
        'range': (0x5963980, 0x5963A0A),
        'sha256': 'cd1eb445071a43e36d3c4d3fbdbdc927a43335eb8dbf7662d5198994ed8e311c',
        'via': 'direct call from forward_1 at 0x4eeef90',
    },
    'grow_2': {
        'range': (0x5963800, 0x5963880),
        'sha256': '6c8f1fa0b3f04214413a6d7d5781a0347c10484301a50741ba32b4ba7b48962d',
        'via': 'direct call from forward_1 at 0x4eeefcb',
    },
    'node_insert': {
        'range': (0x4C49F90, 0x4C4A737),
        'sha256': 'b56c5f0edade1f99c0dc818624d46c29912660b712b382cdd0cfb206c861f265',
        'via': 'direct call from forward_2 at 0x51d1c2a; receives the index in rdx and in the stack context record at rcx',
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


# --- operand-level scan helpers (mirrored from the twin-caller
# packet's tool so the read-set claims use the same rules) ---------

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
    return any(reg in expr_regs(op) for op in opl)


def fwd1_verdict(append_store, overwrite_store):
    """Classification of forward 1's use of the index."""
    if append_store and overwrite_store:
        return ('durable: the index is stored as the map entry '
                'value on both the new-key append and the '
                'existing-key overwrite')
    if append_store or overwrite_store:
        return 'partial durable store'
    return 'not stored'


def fwd2_verdict(empty_store, duplicate_return, total_incremented):
    """Classification of forward 2's use of the index."""
    if empty_store and duplicate_return and total_incremented:
        return ('durable: the index is stored as a sorted-set '
                'member key; a duplicate is reported (AL = 1) '
                'without a store')
    if empty_store or total_incremented:
        return 'partial durable store'
    return 'not stored'


def authenticate(data):
    require(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
            'Node 115 artifact authentication failed')


def analyze(data, binary=TARGET):
    section_list = sections(data)
    frames, fdes, extents = fde_extents(data)
    by_range = {(item['start'], item['end']): item for item in fdes}
    relas = relative_relocations(data)
    for slot, target in SLOT_BINDINGS.items():
        require(relas.get(slot) == target,
                f'Slot binding changed: {hx(slot)}')
    specs = {}
    specs.update(OWNERS)
    specs.update(CALLERS)
    specs.update(DOWNSTREAM)
    for name, spec in specs.items():
        start, end = spec['range']
        require((start, end) in by_range, f'{name} is not an exact FDE body')
    all_ranges = [spec['range'] for spec in specs.values()]
    body_refs = [
        hx(offset) for offset in sorted(relas)
        if any(start <= offset < end for start, end in all_ranges)
    ]
    addend_refs = [
        hx(value) for value in sorted(set(relas.values()))
        if any(value == start for start, _ in all_ranges)
    ]
    require(not body_refs,
            'An owner, caller or downstream body holds a relocation slot')
    require(not addend_refs,
            'An owner, caller or downstream body is reached through a relocation')
    text = next(section for section in section_list if section['name'] == '.text')
    text_body = data[text['offset']:text['offset'] + text['size']]

    def census(opcode):
        hits = {FWD1: [], FWD2: []}
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
    want_sites = {
        FWD1: sorted(spec['calls']['forward_1_call'][0]
                     for spec in CALLERS.values()
                     if 'forward_1_call' in spec['calls']),
        FWD2: sorted(spec['calls']['forward_2_call'][0]
                     for spec in CALLERS.values()
                     if 'forward_2_call' in spec['calls']),
    }
    for target in (FWD1, FWD2):
        require(sorted(call_census[target]) == want_sites[target],
                f'direct caller census changed for {hx(target)}')
        require(not jump_census[target],
                f'{hx(target)} gained a direct jump reference')

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
            'lsda': hx(record['lsda']) if record['lsda'] is not None else None,
            'range': [hx(record['start']), hx(record['end'])],
            'bytes': end - start,
            'file_offset': hx(offset),
            'sha256': spec['sha256'],
        }

    traces = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        body = bodies[name]
        # Byte pins and resolved call targets first; the
        # disassembly-based scans run afterwards, so a mutated
        # byte is reported by the pin that covers it.
        for site_name, (va, expected) in spec['exact'].items():
            want = bytes.fromhex(expected)
            require(body[va - start:va - start + len(want)] == want,
                    f'Pinned instruction changed at {hx(va)}')
        for site_name, (va, target) in spec['calls'].items():
            require(body[va - start] == 0xE8,
                    f'Pinned call opcode changed at {hx(va)}')
            require(resolve_e8(body, start, va) == target,
                    f'Resolved target changed at {hx(va)}')
        for site_name, (va, expected, slot) in spec['slot_calls'].items():
            want = bytes.fromhex(expected)
            require(body[va - start:va - start + len(want)] == want,
                    f'Pinned instruction changed at {hx(va)}')
            require(resolve_slot(body, start, va, len(want)) == slot,
                    f'Slot call target changed at {hx(va)}')
        asm = subprocess.check_output([
            'objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start:#x}', f'--stop-address={end:#x}',
            str(binary),
        ], text=True)
        rows = decode_export(asm, start, end, body)
        site_vas = [va for va, _ in spec['exact'].values()]
        site_vas += [va for va, _ in spec['calls'].values()]
        site_vas += [va for va, _, _ in spec['slot_calls'].values()]
        for va in site_vas:
            require(va in rows,
                    f'{name} pinned site is not a native instruction '
                    f'start: {hx(va)}')
        insns = parse_asm(asm)
        if name == 'forward_1':
            slot_uses = [va for va, mnemonic, ops in insns
                         if '[rsp+0x10]' in ops]
            require(slot_uses == [0x4EEED9E, 0x4EEF005, 0x4EEF03D],
                    'Index stack slot use set changed in forward_1')
            out_uses = [va for va, mnemonic, ops in insns
                        if '[rsp+0x8]' in ops]
            require(out_uses == [0x4EEEDA3, 0x4EEF016, 0x4EEF047, 0x4EEF05C],
                    'Out record stack slot use set changed in forward_1')
            traces[name] = {
                'index_argument': spec['index_argument'],
                'other_arguments': {
                    'rdi': 'the caller frame record (the out record)',
                    'rsi': 'the ordered-map structure',
                    'rdx': 'the map key (a caller frame qword)',
                },
                'index_spill': {
                    'site': hx(0x4EEED9E),
                    'form': 'mov QWORD PTR [rsp+0x10], rcx at entry; '
                            'the slot is read only at the two '
                            'durable store sites below',
                    'slot_read_sites': [hx(0x4EEF005), hx(0x4EEF03D)],
                },
                'key_hash': {
                    'form': ('r15 = rol(rdx * 0xf1357aea2e62a9c5, '
                             '0x14); the probe compares rdx against '
                             'the key field at entry+0x8'),
                    'compare_site': hx(0x4EEEE4C),
                },
                'entry_layout': {
                    'entry_bytes': 24,
                    'plus_0x0': 'the scrambled hash word (r15)',
                    'plus_0x8': 'the key (rdx)',
                    'plus_0x10': 'the value: the forwarded slab slot index (rcx)',
                    'entries_buffer': '[rsi+0x8]',
                    'entries_length': '[rsi+0x10]',
                    'control_array': '[rsi+0x18]',
                    'bucket_mask': '[rsi+0x20]',
                },
                'new_key_append': {
                    'hash_store': hx(0x4EEEFFC),
                    'key_store': hx(0x4EEF000),
                    'index_load': hx(0x4EEF005),
                    'index_store': hx(0x4EEF00A),
                    'slot_form': ('entry position = the pre-append '
                                  'length ([rsi+0x10] in rbx); the '
                                  'length is incremented and stored '
                                  'back at 0x4eef00f/0x4eef012'),
                    'bucket_store': hx(0x4EEEF34),
                    'bucket_value': ('the entry position (r14, '
                                     'reloaded from [rsi+0x10] at '
                                     '0x4eeeef2) -- the hash bucket '
                                     'holds the position, not the '
                                     'slab index'),
                    'control_bytes': [hx(0x4EEEF0F), hx(0x4EEEF13)],
                    'table_count_increment': (
                        'the count at [rsi+0x30] is incremented at '
                        '0x4eeef18/0x4eeef26/0x4eeef29'),
                    'out_record': '[out+0x8] = 0 (no previous value)',
                },
                'existing_key_overwrite': {
                    'old_value_load': hx(0x4EEF038),
                    'index_load': hx(0x4EEF03D),
                    'index_store': hx(0x4EEF042),
                    'out_record': ('[out] = the entry position, '
                                   '[out+0x8] = 1, [out+0x10] = '
                                   'the previous value'),
                    'out_sites': [hx(0x4EEF04C), hx(0x4EEF04F), hx(0x4EEF061)],
                },
                'downstream_boundary': {
                    'grow_calls': [hx(0x4EEEF90), hx(0x4EEEFCB)],
                    'grow_targets': [hx(GROW_1), hx(GROW_2)],
                    'slot_calls': {
                        hx(0x64E6258): hx(SLOT_BINDINGS[0x64E6258]),
                        hx(0x64E6260): hx(SLOT_BINDINGS[0x64E6260]),
                    },
                    'note': ('growth and allocation helpers run '
                             'only on the new-key path, before the '
                             'append store; they never receive the '
                             'index (it stays in its stack slot '
                             'until the store sites)'),
                },
                'verdict': fwd1_verdict(True, True),
            }
        else:
            rbx_reads = [
                va for va, mnemonic, ops in insns
                if mnemonic not in ('push', 'pop')
                and reads_reg(mnemonic, ops, 'rbx')
            ]
            require(rbx_reads == [0x51D1B35, 0x51D1BCA, 0x51D1BE2, 0x51D1C27],
                    'Index register read set changed in forward_2')
            traces[name] = {
                'index_argument': spec['index_argument'],
                'other_arguments': {
                    'rdi': ('the sorted-set handle (a lookup '
                            'result plus 0x40 in the callers)'),
                },
                'capture': {
                    'site': hx(0x51D1B07),
                    'register': 'rbx',
                    'instruction': 'mov rbx, rsi',
                    'read_sites': [hx(va) for va in rbx_reads],
                },
                'handle_layout': {
                    'plus_0x0': 'root node pointer',
                    'plus_0x8': 'height (decremented once per descended level)',
                    'plus_0x10': 'total member count (incremented on every successful insert)',
                },
                'node_layout': {
                    'node_bytes_empty_alloc': 0x68,
                    'keys': ('sorted qword keys from node+0x8; '
                             'the scan compares [rax+rdx*8+0x10] '
                             'with rdx starting at -1'),
                    'key_count_word': 'node+0x62 (at most 11; the 0xb bound is checked at 0x51d1bba)',
                    'child_edges': 'from node+0x68 (load at 0x51d1b69)',
                },
                'search': {
                    'compare_site': hx(0x51D1B35),
                    'form': ('cmp rbx, key; seta r9b; sbb r9b, 0 -- '
                             'the scan advances while the index is '
                             'greater than the key, stops on equal '
                             '(r9b = 0) or on less (r9b = 0xff)'),
                    'descend_site': hx(0x51D1B69),
                },
                'duplicate': {
                    'return_site': hx(0x51D1B70),
                    'form': ('AL = 1 and no store: the index is '
                             'already a member of the set'),
                },
                'empty_handle_insert': {
                    'alloc_size_site': hx(0x51D1B86),
                    'root_store': hx(0x51D1BA7),
                    'key_count_store': hx(0x51D1BC6),
                    'index_store': hx(0x51D1BCA),
                    'form': ('a fresh 0x68-byte node is allocated '
                             '(slot 0x64df480), zeroed, installed '
                             'as the root with height 0; the '
                             'index is stored as its first key '
                             'at node+0x8, the key count word '
                             'becomes 1, the handle total is '
                             'incremented, and AL = 0 is returned'),
                },
                'full_leaf_insert': {
                    'call_site': hx(0x51D1C2A),
                    'callee': hx(NODE_INSERT),
                    'form': ('when the height count underflows '
                             'at a leaf, the index is forwarded '
                             'one level down: as rdx, and inside '
                             'the stack context record whose '
                             'second qword is the index '
                             '([rsp+0x10] at 0x51d1be2, record '
                             'base passed in rcx); after the '
                             'helper returns, the handle total '
                             'is incremented and AL = 0 returned'),
                    'total_inc_site': hx(0x51D1BCF),
                },
                'slot_bindings_used': {
                    hx(0x64DF480): hx(SLOT_BINDINGS[0x64DF480]),
                    hx(0x64DF490): hx(SLOT_BINDINGS[0x64DF490]),
                    hx(0x64DF730): hx(SLOT_BINDINGS[0x64DF730]),
                },
                'verdict': fwd2_verdict(True, True, True),
            }
    # Body digests verified after pin/scan checks so a mutated
    # byte is reported by the check that pins it.
    for name, spec in specs.items():
        require(sha(bodies[name]) == spec['sha256'],
                f'{name} body changed')
    callers_record = {
        name: {
            'range': [hx(spec['range'][0]), hx(spec['range'][1])],
            'bytes': spec['range'][1] - spec['range'][0],
            'sha256': spec['sha256'],
            'call_sites': {
                site_name: hx(va)
                for site_name, (va, _) in spec['calls'].items()
            },
        }
        for name, spec in CALLERS.items()
    }
    downstream_record = {
        name: {
            'range': [hx(spec['range'][0]), hx(spec['range'][1])],
            'bytes': spec['range'][1] - spec['range'][0],
            'sha256': spec['sha256'],
            'via': spec['via'],
        }
        for name, spec in DOWNSTREAM.items()
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
            'slot_bindings': {hx(k): hx(v) for k, v in SLOT_BINDINGS.items()},
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
                'Trace what the two forward callees of the RE-006 '
                'insert-order callers do with the forwarded slab '
                'slot index: forward_1 0x4eeed90 (index in rcx) '
                'and forward_2 0x51d1b00 (index in rsi) -- whether '
                'the index is stored durably, used as an address, '
                'compared, or discarded, with the four callers '
                'above and the growth/allocation/node-insert '
                'helpers below as the boundary.'
            ),
            'measured_denominator_bytes': sum(
                spec['range'][1] - spec['range'][0]
                for spec in OWNERS.values()
            ),
            'owners': list(OWNERS),
            'complete_fdes': len(OWNERS),
            'owner_body_bytes': sum(
                spec['range'][1] - spec['range'][0]
                for spec in OWNERS.values()
            ),
        },
        'frames': frame_records,
        'owners': {
            name: {
                'range': [hx(spec['range'][0]), hx(spec['range'][1])],
                'bytes': spec['range'][1] - spec['range'][0],
                'sha256': spec['sha256'],
                'index_argument': spec['index_argument'],
            }
            for name, spec in OWNERS.items()
        },
        'boundaries': {
            'callers': callers_record,
            'downstream': downstream_record,
            'direct_e8_call_sites': {
                hx(FWD1): [hx(va) for va in want_sites[FWD1]],
                hx(FWD2): [hx(va) for va in want_sites[FWD2]],
            },
            'direct_e9_references': {hx(FWD1): [], hx(FWD2): []},
        },
        'trace': traces,
    }


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    report = analyze(data, binary)
    output.mkdir(parents=True, exist_ok=True)
    raw = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    ranges = [
        spec['range']
        for spec in (list(OWNERS.values()) + list(CALLERS.values())
                     + list(DOWNSTREAM.values()))
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
    for name, spec in OWNERS.items():
        owner_exports = {}
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
            owner_exports[window_name] = {
                'file': safe_name,
                'sha256': sha(rendered.encode()),
                'range': [hx(win_start), hx(win_end)],
            }
        exports[name] = owner_exports
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

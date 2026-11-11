#!/usr/bin/env python3
"""Static packet for the source of the X5 closure environment pair.

Question (RE-005 follow-on, node #115): the X4/X5 cell-layouts packet
(PR #3160) pinned that the X5 spawn body copies the closure
environment pair (closure +0x28 data word, closure +0x30 word, the
half the dispatcher stores as the finished cell's vtable) from a
0x20-byte caller argument struct, but left the provenance of that
struct -- who builds it, and what its first two words are -- as a
boundary.  This packet pins the sole caller of the X5 spawn body and
the construction of the argument struct inside it.

Method: authenticated ELF (size + SHA-256 pinned), PT_LOAD based
virtual reads, .eh_frame extents for the three owner bodies pinned
here, .rela.dyn addends for the static slots, and a full .text scan
for direct (rel32) branches and a full writable-segment scan for
stored copies of the spawn body's address.  The result: the pair's
+0x00 word is a boolean the caller derives from its own fourth
argument (1 iff that argument struct's first word equals 1), and the
+0x08 word is the second word of the same argument struct, a pointer
whose first qword the caller increments with a locked xadd before
the call -- the strong count of a reference-counted allocation, not
a static vtable address.  The consumer pinned here (the dispatcher's
second adapter) confirms the typing: it reads the first word as a
byte boolean and dereferences a bool-indexed pointer pair at +0x1f8
of the struct the second word points to.

No captured code is executed.  The check path fails closed:
identity, owner, pin, slot and audit mismatches all raise before any
packet file is regenerated.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-x5-env-pair-source')
RECORDS = PACKET / 'records.json'

EXPECTED_SIZE = 105896032
EXPECTED_SHA256 = (
    'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249'
    'e98c3867b5301')

SPAWN_X5 = 0x5cf6e80
CALLER = 0x5cf5100
CALL_SITE = 0x5cf5347
CALLER_SLOT = 0x64e7718
ADAPTER1_SLOT = 0x64ecb98
ADAPTER2_SLOT = 0x64ecb88

OWNER_STARTS = {
    'schedule_caller_x5': CALLER,
    'adapter2_x5': 0x5cdce30,
    'adapter1_x5': 0x5cdd010,
}

SECTIONS = (
    (CALLER, 'schedule_caller_x5'),
    (0x5cdce30, 'adapter2_x5'),
)

PINS = (
    # schedule_caller_x5: state-struct loads feeding arg words +0x10/+0x18.
    ('schedule_caller_x5', 0x5cf5259, 7),    # mov rax,[state+0x98]
    ('schedule_caller_x5', 0x5cf5269, 4),    # lock incq [rax]
    ('schedule_caller_x5', 0x5cf527a, 7),    # mov rax,[state+0xb8]
    # schedule_caller_x5: the caller-argument pair loads and clone.
    ('schedule_caller_x5', 0x5cf5286, 4),    # mov r15,[rcx_arg+0x00]
    ('schedule_caller_x5', 0x5cf528a, 5),    # mov rbp,[rcx_arg+0x08]
    ('schedule_caller_x5', 0x5cf52dd, 6),    # mov r8d,1
    ('schedule_caller_x5', 0x5cf52e9, 6),    # lock xadd [rbp],r9
    ('schedule_caller_x5', 0x5cf52ef, 4),    # cmp r15,1
    ('schedule_caller_x5', 0x5cf5308, 3),    # xor r8d,r8d
    # schedule_caller_x5: argument-struct stores (struct base rsp+0x20).
    ('schedule_caller_x5', 0x5cf530b, 5),    # mov [rsp+0x20],r8  (+0x00)
    ('schedule_caller_x5', 0x5cf5310, 5),    # mov [rsp+0x28],rbp (+0x08)
    ('schedule_caller_x5', 0x5cf531a, 5),    # mov [rsp+0x38],r15 (+0x18)
    ('schedule_caller_x5', 0x5cf531f, 5),    # mov [rsp+0x30],r13 (+0x10)
    ('schedule_caller_x5', 0x5cf5333, 4),    # mov [rsp],r12 (stack arg)
    ('schedule_caller_x5', 0x5cf5337, 5),    # lea rdi,[rsp+0x8]
    ('schedule_caller_x5', 0x5cf533c, 5),    # lea rsi,[rsp+0x40]
    ('schedule_caller_x5', 0x5cf5347, 5),    # call spawn_x5
    # adapter2_x5: consumption of the pair.
    ('adapter2_x5', 0x5cdcee3, 3),           # movzx eax,byte [rbx]
    ('adapter2_x5', 0x5cdcee6, 4),           # mov rcx,[rbx+0x08]
    ('adapter2_x5', 0x5cdceea, 2),           # xor al,1
    ('adapter2_x5', 0x5cdceef, 3),           # shl eax,6
    ('adapter2_x5', 0x5cdcef2, 8),           # mov rdi,[rcx+rax+0x1f8]
    ('adapter2_x5', 0x5cdcefe, 4),           # mov rsi,[rbx+0x18]
    ('adapter2_x5', 0x5cdcf0a, 4),           # mov rax,[rbx+0x10]
    ('adapter2_x5', 0x5cdcf13, 4),           # lock decq [rax]
)

HEX = '0123456789abcdef'


def hx(value):
    return '0x%x' % value


def parse_loads(data):
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise ValueError('not a little-endian ELF64 image')
    phoff = struct.unpack_from('<Q', data, 0x20)[0]
    phentsize = struct.unpack_from('<H', data, 0x36)[0]
    phnum = struct.unpack_from('<H', data, 0x38)[0]
    loads = []
    for i in range(phnum):
        p_type, _flags, offset, vaddr, _paddr, filesz, _memsz, _al = \
            struct.unpack_from('<IIQQQQQQ', data, phoff + i * phentsize)
        if p_type == 1:
            loads.append((vaddr, offset, filesz))
    if not loads:
        raise ValueError('no PT_LOAD segments')
    return loads


def read(va, data, size):
    for vaddr, offset, filesz in parse_loads(data):
        if vaddr <= va and va + size <= vaddr + filesz:
            off = offset + (va - vaddr)
            return off, data[off:off + size]
    raise ValueError('unmapped read at %s' % hx(va))


def sections(data):
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    shnum = struct.unpack_from('<H', data, 0x3c)[0]
    shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
    raw = []
    for i in range(shnum):
        vals = struct.unpack_from('<IIQQQQIIQQ', data,
                                  shoff + i * shentsize)
        raw.append(vals)
    str_off = raw[shstrndx][4]
    out = {}
    for vals in raw:
        name_off, _t, _f, addr, off, size = vals[0], vals[1], vals[2], \
            vals[3], vals[4], vals[5]
        end = data.index(b'\0', str_off + name_off)
        name = data[str_off + name_off:end].decode()
        out[name] = {'addr': addr, 'offset': off, 'size': size}
    return out


def fde_extents(data):
    sec = sections(data)['.eh_frame']
    off, size, ehva = sec['offset'], sec['size'], sec['addr']
    extents = []
    p, end = off, off + size
    while p < end:
        length = struct.unpack_from('<I', data, p)[0]
        if length == 0:
            break
        hdr = 4
        if length == 0xffffffff:
            length = struct.unpack_from('<Q', data, p + 4)[0]
            hdr = 12
        cie = struct.unpack_from('<i', data, p + hdr)[0]
        if cie != 0:
            body = p + hdr + 4
            val = struct.unpack_from('<i', data, body)[0]
            begin = (ehva + (body - off)) + val
            rng = struct.unpack_from('<I', data, body + 4)[0]
            extents.append((begin, begin + rng))
        p += hdr + length
    return extents


def relocations(data):
    sec = sections(data)['.rela.dyn']
    off, size = sec['offset'], sec['size']
    out = {}
    for p in range(off, off + size, 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, p)
        if (r_info & 0xffffffff) == 8:  # R_X86_64_RELATIVE
            out[r_offset] = r_addend & 0xffffffffffffffff
    return out


def identity(data):
    digest = hashlib.sha256(data).hexdigest()
    return {'size': len(data), 'sha256': digest}


def owners(data):
    extents = fde_extents(data)
    result = {}
    for role, start in OWNER_STARTS.items():
        match = [(b, e) for b, e in extents if b == start]
        if len(match) != 1:
            raise ValueError('FDE extent for %s not found' % role)
        begin, end = match[0]
        off, raw = read(begin, data, end - begin)
        result[role] = {
            'start': hx(begin),
            'end': hx(end),
            'file_offset': hx(off),
            'bytes': end - begin,
            'sha256': hashlib.sha256(raw).hexdigest(),
        }
    return result


def slot_targets(data):
    rel = relocations(data)
    result = {}
    for name, slot in (('caller_table_slot', CALLER_SLOT),
                       ('x5_adapter1_slot', ADAPTER1_SLOT),
                       ('x5_adapter2_slot', ADAPTER2_SLOT)):
        if slot not in rel:
            raise ValueError('slot %s has no RELATIVE relocation'
                             % hx(slot))
        result[name] = {'slot': hx(slot), 'target': hx(rel[slot])}
    return result


def direct_branch_hits(data, target):
    sec = sections(data)['.text']
    base, off, size = sec['addr'], sec['offset'], sec['size']
    hits = []
    for op, name in ((0xE8, 'call'), (0xE9, 'jmp')):
        needle = bytes([op])
        idx, limit = off, off + size - 5
        while idx < limit:
            j = data.find(needle, idx, limit + 1)
            if j < 0:
                break
            rel = struct.unpack_from('<i', data, j + 1)[0]
            va = base + (j - off)
            if va + 5 + rel == target:
                hits.append({'site': hx(va), 'kind': name})
            idx = j + 1
    return hits


def stored_copies(data, value):
    """Occurrences of a qword value inside the writable PT_LOADs."""
    needle = struct.pack('<Q', value)
    hits = []
    for vaddr, offset, filesz in parse_loads(data):
        writable = False
        phoff = struct.unpack_from('<Q', data, 0x20)[0]
        phentsize = struct.unpack_from('<H', data, 0x36)[0]
        phnum = struct.unpack_from('<H', data, 0x38)[0]
        for i in range(phnum):
            p_type, flags, off2, va2 = struct.unpack_from(
                '<IIQQ', data, phoff + i * phentsize)
            if p_type == 1 and va2 == vaddr and off2 == offset:
                writable = bool(flags & 2)
        if not writable:
            continue
        idx = offset
        while True:
            j = data.find(needle, idx, offset + filesz)
            if j < 0:
                break
            hits.append(hx(vaddr + (j - offset)))
            idx = j + 1
    return hits


def reference_audit(data):
    rel = relocations(data)
    spawn_reloc = sorted(hx(o) for o, a in rel.items() if a == SPAWN_X5)
    caller_reloc = sorted(hx(o) for o, a in rel.items() if a == CALLER)
    return {
        'spawn_x5': {
            'address': hx(SPAWN_X5),
            'direct_branches': direct_branch_hits(data, SPAWN_X5),
            'reloc_addend_slots': spawn_reloc,
            'stored_copies_writable': stored_copies(data, SPAWN_X5),
        },
        'schedule_caller_x5': {
            'address': hx(CALLER),
            'direct_branches': direct_branch_hits(data, CALLER),
            'reloc_addend_slots': caller_reloc,
            'stored_copies_writable': stored_copies(data, CALLER),
        },
    }


def pins(data):
    grouped = {name: [] for _addr, name in SECTIONS}
    for section, addr, size in PINS:
        _off, raw = read(addr, data, size)
        grouped[section].append({
            'address': hx(addr),
            'bytes': raw.hex(),
            'size': size,
        })
    return grouped


def check_pins(data):
    recorded = load_records()['pins']
    current = pins(data)
    if current != recorded:
        raise ValueError('instruction pins do not match records.json')
    return current


def build_records(data):
    ident = identity(data)
    if ident['size'] != EXPECTED_SIZE or \
            ident['sha256'] != EXPECTED_SHA256:
        raise ValueError('artifact identity mismatch: %r' % (ident,))
    own = owners(data)
    expected_owners = {
        'schedule_caller_x5': ('0x5cf5100', '0x5cf55d7', 1239),
        'adapter2_x5': ('0x5cdce30', '0x5cdd008', 472),
        'adapter1_x5': ('0x5cdd010', '0x5cdd032', 34),
    }
    for role, (start, end, size) in expected_owners.items():
        rec = own[role]
        if (rec['start'], rec['end'], rec['bytes']) != (start, end, size):
            raise ValueError('owner extent mismatch for %s' % role)
    slots = slot_targets(data)
    if slots['caller_table_slot']['target'] != hx(CALLER) or \
            slots['x5_adapter1_slot']['target'] != '0x5cdd010' or \
            slots['x5_adapter2_slot']['target'] != '0x5cdce30':
        raise ValueError('slot target mismatch')
    audit = reference_audit(data)
    if audit['spawn_x5']['direct_branches'] != \
            [{'site': hx(CALL_SITE), 'kind': 'call'}] or \
            audit['spawn_x5']['reloc_addend_slots'] or \
            audit['spawn_x5']['stored_copies_writable'] or \
            audit['schedule_caller_x5']['direct_branches'] or \
            audit['schedule_caller_x5']['reloc_addend_slots'] != \
            [hx(CALLER_SLOT)] or \
            audit['schedule_caller_x5']['stored_copies_writable']:
        raise ValueError('reference audit mismatch')
    return {
        'answer': {
            'pair_provenance': [
                {
                    'closure_offset': '0x28',
                    'arg_struct_offset': '0x00',
                    'source': 'boolean derived in the caller: 1 if the '
                              "first word of the caller's fourth-"
                              'argument struct equals 1, else 0',
                    'store_site': '0x5cf530b',
                },
                {
                    'closure_offset': '0x30',
                    'arg_struct_offset': '0x08',
                    'source': 'second word of the caller\'s fourth-'
                              'argument struct, a pointer whose first '
                              'qword the caller increments with a '
                              'locked xadd (strong-count clone of a '
                              'reference-counted allocation) before '
                              'the call',
                    'store_site': '0x5cf5310',
                },
                {
                    'closure_offset': '0x38',
                    'arg_struct_offset': '0x10',
                    'source': 'caller state struct field +0x98, a '
                              'pointer whose first qword the caller '
                              'increments with a locked inc before '
                              'the call',
                    'store_site': '0x5cf531f',
                },
                {
                    'closure_offset': '0x40',
                    'arg_struct_offset': '0x18',
                    'source': 'caller state struct field +0xb8, a '
                              'plain word copied unchanged',
                    'store_site': '0x5cf531a',
                },
            ],
            'static_vtable': 'neither pair word is a static address: '
                             'no load of a static vtable feeds either '
                             'store in the sole caller; the +0x30 word '
                             'is a per-instance heap pointer',
        },
        'artifact': {
            'path': 'artifacts/node/115/hl-node',
            'size': ident['size'],
            'sha256': ident['sha256'],
        },
        'boundaries': {
            'caller_reachability': (
                'The caller body itself has no direct callers in '
                '.text; one RELATIVE relocation (slot 0x64e7718) '
                'stores its address in a writable static table. '
                'Which consumer loads that slot, and so how control '
                'reaches the caller, is not pinned here.'),
            'concrete_type_names': (
                'The concrete Rust type of the reference-counted '
                'struct behind the pair +0x08 word, of the caller '
                'fourth-argument struct, and of the caller state '
                'struct is not named: no symbol or string in the '
                'binary ties a type name to them. What is pinned is '
                'their shape: a strong count at +0x00 of the pair '
                'target, a bool-indexed pointer pair at +0x1f8 of '
                'the pair target (two 0x40-strided entries, the '
                'selected entry +0x10 passed on with the closure '
                '+0x40 word by the second adapter), and the state '
                'fields +0x98 (reference-counted) and +0xb8 (plain '
                'word).'),
            'state_field_provenance': (
                'Where the caller state struct fields +0x98 and '
                '+0xb8 themselves come from is not traced here; '
                'this packet pins only that the caller reads them '
                'out of the state struct it is handed.'),
            'runtime_behaviour': (
                'Which of the two bool-indexed entries is taken at '
                'run time, and what the called entry does with the '
                'closure +0x40 word, are run-time questions; only '
                'the static selection shape is pinned.'),
        },
        'captured_code_executed': False,
        'owners': own,
        'pins': pins(data),
        'reference_audit': audit,
        'slots': slots,
    }


def canonical(records):
    return json.dumps(records, indent=1, sort_keys=True) + '\n'


def load_records():
    return json.loads(RECORDS.read_text())


def generate():
    data = TARGET.read_bytes()
    records = build_records(data)
    PACKET.mkdir(parents=True, exist_ok=True)
    RECORDS.write_text(canonical(records))
    print('wrote', RECORDS)


def check():
    data = TARGET.read_bytes()
    records = build_records(data)
    recorded = load_records()
    if canonical(records) != canonical(recorded):
        raise ValueError('records.json does not match the artifact')
    print('records.json matches the authenticated artifact')


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('generate', 'check'):
        raise SystemExit('usage: packet_env_pair_x5_static.py '
                         'generate|check')
    if sys.argv[1] == 'generate':
        generate()
    else:
        check()

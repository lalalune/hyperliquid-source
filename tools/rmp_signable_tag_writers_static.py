#!/usr/bin/env python3
"""Static trace of the two writer trails above the RE-005 tag sources.

The tag-source packet (#2444) showed that, on the grand_b path, the byte
that decides the rmp-signable serializer's emitted tag (0x61 iff the byte
is 3, else 0x62) is loaded fresh from the context object's +0x1e8 field
in FDEs 0x2ae41e0 (B2) and 0x2cde430 (B3), where the only in-FDE store
writes the low byte of the dword at obj +0xa0 during the entry staging
arm, and from [arg2 +0xbd5] in FDE 0x2e098e0 (B4). This packet traces
the two writer trails one level up:

Trail 1 (B2/B3 +0xa0 staging dword). Both staging arms build the same
0x250-byte record on the frame (B3 through the buffer converter
0x2b7b640) and run the same four helpers over it: the head emitter
0x1506840 (slot 0x64e0a80, traced as an owner in the scratch-name-pair
packet #2317), the default constructor 0x163a4b0 (slot 0x64e1d08), the
spec builder 0x564d700 (slot 0x64e73c0) and the value producer 0x165de90
(slot 0x64e1da8), finished by the apply function 0x564cce0 (slot
0x64e73c8). The constructor zero-writes the record's +0x90 qword; the
apply function is the effective writer of the byte: it reads the
value's "chain" field, classifies the name (Local 0, Sandbox 1,
Testnet 2, Mainnet 3) and stores the class as a single byte at record
+0x90 (0x564ceb5). An unrecognised name reaches the `Result::unwrap()`
panic path and no byte is written. The staging store in B2
(0x2ae447f) and the converter memcpy in B3 then carry record +0x90 into
obj +0xa0, whose low byte lands in obj +0x1e8.

Trail 2 (B4 +0xbd5 byte). B4's only caller, 0x2af77f0 (Z), passes
arg2 = its own rdi object's +0xca0 sub-object, staged at Z entry by a
0xbd8-byte memcpy (0x2af784b) plus movups tail copies from the object
itself. Z's body contains no occurrence of the byte sequence
d5 0b 00 00 at all, so no instruction in Z addresses offset +0xbd5:
the byte B4 reads is the object's own +0xbd5 byte, copied verbatim by
the staging memcpy. Above Z the trail is data-only.

Captured code is never executed; every claim is a byte pin, an
instruction-start-validated census, or a relocation binding read from
the authenticated node #115 artifact.
"""
import argparse
import bisect
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export, require

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
PACKET = ROOT / 'research/work-items/RE-005-node115-rmp-signable-tag-writers'

CTOR = (0x163a4b0, 0x163a66c)
APPLY = (0x564cce0, 0x564cf36)
SPEC = (0x564d700, 0x564df8c)
CONV = (0x2b7b640, 0x2b7b79c)
CALLER_Y = (0x2b404b0, 0x2b40666)
CALLER_X = (0x2ae1690, 0x2ae27b2)
CALLER_Z = (0x2af77f0, 0x2af8bd3)
B2 = (0x2ae41e0, 0x2ae6d66)
B3 = (0x2cde430, 0x2ce0dd1)
B4 = (0x2e098e0, 0x2e11140)

OWNERS = {'record_constructor': CTOR, 'chain_class_writer': APPLY,
          'spec_builder': SPEC, 'buffer_converter': CONV,
          'b2_tls_caller': CALLER_Y, 'b2_b3_caller': CALLER_X,
          'b4_caller_stager': CALLER_Z}
REF_BODIES = {'gb_b2': B2, 'gb_b3': B3, 'gb_b4': B4}

SLOTS = {0x64e0a80: (0x1506840, 'record_head_emitter'),
         0x64e73c0: (0x564d700, 'spec_builder'),
         0x64e73c8: (0x564cce0, 'chain_class_writer'),
         0x64e1d08: (0x163a4b0, 'record_constructor'),
         0x64e1da8: (0x165de90, 'value_producer'),
         0x64ebcb0: (0x5654bf0, 'range_converter'),
         0x64df6a0: (0x1680c30, 'panic_formatter'),
         0x64df830: (0x1680c10, 'panic_stub')}
MEMCPY_SLOT = 0x64df508

CHAIN_NAME_VA = 0x92a7be
KEY_NAME_VA = 0x92ab2c
NODE_NAME_VA = 0x92a890
UNWRAP_STR_VA = 0x92a732
DESC_STR_VA = 0x92ac70
STAMP_STR_VA = 0x92a8d9
GETTER = 0x4e4ca30


def read(data, va, n):
    for sec in sections(data):
        if sec['type'] != 8 and sec['address'] <= va and va + n <= sec['address'] + sec['size']:
            return data[sec['offset'] + va - sec['address']:sec['offset'] + va - sec['address'] + n]
    raise ValueError(f'unmapped read {va:#x}+{n}')


def relocations(data):
    """All .rela.dyn entries as (slot, type, addend, addend file offset)."""
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    out = []
    for i, (off, info, add) in enumerate(
            struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']])):
        out.append((off, info & 0xffffffff, add, sec['offset'] + 24 * i + 16, info >> 32))
    return out


def dynsym_name(data, index):
    sym = next(s for s in sections(data) if s['name'] == '.dynsym')
    strs = next(s for s in sections(data) if s['name'] == '.dynstr')
    st_name = struct.unpack_from('<I', data, sym['offset'] + 24 * index)[0]
    start = strs['offset'] + st_name
    return data[start:data.index(b'\0', start)].decode()


def _pin(body, base, va, hexbytes, what):
    want = bytes.fromhex(hexbytes)
    if body[va - base:va - base + len(want)] != want:
        raise ValueError(f'byte pin failed for {what} at {va:#x}')


def _call_target(body, base, va, insn_len=5):
    disp = struct.unpack_from('<i', body, va - base + 1)[0]
    return va + insn_len + disp


def _slot_target(body, base, va):
    disp = struct.unpack_from('<i', body, va - base + 2)[0]
    return va + 6 + disp


def _lea_target(body, base, va, insn_len=7):
    disp = struct.unpack_from('<i', body, va - base + 3)[0]
    return va + insn_len + disp


def call_census(data, targets):
    """Every direct call/jump site in .text for each target VA, with the
    containing FDE for each site. targets maps role -> VA. Sites are raw
    byte-pattern hits; sites inside packet owners are additionally
    validated as instruction starts by generate()."""
    text = next(s for s in sections(data) if s['name'] == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    _summary, extents, _records = fde_extents(data)
    starts = sorted(e['start'] for e in extents)
    ends = {e['start']: e['end'] for e in extents}

    def owner(va):
        i = bisect.bisect_right(starts, va) - 1
        return starts[i] if i >= 0 and starts[i] <= va < ends[starts[i]] else None

    by_va = {va: role for role, va in targets.items()}
    found = {role: [] for role in targets}
    for opcode in (b'\xe8', b'\xe9'):
        idx = blob.find(opcode)
        while idx != -1:
            site = base + idx
            tgt = site + 5 + struct.unpack_from('<i', blob, idx + 1)[0]
            if tgt in by_va:
                own = owner(site)
                role = next((r for r, rng in list(OWNERS.items()) + list(REF_BODIES.items())
                             if rng[0] == own), None)
                found[by_va[tgt]].append({'site': hex(site),
                                          'kind': 'call' if opcode == b'\xe8' else 'jump',
                                          'owner': role,
                                          'owner_start': hex(own) if own else None})
            idx = blob.find(opcode, idx + 1)
    return found


def slot_census(data, slot):
    """Every ff 15 / ff 25 RIP-relative reference to a slot in .text,
    with the containing FDE for each site."""
    text = next(s for s in sections(data) if s['name'] == '.text')
    blob = data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    _summary, extents, _records = fde_extents(data)
    starts = sorted(e['start'] for e in extents)
    ends = {e['start']: e['end'] for e in extents}

    def owner(va):
        i = bisect.bisect_right(starts, va) - 1
        return starts[i] if i >= 0 and starts[i] <= va < ends[starts[i]] else None

    found = []
    for opcode, kind in ((b'\xff\x15', 'call'), (b'\xff\x25', 'jump')):
        idx = blob.find(opcode)
        while idx != -1:
            site = base + idx
            if site + 6 + struct.unpack_from('<i', blob, idx + 2)[0] == slot:
                own = owner(site)
                role = next((r for r, rng in list(OWNERS.items()) + list(REF_BODIES.items())
                             if rng[0] == own), None)
                found.append({'site': hex(site), 'kind': kind, 'owner': role,
                              'owner_start': hex(own) if own else None})
            idx = blob.find(opcode, idx + 1)
    return sorted(found, key=lambda r: int(r['site'], 16))


def store_census32(body, base, base_rm, disps):
    """VAs of candidate disp32 store instructions in body whose ModRM
    base register is base_rm (mod=10). Covers the REX/no-REX mov-store
    forms (88/89/c7) and the SSE store forms (0f 11 / 0f 29) this
    binary uses. Raw pattern census over the given displacement set;
    every hit in this packet is additionally pinned or enumerated in
    the retained exports."""
    prefixes = (b'', b'\x40', b'\x41', b'\x44', b'\x45', b'\x48', b'\x49', b'\x4c', b'\x4d')
    modrms = [0x80 | (reg << 3) | base_rm for reg in range(8)]
    raw = []
    for prefix in prefixes:
        for opcode in (b'\x88', b'\x89', b'\xc7'):
            for modrm in modrms:
                for disp in disps:
                    pat = prefix + opcode + bytes([modrm]) + struct.pack('<i', disp)
                    idx = body.find(pat)
                    while idx != -1:
                        raw.append((idx, len(pat)))
                        idx = body.find(pat, idx + 1)
        for opcode in (b'\x0f\x11', b'\x0f\x29'):
            for modrm in modrms:
                for disp in disps:
                    pat = prefix + opcode + bytes([modrm]) + struct.pack('<i', disp)
                    idx = body.find(pat)
                    while idx != -1:
                        raw.append((idx, len(pat)))
                        idx = body.find(pat, idx + 1)
    # The same instruction matches once per prefix variant (with and
    # without its REX byte); keep the longest match at each start and
    # drop matches that begin inside an already-kept match.
    hits = []
    covered_until = -1
    for idx, length in sorted(raw, key=lambda t: (t[0], -t[1])):
        if idx < covered_until:
            continue
        hits.append(base + idx)
        covered_until = idx + length
    return hits

CTOR_PINS = [
    (0x163a4be, '0f114720', 'record +0x20 takes the key head (movups from key)'),
    (0x163a4b7, '48894f30', 'record +0x30 takes the key tail qword'),
    (0x163a4d0, '48c7878000000000000000', 'record +0x80 qword = 0'),
    (0x163a4db, '48c7879000000000000000', 'record +0x90 qword = 0 (zeroing store)'),
    (0x163a4e6, '48c787a000000000000000', 'record +0xa0 qword = 0'),
    (0x163a53b, '48c78710010000e7030000', 'record +0x110 = 0x3e7 default'),
    (0x163a560, '48c787e801000000070201', 'record +0x1e8 default = 0x1020700'),
]
APPLY_PINS = [
    (0x564ccf7, '488d35c0da2dfb', 'lea rsi = chain field name'),
    (0x564cd06, 'e825fd7fff', 'call the field getter for "chain"'),
    (0x564cd14, '4883fa07', 'dispatch: chain name length 7'),
    (0x564cd1a, '4883fa05', 'dispatch: chain name length 5'),
    (0x564cd20, 'b94c6f6361', 'Local first-dword immediate 0x61636f4c'),
    (0x564cd2b, '83f06c', 'Local last-byte xor immediate 0x6c'),
    (0x564cd32, '31ed', 'class 0: xor ebp,ebp (Local)'),
    (0x564cd36, 'b953616e64', 'Sandbox first-dword immediate 0x646e6153'),
    (0x564cd3d, 'ba64626f78', 'Sandbox tail-dword immediate 0x786f6264'),
    (0x564cd97, '40b501', 'class 1: mov bpl,1 (Sandbox)'),
    (0x564cd49, 'b954657374', 'Testnet first-dword immediate 0x74736554'),
    (0x564cd50, 'ba746e6574', 'Testnet tail-dword immediate 0x74656e74'),
    (0x564cd9c, '40b502', 'class 2: mov bpl,2 (Testnet)'),
    (0x564cd5c, 'b94d61696e', 'Mainnet first-dword immediate 0x6e69614d'),
    (0x564cd63, 'ba6e6e6574', 'Mainnet tail-dword immediate 0x74656e6e'),
    (0x564cd6b, '40b503', 'class 3: mov bpl,3 (Mainnet)'),
    (0x564cd72, '488d3db9d92dfb', 'lea rdi = unwrap error string'),
    (0x564cd91, 'ff150929e900', 'call the panic formatter slot (unmatched name)'),
    (0x564cd9f, '488d3586dd2dfb', 'lea rsi = key field name'),
    (0x564ce57, 'ff1553eee900', 'call the range converter slot'),
    (0x564ce5d, '837c242010', 'converted tag dword == 0x10 aborts'),
    (0x564ce70, '48894370', 'record +0x70 = converted struct tail qword'),
    (0x564ce7c, '0f114360', 'record +0x60 movups store'),
    (0x564ce85, '0f114350', 'record +0x50 movups store'),
    (0x564ce8e, '0f114340', 'record +0x40 movups store'),
    (0x564cea6, '0f115b30', 'record +0x30 movups store'),
    (0x564ceaa, '0f115320', 'record +0x20 movups store'),
    (0x564ceae, '0f114b10', 'record +0x10 movups store'),
    (0x564ceb2, '0f1103', 'record +0x0 movups store'),
    (0x564ceb5, '4088ab90000000', 'THE BYTE STORE: record +0x90 = class byte'),
    (0x564cebc, '4c897b78', 'record +0x78 = key string field 0'),
    (0x564cec0, '4c89a380000000', 'record +0x80 = key string pointer'),
    (0x564cec7, '4c89bb88000000', 'record +0x88 = key string field 2'),
]
SPEC_PINS = [
    (0x564d725, '488986b0000000', 'record +0xb0 = description pointer (record store 1 of 2)'),
    (0x564d72c, '48c786b800000030000000', 'record +0xb8 = 0x30 (record store 2 of 2)'),
    (0x564d74b, '41ffd4', 'memcpy through r12 copies the record OUT to the frame'),
    (0x564de7f, '48898390000000', 'OUT struct +0x90 = build stamp pointer (not the record)'),
    (0x564de86, '48c7839800000054000000', 'OUT struct +0x98 = 0x54 (not the record)'),
]
CONV_PINS = [
    (0x2b7b654, 'ff15263e9603', 'call the allocator slot for the name buffer'),
    (0x2b7b663, '8b0d2af2dafd', 'load the "hl-node" first dword'),
    (0x2b7b66c, '8b0d1ef2dafd', 'load the "hl-node" tail dword'),
    (0x2b7b674, '48c744245007000000', 'key length = 7'),
    (0x2b7b69b, 'ff1567669603', 'call the constructor slot'),
    (0x2b7b6ac, 'ff150ebd9603', 'call the spec builder slot'),
    (0x2b7b6b8, 'ff15ea669603', 'call the value producer slot'),
    (0x2b7b6f2, '48c70310000000', 'default branch: out dword = 0x10, no apply call'),
    (0x2b7b73f, 'ff1583bc9603', 'call the apply slot'),
    (0x2b7b75d, 'ff15a53d9603', 'memcpy the record head (0x98 bytes) to out'),
]
Y_PINS = [
    (0x2b404f7, '498b2c24', 'rbp = [arg3] (the context cell)'),
    (0x2b40560, '646641c74424440180', 'TLS flag word = 0x8001 around the call'),
    (0x2b40573, '488b7d00', 'B2 arg1 = [rbp] (the context object)'),
    (0x2b40577, 'e8643cfaff', 'call B2'),
]
X_PINS = [
    (0x2ae19b7, '4c8da424a85a0000', 'r12 = frame context object at rsp+0x5aa8'),
    (0x2ae1a41, '4c89e7', 'B2 arg1 = r12'),
    (0x2ae1a44, '4c89ee', 'B2 arg2 = frame buffer rsp+0xb0'),
    (0x2ae1a47, 'e894270000', 'call B2'),
    (0x2ae1edb, '488dbc2480000000', 'B3 arg1 = frame holder at rsp+0x80'),
    (0x2ae1ee3, '488db424682e0000', 'B3 arg2 = frame buffer rsp+0x2e68'),
    (0x2ae1eeb, 'e840c51f00', 'call B3'),
]
Z_PINS = [
    (0x2af7813, '0fb687ca1a0000', 'mode byte load [obj +0x1aca]'),
    (0x2af7839, '4c8dbfa00c0000', 'r15 = obj +0xca0 (the staged copy base)'),
    (0x2af7840, 'bad80b0000', 'staging memcpy length = 0xbd8 (covers +0xbd5)'),
    (0x2af784b, 'ff15b77c9e03', 'staging memcpy call (obj -> obj +0xca0)'),
    (0x2af7851, '0f1083d80b0000', 'tail copy loads [obj +0xbd8]'),
    (0x2af786d, '0f118378180000', 'tail copy stores [obj +0x1878] = staged +0xbd8'),
    (0x2af7f42, '488d83a00c0000', 'rax = obj +0xca0'),
    (0x2af7f49, '4889442420', '[rsp+0x20] = rax (the B4 arg2 slot)'),
    (0x2af80a2, 'bab0000000', 'memcpy length 0xb0 for the rsp+0x260 block'),
    (0x2af80aa, 'ff1558749e03', 'memcpy call for the rsp+0x260 block'),
    (0x2af80bf, '4c89ee', 'B4 arg2 = r13 = [rsp+0x20]'),
    (0x2af80c5, 'e816183100', 'call B4'),
]
OWNER_PINS = {'record_constructor': CTOR_PINS, 'chain_class_writer': APPLY_PINS,
              'spec_builder': SPEC_PINS, 'buffer_converter': CONV_PINS,
              'b2_tls_caller': Y_PINS, 'b2_b3_caller': X_PINS,
              'b4_caller_stager': Z_PINS}
REF_PINS = {
    'gb_b2': [
        (0x2ae4281, 'ff15f9c79f03', 'call the emitter slot'),
        (0x2ae42dc, 'ff1526da9f03', 'call the constructor slot'),
        (0x2ae42f5, 'ff15c530a003', 'call the spec builder slot'),
        (0x2ae430b, 'ff1597da9f03', 'call the value producer slot'),
        (0x2ae437a, 'ff154830a003', 'call the apply slot'),
        (0x2ae447f, '48898ba0000000', 'obj +0xa0 = record +0x90 qword'),
        (0x2ae44c8, '8bbba0000000', 'load edi from [obj +0xa0]'),
        (0x2ae44ce, '4088bbe8010000', 'obj +0x1e8 byte = low byte of the +0xa0 dword'),
    ],
    'gb_b3': [
        (0x2cde525, 'ff1555258003', 'call the emitter slot'),
        (0x2cde533, 'e808d1e9ff', 'call the buffer converter'),
        (0x2cde55e, 'ff15a40f8003', 'memcpy the converted record head into obj +0x10'),
        (0x2cde564, '418bbda0000000', 'load edi from [obj +0xa0]'),
        (0x2cde56b, '4188bde8010000', 'obj +0x1e8 byte = low byte of the +0xa0 dword'),
    ],
    'gb_b4': [
        (0x2e09b01, '450fb6bfd50b0000', 'tag byte load site 1 from [arg2 +0xbd5]'),
        (0x2e09f87, '450fb6bfd50b0000', 'tag byte load site 2 from [arg2 +0xbd5]'),
        (0x2e0b060, '4881c6d50b0000', 'add rsi,0xbd5 forms the descriptor pointer (no write)'),
    ],
}


def _imm32(body, base, va):
    return struct.unpack_from('<I', body, va - base)[0]


def _le_bytes(value, n):
    return value.to_bytes(n, 'little')


def analyze(data):
    require(len(data) == TARGET_SIZE, 'expected pinned node115')
    bodies = {role: read(data, s, e - s) for role, (s, e) in OWNERS.items()}
    refs = {name: read(data, s, e - s) for name, (s, e) in REF_BODIES.items()}

    # --- relocation bindings for every slot this packet reasons about ---
    by_slot = {off: (typ, add, sym) for off, typ, add, _o, sym in relocations(data)}
    bindings = {}
    for slot, (target, name) in SLOTS.items():
        typ, add, _sym = by_slot[slot]
        require(typ == 8 and add == target, f'slot {slot:#x} binding changed')
        bindings[hex(slot)] = {'target': hex(target), 'name': name, 'rela_type': typ}
    typ, _add, sym = by_slot[MEMCPY_SLOT]
    require(typ == 6 and dynsym_name(data, sym) == 'memcpy', 'memcpy slot binding changed')
    bindings[hex(MEMCPY_SLOT)] = {'target': 'memcpy', 'name': 'memcpy', 'rela_type': typ}

    # --- byte pins ---
    for role, pins in OWNER_PINS.items():
        for va, hx, what in pins:
            _pin(bodies[role], OWNERS[role][0], va, hx, what)
    for name, pins in REF_PINS.items():
        for va, hx, what in pins:
            _pin(refs[name], REF_BODIES[name][0], va, hx, what)

    abody, abase = bodies['chain_class_writer'], APPLY[0]
    # --- apply: names, getter, classification decoded from the bytes ---
    require(_lea_target(abody, abase, 0x564ccf7) == CHAIN_NAME_VA, 'chain lea target changed')
    require(read(data, CHAIN_NAME_VA, 5) == b'chain', 'chain field name changed')
    require(_call_target(abody, abase, 0x564cd06) == GETTER, 'getter call target changed')
    require(_lea_target(abody, abase, 0x564cd9f) == KEY_NAME_VA, 'key lea target changed')
    require(read(data, KEY_NAME_VA, 3) == b'key', 'key field name changed')
    require(_lea_target(abody, abase, 0x564cd72) == UNWRAP_STR_VA, 'unwrap lea target changed')
    require(read(data, UNWRAP_STR_VA, 43) == b'called `Result::unwrap()` on an `Err` value',
            'unwrap string changed')
    require(_slot_target(abody, abase, 0x564cd91) == 0x64df6a0, 'panic formatter slot changed')
    require(_slot_target(abody, abase, 0x564ce57) == 0x64ebcb0, 'range converter slot changed')
    local = _le_bytes(_imm32(abody, abase, 0x564cd21), 4) + b'l'
    sandbox = _le_bytes(_imm32(abody, abase, 0x564cd37), 4)[:3] + _le_bytes(_imm32(abody, abase, 0x564cd3e), 4)
    testnet = _le_bytes(_imm32(abody, abase, 0x564cd4a), 4)[:3] + _le_bytes(_imm32(abody, abase, 0x564cd51), 4)
    mainnet = _le_bytes(_imm32(abody, abase, 0x564cd5d), 4)[:3] + _le_bytes(_imm32(abody, abase, 0x564cd64), 4)
    require(local == b'Local' and sandbox == b'Sandbox' and
            testnet == b'Testnet' and mainnet == b'Mainnet',
            'chain classification names changed')
    classes = {'Local': 0, 'Sandbox': 1, 'Testnet': 2, 'Mainnet': 3}

    # --- record-name and spec-string constants ---
    require(read(data, NODE_NAME_VA, 7) == b'hl-node', 'node name changed')
    require(read(data, DESC_STR_VA, 0x30) == b'Reference implementation of Hyperliquid protocol',
            'description string changed')
    require(read(data, STAMP_STR_VA, 0x54) ==
            b'28076c144c66d3f34ca321ac85ca19f461ade137|2026-10-25 16:48:13 +0800|uncommitted=false',
            'build stamp string changed')

    # --- call-target verification at the pinned sites ---
    ybody, ybase = bodies['b2_tls_caller'], CALLER_Y[0]
    xbody, xbase = bodies['b2_b3_caller'], CALLER_X[0]
    zbody, zbase = bodies['b4_caller_stager'], CALLER_Z[0]
    cbody, cbase = bodies['buffer_converter'], CONV[0]
    require(_call_target(ybody, ybase, 0x2b40577) == B2[0], 'Y -> B2 call target changed')
    require(_call_target(xbody, xbase, 0x2ae1a47) == B2[0], 'X -> B2 call target changed')
    require(_call_target(xbody, xbase, 0x2ae1eeb) == B3[0], 'X -> B3 call target changed')
    require(_call_target(zbody, zbase, 0x2af80c5) == B4[0], 'Z -> B4 call target changed')
    require(_call_target(refs['gb_b3'], B3[0], 0x2cde533) == CONV[0], 'B3 -> converter call target changed')
    for body, base, va, slot in (
            (refs['gb_b2'], B2[0], 0x2ae4281, 0x64e0a80), (refs['gb_b2'], B2[0], 0x2ae42dc, 0x64e1d08),
            (refs['gb_b2'], B2[0], 0x2ae42f5, 0x64e73c0), (refs['gb_b2'], B2[0], 0x2ae430b, 0x64e1da8),
            (refs['gb_b2'], B2[0], 0x2ae437a, 0x64e73c8), (refs['gb_b3'], B3[0], 0x2cde525, 0x64e0a80),
            (refs['gb_b3'], B3[0], 0x2cde55e, MEMCPY_SLOT),
            (cbody, cbase, 0x2b7b69b, 0x64e1d08), (cbody, cbase, 0x2b7b6ac, 0x64e73c0),
            (cbody, cbase, 0x2b7b6b8, 0x64e1da8), (cbody, cbase, 0x2b7b73f, 0x64e73c8),
            (cbody, cbase, 0x2b7b75d, MEMCPY_SLOT),
            (zbody, zbase, 0x2af784b, MEMCPY_SLOT), (zbody, zbase, 0x2af80aa, MEMCPY_SLOT)):
        require(_slot_target(body, base, va) == slot, f'slot call target changed at {va:#x}')

    # --- censuses ---
    census = call_census(data, {'b2': B2[0], 'b3': B3[0], 'b4': B4[0], 'conv': CONV[0],
                                'caller_x': CALLER_X[0], 'caller_y': CALLER_Y[0],
                                'caller_z': CALLER_Z[0]})
    require([(s['site'], s['owner']) for s in census['b2']] ==
            [('0x2ae1a47', 'b2_b3_caller'), ('0x2b40577', 'b2_tls_caller')], 'B2 caller census changed')
    require([(s['site'], s['owner']) for s in census['b3']] ==
            [('0x2ae1eeb', 'b2_b3_caller')], 'B3 caller census changed')
    require([(s['site'], s['owner']) for s in census['b4']] ==
            [('0x2af80c5', 'b4_caller_stager')], 'B4 caller census changed')
    require([(s['site'], s['owner']) for s in census['conv']] ==
            [('0x2cde533', 'gb_b3')], 'converter caller census changed')
    require([(s['site'], s['owner_start']) for s in census['caller_x']] ==
            [('0x2cd83a2', '0x2cd8370')], 'X caller census changed')
    require([(s['site'], s['owner_start']) for s in census['caller_y']] ==
            [('0x2453673', '0x24535c0')], 'Y caller census changed')
    require(census['caller_z'] == [], 'Z caller census changed')
    slot_refs = {name: slot_census(data, slot) for slot, (_t, name) in SLOTS.items()
                 if slot in (0x64e0a80, 0x64e73c0, 0x64e73c8, 0x64e1d08, 0x64e1da8)}
    require([(s['site'], s['owner']) for s in slot_refs['spec_builder']] ==
            [('0x2ae42f5', 'gb_b2'), ('0x2b7b6ac', 'buffer_converter')], 'spec slot census changed')
    require([(s['site'], s['owner']) for s in slot_refs['chain_class_writer']] ==
            [('0x2ae437a', 'gb_b2'), ('0x2b7b73f', 'buffer_converter')], 'apply slot census changed')
    require([(s['site'], s['owner']) for s in slot_refs['value_producer']] ==
            [('0x2ae430b', 'gb_b2'), ('0x2b7b6b8', 'buffer_converter')], 'value producer slot census changed')
    require([(s['site'], s['owner']) for s in slot_refs['record_head_emitter']] ==
            [('0x2ae4281', 'gb_b2'), ('0x2aeb2e0', None), ('0x2cb68f0', None), ('0x2cde525', 'gb_b3')],
            'emitter slot census changed')
    ctor_sites = slot_refs['record_constructor']
    require(len(ctor_sites) == 16 and
            [(s['site'], s['owner']) for s in ctor_sites[:2]] ==
            [('0x2ae42dc', 'gb_b2'), ('0x2b7b69b', 'buffer_converter')] and
            all(s['owner_start'] == '0x564e1a0' for s in ctor_sites[2:]),
            'constructor slot census changed')

    # --- store censuses over the record span ---
    apply_span = store_census32(abody, abase, 3, (0x88, 0x90, 0x98))
    require(apply_span == [0x564ceb5, 0x564cec7], 'apply +0x88..0x98 store census changed')
    spec_span = store_census32(bodies['spec_builder'], SPEC[0], 6, (0x88, 0x90, 0x98))
    require(spec_span == [], 'spec builder +0x88..0x98 store census changed')
    spec_writes = store_census32(bodies['spec_builder'], SPEC[0], 6, (0xb0, 0xb8))
    require(spec_writes == [0x564d725, 0x564d72c], 'spec builder record store census changed')
    ctor_writes = store_census32(bodies['record_constructor'], CTOR[0], 7, (0x80, 0x90, 0xa0))
    require(ctor_writes == [0x163a4d0, 0x163a4db, 0x163a4e6], 'constructor store census changed')
    require(abody.count(bytes.fromhex('4088ab90000000')) == 1, 'apply byte store is not unique')
    require(refs['gb_b2'].count(bytes.fromhex('48898ba0000000')) == 1, 'B2 +0xa0 store is not unique')
    require(refs['gb_b2'].count(bytes.fromhex('4088bbe8010000')) == 1, 'B2 +0x1e8 store is not unique')
    require(refs['gb_b3'].count(bytes.fromhex('4188bde8010000')) == 1, 'B3 +0x1e8 store is not unique')

    # --- trail 2 negative: the +0xbd5 displacement bytes ---
    z_bd5 = zbody.count(bytes.fromhex('d50b0000'))
    b4_bd5 = refs['gb_b4'].count(bytes.fromhex('d50b0000'))
    require(z_bd5 == 0, 'Z body gained a 0xbd5 displacement occurrence')
    require(b4_bd5 == 3, 'B4 body 0xbd5 occurrence count changed')

    owners = []
    for role, (start, end) in OWNERS.items():
        body = bodies[role]
        owners.append({'role': role, 'start': hex(start), 'end': hex(end),
                       'file_offset': hex(start - 0x1000), 'bytes': end - start,
                       'sha256': hashlib.sha256(body).hexdigest()})
    return {
        'target_sha256': TARGET_SHA256,
        'captured_code_executed': False,
        'owners': owners,
        'slot_bindings': bindings,
        'caller_census': census,
        'slot_census': slot_refs,
        'chain_classification': {
            'field_name': 'chain', 'field_name_va': hex(CHAIN_NAME_VA),
            'getter': hex(GETTER), 'classes': classes,
            'byte_store': '0x564ceb5', 'byte_store_encoding': '4088ab90000000',
            'unmatched_name': 'reaches the Result::unwrap() panic path at 0x564cd72 '
                              '(formatter slot 0x64df6a0 -> 0x1680c30, int3-terminated); '
                              'no class byte is written',
            'missing_field': 'getter returns null -> panic stub slot 0x64df830 -> 0x1680c10; no write',
        },
        'trail1_staging_dword': {
            'record_size': '0x250',
            'zeroing_store': '0x163a4db (record +0x90 qword = 0, constructor)',
            'writer': '0x564ceb5 (record +0x90 byte = chain class, apply function)',
            'spec_builder_record_stores': ['0x564d725 (+0xb0)', '0x564d72c (+0xb8)'],
            'apply_slot_sites': ['0x2ae437a (B2)', '0x2b7b73f (converter)'],
            'b2_staging_store': '0x2ae447f (obj +0xa0 = record +0x90 qword)',
            'b3_staging': 'converter memcpy at 0x2b7b75d (record head 0x98 bytes to the '
                          'buffer B3 memcpy stages into obj +0x10 at 0x2cde55e)',
            'verdict': 'the +0xa0 dword staged into the context object is the chain class '
                       'byte over the constructor-zeroed qword: written by traced code, '
                       'determined by the "chain" name string inside the produced value',
        },
        'trail2_bd5_byte': {
            'b4_arg2': 'the caller object +0xca0 sub-object, via [rsp+0x20] set at 0x2af7f49',
            'staging_memcpy': '0x2af784b (obj -> obj +0xca0, length 0xbd8 covers +0xbd5)',
            'z_d50b0000_occurrences': z_bd5,
            'b4_d50b0000_occurrences': b4_bd5,
            'verdict': 'no instruction in the caller addresses offset +0xbd5; the byte is '
                       'the caller object\'s own +0xbd5 byte copied verbatim by the staging '
                       'memcpy - input-determined at exactly this offset',
        },
        'boundary': {
            'trail1': 'the "chain" name string inside the value produced by 0x165de90 / '
                      '0x165dfb0 from the spec is input data; its runtime origin above the '
                      'value producer is not traced here',
            'trail2': 'whoever writes the +0xbd5 field of the object that 0x2af77f0 '
                      'receives as arg1 is above 0x2af77f0, which has no direct call site '
                      'in .text; the trail is data-only from there',
            'callers': 'B2 is called only by 0x2ae1690 (frame object) and 0x2b404b0 (TLS '
                       'context cell); B3 only by 0x2ae1690; B4 only by 0x2af77f0',
        },
        'limits': 'Static byte pins, relocation bindings, raw and pattern store censuses '
                  'over the traced bodies, one .text direct-call census and per-slot '
                  'RIP-relative censuses. Whether a given action family ever carries the '
                  'Mainnet class (byte 3) at runtime is not decidable from static bytes '
                  'and is not claimed.',
    }


def executable(path, args, marker=None):
    out = subprocess.run([path, *args], check=True, stdout=subprocess.PIPE).stdout.decode()
    if 'LLVM' in out or (marker is not None and marker not in out):
        raise ValueError(f'unexpected {path} output')
    return out


def generate(binary, output):
    data = Path(binary).read_bytes()
    if len(data) != TARGET_SIZE or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('expected pinned node115')
    result = analyze(data)
    readelf = executable('readelf', ['-wf', str(binary)], marker='FDE').splitlines()
    eh = next(s for s in sections(data) if s['name'] == '.eh_frame')

    def record(line):
        off, size = int(line.split()[0], 16), int(line.split()[1], 16)
        raw = data[eh['offset'] + off:eh['offset'] + off + size + 4]
        return {'va': hex(eh['address'] + off), 'bytes_hex': raw.hex()}

    exports = {}
    for owner in result['owners']:
        start, end = OWNERS[owner['role']]
        lines = [l for l in readelf if 'FDE' in l and f'pc={start:016x}..{end:016x}' in l]
        if len(lines) != 1:
            raise ValueError(f'expected one FDE line for {owner["role"]}')
        fde_line = lines[0]
        cie_ref = fde_line.split('cie=')[1].split()[0]
        cie_lines = [l for l in readelf if len(l.split()) > 3 and l.split()[0] == cie_ref and ' CIE' in l]
        if len(cie_lines) != 1:
            raise ValueError(f'expected one CIE line for {owner["role"]}')
        owner['frames'] = {'fde': record(fde_line), 'cie': record(cie_lines[0])}
        exports[owner['role']] = executable(
            'objdump', ['-d', '-M', 'intel', '--insn-width=16',
                        f'--start-address={start:#x}', f'--stop-address={end:#x}',
                        str(binary)], marker='Disassembly of section')
    # Native validation: every pinned address inside an owner must be an
    # instruction start in that owner's decoded extent; the same check is
    # applied to the referenced #2444 owner bodies for their pins here.
    for role, (start, end) in OWNERS.items():
        starts = set(decode_export(exports[role], start, end, read(data, start, end - start)))
        missing = {hex(va) for va, _h, _w in OWNER_PINS[role] if va not in starts}
        if missing:
            raise ValueError(f'pinned addresses are not instruction starts in {role}: {missing}')
    for name, (start, end) in REF_BODIES.items():
        text = executable('objdump', ['-d', '-M', 'intel', '--insn-width=16',
                                       f'--start-address={start:#x}',
                                       f'--stop-address={end:#x}', str(binary)],
                          marker='Disassembly of section')
        starts = set(decode_export(text, start, end, read(data, start, end - start)))
        missing = {hex(va) for va, _h, _w in REF_PINS[name] if va not in starts}
        if missing:
            raise ValueError(f'pinned addresses are not instruction starts in {name}: {missing}')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    frames = []
    for owner in result['owners']:
        start, end = OWNERS[owner['role']]
        frames += [l for l in readelf if 'FDE' in l and f'pc={start:016x}..{end:016x}' in l]
    (output / 'frames.txt').write_text('\n'.join(frames) + '\n')
    for role in OWNERS:
        (output / f'{role}.objdump.txt').write_text(
            exports[role].replace(str(binary), '<authenticated-node115>'))
    (output / 'records.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', default=str(TARGET))
    ap.add_argument('--output', default=str(PACKET))
    a = ap.parse_args()
    generate(a.binary, a.output)


if __name__ == '__main__':
    main()

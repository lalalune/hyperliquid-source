#!/usr/bin/env python3
"""Export authenticated static evidence for a selected node 94 override path."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
from elf_index import sections
from fde_extents import eh_frame_records, uleb, sleb

ROOT = Path(__file__).resolve().parents[1]
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x1f6da60: ('request argument and override forwarding', '147545170ef1e3182725209a72d440478a762ff47c089a573384207449661330'),
    0x27b86f0: ('override preparation adapter', 'a6405eda42be8ad8bf22217c937bbed29eb06b7ee38a010dc7be572585378e5b'),
    0x1b702d0: ('key sequence adapter', '829bd2a1501eed6ee49a4fdd7678c65e8fbb76326d9035b5946f973de528f15d'),
    0x2806f80: ('address key decoder adapter', '569bf3c62f5ce5b0c596564536c5a57c743ec67e9dea6bab9578f415e2723df4'),
    0x2526540: ('nullable precompile move address adapter', '531ad8baec9df1af75902813651cd8b6b92d22bfc3a29aae41e0b0436c5016e0'),
    0x1b2ad60: ('argument adapter', '8c5ad130536ba1d99e951c90f9d535db0a4ec0720369ac8902deeaa1b3c50a15'),
    0x251f080: ('nullable map parser', 'cad1a855eeebccd23d3ecbfe27409cfbb5ed0c70eae9859d2720c946465c842a'),
    0x1bd8a60: ('address keyed map parser', '35b66c7cce118e7707e97129fe35d9cfe64815641f2b45b71ea0d04be6840160'),
    0x1d278c0: ('account override visitor', 'ad724b5013f24707f86fb49ee93afbf6c7aaac72aff3965f05ff5f5bf39dc83f'),
    0x2441c70: ('account field classifier', '40687c7a02bf432502ec1e3ad7296d70b7db746a8317bf145048e7a0e8f79980'),
    0x2480f00: ('override caller to engine builder', 'af6ef3c27bdaa46193d8d7c8babb40f3d17f9ae9cae142c2e8f272cd45b42a32'),
    0x243fd20: ('account map apply loop', '5627b7bbcb2e4575c4aa2530485525beafa40c4ee6452c2563168ea2802e3b8b'),
    0x1f689b0: ('account data fetch', '5b4aec94877a047cf361964412f8fb41e20c07d53a32772ec4f3d248998d2bf5'),
    0x1eb2640: ('account cache publication', '480941ad92438a4c96622ddb81470608cb67ff48c7513a7a8dd302d6787a79d6'),
    0x1eb2060: ('account cache entry', 'a7d13e239771c60ae257e44343b46f7fffb0b7dbc893eaaf67e28ffc15546c18'),
    0x1eb2c70: ('replace account slot map', '321ebdbe58c4dcdb8c754d25232e73de9f0a4fcde9b5edbadc02b3a285d14e1c'),
    0x26ba9a0: ('construct replacement slot map', '2bacbaad8699879a14994ebbc59178c2a8bfe11d629e8bcd6a4c5a1bff02bd09'),
    0x27c5ce0: ('insert keyed override', '7b7fa6e2ca6d8bdc2ab377aa12430b906fedec42bcbe43792f97d21f21b490b1'),
}

def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


class Image:
    def __init__(self, data):
        require(digest(data) == SHA, 'target digest mismatch')
        self.data = data
        self.secs = sections(data)
        self.cies, fdes = eh_frame_records(data, self.secs)
        self.fdes = {}
        for f in fdes:
            self.fdes.setdefault(f['start'], []).append(f)
        s = self.section('.rela.dyn')
        require(s['size'] % 24 == 0, 'partial RELA record')
        self.relas = {}
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            va, info, addend = struct.unpack_from('<QQq', data, off)
            require(va not in self.relas, 'duplicate RELA slot')
            self.relas[va] = (info, addend, off)

    def section(self, name):
        rows = [s for s in self.secs if s['name'] == name and s['type'] != 8]
        require(len(rows) == 1, 'missing or ambiguous section')
        return rows[0]

    def offset(self, va, size):
        require(type(va) is int and type(size) is int and va >= 0 and size > 0,
                'invalid requested range')
        matches = [s for s in self.secs if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'range not uniquely file backed')
        s = matches[0]
        off = s['offset'] + va - s['address']
        require(off + size <= len(self.data), 'truncated file range')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, va):
        rows = self.fdes.get(va, [])
        require(len(rows) == 1, 'missing or duplicate FDE')
        f = rows[0]
        text = self.section('.text')
        require(text['address'] <= va < f['end'] <= text['address'] + text['size'],
                'invalid executable FDE interval')
        return f

    def relative(self, slot):
        require(slot in self.relas, 'missing relocation')
        info, addend, _ = self.relas[slot]
        require(info == 8, 'not a symbol-free RELATIVE relocation')
        return addend

    def expect(self, va, hexbytes):
        raw = bytes.fromhex(hexbytes)
        require(self.read(va, len(raw)) == raw, 'byte predicate mismatch')
        return raw


# Restricted x86-64 length/operand decoder. No text disassembler output enters
# the evidence. It rejects unsupported encodings instead of guessing lengths.
# This decodes operands, not effects; it never executes or emulates a function.
def instruction(code, pos):
    start = pos
    prefixes = []
    def take(n):
        nonlocal pos
        require(n > 0 and pos + n <= len(code), 'truncated instruction')
        v = code[pos:pos+n]
        pos += n
        require(pos - start <= 15, 'oversized instruction')
        return v
    while pos < len(code) and (code[pos] in (0x66, 0x2e, 0x64, 0x65, 0xf0, 0xf2, 0xf3)
                              or 0x40 <= code[pos] <= 0x4f):
        prefixes.append(take(1)[0])
    rex = next((p for p in reversed(prefixes) if 0x40 <= p <= 0x4f), 0)
    word = 2 if 0x66 in prefixes else 4
    op = take(1)[0]
    opcode = [op]
    kind = 'ordinary'
    immediate = 0
    relative = False
    modrm_needed = False
    if op in (0xe8, 0xe9, 0xeb) or 0x70 <= op <= 0x7f:
        immediate = 4 if op in (0xe8, 0xe9) else 1
        relative = True
        kind = 'call' if op == 0xe8 else 'jump' if op in (0xe9,0xeb) else 'conditional'
    elif op in (0xc3,0xcc):
        kind = 'return' if op == 0xc3 else 'trap'
    elif 0x50 <= op <= 0x5f or op in (0x90,0x98,0x99):
        pass
    elif 0xb0 <= op <= 0xb7 or op in (0x04,0x0c,0x24,0x2c,0x34,0x3c,0xa8,0x6a):
        immediate = 1
    elif 0xb8 <= op <= 0xbf:
        immediate = 8 if rex & 8 else word
    elif op in (0x05,0x0d,0x25,0x2d,0x35,0x3d,0xa9,0x68):
        immediate = word
    elif op == 0x0f:
        op2 = take(1)[0]
        opcode.append(op2)
        if 0x80 <= op2 <= 0x8f:
            relative, immediate, kind = True, 4, 'conditional'
        elif op2 == 0x0b:
            kind = 'trap'
        elif 0xc8 <= op2 <= 0xcf:
            pass
        elif (0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f or op2 in
              (0x10,0x11,0x14,0x15,0x1f,0x28,0x29,0x2a,0x2e,0x54,0x55,0x56,0x57,0x58,0x5c,0x5e,0x60,0x61,0x62,0x64,
               0x6c,0x6d,0x6e,0x6f,0x74,0x75,0x76,0x7e,0x7f,0xaf,0xb0,0xb1,
               0xa3,0xb6,0xb7,0xbc,0xbd,0xbe,0xbf,0xc1,0xd4,0xd6,0xd7,0xdb,0xdf,0xeb,0xef,0xfb)):
            modrm_needed = True
        elif op2 in (0x70,0x71,0x72,0x73,0xba,0xc2,0xc4,0xc5,0xc6):
            modrm_needed, immediate = True, 1
        else:
            raise ValueError('unsupported two-byte opcode')
    elif op in (0x80,0x83,0xc0,0xc1,0xc6,0x6b):
        modrm_needed, immediate = True, 1
    elif op in (0x81,0xc7,0x69):
        modrm_needed, immediate = True, word
    elif op in (0xf6,0xf7,0xfe,0xff,0x63,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8d,
                0xd0,0xd1,0xd2,0xd3) or (op < 0x40 and op % 8 < 4):
        modrm_needed = True
    else:
        raise ValueError('unsupported opcode')
    row = {'kind': kind, 'opcode': bytes(opcode).hex(), 'rex': rex}
    rip_disp = None
    if modrm_needed:
        mr = take(1)[0]
        mod, reg, rm = mr >> 6, (mr >> 3) & 7, mr & 7
        row['modrm'] = mr
        if op == 0xff and reg in (2,4):
            row['kind'] = 'indirect-call' if reg == 2 else 'indirect-jump'
        if op in (0xf6,0xf7) and reg == 0:
            immediate = 1 if op == 0xf6 else word
        displacement = 0
        if mod != 3 and rm == 4:
            sib = take(1)[0]
            row['sib'] = sib
            if mod == 0 and sib & 7 == 5:
                displacement = 4
        elif mod == 0 and rm == 5:
            displacement = 4
            rip_disp = pos
        if mod in (1,2):
            displacement = 1 if mod == 1 else 4
        if displacement:
            row['displacement'] = int.from_bytes(take(displacement), 'little', signed=True)
    if immediate:
        raw = take(immediate)
        row['immediate'] = int.from_bytes(raw, 'little')
        if relative:
            row['target_offset'] = pos + int.from_bytes(raw, 'little', signed=True)
    if rip_disp is not None:
        row['rip_offset'] = pos + struct.unpack_from('<i', code, rip_disp)[0]
    if row['kind'] == 'conditional':
        row['condition'] = opcode[-1] & 15
    row['size'] = pos - start
    row['bytes'] = code[start:pos].hex()
    return row


def decode(code, base):
    rows = []
    pos = 0
    while pos < len(code):
        try:
            row = instruction(code, pos)
        except ValueError as e:
            raise ValueError(f'instruction at {base+pos:#x}: {e}') from e
        row['va'] = base + pos
        for source, dest in [('target_offset','target'),('rip_offset','rip')]:
            if source in row:
                row[dest] = base + row.pop(source)
        rows.append(row)
        pos += row['size']
    boundaries = {r['va'] for r in rows}
    for r in rows:
        if 'target' in r and base <= r['target'] < base + len(code):
            require(r['target'] in boundaries, 'branch into instruction')
    return rows


def tsv(rows, keys):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, keys, delimiter='\t', lineterminator='\n', extrasaction='ignore')
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def js(obj):
    return json.dumps(obj, sort_keys=True, indent=2) + '\n'




def call_sites(image, function, boundaries):
    f = image.fde(function)
    if not f['lsda']:
        return [], None
    sec = image.section('.gcc_except_table')
    end = sec['offset'] + sec['size']
    require(sec['address'] <= f['lsda'] < sec['address']+sec['size'], 'LSDA outside exception section')
    pos = image.offset(f['lsda'],1)
    require(pos+3 <= end, 'truncated LSDA header')
    initial = pos
    data = image.data
    require(data[pos] == 0xff, 'unsupported LSDA LPStart')
    pos += 1
    type_encoding = data[pos]
    pos += 1
    type_base = None
    if type_encoding != 0xff:
        require(type_encoding == 0x9b, 'unsupported LSDA type encoding')
        delta,pos = uleb(data,pos,end)
        type_base = pos + delta
        require(type_base <= end, 'LSDA type base out of section')
    require(data[pos] == 1, 'unsupported call-site encoding')
    pos += 1
    length,pos = uleb(data,pos,end)
    limit = pos + length
    require(limit <= end and (type_base is None or limit <= type_base), 'call-site table out of range')
    rows = []
    previous = function
    while pos < limit:
        record = pos
        begin,pos = uleb(data,pos,limit)
        size,pos = uleb(data,pos,limit)
        landing,pos = uleb(data,pos,limit)
        action,pos = uleb(data,pos,limit)
        begin += function
        finish = begin + size
        require(previous <= begin <= finish <= f['end'], 'invalid exception interval')
        require(begin in boundaries and (finish in boundaries or finish == f['end']),
                'exception interval not at instruction boundary')
        require(not landing or (function <= function+landing < f['end']
                                 and function+landing in boundaries), 'invalid landing pad')
        rows.append(dict(function=hex(function), lsda=hex(f['lsda']),
                         site=hex(begin), end=hex(finish),
                         landing=hex(function+landing) if landing else '', action=action,
                         raw=data[record:pos].hex()))
        previous = finish
    return rows, dict(function=hex(function), lsda=hex(f['lsda']),
                      header_and_call_sites=data[initial:limit].hex(),
                      action_table_file_offset=hex(limit),
                      type_table_file_offset=hex(type_base) if type_base is not None else None,
                      limitation='Action chains and type records are not interpreted.')


# The words in these annotations describe reviewed byte uses, not symbol names.
# Locations of the selected FDE bodies are checked against their body hashes.
EDGES = [
    (0x1f6dcde, 0x1e67a80, 'request argument adapter boundary'),
    (0x1f6dd86, 0x27b86f0, 'request to preparation adapter'),
    (0x27b8aaf, 0x2480f00, 'preparation adapter to override caller'),
    (0x1b2ade5, 0x251f080, 'argument to nullable parser'),
    (0x251f174, 0x1bd8a60, 'non-null map parser'),
    (0x1bd8bd1, 0x1b702d0, 'map-key helper'),
    (0x1b703d6, 0x2806f80, 'key address adapter'),
    (0x2806ff6, 0x156e650, 'key address decoder first arm'),
    (0x280701c, 0x156e650, 'key address decoder second arm'),
    (0x2526624, 0x28070b0, 'move-address value decoder adapter'),
    (0x1bd8c6a, 0x1d278c0, 'map-value visitor'),
    (0x1bd8d19, 0x27c5ce0, 'map insertion'),
    (0x1d27adf, 0x2441c70, 'account-field classifier'),
    (0x1d27f1d, 0x2524360, 'balance value helper'),
    (0x1d27f92, 0x258cd60, 'nonce value helper'),
    (0x1d27dce, 0x2524f90, 'code value helper'),
    (0x1d27ead, 0x2521fd0, 'state value helper'),
    (0x1d27d4d, 0x2521fd0, 'stateDiff value helper'),
    (0x1d27fe2, 0x2526540, 'movePrecompileToAddress value helper'),
    (0x248107e, 0x247e720, 'environment conversion boundary'),
    (0x24810b7, 0x1eb2d90, 'cache construction boundary'),
    (0x24810f6, 0x243fd20, 'override application'),
    (0x24817ce, 0x247fd20, 'engine builder after override'),
    (0x24813a7, 0x247fd20, 'engine builder special branch'),
    (0x243ff2e, 0x1f689b0, 'account data fetch'),
    (0x244024a, 0x1eb2640, 'account publication'),
    (0x2440372, 0x26ba9a0, 'replacement map construction'),
    (0x244038b, 0x1eb2c70, 'replacement map publication'),
    (0x244050d, 0x1eb2060, 'account entry for delta'),
    (0x2440533, 0x27c9ad0, 'delta slot insertion'),
    (0x1eb2c7c, 0x1eb2060, 'account entry for replacement'),
    (0x26bab79, 0x27c9ad0, 'replacement slot insertion'),
    (0x1eb271e, 0x27c4c80, 'code cache entry'),
    (0x1eb29ad, 0x27c3dd0, 'account cache entry'),
    (0x1eb20a0, 0x27c3dd0, 'account entry lookup for slots'),
    (0x1eb2109, 0x37d0fb0, 'backing account for slot entry'),
    (0x1f68b02, 0x37d0fb0, 'external account backing getter'),
]
# Each window is bounded by decoded instruction starts and retains raw bytes.
WINDOWS = [
 ('request-override-argument',0x1f6dcd1,0x1f6dd86),
 ('request-forwarding-call',0x1f6dd64,0x1f6dd8b),
 ('adapter-map-ingress',0x27b86f0,0x27b874a),
 ('adapter-map-egress',0x27b8a58,0x27b8ab4),
 ('argument-call',0x1b2add7,0x1b2ae16),
 ('nullable-null-and-map',0x251f0ef,0x251f1a0),
 ('key-sequence',0x1b703b1,0x1b70426),
 ('key-address-decoder',0x2806fdd,0x2807050),
 ('move-null-and-address',0x25265ac,0x2526674),
 ('map-key-value-and-insert',0x1bd8bc1,0x1bd8d2c),
 ('map-key-probe',0x27c5d68,0x27c5df8),
 ('map-existing-replacement',0x27c5e1d,0x27c5e57),
 ('map-new-entry',0x27c5e6b,0x27c5efc),
 ('field-dispatch',0x1d27ad7,0x1d27b17),
 ('field-guard-diff',0x1d27b64,0x1d27b6d),
 ('field-guard-code',0x1d27bba,0x1d27bc9),
 ('field-guard-state',0x1d27c16,0x1d27c1f),
 ('field-guard-nonce',0x1d27c71,0x1d27c80),
 ('field-guard-move',0x1d27ccd,0x1d27cdb),
 ('field-diff-value',0x1d27d28,0x1d27dac),
 ('field-code-value',0x1d27dac,0x1d27e83),
 ('field-state-value',0x1d27e83,0x1d27efb),
 ('field-balance-value',0x1d27efb,0x1d27f70),
 ('field-nonce-value',0x1d27f70,0x1d27fc3),
 ('field-move-value',0x1d27fc3,0x1d28036),
 ('output-assembly',0x1d28717,0x1d28923),
 ('assembled-output-forward',0x1d28252,0x1d282b6),
 ('output-copy',0x1d28492,0x1d284dd),
 ('classifier',0x2441c70,0x2441d7f),
 ('engine-input-and-conversion',0x248104c,0x24810bc),
 ('engine-override-gate',0x24810bc,0x2481111),
 ('engine-after-override',0x2481111,0x24811d0),
 ('engine-override-failure',0x24812cd,0x248132e),
 ('engine-forward-guards',0x24813d1,0x24813fd),
 ('engine-builder-handoff',0x2481719,0x24817d3),
 ('entry-key-and-value',0x243fe52,0x243ff33),
 ('account-input-and-apply',0x243ffb3,0x244027d),
 ('publish-variant-dispatch',0x1eb2640,0x1eb2691),
 ('publish-code-cache',0x1eb2691,0x1eb272b),
 ('publish-code-clone-dispatch',0x1eb2757,0x1eb276a),
 ('publish-account-cache',0x1eb2955,0x1eb29ba),
 ('storage-selection',0x244024a,0x24402f2),
 ('replacement-construction',0x2440300,0x2440395),
 ('delta-loop',0x2440420,0x2440540),
 ('complete-status',0x24406e4,0x2440721),
 ('conflict-cleanup-and-status',0x24407b4,0x2440862),
 ('account-entry-and-backing',0x1eb2071,0x1eb2120),
 ('account-cache-hit',0x1eb2278,0x1eb2285),
 ('replacement-flag-and-copy',0x1eb2c7c,0x1eb2d6d),
 ('replacement-slot-swap-and-insert',0x26baadf,0x26bab7e),
]
# Predicate followed immediately by a conditional branch; bytes are checked.
BRANCHES = [
 (0x1d27b08,'4883bc24c800000002',0x1d2939b,'balance already seen'),
 (0x1d27c71,'4883bc249800000002',0x1d29412,'nonce already seen'),
 (0x1d27bba,'4883bc24a000000000',0x1d29526,'code already seen'),
 (0x1d27c16,'4885ff',0x1d2959a,'state already seen'),
 (0x1d27b64,'4d85ed',0x1d29489,'stateDiff already seen'),
 (0x1d27ccd,'80bc249000000002',0x1d29324,'movePrecompileToAddress already seen'),
 (0x1f6dceb,'4883fd04',0x1f6dcf6,'request override argument result differs from 4'),
 (0x1f6dd20,'83fd03',0x1f6e0f2,'request override argument result differs from 3'),
 (0x248108b,'3c21',0x2481124,'environment conversion tag differs from 21'),
 (0x24810cf,'4885c0',0x24811ae,'override input word zero'),
 (0x24810fb,'80bc24b001000021',0x24812cd,'override result tag differs from 21'),
 (0x2481111,'4983be2802000000',0x24813d1,'environment word at 228 nonzero'),
 (0x24813ef,'4983be4002000000',0x2481719,'last environment guard word zero'),
 (0x2481719,'4885ed',0x2481722,'selected amount word zero'),
 (0x27c5dc7,'81ffffff0000',0x27c5e1d,'address key comparison mask all ones'),
 (0x1bd8d1e,'83bc24f000000002',0x1bd8bc1,'map insertion returned tag two'),
 (0x1eb20ad,'4d85ff',0x1eb2278,'account entry word zero'),
 (0x1eb2116,'4883f801',0x1eb2285,'backing account tag differs from one'),
 (0x243ffc1,'83bc24e802000001',0x243ffdb,'nonce override tag differs from one'),
 (0x1eb2691,'4885f6',0x1eb2955,'variant-derived code length word zero'),
 (0x1eb26c0,'3dffff0000',0x1eb26ee,'code fingerprint does not match constant'),
 (0x1eb2728,'4d85e4',0x1eb2955,'code cache entry word zero'),
 (0x1eb29b7,'4d85e4',0x1eb2b46,'account cache entry word zero'),
 (0x2440267,'4885ff',0x24402b0,'state word zero'),
 (0x2440274,'4d85f6',0x24407b4,'both state words nonzero'),
 (0x251f0ef,'4183f96e',0x251f16f,'first literal byte differs from n'),
 (0x251f11e,'4180f875',0x251f1e7,'second literal byte differs from u'),
 (0x251f13f,'4180f86c',0x251f1e7,'third literal byte differs from l'),
 (0x251f157,'80f96c',0x251f1e7,'fourth literal byte differs from l'),
 (0x2806ffc,'837c243803',0x2807050,'first address decoder status differs from 3'),
 (0x2807022,'837c242003',0x280707d,'second address decoder status differs from 3'),
 (0x25265db,'4180f875',0x252668f,'move null second byte differs from u'),
 (0x25265fc,'4180f86c',0x252668f,'move null third byte differs from l'),
 (0x2526614,'80f96c',0x252668f,'move null fourth byte differs from l'),
 (0x1b703db,'807c240800',0x1b703ef,'key decoder returned zero error tag'),
]

# Source-level tags are extracted from stores and matched to relocation-backed
# descriptor strings and the actual length-dispatch and visitor tables.
FIELD_SITES = [0x2441ce0,0x2441d48,0x2441c9d,0x2441d0d,0x2441cc4,0x2441d3f]
FIELD_STARTS = [0x2441ccd,0x2441ce9,0x2441c91,0x2441cfb,0x2441ca6,0x2441d16]
FIELD_GUARDS = [0x1d27b08,0x1d27c71,0x1d27bba,0x1d27c16,0x1d27b64,0x1d27ccd]
FIELD_CALLS = [0x1d27f1d,0x1d27f92,0x1d27dce,0x1d27ead,0x1d27d4d,0x1d27fe2]


def relative_table(image, base, count, bounds):
    require(type(count) is int and 0 < count <= 256, 'invalid table count')
    result=[]
    for i in range(count):
        raw=image.read(base+4*i,4)
        displacement=struct.unpack('<i',raw)[0]
        target=base+displacement
        require(target in bounds,'table target is not selected instruction')
        result.append((i,raw,displacement,target))
    return result


def extract_fields(image, by_va):
    # cmp 19 after subtracting 4 establishes a 20-entry dispatch table;
    # the fallback loads a six-element relocation-backed descriptor.
    require(by_va[0x2441c77]['immediate']==19 and by_va[0x2441d59]['immediate']==6,
            'field table bounds changed')
    classifier_bounds={r['va'] for r in decode(image.read(0x2441c70,
                         image.fde(0x2441c70)['end']-0x2441c70),0x2441c70)}
    visitor_bounds={r['va'] for r in decode(image.read(0x1d278c0,
                      image.fde(0x1d278c0)['end']-0x1d278c0),0x1d278c0)}
    lens=relative_table(image,0x3e21ec,by_va[0x2441c77]['immediate']+1,classifier_bounds)
    guards=relative_table(image,0x3b71c4,by_va[0x2441d59]['immediate'],visitor_bounds)
    require(by_va[0x2441c81]['rip']==0x3e21ec and by_va[0x1d27af4]['rip']==0x3b71c4
            and by_va[0x2441d52]['rip']==0x56a67f0,'table base changed')
    rows=[]
    for tag,(store,start,guard,call) in enumerate(zip(FIELD_SITES,FIELD_STARTS,FIELD_GUARDS,FIELD_CALLS)):
        rec=0x56a67f0+16*tag
        pointer=image.relative(rec)
        size=struct.unpack('<Q',image.read(rec+8,8))[0]
        require(0 < size <= 64,'invalid descriptor length')
        raw=image.read(pointer,size)
        name=raw.decode('ascii')
        inst=by_va[store]
        require(inst['bytes']==('c64001'+bytes([tag]).hex()),'wrong field tag store')
        table_target=lens[size-4][3]
        # Both five-byte words enter the same block, then compare separately.
        require(table_target == (0x2441ce9 if tag==3 else start),'length dispatch changed')
        require(guards[tag][3]==guard,'field visitor table changed')
        require(by_va[call]['kind']=='call','field value helper changed')
        rows.append(dict(tag=tag,name=name,name_hex=raw.hex(),name_va=hex(pointer),
            descriptor=hex(rec),descriptor_file_offset=hex(image.offset(rec,16)),
            name_file_offset=hex(image.offset(pointer,size)),size=size,
            classifier_entry=hex(start),tag_store=hex(store),tag_store_bytes=inst['bytes'],
            visitor_target=hex(guard),value_call=hex(call),value_helper=hex(by_va[call]['target'])))
    # Verify name constants used by the classifier, including the overlapping
    # SIMD windows for the 23-byte field. No disassembly output is parsed.
    chunks=[(0x2441c91,2,4,2,0), (0x2441ccd,1,4,0,0), (0x2441cd4,1,4,0,3),
            (0x2441ce9,1,4,1,0),(0x2441cfb,1,4,3,0),(0x2441ca6,2,8,4,0)]
    for va,off,n,tag,name_off in chunks:
        name=bytes.fromhex(rows[tag]['name_hex'])
        require(image.read(va+off,n)==name[name_off:name_off+n], 'field literal mismatch')
    for va,tag,last in [(0x2441cf4,1,4),(0x2441d06,3,4),(0x2441cb7,4,8)]:
        require(by_va[va]['immediate']==bytes.fromhex(rows[tag]['name_hex'])[last], 'field tail mismatch')
    long_name=bytes.fromhex(rows[5]['name_hex'])
    require(by_va[0x2441d1f]['rip']==0x203f90 and by_va[0x2441d27]['rip']==0x2068d0,
            'long field constants changed')
    require(image.read(0x2068d0,16)==long_name[:16] and image.read(0x203f90,16)==long_name[7:23],
            'long field comparison bytes differ')
    return rows,lens,guards


def selected_predicates(by_va, owners):
    out=[]
    for va,raw,expected,meaning in BRANCHES:
        ins=by_va[va]
        require(ins['bytes']==raw,'predicate byte mismatch')
        branch=by_va.get(va+ins['size'])
        require(branch and branch['kind']=='conditional' and branch['target']==expected,
                'predicate branch mismatch')
        out.append(dict(function=hex(owners[va]),predicate=hex(va),bytes=raw,
            branch=hex(branch['va']),branch_bytes=branch['bytes'],condition=branch['condition'],
            taken=hex(branch['target']),fallthrough=hex(branch['va']+branch['size']),meaning=meaning))
    return out


def comparison_specs(image, fields, by_va):
    """Model the classifier's fixed byte windows after external string decoding."""
    extract=lambda va,off,n: image.read(va+off,n)
    tail=lambda va: bytes([by_va[va]['immediate']])
    chunks=[
        [(0,extract(0x2441ccd,1,4)),(3,extract(0x2441cd4,1,4))],
        [(0,extract(0x2441ce9,1,4)),(4,tail(0x2441cf4))],
        [(0,extract(0x2441c91,2,4))],
        [(0,extract(0x2441cfb,1,4)),(4,tail(0x2441d06))],
        [(0,extract(0x2441ca6,2,8)),(8,tail(0x2441cb7))],
        [(0,image.read(0x2068d0,16)),(7,image.read(0x203f90,16))],
    ]
    result=[]
    for field,parts in zip(fields,chunks):
        name=bytes.fromhex(field['name_hex'])
        require(all(name[off:off+len(raw)]==raw for off,raw in parts), 'model literal mismatch')
        result.append(dict(tag=field['tag'],length=field['size'],name=field['name'],
                           chunks=[dict(offset=off,raw=raw.hex()) for off,raw in parts]))
    return result


def classify_decoded_bytes(candidate, specs):
    """Synthetic byte predicates; None denotes the unmodeled fallback call."""
    require(isinstance(candidate,bytes),'field input must be bytes')
    for spec in specs:
        if len(candidate)==spec['length'] and all(
                candidate[c['offset']:c['offset']+len(bytes.fromhex(c['raw']))]==bytes.fromhex(c['raw'])
                for c in spec['chunks']):
            return spec['tag']
    return None


def storage_choice(state_word, diff_word):
    """Synthetic projection of two zero/nonzero predicates, not execution."""
    require(type(state_word) is int and 0 <= state_word < 1<<64,'invalid state word')
    require(type(diff_word) is int and 0 <= diff_word < 1<<64,'invalid diff word')
    if state_word:
        return 'conflict' if diff_word else 'replacement'
    return 'delta' if diff_word else 'none'


def stack_references(instructions):
    """Only explicit [rsp+constant] operands; no alias/dataflow analysis."""
    out=[]
    for r in instructions:
        if r.get('sib')==0x24 and (r['rex'] & 3)==0 and r.get('modrm',0)>>6 != 3:
            out.append(dict(site=hex(r['va']),bytes=r['bytes'],opcode=r['opcode'],
                            displacement=r.get('displacement',0)))
    return out


def derive_layout(by_va, writer_rows):
    """Recover stack/record coordinate arithmetic from authenticated operands."""
    disp=lambda va: by_va[va]['displacement']
    imm=lambda va: by_va[va]['immediate']
    assembled_base=disp(0x1d2881e)
    writer_base=disp(0x243fee5)
    fields={
      'balance_tag':disp(0x1d2881e)-assembled_base,
      'nonce_tag':disp(0x1d28856)-assembled_base,
      'code_tag':disp(0x1d2886e)-assembled_base,
      'state_word':disp(0x1d28896)-assembled_base,
      'stateDiff_word':disp(0x1d288be)-assembled_base,
      'move_tag':disp(0x1d288e0)-assembled_base,
      'move_payload_start':disp(0x1d288ef)-assembled_base,
      'move_payload_last_pair':disp(0x1d2891a)-assembled_base,
    }
    record_size=imm(0x1d28275)
    require(fields=={'balance_tag':0,'nonce_tag':0x28,'code_tag':0x38,'state_word':0x58,
        'stateDiff_word':0x80,'move_tag':0xa8,'move_payload_start':0xa9,
        'move_payload_last_pair':0xbb},'record field offsets changed')
    require(record_size==0xc0 and imm(0x243fe6c)==0xd8 and imm(0x243feed)==0xb8,
            'record sizes changed')
    require(disp(0x244024f)==writer_base+fields['state_word']
            and disp(0x2440257)==writer_base+fields['stateDiff_word']
            and disp(0x243ffc1)==writer_base+fields['nonce_tag']
            and disp(0x243ffdb)==writer_base+fields['code_tag'], 'writer layout changed')
    require(by_va[0x1d2891a]['bytes'].startswith('66'), 'final payload store width changed')
    start=writer_base+fields['move_tag']; end=writer_base+fields['move_payload_last_pair']+2
    stack=stack_references(writer_rows)
    direct=[r for r in stack if start<=r['displacement']<end]
    require(not direct,'unexpected direct stack operand at move field')
    require(by_va[0x24402b0]['bytes']=='4d85f6' and by_va[0x24402b3]['opcode']=='8d'
            and by_va[0x24402bb]['kind']=='conditional' and by_va[0x24402bb]['target']==0x2440593,
            'second storage selection changed')
    require(by_va[0x244071e]['bytes']=='c60021' and by_va[0x244085f]['bytes']=='c6010f',
            'result stores changed')
    # Eight BSWAP opcodes in each loop, including the indirect map builder.
    swaps={}
    for name,lo,hi in [('replacement',0x26bab0b,0x26bab23),('delta',0x244048b,0x24404c3)]:
        rows=[r for r in (writer_rows if name=='delta' else []) if lo<=r['va']<hi]
        if name=='replacement':
            rows=[by_va[x] for x in sorted(by_va) if lo<=x<hi]
        selected=[r for r in rows if r['opcode'].startswith('0f') and
                  0xc8<=int(r['opcode'][2:],16)<=0xcf]
        require(len(selected)==8,'slot byte-swap count changed')
        swaps[name]=[dict(site=hex(r['va']),bytes=r['bytes']) for r in selected]
    choices=[dict(state_word=a,diff_word=b,choice=storage_choice(a,b)) for a in (0,1) for b in (0,1)]
    return (dict(assembled_base=assembled_base,writer_base=writer_base,record_size=record_size,
        bucket_stride=imm(0x243fe6c),copy_tail_bytes=imm(0x243feed),fields=fields,
        direct_rsp_audit=dict(start=start,end=end,entries=direct,
          limitation='Only explicit RSP plus constant operand starts; wider operands, aliases, callbacks and copy source/destination effects are not analyzed.'),
        result_tags=dict(success=imm(0x244071e),conflict=imm(0x244085f)),
        branch_model=choices,slot_swaps=swaps,
        limitation='Offsets describe this selected static path and synthetic predicates, not target runtime behavior.'),stack)




def duplicate_fields(image, by_va, fields):
    """Tie the six selected seen-guard arms to their literal field names."""
    sites=[(0x1d293bf,0x1d293cb,0x1d29408),
           (0x1d29436,0x1d29442,0x1d2947f),
           (0x1d2954a,0x1d29556,0x1d29593),
           (0x1d295be,0x1d295ca,0x1d29607),
           (0x1d294ad,0x1d294b9,0x1d294f6),
           (0x1d29348,0x1d29354,0x1d29391)]
    out=[]
    for field,(pointer_site,length_site,call_site) in zip(fields,sites):
        name_addr=by_va[pointer_site]['rip']
        length=by_va[length_site]['immediate']
        raw=image.read(name_addr,length)
        call=by_va[call_site]
        require(raw.hex()==field['name_hex'],'duplicate field label mismatch')
        require(call['kind']=='call' and call['target']==0x1ebaee0,'duplicate error call changed')
        out.append(dict(tag=field['tag'],name=field['name'],guard=field['visitor_target'],
            label_site=hex(pointer_site),label_va=hex(name_addr),label_file_offset=hex(image.offset(name_addr,length)),
            label_hex=raw.hex(),length=length,call_site=hex(call_site),call_target=hex(call['target'])))
    return out

def boundary_calls(image):
    """Two reviewed five-byte connecting calls, no enclosing body is selected."""
    rows=[]
    for site,expected,name in [(0x1e67b5d,0x1b2ad60,'argument to selected parser'),
                               (0x247dec9,0x243fd20,'preparation to selected writer')]:
        raw=image.read(site,5)
        require(raw[0]==0xe8,'boundary instruction is not direct CALL')
        target=site+5+struct.unpack('<i',raw[1:])[0]
        require(target==expected,'boundary call target changed')
        rows.append(dict(site=hex(site),file_offset=hex(image.offset(site,5)),raw=raw.hex(),
                         target=hex(target),meaning=name))
    return rows



def address_key_equal(left,right):
    """Synthetic projection of the reviewed 16-byte plus 4-byte key comparison."""
    require(isinstance(left,bytes) and isinstance(right,bytes) and len(left)==len(right)==20,
            'address keys must be 20 bytes')
    return left[:16]==right[:16] and left[16:]==right[16:]

def address_route(image,by_va):
    """Record key width, decoder return checks and previously pinned 09 bytes."""
    a=by_va[0x2806ff0]; b=by_va[0x2807016]
    require(a['immediate']==b['immediate']==20,'key decoder width changed')
    c=by_va[0x2806ffc]; d=by_va[0x2807022]
    require(c['immediate']==d['immediate']==3,'key decoder success tag changed')
    require(by_va[0x2807039]['displacement']==17 and by_va[0x280703c]['displacement']==1,
            'address output offsets changed')
    require(by_va[0x2526619]['immediate']==0 and by_va[0x2526659]['immediate']==1,
            'move nullable output tags changed')
    require(by_va[0x2806ff6]['rip']==by_va[0x280701c]['rip']==0x57705c0,
            'address decoder slot changed')
    target=image.relative(0x57705c0)
    require(target==0x156e650,'address decoder relocation changed')
    require(by_va[0x27c5d96]['bytes']=='f3410f6f1c24'
            and by_va[0x27c5daa]['bytes']=='66410f6e5c2410'
            and by_va[0x27c5dc7]['immediate']==0xffff
            and by_va[0x27c5dcd]['target']==0x27c5e1d, 'key equality sequence changed')
    require(by_va[0x27c5e2e]['immediate']==by_va[0x27c5e40]['immediate']==192
            and by_va[0x27c5ee5]['immediate']==216 and by_va[0x27c5ef5]['immediate']==2,
            'map replacement or insertion operands changed')
    sites=[0x27c5d96,0x27c5daa,0x27c5dc7,0x27c5dcd,
           0x27c5e2e,0x27c5e3e,0x27c5e40,0x27c5e4d,0x27c5ee5,0x27c5ef5,
           0x1bd8d1e,0x1b703d6,0x1b703db,0x2806ff0,0x2806ff6,0x2806ffc,
           0x2807016,0x280701c,0x2807022,0x2807039,0x280703c,
           0x1b703ef,0x1b7040b,0x1bd8c93,0x1bd8ca3,0x1bd8cae,
           0x1bd8d09,0x1bd8d19,0x243fe83,0x243fe90,0x2526619,0x2526624,0x2526659]
    return dict(key_width=a['immediate'],decoder_success_status=c['immediate'],
        decoder_slot=hex(by_va[0x2806ff6]['rip']),decoder_target=hex(target),
        address_output_offsets=[by_va[0x280703c]['displacement'],by_va[0x2807039]['displacement']],
        move_null_option_tag=by_va[0x2526619]['immediate'],
        move_nonnull_option_tag=by_va[0x2526659]['immediate'],
        precompile_09_key=image.read(0x574f0c0,20).hex(),
        matched_value_copy_bytes=by_va[0x27c5e2e]['immediate'],
        new_bucket_copy_bytes=by_va[0x27c5ee5]['immediate'],
        new_entry_result_tag=by_va[0x27c5ef5]['immediate'],
        byte_sites=[dict(site=hex(v),bytes=by_va[v]['bytes']) for v in sites],
        limitation='The key-to-09 composition is conditional on an external decoder returning the recorded bytes with success status; routing and callbacks remain external.')


def engine_flow(by_va):
    """Check one caller's shared cache address and the result/engine gates."""
    ctor=by_va[0x24810a6]
    apply=by_va[0x24810ee]
    builder=by_va[0x24817bb]
    alt_builder=by_va[0x2481397]
    require([r['bytes'] for r in (ctor,apply,builder,alt_builder)]==[
        '488dbc24d8040000','488d9424d8040000','488d9424d8040000','488d9424d8040000'],
        'cache stack address operation or argument register changed')
    cache=ctor['displacement']
    require(all(r['displacement']==cache for r in (apply,builder,alt_builder)),
            'cache stack address mismatch')
    require(by_va[0x24810f6]['target']==0x243fd20 and by_va[0x24817ce]['target']==0x247fd20,
            'selected engine flow calls changed')
    require(by_va[0x24810fb]['immediate']==by_va[0x244071e]['immediate']==0x21,
            'override completion status mismatch')
    require(by_va[0x2481103]['target']==0x24812cd,'override error route changed')
    sites=[0x248107e,0x248108b,0x24810a6,0x24810b7,0x24810cf,0x24810d2,
           0x24810ee,0x24810f6,0x24810fb,0x2481103,0x2481111,0x2481119,
           0x24812cd,0x248131c,0x2481329,0x24813d1,0x24813ef,0x24813f7,
           0x2481719,0x248171c,0x2481750,0x24817ab,0x24817bb,0x24817ce]
    return dict(cache_stack_displacement=cache,override_result_success=by_va[0x24810fb]['immediate'],
        apply_function=hex(by_va[0x24810f6]['target']),builder_function=hex(by_va[0x24817ce]['target']),
        error_target=hex(by_va[0x2481103]['target']),
        byte_sites=[dict(site=hex(v),bytes=by_va[v]['bytes']) for v in sites],
        limitation='Same stack address across selected calls; helper aliasing, conditional gates, caller routing and later registry behavior remain external.')


def request_flow(by_va, instructions):
    """Check the selected 40-byte map copies and SysV stack-argument arithmetic."""
    exact={
      0x1f6dcde:'e89d9defff', 0x1f6dceb:'4883fd04', 0x1f6dcef:'7505',
      0x1f6dcf1:'4531f6', 0x1f6dcf6:'4c8bb424e8000000',
      0x1f6dcfe:'0f108424f0000000', 0x1f6dd06:'0f29842480000000',
      0x1f6dd0e:'f30f6f842400010000', 0x1f6dd17:'660f7f842490000000',
      0x1f6dd20:'83fd03', 0x1f6dd23:'0f85c9030000', 0x1f6dd29:'4c893424',
      0x1f6dd2d:'660f6f842480000000', 0x1f6dd36:'0f288c2490000000',
      0x1f6dd3e:'f30f7f442408', 0x1f6dd44:'0f114c2418',
      0x1f6dd80:'4989e0', 0x1f6dd86:'e865a98400',
      0x27b8701:'4c89c3', 0x27b8723:'660f1003', 0x27b8727:'660f104b10',
      0x27b872c:'660f118424880a0000', 0x27b8735:'660f118c24980a0000',
      0x27b873e:'488b4320', 0x27b8742:'48898424a80a0000',
      0x27b89a1:'4c8dac24880a0000', 0x27b8a58:'498b4520',
      0x27b8a5c:'4889842430010000', 0x27b8a64:'f3410f6f4500',
      0x27b8a6a:'f3410f6f4d10', 0x27b8a70:'660f7f8c2420010000',
      0x27b8a79:'660f7f842410010000', 0x27b8a82:'488d842410010000',
      0x27b8a8a:'48890424', 0x27b8aaf:'e84c84ccff',
      0x24810bc:'488bb424e0050000',
    }
    for site,raw in exact.items():
        require(by_va[site]['bytes']==raw,'request forwarding byte mismatch')
    prologue=instructions[0x2480f00]
    require([r['opcode'] for r in prologue[:6]]==['55','57','56','55','54','53'],
            'engine caller push sequence changed')
    require(prologue[6]['va']==0x2480f0a and prologue[6]['opcode']=='81',
            'engine caller stack allocation changed')
    allocation=prologue[6]['immediate']
    stack_arg=by_va[0x24810bc]['displacement']
    word=8
    require(allocation+word*(len(prologue[:6])+1)==stack_arg,
            'stack argument offset inconsistent with frame')
    require(by_va[0x1f6dcde]['target']==0x1e67a80
            and by_va[0x1f6dd86]['target']==0x27b86f0
            and by_va[0x27b8aaf]['target']==0x2480f00,'request call chain changed')
    # Six vector moves plus two scalar words are assembled into 40 bytes.
    first=by_va[0x27b872c]['displacement']
    last=by_va[0x27b8742]['displacement']
    second=by_va[0x27b8a79]['displacement']
    second_last=by_va[0x27b8a5c]['displacement']
    width=last-first+word
    require(width==second_last-second+word==40,'map copy length changed')
    return dict(first_adapter_stack=first,second_adapter_stack=second,map_copy_bytes=width,
        callee_stack_allocation=allocation,saved_register_words=len(prologue[:6]),
        return_address_words=1,stack_argument_displacement=stack_arg,
        byte_sites=[dict(site=hex(v),bytes=by_va[v]['bytes']) for v in exact],
        limitation='The 40-byte dataflow is conditional on the selected branches, normal helper returns, SysV calling convention and no destructive aliases.')

def collect(image):
    functions=[]; code={}; control=[]; refs=[]; unwind=[]; exceptions=[]; lsda=[]
    instructions={}; relocs={}
    from elf_index import unwind_index
    _, index=unwind_index(image.data)
    index_by_start={row['start']:row for row in index}
    for start,(role,expected_hash) in sorted(FUNCTIONS.items()):
        f=image.fde(start)
        require(start in index_by_start and index_by_start[start]['fde']==f['fde'],
                'unwind header and FDE disagree')
        raw=image.read(start,f['end']-start)
        require(digest(raw)==expected_hash,'selected function byte mismatch')
        rows=decode(raw,start); instructions[start]=rows
        functions.append(dict(start=hex(start),end=hex(f['end']),bytes=len(raw),
            file_offset=hex(image.offset(start,len(raw))),fde=hex(f['fde']),cie=hex(f['cie']),
            lsda=hex(f['lsda']) if f['lsda'] else '',sha256=digest(raw),instructions=len(rows),role=role))
        code[hex(start)]=rows
        for kind in ('fde','cie'):
            va=f[kind]; n=struct.unpack('<I',image.read(va,4))[0]+4
            unwind.append(dict(function=hex(start),kind=kind,va=hex(va),
                               file_offset=hex(image.offset(va,n)),raw=image.read(va,n).hex()))
        ex,ls=call_sites(image,start,{r['va'] for r in rows})
        exceptions.extend(ex)
        if ls: lsda.append(ls)
        for r in rows:
            target=r.get('target'); resolved=False
            if 'rip' in r:
                ptr=r['rip']; rec=image.relas.get(ptr)
                refs.append(dict(function=hex(start),site=hex(r['va']),address=hex(ptr),bytes=r['bytes'],
                                 relative_addend=hex(rec[1]) if rec and rec[0]==8 else ''))
                if rec:
                    info,addend,off=rec
                    relocs[ptr]=dict(slot=hex(ptr),info=hex(info),addend=hex(addend),
                                     file_offset=hex(off),raw=image.data[off:off+24].hex())
                    if info==8 and r['kind'].startswith('indirect-'):
                        target=addend; resolved=True
            if r['kind']!='ordinary':
                scope='dynamic' if target is None and r['kind'].startswith('indirect-') else ''
                if target is not None:
                    scope='local' if start<=target<f['end'] else ('selected' if target in FUNCTIONS else 'external')
                control.append(dict(function=hex(start),site=hex(r['va']),kind=r['kind'],bytes=r['bytes'],
                    condition=r.get('condition',''),target=hex(target) if target is not None else '',
                    fallthrough=hex(r['va']+r['size']) if r['kind']=='conditional' or 'call' in r['kind'] else '',
                    target_scope=scope,via_relative_relocation=int(resolved)))
    by_va={r['va']:r for rows in instructions.values() for r in rows}
    owners={r['va']:start for start,rows in instructions.items() for r in rows}
    edges=[]
    for va,expected,meaning in EDGES:
        row=by_va[va]
        require(row['kind'] in ('call','indirect-call'),'selected edge is not a call')
        slot=row.get('rip') if row['kind']=='indirect-call' else None
        target=image.relative(slot) if slot is not None else row.get('target')
        require(target==expected,'selected edge mismatch')
        edges.append(dict(function=hex(owners[va]),site=hex(va),bytes=row['bytes'],
                          slot=hex(slot) if slot is not None else '',target=hex(target),
                          scope='selected' if expected in FUNCTIONS else 'external',meaning=meaning))
    branches=selected_predicates(by_va,owners)
    boundary=boundary_calls(image)
    route=address_route(image,by_va)
    engine=engine_flow(by_va)
    request=request_flow(by_va,instructions)
    fields,lens,guards=extract_fields(image,by_va)
    specs=comparison_specs(image,fields,by_va)
    duplicates=duplicate_fields(image,by_va,fields)
    layout,stack=derive_layout(by_va,instructions[0x243fd20])
    for i in range(len(fields)):
        slot=0x56a67f0+16*i
        info,addend,off=image.relas[slot]
        relocs[slot]=dict(slot=hex(slot),info=hex(info),addend=hex(addend),
                          file_offset=hex(off),raw=image.data[off:off+24].hex())
    tables=[]
    for name,base,fn,entries in [('field-length',0x3e21ec,0x2441c70,lens),
                                  ('field-tag',0x3b71c4,0x1d278c0,guards)]:
        for i,raw,disp,target in entries:
            tables.append(dict(table=name,base=hex(base),entry=i,entry_va=hex(base+4*i),
                file_offset=hex(image.offset(base+4*i,4)),raw=raw.hex(),displacement=disp,target=hex(target),function=hex(fn)))
    pub_bounds={r['va'] for r in instructions[0x1eb2640]}
    require(by_va[0x1eb265d]['rip']==0x3bf238 and by_va[0x1eb275a]['rip']==0x3bf24c,
            'publication variant tables changed')
    variant_count=(by_va[0x1eb275a]['rip']-by_va[0x1eb265d]['rip'])//4
    require(variant_count==5,'publication table width changed')
    pub_first=relative_table(image,0x3bf238,variant_count,pub_bounds)
    require(pub_first[4][3]==0x1eb2955,'publication tag four bypass changed')
    pub_second=relative_table(image,0x3bf24c,variant_count-1,pub_bounds)
    for name,base,entries in [('publish-variant',0x3bf238,pub_first),
                              ('publish-code-clone',0x3bf24c,pub_second)]:
        for i,raw,disp,target in entries:
            tables.append(dict(table=name,base=hex(base),entry=i,entry_va=hex(base+4*i),
                file_offset=hex(image.offset(base+4*i,4)),raw=raw.hex(),displacement=disp,
                target=hex(target),function=hex(0x1eb2640)))
    windows=[]
    for name,start,end in WINDOWS:
        require(start in by_va,'window start is not an instruction boundary')
        start_owner=owners[start]
        rows=[r for r in instructions[start_owner] if start<=r['va']<end]
        require(rows and rows[-1]['va']+rows[-1]['size']==end,f'window {name} end is not a boundary: {end:#x}')
        raw=image.read(start,end-start)
        windows.append(dict(name=name,function=hex(start_owner),start=hex(start),end=hex(end),
                            file_offset=hex(image.offset(start,len(raw))),raw=raw.hex(),sha256=digest(raw)))
    constants=[]
    for name,va,n in [('field-long-first',0x2068d0,16),('field-long-overlap',0x203f90,16),
                      ('precompile-address-from-prior-work',0x574f0c0,20)]:
        raw=image.read(va,n)
        constants.append(dict(name=name,va=hex(va),file_offset=hex(image.offset(va,n)),raw=raw.hex()))
    require(constants[-1]['raw']=='00'*19+'09','precompile object address changed')
    summary=dict(target_sha256=SHA,functions=len(functions),function_bytes=sum(x['bytes'] for x in functions),
        instruction_rows=len(by_va),control_rows=len(control),rip_references=len(refs),
        exceptions=len(exceptions),fields=len(fields),duplicate_fields=len(duplicates),table_entries=len(tables),
        selected_edges=len(edges),selected_branches=len(branches),boundary_calls=len(boundary),semantic_windows=len(windows),
        relocations=len(relocs),
        limitation='Bounded FDE intervals and byte-backed selections; no target execution, source boundary or component equivalence.')
    return {
        'functions.tsv':tsv(functions,['start','end','bytes','file_offset','fde','cie','lsda','sha256','instructions','role']),
        'instructions.json':json.dumps(code,sort_keys=True,separators=(',',':'))+'\n',
        'control.tsv':tsv(control,['function','site','kind','bytes','condition','target','fallthrough','target_scope','via_relative_relocation']),
        'call-edges.tsv':tsv(edges,['function','site','bytes','slot','target','scope','meaning']),
        'branches.tsv':tsv(branches,['function','predicate','bytes','branch','branch_bytes','condition','taken','fallthrough','meaning']),
        'duplicate-errors.tsv':tsv(duplicates,['tag','name','guard','label_site','label_va','label_file_offset','label_hex','length','call_site','call_target']),
        'fields.tsv':tsv(fields,['tag','name','name_hex','name_va','name_file_offset','size','descriptor','descriptor_file_offset',
                                  'classifier_entry','tag_store','tag_store_bytes','visitor_target','value_call','value_helper']),
        'tables.tsv':tsv(tables,['table','base','entry','entry_va','file_offset','raw','displacement','target','function']),
        'rip-references.tsv':tsv(refs,['function','site','address','bytes','relative_addend']),
        'relocations.tsv':tsv([relocs[k] for k in sorted(relocs)],['slot','info','addend','file_offset','raw']),
        'unwind-records.json':js(unwind),'exception-call-sites.tsv':tsv(exceptions,['function','lsda','site','end','landing','action','raw']),
        'lsda-records.json':js(lsda),'windows.json':js(windows),'constants.json':js(constants),'summary.json':js(summary),
        'field-model.json':js(specs),'layout-and-cases.json':js(layout),'address-route.json':js(route),'engine-flow.json':js(engine),'request-flow.json':js(request),
        'boundary-calls.tsv':tsv(boundary,['site','file_offset','raw','target','meaning']),
        'writer-stack-operands.tsv':tsv(stack,['site','bytes','opcode','displacement']),
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    image=Image((ROOT/'artifacts/node/94/hl-node').read_bytes())
    result=collect(image)
    args.out.mkdir(parents=True,exist_ok=True)
    for name,content in sorted(result.items()):
        (args.out/name).write_bytes(content.encode('utf-8'))


if __name__=='__main__':
    main()

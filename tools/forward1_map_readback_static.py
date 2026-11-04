#!/usr/bin/env python3
"""Trace the readers of the node 115 forward-1 ordered map.

RE-006's forward-callee packet (0x4eeed90) records the ordered map
written by the insert callee forward_1: 24-byte entries
{scrambled hash, key, value} in the buffer at map + 0x8, the hash
rol(key * 0xf1357aea2e62a9c5, 0x14), the value the slab slot index
forwarded from the append twins, plus a bucket array whose words
hold entry positions.  The node-insert packet then proved the
forwarded index is durably stored by both forward callees, and
settled negatively that the two slab lookups (0x4da81b0 /
0x4da7880) are not the map readback.  This packet answers the
remaining question: who reads the forward-1 map back.

Method: census first.  A raw scan of .text finds 114 copies of the
hash constant in 84 FDEs.  A probe needs two more shapes on top of
the hash: a bucket-word load (mov -0x8(base), reg, the position
word stored just before the control bytes) and a key compare
against entry + 0x8 with scale-8 addressing (entry index times
three, the 24-byte stride).  Exactly six FDEs carry the constant
and both shapes: forward_1 itself (the writer), the two owners
below, the inlined consumer 0x23e4c80, and the two 12,076-byte
twins 0x23d4790 / 0x23d76c0.  Every other constant user hashes a
different key shape or probes a different layout (the near-twin
insert 0x4ef3170 writes 32-byte entries; 0x4ef8240 / 0x4ef8e20
hash a 32-byte key with SipHash-family constants and probe a
table whose entries sit at +0x0, not +0x8).

Owners (the only standalone reader FDEs):
- contains 0x4ef4010..0x4ef414f (319 bytes): a boolean membership
  probe.  It loads the length once, answers the length-one case
  from the single entry's key, and otherwise recomputes the
  scrambled hash, probes the bucket chain, and compares the key
  at entry + 0x8.  It never loads the entry value at +0x10 and
  never stores to memory: the value is not read here at all.
  81 direct call sites.
- remove 0x4e37a10..0x4e37e5c (1,100 bytes): a swap-remove that
  returns the removed entry's value in rdx (eax = 1 found /
  0 not found).  Its four callers (two twin pairs at
  0x58e1400..0x58e4300) capture rdx as the slab slot index,
  bound it against the slab length at book + 0x90, multiply by
  the 0x110-byte slab stride, and require the slot state dword
  to differ from 2 (vacant) before reading the order copy.
  The length-one path reuses the stored entry hash and never
  recomputes the key hash; the general path recomputes it.

There is no standalone get: every remaining read of an entry
value is inlined at the consumer.  The four RE-006 insert
callers gate on contains, then load entries[position] + 0x10
themselves at the walked position and apply the same slab
bound / stride / state checks; 0x23e4c80 inlines the whole probe
(hash, bucket chain, key compare) and consumes the value the
same way, reading the order copy's +0xb0 fields.  The two
12,076-byte twins inline three probes each whose hit blocks do
not load the probed entry's value in the pinned windows:
membership use at the traced instance (whether the probed table
is the forward-1 map instance is not established; the fields
arrive stack-spilled).

Every cited byte is pinned and validated as a native
instruction start; the reference censuses are re-derived from
raw scans and every E8 site is re-validated as an instruction
start inside its containing FDE.
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = (ROOT / 'research/work-items/'
          'RE-006-node115-forward1-map-readback')
TARGET_SIZE = 105_896_032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7a8278'
                 'fa39f249e98c3867b5301')

CONTAINS = 0x4EF4010
REMOVE = 0x4E37A10
FORWARD_1 = 0x4EEED90
INLINE_GET = 0x23E4C80
TWIN_A = 0x23D4790
TWIN_B = 0x23D76C0
HASH_CONSTANT = 0xF1357AEA2E62A9C5
HASH_CONSTANT_LE = bytes.fromhex('c5a9622eea7a35f1')
SLAB_STRIDE = 0x110

CONTAINS_PINS = {
    0x4ef4014: bytes.fromhex('488b4710'),
    0x4ef4018: bytes.fromhex('4883f801'),
    0x4ef402b: bytes.fromhex('488b4f08'),
    0x4ef4031: bytes.fromhex('483b7108'),
    0x4ef4035: bytes.fromhex('0f94c0'),
    0x4ef4042: bytes.fromhex('48b9c5a9622eea7a35f1'),
    0x4ef404c: bytes.fromhex('480fafce'),
    0x4ef4050: bytes.fromhex('48c1c114'),
    0x4ef4054: bytes.fromhex('4c8b4708'),
    0x4ef4058: bytes.fromhex('4c8b4f18'),
    0x4ef4063: bytes.fromhex('488b7f20'),
    0x4ef40bd: bytes.fromhex('488b53f8'),
    0x4ef40c1: bytes.fromhex('4839c2'),
    0x4ef40cd: bytes.fromhex('4c8d3452'),
    0x4ef40d4: bytes.fromhex('4b3b74f008'),
    0x4ef4108: bytes.fromhex('b801000000'),
    0x4ef4115: bytes.fromhex('31c0'),
    0x4ef4102: bytes.fromhex('ff1518b45e01'),
    0x4ef413c: bytes.fromhex('ff15deb45e01'),
}
REMOVE_PINS = {
    0x4e37a17: bytes.fromhex('488b4710'),
    0x4e37a24: bytes.fromhex('488b16'),
    0x4e37a31: bytes.fromhex('488b4708'),
    0x4e37a35: bytes.fromhex('483b5008'),
    0x4e37a3f: bytes.fromhex('48c7471000000000'),
    0x4e37a47: bytes.fromhex('488b30'),
    0x4e37a4a: bytes.fromhex('488b5010'),
    0x4e37ab8: bytes.fromhex('49837af800'),
    0x4e37af1: bytes.fromhex('49bbc5a9622eea7a35f1'),
    0x4e37afb: bytes.fromhex('4c0fafda'),
    0x4e37aff: bytes.fromhex('49c1c314'),
    0x4e37b03: bytes.fromhex('4c8b4f08'),
    0x4e37b07: bytes.fromhex('488b7718'),
    0x4e37b12: bytes.fromhex('4c8b4720'),
    0x4e37b75: bytes.fromhex('498b4ff8'),
    0x4e37b79: bytes.fromhex('4839c1'),
    0x4e37b89: bytes.fromhex('488d0c49'),
    0x4e37b90: bytes.fromhex('493b54c908'),
    0x4e37c16: bytes.fromhex('488b5728'),
    0x4e37c27: bytes.fromhex('48895728'),
    0x4e37c37: bytes.fromhex('42881416'),
    0x4e37c3b: bytes.fromhex('88540e10'),
    0x4e37c3f: bytes.fromhex('488b4f30'),
    0x4e37c4f: bytes.fromhex('48ffc9'),
    0x4e37c52: bytes.fromhex('48894f30'),
    0x4e37c68: bytes.fromhex('4b8b54d110'),
    0x4e37c74: bytes.fromhex('4b8b5cd910'),
    0x4e37c7e: bytes.fromhex('430f1104d1'),
    0x4e37c83: bytes.fromhex('4b895cd110'),
    0x4e37c88: bytes.fromhex('48894710'),
    0x4e37dcb: bytes.fromhex('49f7da'),
    0x4e37dce: bytes.fromhex('4a894cd6f8'),
    0x4e37dd3: bytes.fromhex('b801000000'),
    0x4e37d3c: bytes.fromhex('31c0'),
    0x4e37de9: bytes.fromhex('ff15e1786a01'),
    0x4e37e30: bytes.fromhex('ff15127a6a01'),
    0x4e37e56: bytes.fromhex('ff1514796a01'),
}
REMOVE_CALLER_A_PINS = {
    0x58e14fb: bytes.fromhex('488d742460'),
    0x58e1500: bytes.fromhex('4c89ff'),
    0x58e1503: bytes.fromhex('e8086555ff'),
    0x58e1508: bytes.fromhex('4883f801'),
    0x58e1512: bytes.fromhex('4889d5'),
    0x58e1515: bytes.fromhex('4889542468'),
    0x58e1544: bytes.fromhex('493baf90000000'),
    0x58e1551: bytes.fromhex('498b8f88000000'),
    0x58e1558: bytes.fromhex('4869c510010000'),
    0x58e155f: bytes.fromhex('833c0102'),
    0x58e1563: bytes.fromhex('0f8442040000'),
}
INSERT_CALLER_1_PINS = {
    0x5904aa8: bytes.fromhex('498b36'),
    0x5904aab: bytes.fromhex('488b7c2408'),
    0x5904ab0: bytes.fromhex('e85bf55eff'),
    0x5904ab5: bytes.fromhex('4983c608'),
    0x5904abc: bytes.fromhex('4883f801'),
    0x5904ac2: bytes.fromhex('488b7c2408'),
    0x5904ac7: bytes.fromhex('488b7710'),
    0x5904acb: bytes.fromhex('4839f2'),
    0x5904ad4: bytes.fromhex('488b4708'),
    0x5904ad8: bytes.fromhex('488d0c52'),
    0x5904adc: bytes.fromhex('488b44c810'),
    0x5904ae4: bytes.fromhex('483b8790000000'),
    0x5904aed: bytes.fromhex('488b4c2408'),
    0x5904af2: bytes.fromhex('4c8ba188000000'),
    0x5904af9: bytes.fromhex('4869c010010000'),
    0x5904b00: bytes.fromhex('41833c0402'),
    0x5904b05: bytes.fromhex('4c89e9'),
    0x5904b08: bytes.fromhex('0f8477ffffff'),
    0x5904e7e: bytes.fromhex('488b7c2408'),
    0x5904e83: bytes.fromhex('4c89f6'),
    0x5904e86: bytes.fromhex('e885f15eff'),
    0x5904e8b: bytes.fromhex('4883f801'),
    0x5904e91: bytes.fromhex('488b7c2408'),
    0x5904e96: bytes.fromhex('488b7710'),
    0x5904ea3: bytes.fromhex('488b4708'),
    0x5904ea7: bytes.fromhex('488d0c52'),
    0x5904eab: bytes.fromhex('488b44c810'),
    0x5904eb0: bytes.fromhex('483b8790000000'),
    0x5904eb9: bytes.fromhex('488b4c2408'),
    0x5904ebe: bytes.fromhex('4c8ba188000000'),
    0x5904ec5: bytes.fromhex('4869c010010000'),
    0x5904ecc: bytes.fromhex('41833c0402'),
    0x5904ed1: bytes.fromhex('7548'),
}
INLINE_GET_PINS = {
    0x23e541a: bytes.fromhex('488b442408'),
    0x23e541f: bytes.fromhex('488b7010'),
    0x23e542c: bytes.fromhex('4d8b64dc08'),
    0x23e5431: bytes.fromhex('4883fe01'),
    0x23e543b: bytes.fromhex('488b442408'),
    0x23e5440: bytes.fromhex('488b4008'),
    0x23e5444: bytes.fromhex('4c3b6008'),
    0x23e544e: bytes.fromhex('31ff'),
    0x23e5450: bytes.fromhex('488d0c7f'),
    0x23e5454: bytes.fromhex('488b4cc810'),
    0x23e5459: bytes.fromhex('488b442408'),
    0x23e545e: bytes.fromhex('483b8890000000'),
    0x23e546b: bytes.fromhex('488b442408'),
    0x23e5470: bytes.fromhex('488b8088000000'),
    0x23e5477: bytes.fromhex('4869c910010000'),
    0x23e547e: bytes.fromhex('833c0802'),
    0x23e5488: bytes.fromhex('4801c8'),
    0x23e548b: bytes.fromhex('f20f1088b0000000'),
    0x23e5503: bytes.fromhex('48b8c5a9622eea7a35f1'),
    0x23e550d: bytes.fromhex('480fafc8'),
    0x23e5511: bytes.fromhex('48c1c114'),
    0x23e551a: bytes.fromhex('498b4008'),
    0x23e551e: bytes.fromhex('498b5018'),
    0x23e5529: bytes.fromhex('4d8b4020'),
    0x23e5581: bytes.fromhex('498b7bf8'),
    0x23e5585: bytes.fromhex('4839f7'),
    0x23e5595: bytes.fromhex('488d1c7f'),
    0x23e559c: bytes.fromhex('4c3b64d808'),
    0x23e55a3: bytes.fromhex('e9a8feffff'),
}
TWIN_A_PINS = {
    0x23d51a3: bytes.fromhex('48b9c5a9622eea7a35f1'),
    0x23d5231: bytes.fromhex('4c3b6cfe08'),
    0x23d5236: bytes.fromhex('75b8'),
    0x23d5238: bytes.fromhex('e953010000'),
    0x23d5591: bytes.fromhex('4c3b6cfe08'),
    0x23d5907: bytes.fromhex('4d3b7cfc08'),
}
TWIN_B_PINS = {
    0x23d80d3: bytes.fromhex('48b9c5a9622eea7a35f1'),
    0x23d8161: bytes.fromhex('4c3b6cfe08'),
    0x23d84c1: bytes.fromhex('4c3b6cfe08'),
    0x23d8837: bytes.fromhex('4d3b7cfc08'),
}

OWNERS = {
    'contains': {
        'range': (0x4EF4010, 0x4EF414F),
        'sha256': ('05b749456b1fccdfb9adc166530c85cc87c16c30'
                   'f5827934ae82a484e0abe891'),
        'pins': CONTAINS_PINS,
        'slot_calls': {
            0x4EF4102: (0x64DF520, 0x1681DA0),
            0x4EF413C: (0x64DF620, 0x1680CBF),
        },
    },
    'remove': {
        'range': (0x4E37A10, 0x4E37E5C),
        'sha256': ('7198d869bf8f939a3f953b36c4e1279a6849240e6'
                   '8cd86dc39518509843a2385'),
        'pins': REMOVE_PINS,
        'slot_calls': {
            0x4E37DE9: (0x64DF6D0, 0x141E2DA),
            0x4E37E30: (0x64DF848, 0x1681E40),
            0x4E37E56: (0x64DF770, 0x1680BD0),
        },
    },
}
BOUNDARIES = {
    'forward_1': {
        'range': (0x4EEED90, 0x4EEF13B),
        'sha256': ('399e403494b758bc98103adc72979271e0d22326718a'
                   '30881de3f904b812e015'),
    },
    'remove_caller_a': {
        'range': (0x58E1400, 0x58E1F34),
        'sha256': ('e978a87b5223ae9319a66a1b651849d36df81823cda'
                   '84d9e0a688bffc74e9827'),
        'pins': REMOVE_CALLER_A_PINS,
        'calls': {0x58E1503: REMOVE},
    },
    'remove_caller_b': {
        'range': (0x58E1F40, 0x58E2A74),
        'sha256': ('34c675f2dda0a756f173c72ca26313f16e6d15d505'
                   '5fd03dc712484d806e5137'),
        'calls': {0x58E2043: REMOVE},
    },
    'remove_caller_c': {
        'range': (0x58E2A80, 0x58E36C0),
        'sha256': ('ae7e16c8b741bb8b3bb7931c82d271e359164e42f'
                   'd9a40c0c96bbe7f56875954'),
        'calls': {0x58E2BCD: REMOVE},
    },
    'remove_caller_d': {
        'range': (0x58E36C0, 0x58E4300),
        'sha256': ('1fbc74ef092d6469a9dc7985286fb9c62e682b6c8'
                   'ceca081fdf2f3181c738e73'),
        'calls': {0x58E380D: REMOVE},
    },
    'insert_caller_1': {
        'range': (0x5901DD0, 0x5905CE9),
        'sha256': ('69712a6423044cdfd8b9a5ddf17ffa1a7c63463814'
                   '71234df8aa587d04e4b2c6'),
        'pins': INSERT_CALLER_1_PINS,
        'calls': {0x5904AB0: CONTAINS, 0x5904E86: CONTAINS},
    },
    'insert_caller_2': {
        'range': (0x5905CF0, 0x5909B21),
        'sha256': ('41b6ea3b11ca2a035f22bfa7703cb11ca5a623eb0a'
                   '3970740b0193580a649e84'),
        'calls': {0x5908D65: CONTAINS},
    },
    'insert_caller_3': {
        'range': (0x5909B30, 0x590DA49),
        'sha256': ('368701b152fa985ad4852bfa862db2edefb73b7c15'
                   'f5c425be49a1e259f6ecc4'),
        'calls': {0x590C810: CONTAINS, 0x590CBE6: CONTAINS},
    },
    'insert_caller_4': {
        'range': (0x590DA50, 0x5911881),
        'sha256': ('17d3fe719c2fc2a12be204c26a182231920e632f8'
                   '1aabf26844f48acf6374bd2'),
        'calls': {0x5910AC5: CONTAINS},
    },
    'inline_get': {
        'range': (0x23E4C80, 0x23E58E5),
        'sha256': ('1ab3f271a6948b076f8b9727aa1bc4bf5cca56c6ef'
                   '60543349de6bb89c78aa9d'),
        'pins': INLINE_GET_PINS,
    },
    'twin_probe_a': {
        'range': (0x23D4790, 0x23D76BC),
        'sha256': ('7ad1af6f3e6a48820816926d88fcfd9a5253aeac4ae'
                   '93cfd7d1d281127a1a24d'),
        'pins': TWIN_A_PINS,
    },
    'twin_probe_b': {
        'range': (0x23D76C0, 0x23DA5EC),
        'sha256': ('ab4d81c3e136290d46843933e062fa51d0f49c6f22'
                   '6ff389f93220e26d945f8d'),
        'pins': TWIN_B_PINS,
    },
}
SLOT_BINDINGS = {
    0x64DF520: 0x1681DA0,
    0x64DF620: 0x1680CBF,
    0x64DF6D0: 0x141E2DA,
    0x64DF770: 0x1680BD0,
    0x64DF848: 0x1681E40,
}
REMOVE_CALL_SITES = [0x58E1503, 0x58E2043, 0x58E2BCD, 0x58E380D]
FORWARD_1_CALL_SITES = [0x4ED91D4, 0x4EDD2BD, 0x5903FCC,
                        0x5908237, 0x590BD2C, 0x590FF97]
RE006_CONTAINS_SITES = {
    'insert_caller_1': [0x5904AB0, 0x5904E86],
    'insert_caller_2': [0x5908D65],
    'insert_caller_3': [0x590C810, 0x590CBE6],
    'insert_caller_4': [0x5910AC5],
}
SIGNATURE_FDES = [FORWARD_1, TWIN_A, TWIN_B, INLINE_GET,
                  REMOVE, CONTAINS]
READBACK = (
    'the forward-1 map has exactly two standalone reader FDEs: '
    'contains, a boolean membership probe that never loads the '
    'entry value, and remove, which returns the removed entry\'s '
    'value in rdx; there is no standalone get — every other read '
    'of an entry value is inlined at the consumer')
CONTAINS_VERDICT = (
    'membership only: contains answers whether the key is '
    'present; it never loads the entry value at +0x10 and never '
    'stores to memory')
REMOVE_VERDICT = (
    'remove returns the removed entry\'s value (the slab slot '
    'index) in rdx with eax = 1, or eax = 0 when the key is '
    'absent; its callers consume rdx as the slab slot index')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hx(value):
    return f'0x{value:x}'


def sha(body):
    return hashlib.sha256(body).hexdigest()


def authenticate(data):
    require(len(data) == TARGET_SIZE, 'Unexpected node 115 size')
    require(sha(data) == TARGET_SHA256, 'Unexpected node 115 digest')


def relative_relocations(data):
    result = {}
    for section in sections(data):
        if section['name'] == '.rela.dyn':
            blob = data[section['offset']:
                        section['offset'] + section['size']]
            for cursor in range(0, len(blob), 24):
                offset, info, addend = struct.unpack_from(
                    '<QQq', blob, cursor)
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


def check_pins(spec, body, start):
    for va, expected in spec.get('pins', {}).items():
        offset = va - start
        require(body[offset:offset + len(expected)] == expected,
                f'Pinned instruction changed: {hx(va)}')
    for va, target in spec.get('calls', {}).items():
        require(body[va - start] == 0xE8,
                f'Pinned call opcode changed: {hx(va)}')
        require(resolve_e8(body, start, va) == target,
                f'Pinned call target changed: {hx(va)}')
    for va, (slot, target) in spec.get('slot_calls', {}).items():
        offset = va - start
        length = len(body[offset:offset + 6])
        require(body[offset] == 0xFF,
                f'Pinned slot call changed: {hx(va)}')
        require(resolve_slot(body, start, va, 6) == slot,
                f'Pinned slot call slot changed: {hx(va)}')


def decode_body(data, start, end, cache):
    """objdump-decode one FDE body from a temp copy of the data.

    Returns (text, rows) where rows maps each native instruction
    start to (opcode, size, source text) via decode_export.
    """
    key = (start, end)
    if key in cache:
        return cache[key]
    _, body = read(data, sections(data), start, end - start)
    with tempfile.NamedTemporaryFile(
            suffix='.bin', delete=False) as handle:
        handle.write(body)
        path = handle.name
    try:
        text = subprocess.check_output([
            'objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
            f'--adjust-vma={start:#x}', path,
        ], text=True)
    finally:
        os.unlink(path)
    rows = decode_export(text, start, end, body)
    cache[key] = (text, rows)
    return cache[key]


_LINE = re.compile(r'^\s+([0-9a-f]+):\t[0-9a-f ]+\t(.*)$')


def text_instructions(text):
    result = []
    for line in text.splitlines():
        match = _LINE.match(line)
        if match:
            result.append((int(match.group(1), 16), match.group(2)))
    return result


def sites_matching(text, pattern):
    regex = re.compile(pattern)
    return [va for va, ins in text_instructions(text) if regex.search(ins)]


def readback_verdict(get_fdes, contains_reads_value,
                     remove_returns_value):
    if get_fdes:
        return 'a standalone get FDE exists'
    if contains_reads_value:
        return 'contains reads the entry value'
    if not remove_returns_value:
        return 'remove does not return the entry value'
    return READBACK


VALUE_LOAD = r'mov\s+0x10\(%r\w+,\s?%r\w+,8\),\s?%r\w+'
KEY_CMP = (r'cmp\s+(?:0x8\(%r\w+,\s?%r\w+,8\),\s?%r\w+'
           r'|%r\w+,\s?0x8\(%r\w+,\s?%r\w+,8\))')
BUCKET = (r'mov\s+-0x8\(%r\w+(?:,\s?%r\w+,8)?\),\s?%r\w+'
          r'|cmpq\s+\$0x0,\s?-0x8\(%r\w+\)')
MEM_STORE = re.compile(
    r'^(?:mov|movb|movw|movl|movq|movups|movaps|movdqa|movdqu'
    r'|and|or|add|sub)\s+[^,\n]+,\s*-?0x[0-9a-f]*\(%'
    r'|^(?:mov|movb|movw|movl|movq)\s+[^,\n]+,\s*\(%')


def analyze(data, binary=TARGET):
    section_list = sections(data)
    summary, fdes, _gaps = fde_extents(data)
    by_range = {(item['start'], item['end']): item for item in fdes}
    by_start = {item['start']: item for item in fdes}
    ordered_starts = sorted(by_start)
    relas = relative_relocations(data)
    for slot, target in SLOT_BINDINGS.items():
        require(relas.get(slot) == target,
                f'Slot binding changed: {hx(slot)}')
    specs = dict(OWNERS)
    specs.update(BOUNDARIES)
    bodies = {}
    frames = {}
    for name, spec in specs.items():
        start, end = spec['range']
        require((start, end) in by_range,
                f'{name} is not an exact FDE body')
        offset, body = read(data, section_list, start, end - start)
        bodies[name] = body
        record = by_range[(start, end)]
        frames[name] = {
            'fde': hx(record['fde']),
            'cie': hx(record['cie']),
            'lsda': (hx(record['lsda'])
                     if record['lsda'] is not None else None),
            'range': [hx(start), hx(end)],
            'bytes': end - start,
            'file_offset': hx(offset),
            'sha256': spec['sha256'],
        }
    # Byte pins and resolved call targets first; the
    # disassembly-based scans run afterwards, so a mutated byte
    # is reported by the pin that covers it.
    for name, spec in specs.items():
        if 'pins' in spec or 'calls' in spec or 'slot_calls' in spec:
            check_pins(spec, bodies[name], spec['range'][0])
    all_ranges = [spec['range'] for spec in specs.values()]
    body_refs = [
        hx(offset) for offset in sorted(relas)
        if any(start <= offset < end for start, end in all_ranges)
    ]
    bound_targets = set(SLOT_BINDINGS.values())
    addend_refs = [
        hx(value) for value in sorted(set(relas.values()))
        if value not in bound_targets
        and any(value == start for start, _ in all_ranges)
    ]
    require(not body_refs,
            'An owner or boundary body holds a relocation slot')
    require(not addend_refs,
            'An owner or boundary body is reached through an '
            'unrecorded relocation')

    text = next(section for section in section_list
                if section['name'] == '.text')
    text_body = data[text['offset']:text['offset'] + text['size']]

    def census(opcode, targets):
        hits = {target: [] for target in targets}
        cursor = text_body.find(bytes([opcode]))
        while cursor != -1:
            site = text['address'] + cursor
            target = site + 5 + struct.unpack_from(
                '<i', text_body, cursor + 1)[0]
            if target in hits:
                hits[target].append(site)
            cursor = text_body.find(bytes([opcode]), cursor + 1)
        return hits

    census_targets = (CONTAINS, REMOVE, FORWARD_1)
    call_census = census(0xE8, census_targets)
    jump_census = census(0xE9, census_targets)
    require(call_census[REMOVE] == REMOVE_CALL_SITES,
            'direct caller census changed')
    require(call_census[FORWARD_1] == FORWARD_1_CALL_SITES,
            'direct caller census changed')
    require(len(call_census[CONTAINS]) == 81,
            'direct caller census changed')
    require(not any(jump_census.values()),
            'direct jump census changed')
    addend_census = {
        hx(target): [hx(offset) for offset, value in sorted(relas.items())
                     if value == target]
        for target in census_targets
    }
    require(not any(addend_census.values()),
            'relocation addend census changed')

    # Every E8 site must be a native instruction start inside its
    # containing FDE (raw scans can land mid-instruction).
    cache = {}

    def fde_of(va):
        import bisect
        index = bisect.bisect_right(ordered_starts, va) - 1
        require(index >= 0, f'No containing FDE for {hx(va)}')
        record = by_start[ordered_starts[index]]
        require(record['start'] <= va < record['end'],
                f'No containing FDE for {hx(va)}')
        return record

    for target in census_targets:
        for site in call_census[target]:
            record = fde_of(site)
            _text, rows = decode_body(
                data, record['start'], record['end'], cache)
            require(site in rows and rows[site][0] == 0xE8,
                    f'Call site is not a native instruction start: '
                    f'{hx(site)}')

    # Probe-signature census: the hash constant appears 114 times
    # in 84 FDEs; a genuine probe of this layout also carries a
    # bucket-word load and a scale-8 key compare at entry + 0x8.
    const_sites = []
    cursor = text_body.find(HASH_CONSTANT_LE)
    while cursor != -1:
        const_sites.append(text['address'] + cursor)
        cursor = text_body.find(HASH_CONSTANT_LE, cursor + 1)
    require(len(const_sites) == 114,
            'hash constant census changed')
    const_fdes = sorted({fde_of(site)['start'] for site in const_sites})
    require(len(const_fdes) == 84, 'hash constant census changed')
    signature = {}
    for fde_start in const_fdes:
        record = by_start[fde_start]
        fde_text, _rows = decode_body(
            data, record['start'], record['end'], cache)
        bucket = sites_matching(fde_text, BUCKET)
        key_cmp = sites_matching(fde_text, KEY_CMP)
        if bucket and key_cmp:
            signature[fde_start] = {
                'bucket_word_sites': [hx(va) for va in bucket],
                'key_compare_sites': [hx(va) for va in key_cmp],
            }
    require(sorted(signature) == sorted(SIGNATURE_FDES),
            'probe signature census changed')

    # Owner decodes and operand scans.
    contains_text, contains_rows = decode_body(
        data, CONTAINS, OWNERS['contains']['range'][1], cache)
    remove_text, remove_rows = decode_body(
        data, REMOVE, OWNERS['remove']['range'][1], cache)
    for name, spec in specs.items():
        for va in spec.get('pins', {}):
            start, end = spec['range']
            _t, rows = decode_body(data, start, end, cache)
            require(va in rows,
                    f'{name} pinned site is not a native '
                    f'instruction start: {hx(va)}')
        for va in spec.get('calls', {}):
            start, end = spec['range']
            _t, rows = decode_body(data, start, end, cache)
            require(va in rows and rows[va][0] == 0xE8,
                    f'{name} call site is not a native '
                    f'instruction start: {hx(va)}')
    contains_value_loads = sites_matching(contains_text, VALUE_LOAD)
    require(contains_value_loads == [],
            'contains loads the entry value')
    contains_stores = [
        va for va, ins in text_instructions(contains_text)
        if MEM_STORE.search(ins)
    ]
    require(contains_stores == [], 'contains stores to memory')
    contains_const = [va for va in const_sites
                      if CONTAINS <= va < OWNERS['contains']['range'][1]]
    require(contains_const == [0x4EF4044],
            'contains hash constant sites changed')
    remove_value_loads = sites_matching(remove_text, VALUE_LOAD)
    require(remove_value_loads == [0x4E37C68, 0x4E37C74],
            'remove entry value loads changed')
    remove_const = [va for va in const_sites
                    if REMOVE <= va < OWNERS['remove']['range'][1]]
    require(remove_const == [0x4E37AF3],
            'remove hash constant sites changed')

    inline_text, _rows = decode_body(
        data, INLINE_GET, BOUNDARIES['inline_get']['range'][1], cache)
    inline_value_loads = sites_matching(inline_text, VALUE_LOAD)
    require(0x23E5454 in inline_value_loads,
            'inline consumer value load changed')
    twin_facts = {}
    for name, start in (('twin_probe_a', TWIN_A), ('twin_probe_b', TWIN_B)):
        twin_text, _r = decode_body(
            data, start, BOUNDARIES[name]['range'][1], cache)
        twin_facts[name] = {
            'hash_constant_sites': len([
                va for va in const_sites
                if start <= va < BOUNDARIES[name]['range'][1]]),
            'probe_signature': signature[start],
        }
    verdict = readback_verdict([], contains_value_loads != [],
                               remove_value_loads != [])
    require(verdict == READBACK, 'readback verdict changed')
    # Body digests last: the pin, census and operand checks above
    # report the specific change first; the digest is the
    # backstop for uncited bytes in digest-pinned bodies.
    for name, spec in specs.items():
        require(sha(bodies[name]) == spec['sha256'],
                f'{name} body changed')

    report = {
        'schema': 'RE-006-node115-forward1-map-readback-v1',
        'target': {
            'path': 'artifacts/node/115/hl-node',
            'bytes': TARGET_SIZE,
            'sha256': TARGET_SHA256,
        },
        'relocation_diagnostics': {
            'relative_relocation_count': len(relas),
            'body_slot_references': body_refs,
            'body_addend_references': addend_refs,
            'slot_bindings': {hx(slot): hx(target)
                              for slot, target in
                              sorted(SLOT_BINDINGS.items())},
            'glob_dat_bindings': {},
        },
        'capture': {
            'fde_records': summary['fde_records'],
            'cie_records': summary['cie_records'],
            'unique_fde_starts': summary['unique_fde_starts'],
        },
        'scope': {
            'instruction': (
                'Trace the read side of the forward-1 ordered map: '
                'census the whole binary for the scrambled-hash '
                'constant and the 24-byte-entry probe shapes, '
                'identify the standalone reader FDEs, and follow '
                'the entry value (the slab slot index) at each '
                'consumer.'),
            'measured_denominator_bytes': 319 + 1100,
            'owners': ['contains', 'remove'],
            'complete_fdes': list(specs),
        },
        'frames': frames,
        'owners': {
            'contains': {
                'range': [hx(va) for va in
                          OWNERS['contains']['range']],
                'sha256': OWNERS['contains']['sha256'],
            },
            'remove': {
                'range': [hx(va) for va in OWNERS['remove']['range']],
                'sha256': OWNERS['remove']['sha256'],
            },
        },
        'boundaries': {
            'direct_e8_call_sites': {
                hx(target): [hx(site) for site in call_census[target]]
                for target in census_targets
            },
            'direct_e9_references': {
                hx(target): [hx(site) for site in jump_census[target]]
                for target in census_targets
            },
            'relative_addend_references': addend_census,
            're006_contains_sites': {
                name: [hx(va) for va in sites]
                for name, sites in RE006_CONTAINS_SITES.items()
            },
            're006_remove_sites': [hx(va) for va in REMOVE_CALL_SITES],
            'probe_signature_census': {
                'hash_constant_raw_hits': len(const_sites),
                'fdes_with_constant': len(const_fdes),
                'signature_fdes': {
                    hx(start): signature[start]
                    for start in SIGNATURE_FDES
                },
                'rejected_near_misses': {
                    '0x4ef3170': ('insert for a different map: '
                                  '32-byte entries, key at +0x18'),
                    '0x4ef8240': ('32-byte SipHash-family key, '
                                  'entries at +0x0'),
                    '0x4ef8e20': ('32-byte SipHash-family key, '
                                  'entries at +0x0'),
                },
            },
            'forward_1_citation': (
                'the writer, traced by the forward-callee packet '
                '(RE-006, 0x4eeed90): 24-byte entries {hash, key, '
                'value = slab slot index} at map + 0x8'),
            'not_readback_citation': (
                'the slab lookups 0x4da81b0 / 0x4da7880 are array '
                'element resolvers (0x58/0x70 strides, no '
                'scrambled-hash probe), settled by the '
                'node-insert-helper packet; not re-traced here'),
        },
        'trace': {
            'contains': {
                'arguments': ('rdi = map, rsi = key (by value)'),
                'length_load': '0x4ef4014',
                'length_one_path': {
                    'entries_load': '0x4ef402b',
                    'key_compare': '0x4ef4031',
                    'bool_from_compare': '0x4ef4035',
                },
                'general_path': {
                    'hash_constant': '0x4ef4042',
                    'hash_multiply': '0x4ef404c',
                    'hash_rotate': '0x4ef4050',
                    'entries_load': '0x4ef4054',
                    'control_load': '0x4ef4058',
                    'mask_load': '0x4ef4063',
                    'bucket_word_load': '0x4ef40bd',
                    'slot_offset_scale3': '0x4ef40cd',
                    'key_compare': '0x4ef40d4',
                },
                'entry_value_load_sites': [],
                'memory_store_sites': [],
                'found_exit': {'site': '0x4ef4108', 'eax': 1},
                'not_found_exit': {'site': '0x4ef4115', 'eax': 0},
                'slot_calls': {
                    '0x4ef4102': '0x64df520',
                    '0x4ef413c': '0x64df620',
                },
                'direct_call_sites': 81,
                'verdict': CONTAINS_VERDICT,
            },
            'remove': {
                'arguments': ('rdi = map, rsi = &key; the key is '
                              'loaded from [rsi] at 0x4e37a24'),
                'length_load': '0x4e37a17',
                'length_one_path': {
                    'key_compare': '0x4e37a35',
                    'length_zeroed': '0x4e37a3f',
                    'stored_hash_reused': '0x4e37a47',
                    'value_loaded_for_return': '0x4e37a4a',
                    'empty_bucket_word_search': '0x4e37ab8',
                    'hash_computed': False,
                },
                'general_path': {
                    'hash_constant': '0x4e37af1',
                    'hash_multiply': '0x4e37afb',
                    'hash_rotate': '0x4e37aff',
                    'entries_load': '0x4e37b03',
                    'control_load': '0x4e37b07',
                    'mask_load': '0x4e37b12',
                    'bucket_word_load': '0x4e37b75',
                    'slot_offset_scale3': '0x4e37b89',
                    'key_compare': '0x4e37b90',
                },
                'found_path': {
                    'removed_value_load': '0x4e37c68',
                    'last_entry_value_load': '0x4e37c74',
                    'last_entry_hash_key_copy': '0x4e37c7e',
                    'last_entry_value_store': '0x4e37c83',
                    'length_store': '0x4e37c88',
                    'count_decrement': '0x4e37c4f',
                    'count_store': '0x4e37c52',
                    'control_marker_stores': ['0x4e37c37', '0x4e37c3b'],
                    'deleted_counter_load': '0x4e37c16',
                    'deleted_counter_store': '0x4e37c27',
                    'moved_entry_bucket_fixup': '0x4e37dce',
                    'value_return_register': 'rdx',
                    'exit': {'site': '0x4e37dd3', 'eax': 1},
                },
                'not_found_exit': {'site': '0x4e37d3c', 'eax': 0},
                'slot_calls': {
                    '0x4e37de9': '0x64df6d0',
                    '0x4e37e30': '0x64df848',
                    '0x4e37e56': '0x64df770',
                },
                'direct_call_sites': [hx(va) for va in
                                      REMOVE_CALL_SITES],
                'verdict': REMOVE_VERDICT,
            },
            'remove_caller_a': {
                'call_site': '0x58e1503',
                'map_argument': ('rdi = r15 (the book structure; '
                                 'the map is its first field)'),
                'key_argument': ('rsi = rsp + 0x60, a pointer to a '
                                 'local record whose first qword '
                                 'is the key'),
                'found_gate': '0x58e1508',
                'removed_index_capture': '0x58e1512',
                'slab_length_bound': '0x58e1544',
                'slab_buffer_load': '0x58e1551',
                'slab_stride_multiply': '0x58e1558',
                'slab_stride': hx(SLAB_STRIDE),
                'vacant_state_check': '0x58e155f',
                'verdict': ('the removed value is consumed as the '
                            'slab slot index: bound against the '
                            'slab length at book + 0x90, scaled by '
                            '0x110, and the slot must not be in '
                            'state 2 (vacant)'),
            },
            'insert_caller_1': {
                'contains_sites': ['0x5904ab0', '0x5904e86'],
                'pattern': (
                    'per walked key: contains(map, key); on a hit '
                    'the caller bounds the walked position '
                    'against the map length and loads '
                    'entries[position] + 0x10 itself'),
                'value_loads': ['0x5904adc', '0x5904eab'],
                'slab_length_bounds': ['0x5904ae4', '0x5904eb0'],
                'slab_stride_multiplies': ['0x5904af9', '0x5904ec5'],
                'vacant_state_checks': ['0x5904b00', '0x5904ecc'],
                'verdict': ('the value readback is inlined in the '
                            'caller; contains supplies only the '
                            'membership gate'),
            },
            'inline_get': {
                'range': [hx(va) for va in
                          BOUNDARIES['inline_get']['range']],
                'probe': 'fully inlined (no call to contains)',
                'hash_constant': '0x23e5503',
                'bucket_word_load': '0x23e5581',
                'key_compare': '0x23e559c',
                'length_one_key_compare': '0x23e5444',
                'value_load': '0x23e5454',
                'slab_length_bound': '0x23e545e',
                'slab_stride_multiply': '0x23e5477',
                'vacant_state_check': '0x23e547e',
                'order_field_read': '0x23e548b',
                'verdict': ('an inlined get: the consumer probes '
                            'the map itself and consumes the '
                            'value as the slab slot index'),
            },
            'twin_probes': {
                name: {
                    'hash_constant_sites':
                        twin_facts[name]['hash_constant_sites'],
                    'key_compare_sites':
                        twin_facts[name]['probe_signature']
                        ['key_compare_sites'],
                }
                for name in ('twin_probe_a', 'twin_probe_b')
            },
            'verdict': verdict,
        },
    }
    return report


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    report = analyze(data, binary)
    output.mkdir(parents=True, exist_ok=True)
    raw = subprocess.check_output(
        ['readelf', '-wf', str(binary)], text=True)
    ranges = [spec['range'] for spec in
              list(OWNERS.values()) + list(BOUNDARIES.values())]
    lines = [
        line.replace(str(binary), '<authenticated-node115>')
        for line in raw.splitlines()
        if any(f'pc={start:016x}..{end:016x}' in line
               for start, end in ranges)
    ]
    require(len(lines) == len(report['frames']),
            'Retained readelf frame changed')
    (output / 'frames.txt').write_text('\n'.join(lines) + '\n')
    exports = {}
    for name, spec in OWNERS.items():
        start, end = spec['range']
        asm = subprocess.check_output([
            'objdump', '-d', '-M', 'intel', '--insn-width=16',
            f'--start-address={start:#x}',
            f'--stop-address={end:#x}',
            str(binary),
        ], text=True)
        safe_name = f'{name}_full_body_{start:x}_{end:x}_objdump.txt'
        rendered = asm.replace(str(binary), '<authenticated-node115>')
        (output / safe_name).write_text(rendered)
        exports[name] = {
            'full_body': {
                'file': safe_name,
                'sha256': sha(rendered.encode()),
                'range': [hx(start), hx(end)],
            },
        }
    report['source_exports'] = exports
    (output / 'records.json').write_text(
        json.dumps(report, indent=2) + '\n')
    return report


def main():
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else TARGET
    output = Path(sys.argv[2]) if len(sys.argv) > 2 else PACKET
    generate(binary, output)
    print(output / 'records.json')


if __name__ == '__main__':
    main()

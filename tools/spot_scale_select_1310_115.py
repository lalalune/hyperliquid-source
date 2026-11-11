#!/usr/bin/env python3
"""Replay a static node115 spot scale-select evidence packet; never execute it.

Subject: FDE 0x5a01310..0x5a015b0 (672 bytes) in node #115 — the spot_meta
scale select. Entry helper: FDE 0x3d1a200..0x3d1a2b4 (180 bytes), reached
only through slot 0x64e6a78.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-spot-scale-select-1310-115'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x5a01310, 0x5a015b0
HSTART, HEND = 0x3d1a200, 0x3d1a2b4
TWIN = 0x2892150
HELPER_SLOT = 0x64e6a78
BOUNDS_SLOT = 0x64df620
UNWRAP_SLOT = 0x64df830
SUBTRACT_SLOT = 0x64df848
BOUNDS_SHIM = 0x1680cbf
UNWRAP_SHIM = 0x1680c10
SUBTRACT_SHIM = 0x1681e40
UNWRAP_MSG_VA = 0x46e992
UNWRAP_MSG = b'called `Option::unwrap()` on a `None` value'
SUBTRACT_MSG_VA = 0x46eb80
SUBTRACT_MSG = b'attempt to subtract with overflow'
SUBTRACT_MSG_LEN = 0x43
# (struct va, file, line, col) for the four retained panic locations.
LOCATIONS = {
    0x6476678: ('l1/src/spot_meta.rs', 590, 25),
    0x64768d8: ('l1/src/spot_meta.rs', 119, 33),
    0x6476a30: ('l1/src/spot_meta.rs', 1055, 9),
    0x6493b30: ('/home/ubuntu/hl/code_Mainnet/z_vendor/indexmap/src/map.rs', 762, 26),
}
HELPER_SUBCALLS = (0x47172c0, 0x3ed2180)

SUBJECT_ANCHORS = {
        0x5a01310: ('push', 'r15'),
        0x5a01312: ('push', 'r14'),
        0x5a01314: ('push', 'rbx'),
        0x5a01315: ('mov', 'r15, rdx'),
        0x5a01318: ('mov', 'r14, rsi'),
        0x5a0131b: ('mov', 'rbx, rdi'),
        0x5a0131e: ('call', 'qword ptr [rip + 0xae5754]'),
        0x5a01324: ('test', 'rax, rax'),
        0x5a01327: ('je', '0x5a0132f'),
        0x5a01329: ('pop', 'rbx'),
        0x5a0132a: ('pop', 'r14'),
        0x5a0132c: ('pop', 'r15'),
        0x5a0132e: ('ret', ''),
        0x5a0132f: ('mov', 'eax, 1'),
        0x5a01334: ('cmp', 'r15, 0x186a0'),
        0x5a0133b: ('jb', '0x5a01485'),
        0x5a01341: ('mov', 'eax, 0xa'),
        0x5a01346: ('cmp', 'r15, 0xf4240'),
        0x5a0134d: ('jb', '0x5a01485'),
        0x5a01353: ('mov', 'eax, 0x64'),
        0x5a01358: ('cmp', 'r15, 0x989680'),
        0x5a0135f: ('jb', '0x5a01485'),
        0x5a01365: ('mov', 'eax, 0x3e8'),
        0x5a0136a: ('cmp', 'r15, 0x5f5e100'),
        0x5a01371: ('jb', '0x5a01485'),
        0x5a01377: ('mov', 'eax, 0x2710'),
        0x5a0137c: ('cmp', 'r15, 0x3b9aca00'),
        0x5a01383: ('jb', '0x5a01485'),
        0x5a01389: ('mov', 'rcx, r15'),
        0x5a0138c: ('shr', 'rcx, 0xa'),
        0x5a01390: ('mov', 'eax, 0x186a0'),
        0x5a01395: ('cmp', 'rcx, 0x9502f9'),
        0x5a0139c: ('jb', '0x5a01485'),
        0x5a013a2: ('mov', 'rcx, r15'),
        0x5a013a5: ('shr', 'rcx, 0xb'),
        0x5a013a9: ('mov', 'eax, 0xf4240'),
        0x5a013ae: ('cmp', 'rcx, 0x2e90edd'),
        0x5a013b5: ('jb', '0x5a01485'),
        0x5a013bb: ('mov', 'rcx, r15'),
        0x5a013be: ('shr', 'rcx, 0xc'),
        0x5a013c2: ('mov', 'eax, 0x989680'),
        0x5a013c7: ('cmp', 'rcx, 0xe8d4a51'),
        0x5a013ce: ('jb', '0x5a01485'),
        0x5a013d4: ('mov', 'rcx, r15'),
        0x5a013d7: ('shr', 'rcx, 0xd'),
        0x5a013db: ('mov', 'eax, 0x5f5e100'),
        0x5a013e0: ('cmp', 'rcx, 0x48c27395'),
        0x5a013e7: ('jb', '0x5a01485'),
        0x5a013ed: ('movabs', 'rcx, 0x5af3107a3fff'),
        0x5a013f7: ('mov', 'eax, 0x3b9aca00'),
        0x5a013fc: ('cmp', 'r15, rcx'),
        0x5a013ff: ('jbe', '0x5a01485'),
        0x5a01405: ('movabs', 'rax, 0x38d7ea4c67fff'),
        0x5a0140f: ('cmp', 'r15, rax'),
        0x5a01412: ('jbe', '0x5a01454'),
        0x5a01414: ('movabs', 'rdx, 0x2386f26fc0ffff'),
        0x5a0141e: ('cmp', 'r15, rdx'),
        0x5a01421: ('jbe', '0x5a01460'),
        0x5a01423: ('movabs', 'rdx, 0x16345785d8a0000'),
        0x5a0142d: ('cmp', 'r15, rdx'),
        0x5a01430: ('jb', '0x5a0146c'),
        0x5a01432: ('movabs', 'rdx, 0xde0b6b3a7640000'),
        0x5a0143c: ('cmp', 'r15, rdx'),
        0x5a0143f: ('jb', '0x5a01478'),
        0x5a01441: ('movabs', 'rdx, 0x8ac7230489e80000'),
        0x5a0144b: ('cmp', 'r15, rdx'),
        0x5a0144e: ('cmovb', 'rax, rcx'),
        0x5a01452: ('jmp', '0x5a01482'),
        0x5a01454: ('movabs', 'rax, 0x2540be3ff'),
        0x5a0145e: ('jmp', '0x5a01482'),
        0x5a01460: ('movabs', 'rax, 0x174876e7ff'),
        0x5a0146a: ('jmp', '0x5a01482'),
        0x5a0146c: ('movabs', 'rax, 0xe8d4a50fff'),
        0x5a01476: ('jmp', '0x5a01482'),
        0x5a01478: ('movabs', 'rax, 0x9184e729fff'),
        0x5a01482: ('inc', 'rax'),
        0x5a01485: ('mov', 'rsi, qword ptr [rbx + 0x10]'),
        0x5a01489: ('cmp', 'r14, rsi'),
        0x5a0148c: ('jae', '0x5a01593'),
        0x5a01492: ('shl', 'r14, 5'),
        0x5a01496: ('mov', 'rsi, qword ptr [rbx + 8]'),
        0x5a0149a: ('mov', 'rdx, qword ptr [rbx + 0x28]'),
        0x5a0149e: ('mov', 'rcx, qword ptr [rsi + r14 + 8]'),
        0x5a014a3: ('cmp', 'rcx, rdx'),
        0x5a014a6: ('jae', '0x5a01586'),
        0x5a014ac: ('mov', 'rsi, qword ptr [rsi + r14]'),
        0x5a014b0: ('cmp', 'rsi, rdx'),
        0x5a014b3: ('jae', '0x5a01586'),
        0x5a014b9: ('mov', 'rdi, qword ptr [rbx + 0x20]'),
        0x5a014bd: ('imul', 'rcx, rcx, 0x158'),
        0x5a014c4: ('movzx', 'edx, byte ptr [rdi + rcx + 0x49]'),
        0x5a014c9: ('imul', 'rcx, rsi, 0x158'),
        0x5a014d0: ('sub', 'dl, byte ptr [rdi + rcx + 0x48]'),
        0x5a014d4: ('jb', '0x5a015a3'),
        0x5a014da: ('mov', 'ecx, 1'),
        0x5a014df: ('jne', '0x5a014ee'),
        0x5a014e1: ('cmp', 'rcx, rax'),
        0x5a014e4: ('cmovb', 'rax, rcx'),
        0x5a014e8: ('pop', 'rbx'),
        0x5a014e9: ('pop', 'r14'),
        0x5a014eb: ('pop', 'r15'),
        0x5a014ed: ('ret', ''),
        0x5a014ee: ('movzx', 'esi, dl'),
        0x5a014f1: ('test', 'sil, 1'),
        0x5a014f5: ('je', '0x5a01501'),
        0x5a014f7: ('mov', 'ecx, 0xa'),
        0x5a014fc: ('cmp', 'esi, 1'),
        0x5a014ff: ('je', '0x5a014e1'),
        0x5a01501: ('test', 'dl, 2'),
        0x5a01504: ('je', '0x5a01514'),
        0x5a01506: ('imul', 'rcx, rcx, 0x64'),
        0x5a0150a: ('mov', 'edi, esi'),
        0x5a0150c: ('and', 'edi, 0xfffffffe'),
        0x5a0150f: ('cmp', 'edi, 2'),
        0x5a01512: ('je', '0x5a014e1'),
        0x5a01514: ('test', 'dl, 4'),
        0x5a01517: ('je', '0x5a0152a'),
        0x5a01519: ('imul', 'rcx, rcx, 0x2710'),
        0x5a01520: ('mov', 'edi, esi'),
        0x5a01522: ('and', 'edi, 0xfffffffc'),
        0x5a01525: ('cmp', 'edi, 4'),
        0x5a01528: ('je', '0x5a014e1'),
        0x5a0152a: ('test', 'dl, 8'),
        0x5a0152d: ('je', '0x5a01540'),
        0x5a0152f: ('imul', 'rcx, rcx, 0x5f5e100'),
        0x5a01536: ('mov', 'edi, esi'),
        0x5a01538: ('and', 'edi, 0xfffffff8'),
        0x5a0153b: ('cmp', 'edi, 8'),
        0x5a0153e: ('je', '0x5a014e1'),
        0x5a01540: ('test', 'dl, 0x10'),
        0x5a01543: ('je', '0x5a01329'),
        0x5a01549: ('mov', 'rdi, rax'),
        0x5a0154c: ('movabs', 'rdx, 0x2386f26fc0ffff'),
        0x5a01556: ('inc', 'rdx'),
        0x5a01559: ('mov', 'rax, rcx'),
        0x5a0155c: ('mul', 'rdx'),
        0x5a0155f: ('seto', 'dl'),
        0x5a01562: ('and', 'esi, 0xfffffff0'),
        0x5a01565: ('cmp', 'esi, 0x10'),
        0x5a01568: ('jne', '0x5a0157d'),
        0x5a0156a: ('mov', 'rcx, rax'),
        0x5a0156d: ('test', 'dl, dl'),
        0x5a0156f: ('mov', 'rax, rdi'),
        0x5a01572: ('je', '0x5a014e1'),
        0x5a01578: ('jmp', '0x5a01329'),
        0x5a0157d: ('mov', 'rax, rdi'),
        0x5a01580: ('pop', 'rbx'),
        0x5a01581: ('pop', 'r14'),
        0x5a01583: ('pop', 'r15'),
        0x5a01585: ('ret', ''),
        0x5a01586: ('lea', 'rdi, [rip + 0xa7534b]'),
        0x5a0158d: ('call', 'qword ptr [rip + 0xade29d]'),
        0x5a01593: ('lea', 'rdx, [rip + 0xa750de]'),
        0x5a0159a: ('mov', 'rdi, r14'),
        0x5a0159d: ('call', 'qword ptr [rip + 0xade07d]'),
        0x5a015a3: ('lea', 'rdi, [rip + 0xa75486]'),
        0x5a015aa: ('call', 'qword ptr [rip + 0xade298]'),
}

HELPER_ANCHORS = {
        0x3d1a200: ('push', 'r14'),
        0x3d1a202: ('push', 'rbx'),
        0x3d1a203: ('push', 'rax'),
        0x3d1a204: ('mov', 'rax, qword ptr [rdi + 0x10]'),
        0x3d1a208: ('cmp', 'rsi, rax'),
        0x3d1a20b: ('jae', '0x3d1a28b'),
        0x3d1a20d: ('mov', 'rax, qword ptr [rdi + 8]'),
        0x3d1a211: ('shl', 'rsi, 5'),
        0x3d1a215: ('mov', 'rdx, qword ptr [rax + rsi]'),
        0x3d1a219: ('mov', 'qword ptr [rsp], rdx'),
        0x3d1a21d: ('mov', 'rax, qword ptr [rdi + 0x58]'),
        0x3d1a221: ('test', 'rax, rax'),
        0x3d1a224: ('je', '0x3d1a238'),
        0x3d1a226: ('cmp', 'rax, 1'),
        0x3d1a22a: ('jne', '0x3d1a240'),
        0x3d1a22c: ('mov', 'rax, qword ptr [rdi + 0x50]'),
        0x3d1a230: ('cmp', 'rdx, qword ptr [rax + 8]'),
        0x3d1a234: ('je', '0x3d1a274'),
        0x3d1a236: ('xor', 'eax, eax'),
        0x3d1a238: ('add', 'rsp, 8'),
        0x3d1a23c: ('pop', 'rbx'),
        0x3d1a23d: ('pop', 'r14'),
        0x3d1a23f: ('ret', ''),
        0x3d1a240: ('mov', 'r14, rax'),
        0x3d1a243: ('lea', 'rbx, [rdi + 0x48]'),
        0x3d1a247: ('mov', 'rax, qword ptr [rdi + 0x80]'),
        0x3d1a24e: ('mov', 'rsi, qword ptr [rdi + 0x88]'),
        0x3d1a255: ('mov', 'rdi, rax'),
        0x3d1a258: ('call', '0x47172c0'),
        0x3d1a25d: ('mov', 'rdx, rsp'),
        0x3d1a260: ('mov', 'rdi, rbx'),
        0x3d1a263: ('mov', 'rsi, rax'),
        0x3d1a266: ('call', '0x3ed2180'),
        0x3d1a26b: ('test', 'al, 1'),
        0x3d1a26d: ('je', '0x3d1a281'),
        0x3d1a26f: ('cmp', 'rdx, r14'),
        0x3d1a272: ('jae', '0x3d1a29e'),
        0x3d1a274: ('mov', 'eax, 0x3e8'),
        0x3d1a279: ('add', 'rsp, 8'),
        0x3d1a27d: ('pop', 'rbx'),
        0x3d1a27e: ('pop', 'r14'),
        0x3d1a280: ('ret', ''),
        0x3d1a281: ('xor', 'eax, eax'),
        0x3d1a283: ('add', 'rsp, 8'),
        0x3d1a287: ('pop', 'rbx'),
        0x3d1a288: ('pop', 'r14'),
        0x3d1a28a: ('ret', ''),
        0x3d1a28b: ('lea', 'rdx, [rip + 0x275c3e6]'),
        0x3d1a292: ('mov', 'rdi, rsi'),
        0x3d1a295: ('mov', 'rsi, rax'),
        0x3d1a298: ('call', 'qword ptr [rip + 0x27c5382]'),
        0x3d1a29e: ('mov', 'rsi, r14'),
        0x3d1a2a1: ('lea', 'rax, [rip + 0x2779888]'),
        0x3d1a2a8: ('mov', 'rdi, rdx'),
        0x3d1a2ab: ('mov', 'rdx, rax'),
        0x3d1a2ae: ('call', 'qword ptr [rip + 0x27c536c]'),
}


def _anchors(body, start, anchors, label):
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, start))
    if sum(i.size for i in instructions) != len(body):
        raise ValueError(f'Incomplete native decode in {label}')
    decoded = {i.address: (i.mnemonic, i.op_str) for i in instructions}
    if set(decoded) != set(anchors):
        raise ValueError(f'{label} instruction set changed')
    for pc, expected in anchors.items():
        if decoded.get(pc) != expected:
            raise ValueError(f'{label} instruction changed at {pc:#x}')
    return instructions


def check_body(body):
    return _anchors(body, START, SUBJECT_ANCHORS, 'Subject')


def check_helper_body(body):
    return _anchors(body, HSTART, HELPER_ANCHORS, 'Helper')


def cascade_transcribed(v):
    """Literal transcription of the subject's band cascade on the reference."""
    if v < 10**5:
        return 1
    if v < 10**6:
        return 10
    if v < 10**7:
        return 100
    if v < 10**8:
        return 1000
    if v < 10**9:
        return 10**4
    if (v >> 10) < 0x9502F9:
        return 10**5
    if (v >> 11) < 0x2E90EDD:
        return 10**6
    if (v >> 12) < 0xE8D4A51:
        return 10**7
    if (v >> 13) < 0x48C27395:
        return 10**8
    if v <= 10**14 - 1:
        return 10**9
    if v <= 10**15 - 1:
        return (10**10 - 1) + 1
    if v <= 10**16 - 1:
        return (10**11 - 1) + 1
    if v < 10**17:
        return (10**12 - 1) + 1
    if v < 10**18:
        return (10**13 - 1) + 1
    if v < 10**19:
        return (10**14 - 1) + 1
    return (10**15 - 1) + 1


def cascade_closed(v):
    digits = len(str(v)) if v else 1
    return 10 ** max(0, digits - 5)


def pow10_transcribed(d):
    """Literal transcription of the subject's bit-walk for 10**d.

    Returns ('value', 10**d) when the walk reaches the min exit with the
    product, or ('cascade', None) when the walk saturates to the cascade
    result (exponent bits above 2**4 remain, or the 10**16 multiply
    overflows u64, or bits above 2**5 remain after it).
    """
    rcx = 1
    if d == 0:
        return ('value', rcx)
    if d & 1:
        rcx = 10
        if d == 1:
            return ('value', rcx)
    if d & 2:
        rcx *= 100
        if d & ~1 == 2:
            return ('value', rcx)
    if d & 4:
        rcx *= 10000
        if d & ~3 == 4:
            return ('value', rcx)
    if d & 8:
        rcx *= 10**8
        if d & ~7 == 8:
            return ('value', rcx)
    if not (d & 0x10):
        return ('cascade', None)
    product = rcx * 10**16
    overflow = product > 0xFFFFFFFFFFFFFFFF
    if d & ~0xF != 0x10:
        return ('cascade', None)
    if overflow:
        return ('cascade', None)
    return ('value', product & 0xFFFFFFFFFFFFFFFF)


def subject_model(override, ref, pair_first, pair_second,
                  table_count, byte_first, byte_second):
    """Decision table of the subject FDE over abstract object fields.

    override is the entry helper's return (0 or 1000); pair_first and
    pair_second are the loaded 32-byte pair entries; byte_first and
    byte_second are the table bytes at pair_first+0x48 and
    pair_second+0x49. Returns ('return', value) or ('panic', kind) with
    kind in {'unwrap_none', 'subtract_overflow'}. The index bounds panic
    belongs to the helper stage (see helper_model): the helper runs first
    with the same count, so the subject's own identical bounds exit at
    spot_meta.rs:590:25 is shadowed by it.
    """
    if override != 0:
        return ('return', override)
    cascade = cascade_transcribed(ref)
    if pair_second >= table_count:
        return ('panic', 'unwrap_none')
    if pair_first >= table_count:
        return ('panic', 'unwrap_none')
    d = byte_second - byte_first
    if d < 0:
        return ('panic', 'subtract_overflow')
    kind, product = pow10_transcribed(d)
    if kind == 'cascade':
        return ('return', cascade)
    return ('return', min(cascade, product))


def helper_model(idx, pair_count, pair_first, tag, tag1_target,
                 lookup_found=None, lookup_value=None):
    """Decision table of the entry helper over abstract object fields.

    Returns ('return', 0|1000) or ('panic', 'bounds'|'map_bounds').
    The tag>=2 lookup is modelled by (lookup_found, lookup_value).
    """
    if idx >= pair_count:
        return ('panic', 'bounds')
    if tag == 0:
        return ('return', 0)
    if tag == 1:
        return ('return', 1000 if pair_first == tag1_target else 0)
    if not lookup_found:
        return ('return', 0)
    if lookup_value >= tag:
        return ('panic', 'map_bounds')
    return ('return', 1000)


def check_window(body, start, site):
    """Check one caller excerpt window: it must decode fully and end in
    the direct call to the subject."""
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, start))
    if sum(i.size for i in instructions) != len(body):
        raise ValueError(f'Incomplete caller window decode at {start:#x}')
    decoded = {i.address: (i.mnemonic, i.op_str) for i in instructions}
    if decoded.get(site) != ('call', '0x5a01310'):
        raise ValueError(f'Caller window does not call the subject at {site:#x}')
    return instructions


def _choose_window(read, site):
    """Deterministic excerpt window: the smallest cleanly decoding window
    in [10, 0x30] bytes before the call site that ends in the call."""
    for delta in range(10, 0x31):
        start = site - delta
        body, offset = read(start, delta + 5)
        ins = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, start))
        if sum(i.size for i in ins) == len(body) and ins and \
                ins[-1].address == site and ins[-1].mnemonic == 'call':
            return start, body, offset
    raise ValueError(f'No clean caller window at {site:#x}')


def produce(data=None):
    data = TARGET.read_bytes() if data is None else data
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Node115 digest mismatch')
    secs = sections(data)
    secmap = {s['name']: s for s in secs}

    def read(va, count):
        mapping = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + count <= s['address'] + s['size']]
        if len(mapping) != 1:
            raise ValueError('Ambiguous or missing VA mapping')
        off = mapping[0]['offset'] + va - mapping[0]['address']
        return data[off:off + count], off

    _, fdes = eh_frame_records(data)

    def fde_extent(va):
        found = [f for f in fdes if f['start'] == va]
        if len(found) != 1:
            raise ValueError(f'Exact FDE missing at {va:#x}')
        return found[0]

    def enclosing(va):
        found = [f for f in fdes if f['start'] <= va < f['end']]
        if len(found) != 1:
            raise ValueError(f'Enclosing FDE ambiguous at {va:#x}')
        return found[0]

    fde = [f for f in fdes if f['start'] == START and f['end'] == END]
    if len(fde) != 1:
        raise ValueError('Exact subject FDE missing')
    fde_extent(HSTART)

    body, offset = read(START, END - START)
    instructions = check_body(body)
    hbody, hoffset = read(HSTART, HEND - HSTART)
    hinstructions = check_helper_body(hbody)

    rela = secmap['.rela.dyn']
    relocs = list(struct.iter_unpack('<QQq', data[rela['offset']:rela['offset'] + rela['size']]))
    relmap = {slot: addend for slot, info, addend in relocs if info == 8}

    def relocation_at(va):
        found = [dict(offset=slot, info=info, addend=addend)
                 for slot, info, addend in relocs if slot == va]
        if len(found) != 1 or found[0]['info'] != 8:
            raise ValueError(f'Relocation changed at {va:#x}')
        return found[0]

    slots = []
    for slot, expected in ((HELPER_SLOT, HSTART), (BOUNDS_SLOT, BOUNDS_SHIM),
                           (UNWRAP_SLOT, UNWRAP_SHIM), (SUBTRACT_SLOT, SUBTRACT_SHIM)):
        raw, slot_offset = read(slot, 8)
        rel = relocation_at(slot)
        if rel['addend'] != expected:
            raise ValueError(f'Slot {slot:#x} does not resolve to {expected:#x}')
        slots.append(dict(slot=slot, file_offset=slot_offset, raw_hex=raw.hex(),
                          relocations=[rel], resolved=expected))

    # Panic location structs: (file ptr via relocation, len, line, col).
    locations = []
    for va, (path, line, col) in sorted(LOCATIONS.items()):
        raw, loff = read(va, 0x18)
        ptr, ln, ln_no, cl = struct.unpack('<QQII', raw)
        rel = relocation_at(va)
        text_raw, _ = read(rel['addend'], ln)
        if text_raw.decode() != path or ln != len(path) or ln_no != line or cl != col:
            raise ValueError(f'Location struct changed at {va:#x}')
        locations.append(dict(struct_va=va, file_offset=loff,
                              file_ptr=rel['addend'], file_len=ln,
                              file=path, line=ln_no, col=cl,
                              relocations=[rel], raw_hex=raw.hex()))

    # Panic shim string loads: unwrap shim (0x1680c10) and subtract shim
    # (0x1681e40) each load a static message pointer and a length immediate.
    def shim_string(shim, msg_va, msg, len_imm):
        sbody, _ = read(shim, 0x14)
        ins = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(sbody, shim))
        dec = {i.address: i for i in ins}
        lea = [i for i in ins if i.mnemonic == 'lea']
        movs = [i for i in ins if i.mnemonic == 'mov' and i.op_str.startswith('esi,')]
        if len(lea) != 1 or len(movs) != 1:
            raise ValueError(f'Panic shim shape changed at {shim:#x}')
        disp = struct.unpack_from('<i', lea[0].bytes, len(lea[0].bytes) - 4)[0]
        if lea[0].address + lea[0].size + disp != msg_va:
            raise ValueError(f'Panic shim does not load its message at {shim:#x}')
        if movs[0].op_str != f'esi, {len_imm:#x}':
            raise ValueError(f'Panic shim length changed at {shim:#x}')
        raw, moff = read(msg_va, len(msg))
        if raw != msg:
            raise ValueError(f'Panic message changed at {msg_va:#x}')
        return dict(shim=shim, shim_fde=fde_extent(shim), message_va=msg_va,
                    message_file_offset=moff, message_length_immediate=len_imm,
                    message_text=msg.decode())

    panic_shims = [shim_string(UNWRAP_SHIM, UNWRAP_MSG_VA, UNWRAP_MSG, len(UNWRAP_MSG)),
                   shim_string(SUBTRACT_SHIM, SUBTRACT_MSG_VA, SUBTRACT_MSG,
                               SUBTRACT_MSG_LEN)]

    # Whole-text census: direct sites to the subject, and every decode-
    # verified indirect call/jump through the helper's slot.
    text = secmap['.text']
    blob = data[text['offset']:text['offset'] + text['size']]
    tbase = text['address']

    def direct_sites(target):
        found = []
        for op in (0xE8, 0xE9):
            i = blob.find(bytes([op]))
            while i != -1:
                if i + 5 <= len(blob):
                    disp = struct.unpack_from('<i', blob, i + 1)[0]
                    va = tbase + i
                    if va + 5 + disp == target:
                        found.append((va, 'call' if op == 0xE8 else 'jmp'))
                i = blob.find(bytes([op]), i + 1)
        return sorted(found)

    sites = direct_sites(START)
    calls = [va for va, kind in sites if kind == 'call']
    jumps = [va for va, kind in sites if kind == 'jmp']
    caller_records = []
    for site in calls:
        enc = enclosing(site)
        wstart, wbody, woffset = _choose_window(read, site)
        check_window(wbody, wstart, site)
        decoded = {i.address: i for i in
                   Cs(CS_ARCH_X86, CS_MODE_64).disasm(wbody, wstart)}
        provenance = {}
        for reg in ('rsi', 'rdx', 'rdi'):
            setups = [i.op_str for pc, i in sorted(decoded.items())
                      if pc < site and i.mnemonic == 'mov'
                      and i.op_str.startswith(f'{reg},')]
            if setups:
                provenance[reg] = setups[-1]
        caller_records.append(dict(site=site, caller_fde=enc, kind='call',
                                   excerpt_window=dict(start=wstart, end=site + 5),
                                   excerpt_file_offset=woffset,
                                   excerpt_sha256=hashlib.sha256(wbody).hexdigest(),
                                   last_arg_setup=provenance))
    caller_fdes = sorted({(c['caller_fde']['start'], c['caller_fde']['end'])
                          for c in caller_records})

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    slot_sites = []
    for op in (b'\xff\x15', b'\xff\x25'):
        i = blob.find(op)
        while i != -1:
            if i + 6 <= len(blob):
                disp = struct.unpack_from('<i', blob, i + 2)[0]
                va = tbase + i
                if va + 6 + disp == HELPER_SLOT:
                    enc = enclosing(va)
                    ebody, _ = read(enc['start'], va + 6 - enc['start'])
                    ins = list(md.disasm(ebody, enc['start']))
                    if any(x.address == va and x.mnemonic == 'call' for x in ins):
                        slot_sites.append(dict(site=va, kind='call_indirect',
                                               caller_fde=enc))
            i = blob.find(op, i + 1)
    if [s['site'] for s in slot_sites] != [TWIN + 0xE, START + 0xE]:
        raise ValueError('Helper slot census changed')

    def stored_and_addends(target):
        needle = struct.pack('<Q', target)
        stored = []
        for s in secs:
            if s['type'] == 8 or s['size'] == 0 or s['name'].startswith('.rela'):
                continue
            seg = data[s['offset']:s['offset'] + s['size']]
            j = seg.find(needle)
            while j != -1:
                stored.append(dict(section=s['name'], va=s['address'] + j))
                j = seg.find(needle, j + 1)
        addends = [slot for slot, _, addend in relocs if addend == target]
        return stored, addends

    s_stored, s_addends = stored_and_addends(START)
    h_stored, h_addends = stored_and_addends(HSTART)
    if s_stored or s_addends or h_stored or h_addends != [HELPER_SLOT]:
        raise ValueError('Stored/addend census changed')
    census = dict(direct_call_sites=calls, direct_tail_jumps=jumps,
                  caller_fdes=[dict(start=a, end=b) for a, b in caller_fdes],
                  stored_qwords=s_stored, relative_addends=s_addends,
                  helper=dict(direct_call_sites=[va for va, _ in direct_sites(HSTART)],
                              slot_call_sites=slot_sites,
                              stored_qwords=h_stored,
                              relative_addends=h_addends))

    edges = []
    for i in instructions:
        if i.mnemonic == 'call' or i.mnemonic.startswith('j'):
            edges.append(dict(pc=i.address, bytes=i.bytes.hex(),
                              mnemonic=i.mnemonic, operand=i.op_str))
    helper_edges = []
    for i in hinstructions:
        if i.mnemonic == 'call' or i.mnemonic.startswith('j'):
            helper_edges.append(dict(pc=i.address, bytes=i.bytes.hex(),
                                     mnemonic=i.mnemonic, operand=i.op_str))
    helpers = [dict(target=t, fdes=[fde_extent(t)],
                    semantic_status='entry helper sub-call; body unmeasured here')
               for t in HELPER_SUBCALLS]
    helpers += [dict(target=BOUNDS_SHIM, fdes=[fde_extent(BOUNDS_SHIM)],
                     semantic_status='panic_bounds_check shim; entered with '
                                     '(index, len, &Location)'),
                dict(target=UNWRAP_SHIM, fdes=[fde_extent(UNWRAP_SHIM)],
                     semantic_status='unwrap-on-None panic shim; entered with '
                                     '&Location only'),
                dict(target=SUBTRACT_SHIM, fdes=[fde_extent(SUBTRACT_SHIM)],
                     semantic_status='subtract-overflow panic shim; entered '
                                     'with &Location only')]
    return dict(target_sha256=SHA, target_bytes=len(data),
                component='spot metadata scale select (l1/src/spot_meta.rs)',
                base_commit='05bc2de303c05525b71e7e257426e741bc66a390',
                start=START, end=END, file_offset=offset, fde=fde[0],
                body_sha256=hashlib.sha256(body).hexdigest(), body_hex=body.hex(),
                native_instructions=len(instructions),
                call_and_branch_edges=edges, indirect_slots=slots,
                locations=locations, panic_shims=panic_shims,
                callers=caller_records, census=census,
                helper=dict(start=HSTART, end=HEND, file_offset=hoffset,
                            fde=fde_extent(HSTART),
                            body_sha256=hashlib.sha256(hbody).hexdigest(),
                            body_hex=hbody.hex(),
                            native_instructions=len(hinstructions),
                            call_and_branch_edges=helper_edges),
                twin=dict(start=TWIN, fde=fde_extent(TWIN),
                          semantic_status='second compiled copy of the same '
                                          'source function in another crate; '
                                          'it enters through the same helper '
                                          'slot 0x64e6a78 (its call site is in '
                                          'the census); recorded only, not pinned'),
                direct_helpers=helpers,
                raw_equal=None, normalized_only=None, unmatched=None,
                implementation='not implemented', gates_changed=False)


def canonical_export(raw):
    # Text-only trailing whitespace; original instruction bytes remain unchanged.
    return b'\n'.join(line.rstrip() for line in raw.splitlines()) + b'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    result = produce()
    expected = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.write:
        PACKET.mkdir(parents=True, exist_ok=True)
        (PACKET / 'records.json').write_text(expected)
        (PACKET / 'native.asm').write_bytes(canonical_export(subprocess.check_output([
            'objdump', '-d', '-M', 'intel', f'--start-address={START}',
            f'--stop-address={END}', str(TARGET.relative_to(ROOT))], cwd=ROOT)))
        (PACKET / 'helper_native.asm').write_bytes(canonical_export(subprocess.check_output([
            'objdump', '-d', '-M', 'intel', f'--start-address={HSTART}',
            f'--stop-address={HEND}', str(TARGET.relative_to(ROOT))], cwd=ROOT)))
        chunks = []
        for caller in result['callers']:
            w = caller['excerpt_window']
            chunks.append(subprocess.check_output([
                'objdump', '-d', '-M', 'intel', f"--start-address={w['start']}",
                f"--stop-address={w['end']}", str(TARGET.relative_to(ROOT))], cwd=ROOT))
        (PACKET / 'callers_excerpt.asm').write_bytes(
            canonical_export(b''.join(chunks)))
    elif (PACKET / 'records.json').read_text() != expected:
        raise ValueError('Retained records differ from authenticated input')
    print(json.dumps({k: result[k] for k in ('start', 'end', 'native_instructions', 'body_sha256')}))


if __name__ == '__main__':
    main()

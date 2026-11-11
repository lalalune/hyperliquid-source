#!/usr/bin/env python3
"""Bind node #115 block-step name bytes and the one host that formats them.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-step-names-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Name writer: one FDE, one jump table, six 21-byte arms.
START = 0x41c9f80
END = 0x41ca014
TABLE = 0x7c6438
WRITER_SLOT = 0x64df720
WRITER = 0x167fa70
POINTER_SLOT = 0x64ea680
# Tag order is the jump-table index, not the order of the arms in the body.
NAMES = (
    (0x7c6fce, b'RecoveredSignerToUser'),
    (0x7c6fe3, b'BeginBlock'),
    (0x7c6fed, b'DeliverSignedActions'),
    (0x4599d8, b'EndBlock'),
    (0x7c7001, b'Commit'),
    (0x7c7007, b'RespHashCheck'),
)
PROLOGUE = bytes.fromhex('4889f00fb60f488d15')
DISPATCH = bytes.fromhex('48630c8a4801d1ffe1')

# Host: the only instruction that loads POINTER_SLOT.
HOST_START = 0x4da7e20
HOST_END = 0x4da81a5
LOAD_SITE = 0x4da7fd1
HOST_TABLE = 0x915300
HOST_DISPATCH = 0x4da7e63
# Per-tag f64 loads. Tags 4 and 5 share one arm.
HOST_ARMS = {
    1: (0x4da7f0a, 0x459cc0),
    2: (0x4da7ec3, 0x4598a0),
    3: (0x4da7ed0, 0x459038),
    4: (0x4da7e7a, 0x458e48),
    5: (0x4da7e7a, 0x458e48),
}
TAG0_ARM = 0x4da7edd
TAG0_GLOBAL_GOT = 0x64e0918
TAG0_GLOBAL = 0x64f06c0
TAG0_TABLE = 0x917580
TAG0_TABLE_LEN = 23
TAG0_BIAS = 10
FALLBACK_SITE = 0x4da7f62
FALLBACK = 0x4593a0
DIVISOR = 0x4593e8
INFINITY = 0x459010
FORMAT_SITE = 0x4da7f90
FORMAT_SLOT = 0x64df6e8
FORMAT = 0x141e3a0
STR_CALLBACK = 0x5616320
SEQ_TASK = 0x459820
L1_PAIR = 0x649cc90
TEMPLATE = 0x440e47
RIP_MODRM = {0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d}

# Exact instruction windows. Each RIP target below is decoded from these bytes.
HOST_WINDOWS = {
    0x4da7e63: '440fb62a0fb606488d0d8fd4b6fb486304814801c8ffe0',
    0x4da7e7a: 'f20f1005c60f6bfbe9e3000000',
    0x4da7ec3: 'f20f1005d5196bfbe99a000000',
    0x4da7ed0: 'f20f100560116bfbe98d000000',
    0x4da7edd: '4c8b25348a7301418b44245085c07527410fb644244804f63c1773690fb6c0488d0d7df6b6fbf20f1004c1eb60',
    0x4da7f0a: 'f20f1005ae1d6bfbeb56',
    0x4da7f62: 'f20f100536146bfbf20f11442438f20f5e0570146bfb660f2e0590106bfb660f57c97404660f28c8f20f114c2408',
    0x4da7f90: ('488d0589186bfb488944241048c744241808000000488d4424104889442440'
                '488d056ae386004889442448488d0dce4c6f0148894c245048894424584889742460'
                '488b05a82674014889442468488d35638e69fb488dbc24a8020000488d542440ff15f1767301'),
}


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return off, data[off:off + size]


def rip_target(body, start, offset, prefix, length):
    if body[offset:offset + len(prefix)] != prefix:
        raise ValueError(f'instruction at {start + offset:#x} changed')
    return start + offset + length + struct.unpack_from('<i', body, offset + len(prefix))[0]


def relocations(data):
    rows = []
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        blob = data[sec['offset']:sec['offset'] + sec['size']]
        rows.extend(struct.iter_unpack('<QQq', blob))
    return rows


def text_slot_loads(data, slot):
    """RIP-relative loads and indirect calls that name one slot.

    The encodings are 48/4c 8b, 48/4c 8d with a RIP modrm, and ff 15 / ff 25.
    Other encodings are outside this count.
    """
    text = next((s for s in sections(data) if s['name'] == '.text'), None)
    if text is None:
        raise ValueError('no .text section')
    raw = data[text['offset']:text['offset'] + text['size']]
    hits = []
    for prefix, extra in ((b'\x48\x8b', 1), (b'\x4c\x8b', 1), (b'\x48\x8d', 1), (b'\x4c\x8d', 1),
                          (b'\xff\x15', 0), (b'\xff\x25', 0)):
        start = 0
        while True:
            index = raw.find(prefix, start)
            if index < 0:
                break
            start = index + 1
            if extra and (index + 2 >= len(raw) or raw[index + 2] not in RIP_MODRM):
                continue
            length = 6 + extra
            if index + length > len(raw):
                continue
            disp = struct.unpack_from('<i', raw, index + 2 + extra)[0]
            site = text['address'] + index
            if site + length + disp == slot:
                hits.append(site)
    return sorted(hits)


def f64(data, va):
    return struct.unpack('<d', read_va(data, va, 8)[1])[0]


def bind_writer(data, fdes):
    frames = [f for f in fdes if f['start'] == START]
    if len(frames) != 1 or frames[0]['end'] != END:
        raise ValueError('name-writer FDE changed')
    fileoff, body = read_va(data, START, END - START)
    if len(body) != 148:
        raise ValueError('name-writer extent changed')
    if body[:len(PROLOGUE)] != PROLOGUE or body[13:22] != DISPATCH:
        raise ValueError('tag load or jump-table dispatch changed')
    if rip_target(body, START, 6, b'\x48\x8d\x15', 7) != TABLE:
        raise ValueError('jump table address changed')
    arms = {}
    for index in range(6):
        offset = 0x16 + index * 21
        name_va = rip_target(body, START, offset, b'\x48\x8d\x35', 7)
        if body[offset + 7] != 0xba:
            raise ValueError('name length immediate changed')
        length = struct.unpack_from('<I', body, offset + 8)[0]
        if body[offset + 12:offset + 15] != b'\x48\x89\xc7':
            raise ValueError('writer argument move changed')
        if rip_target(body, START, offset + 15, b'\xff\x25', 6) != WRITER_SLOT:
            raise ValueError('writer slot changed')
        arms[START + offset] = (name_va, length)
    if 0x16 + 6 * 21 != len(body):
        raise ValueError('arm packing changed')
    _, table_bytes = read_va(data, TABLE, 8 * 4)
    tags = []
    for tag, (expect_va, expect_name) in enumerate(NAMES):
        dest = TABLE + struct.unpack_from('<i', table_bytes, tag * 4)[0]
        if dest not in arms:
            raise ValueError(f'tag {tag} misses the six arms')
        name_va, length = arms[dest]
        if (name_va, length) != (expect_va, len(expect_name)):
            raise ValueError(f'tag {tag} slice changed')
        if read_va(data, name_va, length)[1] != expect_name:
            raise ValueError(f'tag {tag} bytes changed')
        tags.append({'tag': tag, 'arm_va': hex(dest), 'name_va': hex(name_va),
                     'length': length, 'name': expect_name.decode('ascii')})
    outside = []
    for tag in (6, 7):
        dest = TABLE + struct.unpack_from('<i', table_bytes, tag * 4)[0]
        if START <= dest < END:
            raise ValueError(f'table entry {tag} lands inside the FDE')
        outside.append(hex(dest))
    order = (0, 1, 2, 4, 5)
    packed = b''.join(NAMES[i][1] for i in order)
    cursor = NAMES[0][0]
    for index in order:
        if NAMES[index][0] != cursor:
            raise ValueError('packed names are not contiguous')
        cursor += len(NAMES[index][1])
    if read_va(data, NAMES[0][0], len(packed))[1] != packed:
        raise ValueError('packed name bytes changed')
    endblock_after = read_va(data, NAMES[3][0] + len(NAMES[3][1]), 1)[1]
    if endblock_after != b'\x00':
        raise ValueError('EndBlock is no longer followed by NUL')
    return fileoff, body, tags, outside, packed


def bind_host(data, fdes):
    hosts = [f for f in fdes if f['start'] <= LOAD_SITE < f['end']]
    if len(hosts) != 1 or (hosts[0]['start'], hosts[0]['end']) != (HOST_START, HOST_END):
        raise ValueError('pointer load is not in the recorded host FDE')
    for va, expect in HOST_WINDOWS.items():
        if read_va(data, va, len(expect) // 2)[1] != bytes.fromhex(expect):
            raise ValueError(f'host window {va:#x} changed')
    win = bytes.fromhex(HOST_WINDOWS[HOST_DISPATCH])
    # movzx r13d, byte [rdx]; movzx eax, byte [rsi]
    if win[:7] != bytes.fromhex('440fb62a0fb606'):
        raise ValueError('host tag load changed')
    if rip_target(win, HOST_DISPATCH, 7, b'\x48\x8d\x0d', 7) != HOST_TABLE:
        raise ValueError('host jump table changed')
    _, table_bytes = read_va(data, HOST_TABLE, 8 * 4)
    dests = [HOST_TABLE + struct.unpack_from('<i', table_bytes, 4 * t)[0] for t in range(8)]
    if dests[0] != TAG0_ARM:
        raise ValueError('host tag 0 arm changed')
    constants = {}
    for tag, (arm, const) in HOST_ARMS.items():
        if dests[tag] != arm:
            raise ValueError(f'host tag {tag} arm changed')
        body = bytes.fromhex(HOST_WINDOWS[arm])
        if rip_target(body, arm, 0, b'\xf2\x0f\x10\x05', 8) != const:
            raise ValueError(f'host tag {tag} constant address changed')
        constants[tag] = {'arm_va': hex(arm), 'f64_va': hex(const), 'value': f64(data, const)}
    host_outside = [hex(d) for d in dests[6:] if not HOST_START <= d < HOST_END]
    if len(host_outside) != 2:
        raise ValueError('host table entries 6 and 7 changed')
    tag0 = bytes.fromhex(HOST_WINDOWS[TAG0_ARM])
    if rip_target(tag0, TAG0_ARM, 0, b'\x4c\x8b\x25', 7) != TAG0_GLOBAL_GOT:
        raise ValueError('tag 0 global slot changed')
    if tag0[7:11] != bytes.fromhex('418b4424') or tag0[11] != 0x50:
        raise ValueError('tag 0 state load changed')
    if tag0[16:21] != bytes.fromhex('410fb64424') or tag0[21] != 0x48:
        raise ValueError('tag 0 byte load changed')
    if tag0[22:26] != bytes.fromhex('04f63c17'):
        raise ValueError('tag 0 bias or bound changed')
    if rip_target(tag0, TAG0_ARM, 31, b'\x48\x8d\x0d', 7) != TAG0_TABLE:
        raise ValueError('tag 0 table changed')
    relocs = relocations(data)
    got = [(info, addend) for slot, info, addend in relocs if slot == TAG0_GLOBAL_GOT]
    if got != [(8, TAG0_GLOBAL)]:
        raise ValueError('tag 0 global relocation changed')
    tag0_table = [f64(data, TAG0_TABLE + 8 * i) for i in range(TAG0_TABLE_LEN)]
    tail = bytes.fromhex(HOST_WINDOWS[FALLBACK_SITE])
    if rip_target(tail, FALLBACK_SITE, 0, b'\xf2\x0f\x10\x05', 8) != FALLBACK:
        raise ValueError('fallback constant changed')
    if rip_target(tail, FALLBACK_SITE, 14, b'\xf2\x0f\x5e\x05', 8) != DIVISOR:
        raise ValueError('divisor changed')
    if rip_target(tail, FALLBACK_SITE, 22, b'\x66\x0f\x2e\x05', 8) != INFINITY:
        raise ValueError('infinity compare changed')
    fmt = bytes.fromhex(HOST_WINDOWS[FORMAT_SITE])
    if rip_target(fmt, FORMAT_SITE, 0, b'\x48\x8d\x05', 7) != SEQ_TASK:
        raise ValueError('seq_task slice changed')
    if fmt[12:21] != bytes.fromhex('48c744241808000000'):
        raise ValueError('seq_task length changed')
    if rip_target(fmt, FORMAT_SITE, 31, b'\x48\x8d\x05', 7) != STR_CALLBACK:
        raise ValueError('str callback changed')
    if rip_target(fmt, FORMAT_SITE, 43, b'\x48\x8d\x0d', 7) != L1_PAIR:
        raise ValueError('second argument changed')
    if rip_target(fmt, FORMAT_SITE, 65, b'\x48\x8b\x05', 7) != POINTER_SLOT:
        raise ValueError('step callback load changed')
    if rip_target(fmt, FORMAT_SITE, 77, b'\x48\x8d\x35', 7) != TEMPLATE:
        raise ValueError('template changed')
    if rip_target(fmt, FORMAT_SITE, 97, b'\xff\x15', 6) != FORMAT_SLOT:
        raise ValueError('format call slot changed')
    if [(i, a) for s, i, a in relocs if s == FORMAT_SLOT] != [(8, FORMAT)]:
        raise ValueError('format relocation changed')
    pair_rel = sorted((s, a) for s, i, a in relocs if s in (L1_PAIR, L1_PAIR + 16) and i == 8)
    if pair_rel != [(L1_PAIR, 0x9172e5), (L1_PAIR + 16, 0x9172e7)]:
        raise ValueError('second argument relocations changed')
    _, pair = read_va(data, L1_PAIR, 32)
    if struct.unpack_from('<Q', pair, 8)[0] != 2 or struct.unpack_from('<Q', pair, 24)[0] != 11:
        raise ValueError('second argument lengths changed')
    seq = read_va(data, SEQ_TASK, 8)[1]
    first = read_va(data, 0x9172e5, 2)[1]
    following = read_va(data, 0x9172e7, 11)[1]
    template = read_va(data, TEMPLATE, 8)[1]
    if (seq, first, following) != (b'seq_task', b'l1', b'begin_block'):
        raise ValueError('format argument bytes changed')
    callback = read_va(data, STR_CALLBACK, 19)[1]
    if callback[:13] != bytes.fromhex('4889f0488b37488b57084889c7') or \
            rip_target(callback, STR_CALLBACK, 13, b'\xff\x25', 6) != WRITER_SLOT:
        raise ValueError('str callback body changed')
    return {
        'fde': {'start_va': hex(HOST_START), 'end_va': hex(HOST_END)},
        'tag_jump_table_va': hex(HOST_TABLE),
        'table_entries_6_7_outside_fde': host_outside,
        'tag_constants': {str(k): v for k, v in sorted(constants.items())},
        'tag0': {
            'arm_va': hex(TAG0_ARM),
            'global_got_va': hex(TAG0_GLOBAL_GOT),
            'global_va': hex(TAG0_GLOBAL),
            'state_dword_offset': '0x50',
            'index_byte_offset': '0x48',
            'index_bias': TAG0_BIAS,
            'table_va': hex(TAG0_TABLE),
            'table_len': TAG0_TABLE_LEN,
            'table': tag0_table,
            'fallback_f64_va': hex(FALLBACK),
            'fallback': f64(data, FALLBACK),
        },
        'post_select': {
            'divisor': f64(data, DIVISOR),
            'compare_value': repr(f64(data, INFINITY)),
            'equal_or_unordered_result': 0.0,
        },
        'format': {
            'site_va': hex(FORMAT_SITE),
            'call_slot_va': hex(FORMAT_SLOT),
            'call_target_va': hex(FORMAT),
            'template_va': hex(TEMPLATE),
            'template_bytes': template.hex(),
            'arguments': [
                {'value': 'stack &str', 'bytes': seq.decode(), 'callback_va': hex(STR_CALLBACK)},
                {'value': hex(L1_PAIR), 'bytes': first.decode(), 'callback_va': hex(STR_CALLBACK)},
                {'value': 'incoming rsi tag pointer', 'callback_va': hex(START)},
            ],
            'str_callback_tail_slot_va': hex(WRITER_SLOT),
        },
    }


def bind(data, fdes):
    fileoff, body, tags, outside, packed = bind_writer(data, fdes)
    relocs = relocations(data)
    pointers = [(slot, info) for slot, info, addend in relocs if addend == START]
    if pointers != [(POINTER_SLOT, 8)]:
        raise ValueError('function-pointer relocation changed')
    if [(i, a) for s, i, a in relocs if s == WRITER_SLOT] != [(8, WRITER)]:
        raise ValueError('writer relocation changed')
    loads = text_slot_loads(data, POINTER_SLOT)
    if loads != [LOAD_SITE]:
        raise ValueError('pointer load census changed')
    host = bind_host(data, fdes)
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'function': {
            'start_va': hex(START),
            'end_va': hex(END),
            'file_offset': hex(fileoff),
            'bytes': len(body),
            'sha256': hashlib.sha256(body).hexdigest(),
        },
        'jump_table_va': hex(TABLE),
        'tags': tags,
        'table_entries_6_7_outside_fde': outside,
        'packed_names_va': hex(NAMES[0][0]),
        'packed_names': packed.decode('ascii'),
        'endblock_followed_by_nul': True,
        'writer_slot_va': hex(WRITER_SLOT),
        'writer_va': hex(WRITER),
        'pointer_slot_va': hex(POINTER_SLOT),
        'pointer_reloc_count': 1,
        'pointer_load_site_va': hex(LOAD_SITE),
        'pointer_load_count': 1,
        'pointer_load_encodings': '48/4c 8b, 48/4c 8d with RIP modrm, ff 15, ff 25',
        'host': host,
        'node94_comparison': {
            'tag0_name_94': 'RecoverUsers',
            'tag0_name_115': 'RecoveredSignerToUser',
            'tags_1_to_5_names_equal': True,
            'function_bytes_94': 148,
            'function_bytes_115': len(body),
        },
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(f"{result['function']['start_va']} tags={len(result['tags'])} loads={result['pointer_load_count']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

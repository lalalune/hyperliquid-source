#!/usr/bin/env python3
"""Bind node #94 block-step name bytes. The captured binary is not executed."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

TARGET = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-008-abci-step-names-94'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START = 0x3b998a0
END = 0x3b99934
TABLE = 0x5b2e1c
WRITER_SLOT = 0x576e000
WRITER = 0x1573450
POINTER_SLOT = 0x5776290
LOAD_SITE = 0x492619f
LOAD_FDE = 0x4925f10
# Tag order is the jump-table index, not the order of the arms in the body.
NAMES = (
    (0x5b6973, b'RecoverUsers'),
    (0x5b697f, b'BeginBlock'),
    (0x5b6989, b'DeliverSignedActions'),
    (0x20aea8, b'EndBlock'),
    (0x5b699d, b'Commit'),
    (0x5b69a3, b'RespHashCheck'),
)
PROLOGUE = bytes.fromhex('4889f00fb60f488d15')
DISPATCH = bytes.fromhex('48630c8a4801d1ffe1')
RIP_MODRM = {0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d}


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
        for slot, info, addend in struct.iter_unpack('<QQq', blob):
            rows.append((slot, info, addend))
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
            disp_at = 2 + extra
            disp = struct.unpack_from('<i', raw, index + disp_at)[0]
            site = text['address'] + index
            if site + length + disp == slot:
                hits.append(site)
    return hits


def bind(data, fdes):
    frames = [f for f in fdes if f['start'] == START]
    if len(frames) != 1 or frames[0]['end'] != END:
        raise ValueError('name-writer FDE changed')
    fileoff, body = read_va(data, START, END - START)
    if len(body) != 148:
        raise ValueError('name-writer extent changed')
    if body[:len(PROLOGUE)] != PROLOGUE or body[13:22] != DISPATCH:
        raise ValueError('tag load or jump-table dispatch changed')
    table = rip_target(body, START, 6, b'\x48\x8d\x15', 7)
    if table != TABLE:
        raise ValueError('jump table address changed')
    arms = []
    for index in range(6):
        offset = 0x16 + index * 21
        name_va = rip_target(body, START, offset, b'\x48\x8d\x35', 7)
        if body[offset + 7] != 0xba:
            raise ValueError('name length immediate changed')
        length = struct.unpack_from('<I', body, offset + 8)[0]
        if body[offset + 12:offset + 15] != b'\x48\x89\xc7':
            raise ValueError('writer argument move changed')
        slot = rip_target(body, START, offset + 15, b'\xff\x25', 6)
        if slot != WRITER_SLOT:
            raise ValueError('writer slot changed')
        arms.append({'va': START + offset, 'name_va': name_va, 'length': length})
    if 0x16 + 6 * 21 != len(body):
        raise ValueError('arm packing changed')
    arm_at = {arm['va']: arm for arm in arms}
    _, table_bytes = read_va(data, table, 7 * 4)
    tags = []
    for tag, (expect_va, expect_name) in enumerate(NAMES):
        rel = struct.unpack_from('<i', table_bytes, tag * 4)[0]
        dest = table + rel
        arm = arm_at.get(dest)
        if arm is None:
            raise ValueError(f'tag {tag} misses the six arms')
        if arm['length'] != len(expect_name) or arm['name_va'] != expect_va:
            raise ValueError(f'tag {tag} slice changed')
        _, raw = read_va(data, arm['name_va'], arm['length'])
        if raw != expect_name:
            raise ValueError(f'tag {tag} bytes changed')
        tags.append({
            'tag': tag,
            'arm_va': hex(dest),
            'name_va': hex(arm['name_va']),
            'length': arm['length'],
            'name': expect_name.decode('ascii'),
        })
    seventh = table + struct.unpack_from('<i', table_bytes, 24)[0]
    if START <= seventh < END:
        raise ValueError('a seventh arm appeared inside the FDE')
    packed = b''.join(name for _, name in (NAMES[i] for i in (0, 1, 2, 4, 5)))
    pack_va = NAMES[0][0]
    _, pack = read_va(data, pack_va, len(packed))
    if pack != packed:
        raise ValueError('packed name bytes changed')
    cursor = pack_va
    for index in (0, 1, 2, 4, 5):
        va, name = NAMES[index]
        if va != cursor:
            raise ValueError('packed names are not contiguous')
        cursor += len(name)
    _, neighbor = read_va(data, NAMES[3][0] + len(NAMES[3][1]), 9)
    if neighbor != b'fee_rate\x00':
        raise ValueError('EndBlock neighbor changed')
    relocs = relocations(data)
    pointers = [(slot, info, addend) for slot, info, addend in relocs if addend == START]
    if pointers != [(POINTER_SLOT, 8, START)]:
        raise ValueError('function-pointer relocation changed')
    writers = [(info, addend) for slot, info, addend in relocs if slot == WRITER_SLOT]
    if writers != [(8, WRITER)]:
        raise ValueError('writer relocation changed')
    loads = text_slot_loads(data, POINTER_SLOT)
    if loads != [LOAD_SITE]:
        raise ValueError('pointer load census changed')
    _, load = read_va(data, LOAD_SITE, 7)
    if load[:3] != b'\x48\x8b\x05' or rip_target(load, LOAD_SITE, 0, b'\x48\x8b\x05', 7) != POINTER_SLOT:
        raise ValueError('pointer load instruction changed')
    hosts = [f for f in fdes if f['start'] <= LOAD_SITE < f['end']]
    if len(hosts) != 1 or hosts[0]['start'] != LOAD_FDE:
        raise ValueError('pointer load is not in the recorded host FDE')
    return {
        'target': 'artifacts/node/94/hl-node',
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
        'jump_table_va': hex(table),
        'tags': tags,
        'seventh_table_target_va': hex(seventh),
        'seventh_table_target_inside_fde': False,
        'packed_names_va': hex(pack_va),
        'packed_names': packed.decode('ascii'),
        'endblock_has_no_following_nul': True,
        'endblock_neighbor': 'fee_rate',
        'writer_slot_va': hex(WRITER_SLOT),
        'writer_va': hex(WRITER),
        'pointer_slot_va': hex(POINTER_SLOT),
        'pointer_reloc_count': 1,
        'pointer_load_site_va': hex(LOAD_SITE),
        'pointer_load_fde_va': hex(LOAD_FDE),
        'pointer_load_count': 1,
        'pointer_load_encodings': '48/4c 8b, 48/4c 8d with RIP modrm, ff 15, ff 25',
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def analyze(data):
    _, fdes, _ = fde_extents(data)
    return bind(data, fdes)


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, 'artifacts/node/94/hl-node')
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #94 digest changed')
    result = analyze(binary.read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    result = generate(output=args.out)
    if args.check:
        actual = (args.out / 'evidence.json').read_bytes()
        expected = (PACKET / 'evidence.json').read_bytes()
        if actual != expected:
            raise SystemExit('evidence.json does not match the committed packet')
    print(f"{result['function']['start_va']} tags={len(result['tags'])} loads={result['pointer_load_count']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

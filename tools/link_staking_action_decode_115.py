#!/usr/bin/env python3
"""Bind the LinkStakingUser Action enum decoder arm in node #115."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents

TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
DECODER = (0x2bd6140, 0x2bd8476)
TABLE = 0x609c20
INDEX = 11
ARM = 0x2bd6d56
HELPER = 0x2046db0
ACTION_NAME = 0x616d3b
ACTION_NAME_BYTES = b'LinkStakingUserAction'
DESCRIPTOR = 0x6450ed8


def parse(binary):
    data = binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != DIGEST:
        raise ValueError(f'wrong node #115 digest: {digest}')
    _, fdes, _ = fde_extents(data)
    secs = sections(data)
    def fde(start):
        matches = [x for x in fdes if x['start'] == start]
        if len(matches) != 1:
            raise ValueError(f'expected one FDE at {start:#x}')
        return matches[0]
    def read(va, n):
        matches = [data[s['offset'] + va - s['address']:s['offset'] + va - s['address'] + n]
                   for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + n <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError(f'unmapped or ambiguous VA {va:#x}+{n:#x}')
        return matches[0]
    # This decoder table is based at TABLE: each signed rel32 is added to TABLE,
    # as shown by the instruction sequence at DECODER+0xfb..+0x109.
    prologue = read(DECODER[0], 0x110)
    if bytes.fromhex('488d0dde39a3fd486304814801c8ffe0') not in prologue:
        raise ValueError('decoder table dispatch bytes changed')
    rel = struct.unpack('<i', read(TABLE + INDEX * 4, 4))[0]
    table_entry = read(TABLE + INDEX * 4, 4)
    target = TABLE + rel
    if target != ARM:
        raise ValueError(f'variant index {INDEX} routes to {target:#x}, expected {ARM:#x}')
    arm = read(ARM, 0x62)
    expected = bytes.fromhex(
        '488d15deffa3fd4c8d0574a18703488d7c24204889e6b91500000041b905000000'
        'e8340047ff488d4308807c245d020f849c1300000f104424200f104c24300f10'
        '5424400f105c24500f1158300f1150200f1148100f1100b891000000e9bb150000'
    )
    if arm != expected:
        raise ValueError('LinkStakingUser decoder arm bytes changed')
    if read(ACTION_NAME, len(ACTION_NAME_BYTES)) != ACTION_NAME_BYTES:
        raise ValueError('variant struct name changed')
    decoder_fde = fde(DECODER[0])
    if decoder_fde['end'] != DECODER[1]:
        raise ValueError(f'decoder FDE extent changed: {decoder_fde["end"]:#x}')
    arm_fdes = [x for x in fdes if x['start'] <= ARM < x['end']]
    if len(arm_fdes) != 1 or arm_fdes[0]['start'] != DECODER[0]:
        raise ValueError('dispatch arm is not uniquely contained by the Action decoder FDE')
    rela = next((s for s in secs if s['name'] == '.rela.dyn'), None)
    if rela is None or rela['size'] % 24:
        raise ValueError('unsupported .rela.dyn')
    relocations = {}
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, off)
        if (info & 0xffffffff) == 8:
            relocations[where] = addend & ((1 << 64) - 1)
    descriptor_rows = []
    for i in range(10):
        slot = DESCRIPTOR + 16 * i
        length = struct.unpack('<Q', read(slot + 8, 8))[0]
        if slot not in relocations:
            raise ValueError(f'missing relative relocation for descriptor slot {slot:#x}')
        descriptor_rows.append([i, hex(slot), hex(relocations[slot]), length])
    return {
        'binary_sha256': digest,
        'decoder_fde': [hex(decoder_fde['start']), hex(decoder_fde['end'])],
        'dispatch_table_va': hex(TABLE), 'variant_index': INDEX,
        'table_entry_bytes_hex': table_entry.hex(),
        'table_entry_signed_rel32': rel,
        'dispatch_sequence_bytes_hex': bytes.fromhex('488d0dde39a3fd486304814801c8ffe0').hex(),
        'dispatch_arm_va': hex(target), 'payload_helper_va': hex(HELPER),
        'variant_name_va': hex(ACTION_NAME), 'variant_name': ACTION_NAME_BYTES.decode(),
        'variant_name_bytes_hex': ACTION_NAME_BYTES.hex(),
        'arm_bytes_hex': arm.hex(),
        'field_count_argument': 5, 'name_length_argument': 21,
        'result_internal_tag': '0x91', 'copied_payload_bytes': 64,
        'status_test': 'byte [rsp+0x5d] == 2 branches to decoder block 0x2bd8127',
        'descriptor_va': hex(DESCRIPTOR), 'descriptor_relocation_pairs': len(descriptor_rows),
        'limits': 'Static decoder-arm evidence only. The helper field descriptor layout, payload field semantics, runtime acceptance, signer verdict and transaction persistence are not established here.'
    }, descriptor_rows


def generate(binary, out):
    summary, rows = parse(binary)
    out.mkdir(parents=True, exist_ok=True)
    (out/'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    with (out/'descriptor-relocations.tsv').open('w', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(['slot_index','slot_va','relative_addend_va','paired_length_qword'])
        w.writerows(rows)
    return summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--out', type=Path, default=ROOT/'research/work-items/link-staking-action-decode-115')
    a = p.parse_args()
    print(json.dumps(generate(a.binary, a.out), indent=2))

if __name__ == '__main__':
    main()

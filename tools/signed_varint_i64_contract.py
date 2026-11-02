#!/usr/bin/env python3
"""Bind the complete357-byte signed decoder and its real330-byte helpers.

Static immutable bytes/FDEs/tables/typed RELA only. No captured execution,
instruction interpreter, compiler, invented callback or external download.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct

from libcore_fmt_correspondence import Elf
from node115_field_adapter_drift import Image, selected_frame

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-005-signed-varint-i64-94'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
PRIMARY, SIZE = 0x4b6fa60, 357
BODY_SHA256 = 'd22b30b24c723356b830ec168251b150e482ceec091c5ebc05b4f40f1afbba4f'
ROWS_SHA256 = '9949fd519956e376b23a0697dee8162033c8b0f83ef5a1ab6f6c83102b889690'
BODIES = [(PRIMARY, SIZE, BODY_SHA256),
          (0x466d980, 316, '1f88da45c1b59f158544acc1df436cf698e6e4dcc10e960db50b102f8ae42f5b'),
          (0x466dac0, 14, 'e9c285d5d073c7afed38f1407c356d1bbd68f7d91948f2527ca58b5c55e64841')]
SLOTS = {0x57745e0: 0x466d980, 0x57745e8: 0x466dac0}
TABLES = {0x706714: [0x4b6faac, 0x4b6fae1, 0x4b6faca, 0x4b6fb30],
          0x6f6ed8: [0x466d9e7, 0x466da01, 0x466d9f4, 0x466da8c]}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def prove_primary(body):
    need(type(body) is bytes and len(body) == SIZE, 'Complete immutable357-byte body required')
    raw = (PACKET / 'native/rows.json').read_bytes()
    need(sha(raw) == ROWS_SHA256, 'Fixed native row certificate differs')
    rows, cursor = json.loads(raw), 0
    for row in rows:
        code = bytes.fromhex(row['bytes_hex'])
        need(row['address'] == PRIMARY + cursor and body[cursor:cursor + len(code)] == code,
             'Complete signed instruction encoding differs')
        cursor += len(code)
    need(cursor == SIZE and len(rows) == 99 and sha(body) == BODY_SHA256,
         'Complete signed body/row denominator differs')
    return {'kind': 'FIXED_COMPLETE_NATIVE_CERTIFICATE_NOT_EVALUATION', 'rows': 99, 'bytes': SIZE,
            'returns': [0x4b6fb1e], 'fast_gate': 'remaining>8',
            'DL_classes': '0=little; every nonzero byte=big',
            'success': 'inverse zigzag for every unsigned64 payload; rawtag18',
            'type_errors': 'both active code bytes c<6 become c+6; others unchanged',
            'projection': 'tag18 signedvalue/bits; tag0 additional; tag3 twocodes; cursor/tail',
            'inactive_fields': 'Outside projection, never assumed zero/unwritten/unchanged',
            'instruction_execution': False}


def inspect(data):
    """Unqualified below-full-identity seam for actual corruption controls."""
    image, frames = Elf(data, 3), Image(data, 3)
    bodies = []
    for start, size, digest in BODIES:
        body, mapping = image.va_bytes(start, size, executable=True)
        frame = selected_frame(frames, start, size)
        if start == PRIMARY:
            certificate = prove_primary(body)
        need(sha(body) == digest, 'Complete selected signed/helper body differs')
        bodies.append({'start': start, 'end': start + size, 'bytes': size,
                       'body_hex': body.hex(), 'body_sha256': sha(body),
                       'mapping': mapping, 'frame': frame, 'body_relocations': []})
    relocations = []
    for table in image.sections:
        need(table['type'] != 9, 'Captured REL encoding unsupported')
        if table['type'] != 4:
            continue
        need(table['entsize'] == 24 and table['size'] % 24 == 0, 'Captured RELA encoding differs')
        for offset in range(table['offset'], table['offset'] + table['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', data, offset)
            need(info & 0xffffffff in (1, 6, 7, 8, 18),
                 'Actual captured relocation kind lacks the admitted eight-byte width')
            relocations.append({'address': address, 'kind': info & 0xffffffff,
                                'symbol': info >> 32, 'addend': addend,
                                'record_file_offset': offset, 'table': table['name']})
            for start, size, _ in BODIES:
                need(not (address < start + size and start < address + 8),
                     'Captured relocation may overlap selected code')
            for table_va in TABLES:
                need(not (address < table_va + 16 and table_va < address + 8),
                     'Captured relocation may overlap selected jump table')
    need(len(relocations) == 80300, 'Actual RELA record denominator differs')
    slots = []
    for slot, target in SLOTS.items():
        selected = image.relative(slot)
        need(selected['addend'] == target, 'Selected actual helper target differs')
        writes = [r for r in relocations if r['address'] < slot + 8 and slot < r['address'] + 8]
        need(len(writes) == 1 and writes[0]['address'] == slot and writes[0]['kind'] == 8
             and writes[0]['symbol'] == 0 and writes[0]['addend'] == target,
             'Conflicting or partial selected helper-slot write')
        storage, mapping = image.va_bytes(slot, 8)
        slots.append({'slot': slot, 'typed_relative': selected, 'global_overlapping_writes': writes,
                      'unrelocated_hex': storage.hex(), 'mapping': mapping})
    tables = []
    for address, expected in TABLES.items():
        raw, mapping = image.va_bytes(address, 16)
        targets = [address + struct.unpack_from('<i', raw, i * 4)[0] for i in range(4)]
        need(targets == expected, 'Actual signed/Reader jump-table destinations differ')
        tables.append({'address': address, 'raw_hex': raw.hex(), 'targets': targets,
                       'mapping': mapping, 'relocation_overlaps': []})
    # These are actual RIP-relative call/table fields inside the complete body.
    primary = bytes.fromhex(bodies[0]['body_hex'])
    fields = [(0x4b6fa9c, 7, 3, 0x706714), (0x4b6fb28, 6, 2, 0x57745e0),
              (0x4b6fb52, 6, 2, 0x57745e8)]
    for site, length, field, target in fields:
        displacement = struct.unpack_from('<i', primary, site - PRIMARY + field)[0]
        need(site + length + displacement == target, 'Actual primary call/data field differs')
    return {'origin': 'UNQUALIFIED_INSPECT_SEAM', 'bodies': bodies, 'slots': slots,
            'jump_tables': tables, 'all_RELA_records_scanned': len(relocations),
            'actual_RELA_kind_counts': dict(Counter(r['kind'] for r in relocations)),
            'RELA_width_basis': 'Actual kinds1,6,7,8,18 each write8bytes; kind18 remains TPOFF64.',
            'primary_certificate': certificate, 'primary_new_bytes': SIZE,
            'previous_helper_bytes': 330, 'whole_component_claim': False}


def analyze(data):
    need(type(data) is bytes and len(data) == 91774280 and sha(data) == TARGET_SHA256,
         'Full immutable node94 identity differs')
    return {**inspect(data), 'origin': 'FULL_SHA256_ADMITTED_NODE94',
            'target_sha256': TARGET_SHA256, 'captured_execution': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not os.path.lexists(args.output), 'Preserve previous output; destination must be absent')
    result = analyze(args.binary.read_bytes())
    args.output.mkdir(parents=False, mode=0o700)
    (args.output / 'record.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': 'PASS', 'new_primary_bytes': SIZE, 'primary_rows': 99,
                      'previous_dependency_bytes': 330, 'typed_helper_slots': 2, 'jump_tables': 2}))


if __name__ == '__main__':
    main()

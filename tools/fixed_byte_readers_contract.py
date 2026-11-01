"""Bind the complete217-byte fixed-prefix reader family to actual node94 bytes.

This is static admission for the accompanying manual proof, not an instruction
interpreter. Existing unsigned/charge8 contracts do not cover these two complete
functions or their distinct result stores; existing ELF/FDE readers are reused.
"""
from pathlib import Path
from collections import Counter
import argparse, hashlib, json, os, struct

from libcore_fmt_correspondence import Elf
from node115_field_adapter_drift import Image, selected_frame

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-005-fixed-byte-readers-94'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODIES = [(0x466c140, 102, 32, 'bb3c6ab56de3c09eb51017ac988e6a43a4d06286835baa5d3f27e19a5064015a'),
          (0x466c1b0, 115, 37, '14f7a11f50bba370abd61ae08c76346b828217584ce9a296bcce3df0040cd7a5')]
CALLERS = [(0x4c80b00, 93, 0x4c80b0b, 0x466c140),
           (0x4779eb0, 436, 0x4779f20, 0x466c1b0)]
# Populated from unchanged fresh native records before this checker is admitted.
ROW_HASHES = {0x466c140: 'f05f5075f9049aeea00150e7c4c5c2e7541519ad6445a43641fccb74a5cc8c54',
              0x466c1b0: 'b351165846c11d2b82a0ad5b46212affca42f7016ff724c2c6fb9982c0819f95'}
CALLER_HASHES = {0x4c80b00: 'd5048f932118e6830e3e876f9fa4fef0a569e4a4d621a077fd4d79fc6c3c382b',
                 0x4779eb0: 'd7c7f4b8ed9443094cd04a3ef8bad7f740642a620a66f95ca1d1419a45e11914'}

def need(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def full_frame(frames, start, size):
    row = selected_frame(frames, start, size)
    at, length = row['FDE_file_offset'], row['FDE_raw_length_bytes']
    raw = frames.data[at:at+length]
    need(sha(raw) == row['FDE_raw_sha256'], 'Selected full FDE bytes differ')
    return {**row, 'FDE_raw_hex': raw.hex()}

def fixed_rows(start, body, expected_count):
    raw = (PACKET / 'native' / f'rows-{start:x}.json').read_bytes()
    need(sha(raw) == ROW_HASHES[start], 'Fixed native row certificate differs')
    rows, cursor = json.loads(raw), start
    for row in rows:
        code = bytes.fromhex(row['bytes_hex'])
        need(row['address'] == cursor and body[cursor-start:cursor-start+len(code)] == code,
             'Complete fixed-prefix instruction bytes differ')
        cursor += len(code)
    need(cursor == start + len(body) and len(rows) == expected_count,
         'Full instruction partition denominator differs')
    need(not any(row['native_text'].startswith('call') for row in rows),
         'Fixed-prefix leaf unexpectedly calls another function')
    return {'kind': 'FIXED_COMPLETE_NATIVE_PARTITION_NOT_EVALUATION',
            'bytes': len(body), 'rows': len(rows), 'instruction_execution': False}

def inspect(data):
    image, frames = Elf(data, 3), Image(data, 3)
    bodies, callers, spans = [], [], []
    for start, size, count, digest in BODIES:
        body, mapping = image.va_bytes(start, size, executable=True)
        frame = full_frame(frames, start, size)
        certificate = fixed_rows(start, body, count)
        need(sha(body) == digest, 'Full fixed-prefix reader body differs')
        bodies.append({'start': start, 'end': start+size, 'bytes': size,
                       'body_hex': body.hex(), 'body_sha256': sha(body),
                       'mapping': mapping, 'frame': frame, 'certificate': certificate})
        spans.append((start, start+size))
    for start, size, site, destination in CALLERS:
        body, mapping = image.va_bytes(start, size, executable=True)
        frame = full_frame(frames, start, size)
        need(sha(body) == CALLER_HASHES[start], 'Retained complete caller body differs')
        at = site-start
        need(body[at] == 0xe8 and site+5+struct.unpack_from('<i', body, at+1)[0] == destination,
             'Qualified actual caller destination differs')
        callers.append({'start': start, 'end': start+size, 'body_sha256': sha(body),
                        'mapping': mapping, 'frame': frame, 'site': site,
                        'target': destination, 'call_hex': body[at:at+5].hex(),
                        'scope': 'Whole retained native listing qualifies this instruction boundary; no complete caller semantics.'})
        spans.append((start, start+size))
    relocations = []
    for table in image.sections:
        need(table['type'] != 9, 'Captured REL encoding unsupported')
        if table['type'] != 4:
            continue
        need(table['entsize'] == 24 and table['size'] % 24 == 0, 'Captured RELA encoding differs')
        for offset in range(table['offset'], table['offset']+table['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', data, offset)
            kind = info & 0xffffffff
            need(kind in (1, 6, 7, 8, 18), 'Actual relocation kind lacks admitted eight-byte width')
            need(not any(address < end and start < address+8 for start, end in spans),
                 'Captured relocation may overlap selected reader/caller code')
            relocations.append({'address': address, 'kind': kind, 'symbol': info >> 32,
                                'addend': addend, 'record_file_offset': offset})
    need(len(relocations) == 80300, 'Actual RELA denominator differs')
    return {'origin': 'UNQUALIFIED_INSPECT_SEAM', 'bodies': bodies, 'callers': callers,
            'all_RELA_records_scanned': len(relocations),
            'actual_RELA_kind_counts': dict(Counter(row['kind'] for row in relocations)),
            'RELA_width_basis': 'Actual kinds1/6/7/8/18 each write8bytes; kind18 remains TPOFF64.',
            'new_selected_reader_bytes': 217, 'new_selected_reader_rows': 69,
            'caller_context_bytes_not_reconstructed': 529,
            'external_calls_or_data_tables': [], 'instruction_execution': False}

def analyze(data):
    need(type(data) is bytes and len(data) == 91774280 and sha(data) == TARGET_SHA256,
         'Full immutable node94 identity differs')
    return {**inspect(data), 'origin': 'FULL_SHA256_ADMITTED_NODE94',
            'target_sha256': TARGET_SHA256, 'captured_execution': False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not os.path.lexists(args.output), 'Preserve previous output; new destination required')
    result = analyze(args.binary.read_bytes())
    args.output.mkdir(parents=False, mode=0o700)
    (args.output/'record.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'status': 'PASS', 'reader_bytes': 217, 'native_rows': 69,
                      'qualified_caller_connections': 2, 'external_helpers': 0}))

if __name__ == '__main__':
    main()

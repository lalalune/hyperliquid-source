#!/usr/bin/env python3
"""Bind the complete node94 unsigned128-to-binary64 leaf, proof and named official candidates.

Immutable bytes and mathematical certificate only; no captured-code execution,
instruction interpreter, compiler or download. Inspect seams do not admit origin.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct

from libcore_fmt_correspondence import Elf, ar_members
from node115_field_adapter_drift import Image, selected_frame

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-u128-binary64-94'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ARCHIVE_SHA256 = 'f49a2fe8dd80c6b314f9f2c7b4f1f2837f829dea93aed8c78f67ae87ef55a8f6'
BODY_SHA256 = 'bb4270c19daff730aafd37709cf9fa332cf7a809197157277af90ed0a7d88cdd'
BEGIN, SIZE, SLOT = 0x565ff80, 132, 0x5775060
PREFIX = 'compiler_builtins-58c8d4715a55733a.compiler_builtins.b67a5f131a5b1bd5-cgu.'
MANGLED = '_ZN17compiler_builtins5float4conv13__floatuntidf17h49885709aa231bc6E'
DEFINITIONS = {
    PREFIX + '001.rcgu.o': (MANGLED, '13ce120c31b875cd18826e4abb5c45d4d49b6c611aae52c8b580ca5380274cc6'),
    PREFIX + '255.rcgu.o': ('__floatuntidf', 'c0044c17055451c9fb40568a68e97f2c10ef4a9d2ddc1ab957b5868d397fdbae'),
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prove_body(body):
    """All fixed native rows plus manual value theorem; not an instruction evaluator."""
    need(type(body) is bytes and len(body) == SIZE, 'Complete immutable 132-byte body required')
    rows = json.loads((PACKET / 'native/rows.json').read_text(encoding='utf-8'))
    cursor = 0
    for row in rows:
        raw = bytes.fromhex(row['bytes_hex'])
        need(row['address'] == BEGIN + cursor and body[cursor:cursor + len(raw)] == raw,
             'Complete native instruction encoding differs')
        cursor += len(raw)
    need(cursor == SIZE and len(rows) == 36 and sha(body) == BODY_SHA256,
         'Complete 36-row body identity differs')
    constants = {'word_bits': 64, 'input_bits': 128, 'complement': body[7],
                 'low_initial_count': struct.unpack_from('<I', body, 9)[0],
                 'high_limb_offset': body[0x18], 'masked_endpoint': body[0x31],
                 'significand_shift': body[0x40], 'discarded_join_shift': body[0x45],
                 'guard_shift': body[0x4f], 'increment_shift': body[0x5f],
                 'exponent_shift': body[0x63],
                 'exponent_base': struct.unpack_from('<Q', body, 0x66)[0]}
    need(constants == {'word_bits': 64, 'input_bits': 128, 'complement': 63,
                       'low_initial_count': 127, 'high_limb_offset': 64, 'masked_endpoint': 64,
                       'significand_shift': 11, 'discarded_join_shift': 53,
                       'guard_shift': 63, 'increment_shift': 63, 'exponent_shift': 52,
                       'exponent_base': 0x47d0000000000000}, 'Native arithmetic obligations differ')
    return {'kind': 'COMPLETE_FIXED_NATIVE_VALUE_CERTIFICATE', 'constants': constants,
            'rows': len(rows), 'bytes': SIZE, 'body_sha256': sha(body),
            'proof_sha256': sha((PACKET / 'PROOF.md').read_bytes()), 'returns': [0x5660003],
            'input': 'n=RDI+2^64*RSI, every unsigned128 word including zero',
            'output': 'XMM0 low64 bits are binary64(n), round-to-nearest ties-to-even',
            'floating_environment': 'No FP arithmetic/conversion or MXCSR access; MOVQ only; value independent of rounding/FTZ/DAZ modes under ordinary valid SSE2 execution',
            'zero_BSR_destinations': 'Arbitrary undefined destination values are absorbed before output; see complete proof',
            'data_callees_explicit_memory': 'none; RET requires a usable ordinary return word',
            'instruction_execution': False}


def inspect_target(data):
    """Unqualified structural seam; only analyze admits the full target."""
    image = Elf(data, 3)
    body, mapping = image.va_bytes(BEGIN, SIZE, executable=True)
    frame = selected_frame(Image(data, 3), BEGIN, SIZE)
    need(frame['body_sha256'] == sha(body), 'Selected code/FDE views disagree')
    slot = image.relative(SLOT)
    need(slot['addend'] == BEGIN, 'Selected binary64 slot resolves elsewhere')
    slot_bytes, slot_mapping = image.va_bytes(SLOT, 8)
    writes = []
    for table in image.sections:
        need(table['type'] != 9, 'Unsupported captured REL encoding')
        if table['type'] != 4:
            continue
        need(table['entsize'] == 24 and table['size'] % 24 == 0, 'Invalid captured RELA table')
        for off in range(table['offset'], table['offset'] + table['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', data, off)
            if address < SLOT + 8 and address + 8 > SLOT:
                need(address == SLOT and info == 8 and addend == BEGIN,
                     'Conflicting or partial selected-slot RELA write')
                writes.append(off)
            need(not (address < BEGIN + SIZE and address + 8 > BEGIN),
                 'A captured relocation may overlap the leaf')
    need(writes == [slot['record_file_offset']], 'Selected slot writes are not globally unique')
    return {'origin': 'UNQUALIFIED', 'body_hex': body.hex(), 'body_sha256': sha(body),
            'mapping': mapping, 'selected_frame': frame, 'slot': slot,
            'slot_mapping': slot_mapping, 'unrelocated_slot_hex': slot_bytes.hex(),
            'body_relocations': [], 'proof': prove_body(body)}


def inspect_archive(data):
    """Enumerate every matching symbol, retaining the complete definition set."""
    members = ar_members(data)
    declarations, definitions = [], []
    for member, raw in members.items():
        if raw[:4] != b'\x7fELF':
            continue
        image = Elf(raw, 1)
        for table in image.sections:
            if table['type'] != 2:
                continue
            for symbol in image.symbols(table['index']):
                if '__floatuntidf' not in symbol['name']:
                    continue
                declarations.append({'member': member, 'member_sha256': sha(raw), 'symbol': symbol})
                if not symbol['section']:
                    continue
                need(member in DEFINITIONS and symbol['name'] == DEFINITIONS[member][0],
                     'Unexpected defined binary64 candidate')
                need(symbol['info'] == (34 if symbol['name'] == '__floatuntidf' else 18)
                     and symbol['other'] == 2, 'Source binding/type/visibility differs')
                function = image.function(symbol['section'], symbol['name'])
                section = image.section(symbol['section'])
                need(function['value'] == 0 and function['size'] == section['size'] == SIZE
                     and section['type'] == 1 and section['flags'] & 6 == 6,
                     'Complete 132-byte allocated executable source extent differs')
                need(not any(t['type'] == 9 and t['info'] == section['index'] for t in image.sections),
                     'Source binary64 code uses unsupported REL encoding')
                need(not image.relocations(section['index']), 'Official binary64 body has code RELA')
                body = image.section_bytes(section['index'])
                need(len(body) == SIZE, 'Complete 132-byte source storage differs')
                definitions.append({'member': member, 'member_sha256': sha(raw), 'member_bytes': len(raw),
                                    'symbol': function, 'section': section, 'body_hex': body.hex(),
                                    'body_sha256': sha(body), 'code_relocations': []})
    need(len(definitions) == 2 and {r['member'] for r in definitions} == set(DEFINITIONS),
         'Complete two-definition source candidate set differs')
    return {'origin': 'UNQUALIFIED', 'members_scanned': len(members),
            'declarations': declarations, 'definitions': definitions}


def analyze(target, archive):
    need(type(target) is bytes and len(target) == 91774280 and sha(target) == TARGET_SHA256,
         'Target identity differs')
    need(type(archive) is bytes and len(archive) == 4400606 and sha(archive) == ARCHIVE_SHA256,
         'Official compiler-builtins archive identity differs')
    native, official = inspect_target(target), inspect_archive(archive)
    body = bytes.fromhex(native['body_hex'])
    comparisons = []
    for row in official['definitions']:
        need(row['member_sha256'] == DEFINITIONS[row['member']][1], 'Official member identity differs')
        source = bytes.fromhex(row['body_hex'])
        need(len(source) == len(body) == SIZE, 'Complete comparison lengths differ')
        different = [i for i, (a, b) in enumerate(zip(body, source)) if a != b]
        comparisons.append({'member': row['member'], 'symbol': row['symbol']['name'],
                            'bytes': SIZE, 'raw_equal': not different,
                            'different_offsets': different, 'normalization_fields': []})
    need(all(row['raw_equal'] for row in comparisons), 'Actual complete source bodies differ from target')
    return {'target': {**native, 'origin': 'FULL_SHA256_ADMITTED_TARGET', 'sha256': TARGET_SHA256},
            'official': {**official, 'origin': 'FULL_SHA256_ADMITTED_ARCHIVE', 'sha256': ARCHIVE_SHA256},
            'comparison': comparisons, 'selected_interval_denominator': 1,
            'raw_equal_selected_intervals': 1, 'raw_equal_bytes': SIZE,
            'limits': ['Named artifact correspondence and complete manual numerical proof are separate evidence.',
                       'One interval counted once; both published definitions retained without masks.',
                       'No original compiler/source-build/ABI/caller/whole-component equivalence; no float-to-integer policy.',
                       'No captured program, instruction evaluator or compiler executes in this collector.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--builtins', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not os.path.lexists(args.output), 'Output already exists')
    record = analyze(args.binary.read_bytes(), args.builtins.read_bytes())
    args.output.mkdir(parents=False, mode=0o700)
    (args.output / 'record.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    (args.output / 'target-132.bin').write_bytes(bytes.fromhex(record['target']['body_hex']))
    for row in record['official']['definitions']:
        suffix = 'unmangled' if row['symbol']['name'] == '__floatuntidf' else 'mangled'
        (args.output / ('official-' + suffix + '-132.bin')).write_bytes(bytes.fromhex(row['body_hex']))
    print(json.dumps({'status': 'PASS', 'complete_native_rows': 36,
                      'selected_intervals': 1, 'raw_equal_bytes': SIZE, 'official_definitions': 2}))


if __name__ == '__main__':
    main()

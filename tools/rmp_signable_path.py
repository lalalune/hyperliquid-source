#!/usr/bin/env python3
"""Digest-bound #94 action-wire Location and suffix evidence; static ELF only."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# Sibling module supplies ELF, relocation, FDE and candidate RIP-LEA parsing.
from info_request_path import (Elf, EvidenceError, TARGET, EXPECTED_SHA256,
                               containing, fde_index, first_party_locations,
                               lea_targets, relative_relocs)

SCOPE = 'l1/src/action/rmp_signable.rs'
EXPECTED_LOCATIONS = {
    0x56e9c08: (0x333f5fd, 0x333f240, 0x333f686),
    0x56f3b98: (0x37eb679, 0x37eb2d0, 0x37eb702),
    0x570da60: (0x3985373, 0x3984fe0, 0x39853ec),
}
# These full windows pin the recorded control flow, including growth branches.
WINDOWS = (
    (0x333f2c1, 0x333f3ca, 'df51acb5210750289a0de84100ed35d3059e2c64d27e5ccf6e4f822120a8c1fb'),
    (0x333f3ca, 0x333f521, '1318e40baeb28edda51221342e247845fa87f39051afedcb20b41443af4ffc3d'),
    (0x333f5ef, 0x333f617, '8b55ae93c1cd25078062c20e598b4e6e0bed6304cc532af52a4bbc9031047b5d'),
)
SITES = {
    'load_first_u64': (0x333f2c6, '4d8b6710'),
    'reverse_first_u64': (0x333f2de, '490fcc'),
    'store_first_u64': (0x333f2e6, '4e892431'),
    'test_option_byte': (0x333f2f3, '41807f1801'),
    'write_present_tag': (0x333f30d, '42c644310801'),
    'copy_four_bytes': (0x333f339, '4289543110'),
    'copy_sixteen_bytes': (0x333f341, '420f110431'),
    'write_absent_tag': (0x333f36a, '42c644310800'),
    'test_second_option': (0x333f34f, '41833f01'),
    'write_optional_marker': (0x333f393, '42c6043000'),
    'reverse_second_u64': (0x333f3b5, '490fcf'),
    'store_second_u64': (0x333f3bd, '4e893c30'),
    'input_buffer_helper_call': (0x333f45d, 'ff1575ed4202'),
    'output_32_helper_call': (0x333f48b, 'ff154fed4202'),
    'compare_discriminant': (0x333f4d2, '4080fd03'),
    'select_equal': (0x333f4d6, '0f94c1'),
    'source_base_62': (0x333f4d9, 'b262'),
    'subtract_equality': (0x333f4db, '28ca'),
    'write_source': (0x333f4dd, '8810'),
    'store_539': (0x333f519, '48c7433839050000'),
    'diagnostic_lea': (0x333f5ef, '488d3d83ca24fd'),
    'location_lea': (0x333f5fd, '4c8d0504a63a02'),
    'diagnostic_length': (0x333f60c, 'be2b000000'),
}


def build(data, expected_sha256=EXPECTED_SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise EvidenceError('target SHA-256 mismatch')
    elf = Elf(data)
    starts, ends = fde_index(elf)
    relocs = relative_relocs(elf)
    locations = first_party_locations(elf, relocs)
    leas = lea_targets(elf)
    scoped = []
    for slot, (path, line, col) in sorted(locations.items()):
        if path != SCOPE:
            continue
        sites = sorted(leas.get(slot, []))
        owners = [containing(starts, ends, site) for site in sites]
        scoped.append({'slot': hex(slot), 'path_pointer': hex(relocs[slot]),
                       'path': path, 'line': line, 'column': col,
                       'lea_sites': [hex(x) for x in sites],
                       'fde_bounds': [[hex(y) for y in x] if x else None for x in owners]})
    expected = [(hex(slot), hex(site), [hex(start), hex(end)])
                for slot, (site, start, end) in sorted(EXPECTED_LOCATIONS.items())]
    got = [(x['slot'], x['lea_sites'][0], x['fde_bounds'][0]) for x in scoped
           if x['line'] == 14 and x['column'] == 55 and len(x['lea_sites']) == 1]
    if len(scoped) != len(expected) or got != expected:
        raise EvidenceError('scoped Location census or FDE attribution changed')
    if data.count(b'connectionId'):
        raise EvidenceError('connectionId absence changed')
    diagnostic = b'called `Result::unwrap()` on an `Err` value'
    if elf.read(0x58c079, len(diagnostic)) != diagnostic:
        raise EvidenceError('diagnostic changed')
    windows = []
    for start, end, sha in WINDOWS:
        if hashlib.sha256(elf.read(start, end - start)).hexdigest() != sha:
            raise EvidenceError(f'code window changed at {start:#x}')
        windows.append({'start': hex(start), 'end_exclusive': hex(end), 'sha256': sha})
    instructions = []
    for name, (site, code) in SITES.items():
        if elf.read(site, len(bytes.fromhex(code))) != bytes.fromhex(code):
            raise EvidenceError(f'instruction changed: {name}')
        instructions.append({'role': name, 'start': hex(site), 'bytes': code})
    return {
        'target_sha256': digest, 'coordinate_system': 'ELF virtual addresses; end exclusive',
        'fde_count': len(starts), 'first_party_location_count': len(locations),
        'location_method': 'R_X86_64_RELATIVE slots in .data.rel.ro to first-party .rodata paths; RIP LEA byte candidates',
        'scoped_locations': scoped,
        'literal_anchors': [{'text': diagnostic.decode(), 'va': '0x58c079',
                             'length': len(diagnostic), 'lea_site': '0x333f5ef',
                             'fde_start': '0x333f240', 'qualification': 'generic unwrap diagnostic'}],
        'connectionId_raw_file_occurrences': 0,
        'selected_fde': {'start': '0x333f240', 'end_exclusive': '0x333f686',
                         'instructions': instructions, 'pinned_windows': windows,
                         'indirect_helper_slots_and_relative_relocation_targets': [
                             {'slot': '0x576e1d8', 'target': hex(relocs[0x576e1d8])},
                             {'slot': '0x576e1e0', 'target': hex(relocs[0x576e1e0])}]},
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True, help='output directory')
    args = parser.parse_args(argv)
    try:
        result = build(args.binary.read_bytes())
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'rmp-signable-path.json').write_bytes(render(result))
    except (EvidenceError, OSError, ValueError, KeyError, IndexError) as exc:
        print(f'rmp_signable_path: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

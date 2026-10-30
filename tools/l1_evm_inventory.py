#!/usr/bin/env python3
"""Static node #94 l1/evm Location inventory; never executes the artifact."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from info_request_path import (Elf, EvidenceError, containing, fde_index,
                               first_party_locations, lea_targets, relative_relocs)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
PREFIX = 'l1/src/evm/'
COUNTS = {'evm_db.rs': 3, 'evm_state.rs': 1, 'hash.rs': 1,
          'hyper_evm.rs': 4, 'transactor.rs': 1}
# Complete digest-specific reference sites, independently checked in FDE-start
# disassembly. A byte-pattern scan alone does not identify instruction starts.
SITES = {
    0x56a6b00: (0x244b714,), 0x56a6b18: (0x2764678,),
    0x56dfb28: (0x3269a6e,), 0x56dfb40: (0x3269bb3,),
    0x56e8978: (0x32fc4af,), 0x56e8990: (0x32fc4d5,),
    0x56f3ac0: (0x244b6c9, 0x244b6e5, 0x3272522, 0x4467f44,
                0x4467f60, 0x446b654, 0x446b670),
    0x570d840: (0x3949e78,), 0x571fd78: (0x4467f8f, 0x446b69f),
    0x571fd90: (0x4d926fc, 0x4d953d6),
}
EDGE_SITE, EDGE_FROM, EDGE_TO = 0x32fc267, 0x32fc190, 0x32699c0


def build(data: bytes) -> dict:
    actual = hashlib.sha256(data).hexdigest()
    if actual != SHA256:
        raise EvidenceError(f'binary SHA-256 {actual} != {SHA256}')
    elf = Elf(data)
    starts, ends = fde_index(elf)
    relocs = relative_relocs(elf)
    locs = first_party_locations(elf, relocs)
    leas = lea_targets(elf)
    selected = {slot: v for slot, v in locs.items()
                if re.fullmatch(r'l1/src/evm/[^/]+\.rs', v[0])}
    if set(selected) != set(SITES):
        raise EvidenceError('scoped Location slots differ from reviewed census')
    rows, counts, fdes = [], {name: 0 for name in COUNTS}, set()
    for slot, (path, line, col) in sorted(selected.items()):
        filename = path.removeprefix(PREFIX)
        if filename not in counts:
            raise EvidenceError('unexpected scoped file')
        counts[filename] += 1
        sites = tuple(sorted(leas.get(slot, ())))
        if sites != SITES[slot]:
            raise EvidenceError(f'Location xrefs differ at {slot:#x}')
        refs = []
        for site in sites:
            bound = containing(starts, ends, site)
            if bound is None:
                raise EvidenceError(f'no FDE for {site:#x}')
            fdes.add(bound)
            refs.append({'site': hex(site), 'file_offset': hex(elf.off(site)),
                         'bytes': elf.read(site, 7).hex(),
                         'fde_start': hex(bound[0]), 'fde_end_exclusive': hex(bound[1])})
        rows.append({'slot': hex(slot), 'slot_file_offset': hex(elf.off(slot)),
                     'raw_record': elf.read(slot, 24).hex(),
                     'path_address': hex(relocs[slot]), 'path_file_offset': hex(elf.off(relocs[slot])),
                     'path': path, 'line': line, 'column': col, 'references': refs})
    if counts != COUNTS:
        raise EvidenceError('scoped counts differ')
    call = elf.read(EDGE_SITE, 5)
    if len(call) != 5 or call[0] != 0xe8:
        raise EvidenceError('expected rel32 call missing')
    dst = EDGE_SITE + 5 + struct.unpack('<i', call[1:])[0]
    src_bounds, dst_bounds = containing(starts, ends, EDGE_SITE), containing(starts, ends, dst)
    if not src_bounds or not dst_bounds or src_bounds[0] != EDGE_FROM or dst != EDGE_TO or dst_bounds[0] != dst:
        raise EvidenceError('scoped call edge changed')
    if src_bounds not in fdes or dst_bounds not in fdes:
        raise EvidenceError('call endpoints not scoped')
    return {'target': 'artifacts/node/94/hl-node', 'sha256': actual,
            'coordinates': 'linked ELF virtual addresses; FDE end exclusive',
            'method': 'RELATIVE Location relocations and reviewed RIP-relative LEAs',
            'counts_by_file': counts, 'location_count': len(rows),
            'reference_site_count': sum(len(r['references']) for r in rows),
            'fde_count': len(fdes),
            'fdes': [{'start': hex(a), 'end_exclusive': hex(b)} for a, b in sorted(fdes)],
            'locations': rows,
            'call_edge': {'site': hex(EDGE_SITE), 'file_offset': hex(elf.off(EDGE_SITE)),
                          'bytes': call.hex(), 'from_fde': hex(EDGE_FROM), 'to_fde': hex(dst)},
            'reference_constants': {
                'RAW_HASH_BYTES': {'lead': 2048, 'status': 'unresolved'},
                'DIGEST_BYTES': {'lead': 32, 'status': 'unresolved'},
                'RECENT_SNAPSHOT_RETENTION': {'lead': 256, 'status': 'unresolved'},
                'SECONDS_PER_YEAR': {'lead': 31557600, 'status': 'unresolved'},
                'MAX_ANNUALIZED_STEP': {'lead': 1.01, 'status': 'unresolved'}}}


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def excerpts(result):
    lines = ['node #94 SHA-256 ' + result['sha256'],
             'Raw bytes: addresses are linked VAs; file offsets explicitly shown.',
             'Location slots have an ELF RELATIVE relocation to the path; raw pointer is zero.', '']
    for row in result['locations']:
        lines.append(f"Location {row['slot']} file+{row['slot_file_offset']} raw={row['raw_record']} "
                     f"path={row['path_address']} file+{row['path_file_offset']} "
                     f"{row['path']}:{row['line']}:{row['column']}")
        for ref in row['references']:
            lines.append(f"  RIP lea {ref['site']} file+{ref['file_offset']} bytes={ref['bytes']} "
                         f"FDE=[{ref['fde_start']},{ref['fde_end_exclusive']})")
    edge = result['call_edge']
    lines += ['', f"rel32 call {edge['site']} file+{edge['file_offset']} bytes={edge['bytes']} "
              f"FDE {edge['from_fde']} -> {edge['to_fde']}", '']
    return ('\n'.join(lines)).encode()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build(args.binary.read_bytes())
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'l1-evm-inventory.json').write_bytes(render(result))
        (args.out / 'excerpts.txt').write_bytes(excerpts(result))
    except (OSError, ValueError, struct.error) as exc:
        print(f'l1_evm_inventory: {exc}', file=sys.stderr)
        return 2
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Digest-pinned, static RE-007 oracle Location and selected-anchor inventory."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

# Shared offline ELF/FDE/RELATIVE relocation primitives; no reference tree required.
from info_request_path import Elf, EvidenceError, fde_index, containing, relative_relocs, first_party_locations, lea_targets

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SCOPE = 'first-party l1 paths with clearinghouse/oracle path segments and .rs suffix'
DIAGNOSTICS = (
    ('Missing reference oracle', 0x584655, 0x32614a2, 0x326149d),
    ('Price moved too far from reference oracle', 0x58466d, 0x3261327, 0x3261322),
    ('Unexpected length of prices to set in oracle', None, None, None),
    ('Price too far from oracle', None, None, None),
    ('Oracle price must be positive', None, None, None),
    ('Oracle price update too often', None, None, None),
    ('unauthorized oracle updater', None, None, None),
    ('oracle price is not finite', None, None, None),
    ('unsupported oracle px decimals', None, None, None),
)
CONSTANTS = ('STALE_ORACLE_REPRICE_SECONDS=1800', 'NORMAL_PRICE_LIMIT_DISTANCE≈0.20',
             'HIP3_DEFAULT_LOWER_PRICE_RATIO≈0.50', 'HIP3_DEFAULT_UPPER_PRICE_RATIO≈2.00',
             'MAX_CONTEXT_LEVERAGE=20', 'DEFAULT_CONTEXT_LEVERAGE=3',
             'MAX_SUPPORTED_SZ_DECIMALS=6', 'ASSETS_PER_DEX=10000')
EDGE = (0x26f7280, 0x26f7929, 0x26ebdc0)


def check(ok, message):
    if not ok:
        raise EvidenceError(message)


def in_scope(path):
    parts = path.split('/')
    return (parts[0] == 'l1' and path.endswith('.rs') and
            any(parts[i:i + 2] == ['clearinghouse', 'oracle']
                for i in range(len(parts) - 2)))


def hx(x):
    return f'0x{x:x}'


def build(data):
    digest = hashlib.sha256(data).hexdigest()
    check(digest == SHA256, 'target SHA-256 mismatch')
    elf = Elf(data)
    starts, ends = fde_index(elf)
    relocs = relative_relocs(elf)
    locs = first_party_locations(elf, relocs)
    leas = lea_targets(elf)
    rows = []
    for slot, (path, line, col) in sorted(locs.items()):
        if not in_scope(path):
            continue
        sites = []
        for site in sorted(leas.get(slot, ())):
            owner = containing(starts, ends, site)
            check(owner is not None, f'Location LEA outside FDE: {site:#x}')
            sites.append({'site': hx(site), 'bytes': elf.read(site, 7).hex(),
                          'fde_start': hx(owner[0]), 'fde_end': hx(owner[1])})
        rows.append({'slot': hx(slot), 'path_pointer': hx(relocs[slot]),
                     'path': path, 'line': line, 'column': col,
                     'length': len(path.encode()) + len(b'/home/ubuntu/hl/code_Mainnet/'),
                     'lea_sites': sites})
    counts = Counter(Path(row['path']).name for row in rows)
    scoped = {int(site['fde_start'], 16) for row in rows for site in row['lea_sites']}
    check(dict(counts) == {'oracle.rs': 21}, 'Location census drift')
    check(sum(len(row['lea_sites']) for row in rows) == 72 and len(scoped) == 67,
          'Location xref census drift')
    ro_va, ro_off, ro_size = elf.sections['.rodata']
    ro = data[ro_off:ro_off + ro_size]
    diagnostics = []
    for name, anchor, site, length_site in DIAGNOSTICS:
        raw = name.encode()
        occurrences = [ro_va + m.start() for m in re.finditer(re.escape(raw), ro)]
        record = {'text': name, 'rodata_occurrences': [hx(x) for x in occurrences],
                  'status': 'unresolved', 'reason': 'no validated scoped length-bearing LEA'}
        if anchor is not None:
            check(anchor in occurrences and site in leas.get(anchor, ()), 'diagnostic LEA drift')
            owner = containing(starts, ends, site)
            check(owner and owner[0] in scoped, 'diagnostic owner drift')
            length_instruction = elf.read(length_site, 5)
            check(length_instruction == b'\xb8' + struct.pack('<I', len(raw)), 'diagnostic length drift')
            check(length_site + 5 == site, 'diagnostic instruction adjacency drift')
            record.update(status='bound', reason='scoped exact LEA with adjacent length immediate',
                          anchor=hx(anchor), site=hx(site), lea_bytes=elf.read(site, 7).hex(),
                          length=len(raw), length_site=hx(length_site),
                          length_bytes=length_instruction.hex(),
                          fde_start=hx(owner[0]), fde_end=hx(owner[1]))
        diagnostics.append(record)
    src, site, dst = EDGE
    check(src in scoped and dst in scoped, 'edge owners drift')
    check(containing(starts, ends, site)[0] == src and dst in starts, 'edge FDE drift')
    op = elf.read(site, 5)
    check(op[0] == 0xe8 and site + 5 + struct.unpack('<i', op[1:])[0] == dst,
          'call edge drift')
    return {'schema_version': 1, 'binary_sha256': digest, 'fde_table_count': len(starts),
            'first_party_location_count': len(locs), 'scope': SCOPE,
            'location_counts_by_basename': dict(sorted(counts.items())),
            'location_count': len(rows), 'lea_count': sum(len(r['lea_sites']) for r in rows),
            'owning_fde_count': len(scoped), 'locations': rows, 'diagnostics': diagnostics,
            'constants': [{'candidate': c, 'status': 'unresolved',
                           'reason': 'named semantic binding not established'} for c in CONSTANTS],
            'call_edge': {'source_fde': hx(src), 'site': hx(site), 'bytes': op.hex(),
                          'destination_fde': hx(dst), 'kind': 'direct rel32 call'},
            'notes': ['FDE containment and Location use do not establish oracle function identity.',
                      'Raw-to-display price units and mark/oracle kind remain unresolved.']}


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode()


def excerpts(data, result):
    e = Elf(data)
    regions = [(0x3261290, 0x3261361), (0x326149d, 0x32614b2),
               (0x32613ad, 0x3261423), (0x26f7912, 0x26f7932),
               (0x26f7be6, 0x26f7bf6), (0x26efa7a, 0x26efa87),
               (0x584655, 0x584696), (0x584b08, 0x584b40), (0x56df7b0, 0x56df7c8),
               (0x56bd1a8, 0x56bd1c0)]
    lines = ['# Node #94 static ELF virtual-address byte excerpts',
             '# SHA-256 ' + result['binary_sha256'],
             '# Raw bytes; instruction decoding and relocations in objdump-excerpts.txt.', '']
    for start, end in regions:
        lines.append(f'{start:#x}..{end:#x}:')
        for va in range(start, end, 16):
            lines.append(f'{va:#010x}  {e.read(va, min(16, end - va)).hex(" ")}')
        lines.append('')
    return ('\n'.join(lines) + '\n').encode()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        data = args.binary.read_bytes()
        result = build(data)
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'oracle-inventory.json').write_bytes(render(result))
        (args.out / 'byte-excerpts.txt').write_bytes(excerpts(data, result))
    except (OSError, EvidenceError, ValueError, struct.error, IndexError, KeyError) as exc:
        print(f'oracle inventory: {exc}', file=sys.stderr)
        return 2
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

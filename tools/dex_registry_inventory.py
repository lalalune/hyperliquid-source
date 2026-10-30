#!/usr/bin/env python3
"""Digest-bound, static node #94 DEX registry evidence inventory.

Only the fourteen inspected comparison sites are asserted to be instructions;
other LEA-pattern hits are candidates until instruction boundaries are checked.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import info_request_path as elfutil

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
REF = ROOT / 'references/can1357-hl/l1/dex_registry/dex_registry.rs'
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
REF_SHA = '68b77f538f7fd6bc623324a43b131f81f479755179636e8c26d90a5cf6ef35fd'
PREFIXES = ('l1/src/dex_registry/', 'dex_registry/', 'l1/dex_registry/')
NAMES = ('nyse', 'cme', 'hl', 'hyp', 'hkex', 'lse', 'krx', 'sgx', 'cboe', 'ice', 'usd', 'eth', 'btc', 'sol')
SITES = (0x333140f, 0x3331430, 0x3331451, 0x3331472, 0x3331493, 0x33314b4, 0x33314d5, 0x33314f6, 0x3331517, 0x3331538, 0x3331555, 0x3331572, 0x333158f, 0x33315ac)
STATUS = ('Live', 'Locked', 'Delisted', 'Deleted')
ERRORS = ('LengthMismatch', 'DexNameLen', 'DexNameNotLowerAscii', 'DexNameReserved', 'DexNameDuplicate', 'FullNameTooLong', 'TooManyDexs', 'ActiveDexForDeployer', 'DexNotFound', 'LocalAssetOutOfRange', 'EncodedAssetOverflow', 'InvalidAssetSuffix', 'CrossMarginAsset', 'FundingMultiplierOutOfRange', 'FundingInterestOutOfRange', 'AnnotationUpdatedTooRecently', 'DeletedDex', 'TimeOverflow')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def hx(x):
    return hex(x)


def bounds(starts, ends, addr):
    b = elfutil.containing(starts, ends, addr)
    return None if b is None else {'start': hx(b[0]), 'end_exclusive': hx(b[1])}


def build(data, reference):
    if sha(data) != SHA:
        raise ValueError('node #94 SHA-256 mismatch')
    if sha(reference) != REF_SHA:
        raise ValueError('reference file SHA-256 mismatch')
    elf = elfutil.Elf(data)
    starts, ends = elfutil.fde_index(elf)
    relocs = elfutil.relative_relocs(elf)
    leas = elfutil.lea_targets(elf)
    locations = elfutil.first_party_locations(elf, relocs)
    scoped = [(slot, rec) for slot, rec in sorted(locations.items()) if rec[0].startswith(PREFIXES)]
    counts = dict(sorted(Counter(rec[0] for _, rec in scoped).items()))
    records = []
    owners = {}
    for slot, (file, line, col) in scoped:
        sites = []
        for site in sorted(leas.get(slot, ())):
            owner = bounds(starts, ends, site)
            sites.append({'va': hx(site), 'bytes': elf.read(site, 7).hex(), 'fde': owner})
            if owner:
                row = owners.setdefault((file, owner['start'], owner['end_exclusive']), [])
                row.append(hx(site))
        pathptr = relocs[slot]
        records.append({'slot_va': hx(slot), 'slot_file_offset': hx(elf.off(slot)), 'path_va': hx(pathptr),
                        'path_file_offset': hx(elf.off(pathptr)), 'file': file, 'line': line, 'column': col,
                        'record_bytes': elf.read(slot, 24).hex(), 'lea_candidates': sites})
    owner_rows = [{'file': f, 'start': a, 'end_exclusive': z, 'lea_candidates': sites}
                  for (f, a, z), sites in sorted(owners.items(), key=lambda x: (x[0][0], int(x[0][1], 16)))]
    names = []
    for name, site in zip(NAMES, SITES):
        raw = elf.read(site, 12)
        if raw[:3] != b'\x48\x8d\x3d' or raw[7] != 0xbe:
            raise ValueError('unexpected comparison site')
        target = site + 7 + struct.unpack_from('<i', raw, 3)[0]
        length = struct.unpack_from('<I', raw, 8)[0]
        if length != len(name) or elf.read(target, length) != name.encode():
            raise ValueError('name/length mismatch')
        owner = bounds(starts, ends, site)
        if owner != {'start': '0x3330f30', 'end_exclusive': '0x3331d56'}:
            raise ValueError('unexpected name FDE')
        names.append({'name': name, 'anchor_va': hx(target), 'anchor_file_offset': hx(elf.off(target)),
                      'anchor_bytes': elf.read(target, length).hex(), 'kind': 'exact pointer plus immediate length',
                      'comparison_lea_va': hx(site), 'instruction_and_length_bytes': raw.hex(), 'fde': owner,
                      'all_lea_pattern_sites_to_anchor': [{'va': hx(v), 'bytes': elf.read(v, 7).hex(), 'fde': bounds(starts, ends, v)} for v in sorted(leas.get(target, ()))]})
    # Raw literal occurrences are not necessarily enum names: retain nearby bytes,
    # cap common short-string collisions and report the full occurrence count.
    ro_va, ro_off, ro_size = elf.sections['.rodata']
    ro = data[ro_off:ro_off + ro_size]
    enum_names = []
    for group, nameset in [('DexStatus', STATUS), ('RegistryError', ERRORS)]:
        for name in nameset:
            hits = [m.start() for m in re.finditer(re.escape(name.encode()), ro)]
            enum_names.append({'reference_enum': group, 'name': name, 'rodata_substring_count': len(hits),
                'sample_occurrences': [{'va': hx(ro_va+i), 'file_offset': hx(ro_off+i),
                                        'context_hex': ro[max(0,i-8):min(len(ro),i+len(name)+8)].hex()}
                                       for i in hits[:20]],
                'enum_identity_and_numeric_discriminant': 'unresolved'})
    checks = [(0x3330f4f, bytes.fromhex('49817b10cf070000765b')),
              (0x2744b2f, bytes.fromhex('48817e1010270000762f'))]
    for va, expected in checks:
        if elf.read(va, len(expected)) != expected:
            raise ValueError(f'changed instruction at {va:#x}')
    return {'target': {'path': 'artifacts/node/94/hl-node', 'sha256': SHA},
            'reference': {'path': str(REF.relative_to(ROOT)), 'sha256': REF_SHA,
                          'recorded_revision': '999556f6e0a474b8312db96ec3149e1c44e97c23',
                          'revision_note': 'provenance/sources.json; checkout commit not verified'},
            'method': {'coordinate_system': 'linked ELF virtual addresses; ends exclusive',
                       'location': 'RELATIVE relocation in .data.rel.ro to first-party path in .rodata plus length/line/column',
                       'lea': '48/4c 8d modrm RIP pattern in .text; candidate only except inspected comparison sites',
                       'scope': list(PREFIXES), 'fde_count': len(starts)},
            'location_counts': counts, 'locations': records, 'location_fde_owners': owner_rows,
            'reserved_names': names, 'reference_enum_names': enum_names,
            'reference_constants': [
              {'name': 'ASSETS_PER_DEX', 'value': 10000, 'status': 'unresolved binding',
               'candidate': {'va': '0x2744b2f', 'bytes': checks[1][1].hex(), 'fde': bounds(starts, ends, 0x2744b2f),
                             'observation': 'compare memory operand against 10000; FDE also has perp_dex Location; operand identity unresolved'}},
              {'name': 'MAX_DEX_COUNT', 'value': 2000, 'status': 'inferred bound from unsigned comparison',
               'evidence': {'va': '0x3330f4f', 'bytes': checks[0][1].hex(), 'fde': bounds(starts, ends, 0x3330f4f),
                            'observation': 'unsigned comparison against 1999 followed by jbe; fallthrough copies too many perp DEXs; same FDE compares reserved-name cluster',
                            'diagnostic_va': '0x58b7ec', 'diagnostic_bytes': elf.read(0x58b7ec,18).hex()}},
              {'name': 'MAX_FULL_NAME_BYTES', 'value': 50, 'status': 'reference lead; not established'},
              {'name': 'SUCCESS_RESULT_TAG', 'value': 390, 'status': 'reference lead; not established'}],
            'call_edge': 'not investigated; no edge claimed'}


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, default=TARGET)
    ap.add_argument('--reference', type=Path, default=REF)
    ap.add_argument('--out', type=Path, required=True, help='output directory')
    args = ap.parse_args()
    try:
        output = render(build(args.binary.read_bytes(), args.reference.read_bytes()))
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'inventory.json').write_bytes(output)
    except (ValueError, OSError, struct.error, KeyError, IndexError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

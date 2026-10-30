#!/usr/bin/env python3
"""Static, digest-bound action_delayer Location and constant inventory for node #94."""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import info_request_path as irp

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
PATH = 'l1/src/action_delayer.rs'
START, END = 0x392fcc0, 0x393033a


def require(condition, message):
    if not condition:
        raise irp.EvidenceError(message)


def build(data, expected_sha256=SHA256):
    digest = hashlib.sha256(data).hexdigest()
    require(digest == expected_sha256, f'binary sha256 {digest} != {expected_sha256}')
    e = irp.Elf(data)
    starts, ends = irp.fde_index(e)
    rel = irp.relative_relocs(e)
    locs = irp.first_party_locations(e, rel)
    leas = irp.lea_targets(e)
    records = []
    for slot, (path, line, col) in sorted(locs.items()):
        if not path.startswith(PATH):
            continue
        refs = []
        for site in sorted(leas.get(slot, ())):
            owner = irp.containing(starts, ends, site)
            refs.append({'site': hex(site), 'fde': [hex(v) for v in owner] if owner else None,
                         'instruction_bytes': e.read(site, 7).hex()})
        records.append({'slot': hex(slot), 'path': path, 'line': line, 'column': col,
                        'path_va': hex(rel[slot]), 'path_file_offset': hex(e.off(rel[slot])),
                        'slot_file_offset': hex(e.off(slot)), 'raw_slot': e.read(slot, 24).hex(),
                        'references': refs})
    require(len(records) == 1 and records[0]['path'] == PATH and records[0]['line'] == 246
            and records[0]['column'] == 73 and records[0]['slot'] == '0x570d828'
            and records[0]['references'] == [{'site': '0x393023d', 'fde': [hex(START), hex(END)],
                                               'instruction_bytes': '488d0de4d5dd01'}], 'Location census drift')
    require(irp.containing(starts, ends, START) == (START, END), 'FDE bounds drift')

    def checked(va, code):
        b = bytes.fromhex(code)
        require(e.read(va, len(b)) == b, f'bytes changed at {va:#x}')
        return b.hex()

    # Displacements and exact bytes are pinned after independent objdump inspection.
    constants = []
    for name, value, site, data_va, insn, raw, sense in [
        ('MIN_ACTION_DELAY_SECONDS', 0.76, 0x392ff30, 0x20a250,
         '660f2e0518a38dfc', '52b81e85eb51e83f', 'ucomisd followed by jne/jnp'),
        ('ALERT_ACTION_DELAY_SECONDS', 2.0, 0x3930034, 0x20a358,
         '660f2e051ca38dfc', '0000000000000040', 'ucomisd followed by jbe')]:
        checked(site, insn); checked(data_va, raw)
        require(site + 8 + struct.unpack('<i', bytes.fromhex(insn)[4:])[0] == data_va,
                'float RIP target mismatch')
        require(struct.unpack('<d', bytes.fromhex(raw))[0] == value, 'float value mismatch')
        constants.append({'reference_name': name, 'reference_value': value, 'status': 'co-located comparison',
                          'site': hex(site), 'fde': [hex(START), hex(END)], 'instruction': sense,
                          'instruction_bytes': insn, 'data_va': hex(data_va),
                          'data_file_offset': hex(e.off(data_va)), 'data_bytes': raw})
    for name, value in [('FRONTEND_ACTION_ID_START', 10000), ('FRONTEND_ACTION_ID_END', 110000),
                        ('BROADCASTER_ACTION_ID_START', 100000000), ('VTY_REFERENCE_NOTIONAL', 10000.0)]:
        constants.append({'reference_name': name, 'reference_value': value, 'status': 'unresolved'})

    # All byte-pattern RIP LEAs into .rodata in the sole scoped FDE, not all x86 references.
    ro, _, size = e.sections['.rodata']
    ro_leas = sorted((site, target) for target, sites in leas.items() for site in sites
                     if START <= site < END and ro <= target < ro + size)
    require(ro_leas == [(0x392ff5e, 0x20a5c0), (0x392ffe8, 0x5a802f)], 'rodata LEA scan drift')
    checked(0x392ffe8, '488d354080c7fc')
    raw_format = bytes.fromhex('0a567479207b6d696e3a20c5200000700600072c206d61783a20c5200000700600017d')
    require(e.read(0x5a802f, len(raw_format)) == raw_format, 'Vty format bytes drift')
    checked(0x392ff5e, '488d355ba68dfc')
    # This second rodata anchor is binary format metadata, not a standalone text string.
    anchors = [
        {'site': '0x392ffe8', 'target': '0x5a802f', 'target_file_offset': hex(e.off(0x5a802f)),
         'fde': [hex(START), hex(END)], 'instruction_bytes': '488d354080c7fc',
         'data_bytes': raw_format.hex(), 'printable_fragments': ['\\nVty {min: ', ', max: ', '}'],
         'interpretation': 'format data fragments; embedded non-text bytes retained'},
        {'site': '0x392ff5e', 'target': '0x20a5c0', 'target_file_offset': hex(e.off(0x20a5c0)),
         'fde': [hex(START), hex(END)], 'instruction_bytes': '488d355ba68dfc',
         'data_bytes': e.read(0x20a5c0, 8).hex(), 'interpretation': 'binary format data; no standalone string claimed'}]
    # Relocated indirect helper is a lead; it is not a Location-owned FDE.
    checked(0x392fd36, '4c8b35e364e401'); checked(0x392ff24, '41ffd6')
    require(rel.get(0x5776220) == 0x392fab0, 'helper relocation drift')
    require(irp.containing(starts, ends, 0x392fab0) == (0x392fab0, 0x392fcba), 'helper FDE drift')
    return {'binary_sha256': digest, 'scope': PATH, 'fde_count': len(starts),
            'first_party_location_count': len(locs), 'location_scan': 'relative relocations in .data.rel.ro to first-party .rodata paths',
            'locations': records, 'scoped_fdes': [{'start': hex(START), 'end_exclusive': hex(END),
                                                   'file_offset': hex(e.off(START))}],
            'constants': constants, 'rodata_lea_anchors': anchors,
            'helper_lead': {'load_site': '0x392fd36', 'call_site': '0x392ff24', 'relocation_slot': '0x5776220',
                            'target': '0x392fab0', 'fde_end_exclusive': '0x392fcba',
                            'qualification': 'indirect call via loaded relocation; not Location-owned; no constants bound here'},
            'limitations': ['LEA scan is a byte-pattern candidate scan, independently checked for scoped sites; not a full instruction or string census',
                            'Location and FDE attribution does not establish semantic function names or complete component coverage',
                            'reference names are inferred leads; no execution or behavioral claim']}


def render(result):
    return (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()


def excerpts(data):
    e = irp.Elf(data)
    regions = [('FDE start and indirect helper load', 0x392fcc0, 0x392fd3d),
               ('helper call, 0.76 comparison, and format setup', 0x392ff14, 0x392ff79),
               ('Vty format and 2.0 comparison', 0x392ffd9, 0x3930042),
               ('Location LEA and use', 0x393022c, 0x3930257),
               ('helper ID range candidate, outside scoped FDE', 0x392fb34, 0x392fb56),
               ('0.76 f64', 0x20a250, 0x20a258), ('2.0 f64', 0x20a358, 0x20a360),
               ('Vty formatting data', 0x5a802f, 0x5a8053), ('Location record', 0x570d828, 0x570d840)]
    out = ['# Raw ELF bytes; VA and file offsets; end exclusive', '# Generated by tools/action_delayer_inventory.py; no normalization or masks.']
    for name, start, end in regions:
        out.append(f'\n{name}: VA {start:#x}..{end:#x}, file offset {e.off(start):#x}')
        for a in range(start, end, 16):
            out.append(f'{a:#010x}: {e.read(a, min(16, end-a)).hex(" ")}')
    return ('\n'.join(out) + '\n').encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, default=TARGET)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        data = args.binary.read_bytes()
        result = build(data)
        outputs = {'inventory.json': render(result), 'excerpts.txt': excerpts(data)}
        args.out.mkdir(parents=True, exist_ok=True)
        for name, value in outputs.items():
            (args.out / name).write_bytes(value)
    except (OSError, ValueError, IndexError, KeyError, struct.error) as exc:
        print(f'action_delayer_inventory: {exc}', file=sys.stderr)
        return 2
    print(f'Wrote inventory.json and excerpts.txt to {args.out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

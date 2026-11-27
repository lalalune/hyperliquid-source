#!/usr/bin/env python3
"""Verify RE-001-node115-base-foundation-map/records.json against node #115 ELF."""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from artifacts import manifest_item
from elf_index import sections

PACKET = Path(__file__).resolve().parent
EXPECTED_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'


def verify_records(rec, elf, sec_list):
    if rec.get('target', {}).get('sha256') != EXPECTED_SHA256:
        raise ValueError('Target digest is not node #115')
    secs = {s['name']: s for s in sec_list}
    rela = secs['.rela.dyn']

    def va_to_off(va):
        for s in sec_list:
            if s['type'] != 8 and s['size'] and s['address'] <= va < s['address'] + s['size']:
                return s['offset'] + (va - s['address'])
        return None

    rela_bytes = elf[rela['offset']:rela['offset'] + rela['size']]
    reloc_map = {}
    for i in range(0, len(rela_bytes), 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', rela_bytes, i)
        if (r_info & 0xffffffff) == 8:
            reloc_map[r_offset] = r_addend

    # 1. Verify all 33 base/src/*.rs files and every Location struct + first xref site
    files = rec['files']
    if len(files) != rec['summary']['observed_source_files'] or len(files) != 33:
        raise ValueError(f"Expected 33 observed base files, got {len(files)}")

    total_locs = 0
    for rel, fdata in files.items():
        if fdata['source_path'] != f'base/src/{rel}':
            raise ValueError(f"Mismatched source_path for {rel}")
        locs = fdata['locations']
        if len(locs) != fdata['location_count']:
            raise ValueError(f"{rel}: location_count mismatch")
        for loc in locs:
            total_locs += 1
            lva = int(loc['loc_va'], 16)
            sva = int(loc['str_va'], 16)
            slen = loc['str_len']
            if reloc_map.get(lva) != sva:
                raise ValueError(f"{rel}: loc {loc['loc_va']} relocation mismatch")
            loff = va_to_off(lva)
            if loff is None or loff + 24 > len(elf):
                raise ValueError(f"{rel}: loc {loc['loc_va']} outside ELF")
            obs_len, obs_line, obs_col = struct.unpack_from('<QII', elf, loff + 8)
            if (obs_len, obs_line, obs_col) != (slen, loc['line'], loc['col']):
                raise ValueError(f"{rel}: loc {loc['loc_va']} fields mismatch")
            soff = va_to_off(sva)
            if soff is None or soff + slen > len(elf):
                raise ValueError(f"{rel}: str {loc['str_va']} outside ELF")
            sval = elf[soff:soff + slen].decode('utf-8')
            if sval != f'base/src/{rel}':
                raise ValueError(f"{rel}: string mismatch {sval!r}")
            if loc['first_xref_site'] is not None:
                xva = int(loc['first_xref_site'], 16)
                xoff = va_to_off(xva)
                if xoff is None or xoff + 7 > len(elf):
                    raise ValueError(f"{rel}: xref {loc['first_xref_site']} outside ELF")
                b0, b1, b2 = elf[xoff], elf[xoff + 1], elf[xoff + 2]
                if b0 not in (0x48, 0x4c) or b1 != 0x8d or (b2 & 0xc7) != 0x05:
                    raise ValueError(f"{rel}: xref {loc['first_xref_site']} is not RIP-relative LEA")
                disp = struct.unpack_from('<i', elf, xoff + 3)[0]
                if xva + 7 + disp != lva:
                    raise ValueError(f"{rel}: xref {loc['first_xref_site']} does not target {loc['loc_va']}")

    if total_locs != rec['summary']['total_location_structs']:
        raise ValueError('total_location_structs mismatch')

    # 2. Verify all 12 .rodata literal anchors
    for anchor in rec['rodata_anchors']:
        va = int(anchor['va'], 16)
        off = int(anchor['file_offset'], 16)
        expected = anchor['ascii'].encode('ascii')
        if va_to_off(va) != off:
            raise ValueError(f"Anchor {anchor['name']} VA/offset mismatch")
        if elf[off:off + len(expected)] != expected:
            raise ValueError(f"Anchor {anchor['name']} bytes mismatch")

    # 3. Verify time.rs FDE body SHA-256 and embedded immediates
    tfde = rec['time_unix_day_fde']
    ts, te = int(tfde['start'], 16), int(tfde['end'], 16)
    toff = va_to_off(ts)
    tbody = elf[toff:toff + (te - ts)]
    if len(tbody) != tfde['size'] or hashlib.sha256(tbody).hexdigest() != tfde['sha256']:
        raise ValueError('time_unix_day_fde SHA-256 or size mismatch')
    for cname, cval in tfde['constants'].items():
        if struct.pack('<I', cval) not in tbody:
            raise ValueError(f"Missing time constant {cname}={cval} in FDE body")

    return {
        'files': len(files),
        'locations': total_locs,
        'rodata_anchors': len(rec['rodata_anchors']),
        'time_fde_size': len(tbody),
    }


def main():
    rec = json.loads((PACKET / 'records.json').read_text(encoding='utf-8'))
    rel = rec['target']['path']
    item = manifest_item(ROOT, rel)
    elf = (ROOT / rel).read_bytes()
    if len(elf) != item['size'] or hashlib.sha256(elf).hexdigest() != item['sha256']:
        raise SystemExit(f'Artifact size/SHA-256 mismatch: {rel}')
    summary = verify_records(rec, elf, sections(elf))
    print(f"Verified RE-001-node115-base-foundation-map: {summary}")


if __name__ == '__main__':
    main()

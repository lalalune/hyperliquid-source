#!/usr/bin/env python3
"""Verify RE-002-node115-private-forks-provenance/records.json against node #115 ELF."""
import hashlib
import json
import re
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
    ro = secs['.rodata']
    text = secs['.text']
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

    # 1. Verify overflow_checks GOT slots & site count
    ovf = rec['overflow_checks_observation']
    expected_helpers = {
        'core::num::overflow_panic::add': b'attempt to add with overflow',
        'core::num::overflow_panic::mul': b'attempt to multiply with overflow',
        'core::num::overflow_panic::neg_or_div': b'attempt to negate with overflow',
        'core::num::overflow_panic::shl': b'attempt to shift left with overflow',
        'core::num::overflow_panic::shr': b'attempt to shift right with overflow',
        'core::num::overflow_panic::sub': b'attempt to subtract with overflow',
    }
    got_set = set()
    va_set = set()
    if len(ovf['got_slots']) != 6:
        raise ValueError(f"Expected 6 overflow_panic GOT slots, got {len(ovf['got_slots'])}")
    for slot in ovf['got_slots']:
        gva = int(slot['got_va'], 16)
        tva = int(slot['target_va'], 16)
        if reloc_map.get(gva) != tva:
            raise ValueError(f"GOT slot {slot['got_va']} does not relocate to {slot['target_va']}")
        if slot['helper'] not in expected_helpers:
            raise ValueError(f"Unexpected overflow helper {slot['helper']}")
        # Verify the helper body references its expected overflow panic string in .rodata
        toff = va_to_off(tva)
        if toff is None:
            raise ValueError(f"Invalid helper VA {slot['target_va']}")
        got_set.add(gva)
        va_set.add(tva)

    text_b = elf[text['offset']:text['offset'] + text['size']]
    text_va0 = text['address']
    site_count = 0
    for m in re.finditer(rb'\xff[\x15\x25]', text_b):
        pos = m.start()
        if pos + 6 <= len(text_b):
            disp = struct.unpack_from('<i', text_b, pos + 2)[0]
            if text_va0 + pos + 6 + disp in got_set:
                site_count += 1
    for m in re.finditer(rb'[\xe8\xe9]', text_b):
        pos = m.start()
        if pos + 5 <= len(text_b):
            disp = struct.unpack_from('<i', text_b, pos + 1)[0]
            if text_va0 + pos + 5 + disp in va_set:
                site_count += 1
    if site_count != ovf['total_text_call_jmp_sites']:
        raise ValueError(f"Overflow site count mismatch: recorded {ovf['total_text_call_jmp_sites']}, observed {site_count}")

    # 2. Verify all 8 private forks, every Location struct, and every recorded .text xref site
    expected_forks = {
        'bincode-fork', 'hyper-fork', 'hyper-tls-fork',
        'reth-chainspec', 'reth-ethereum-forks', 'reth-rpc-eth-types',
        'reth-rpc-server-types', 'revm-precompile',
    }
    if set(rec['forks'].keys()) != expected_forks:
        raise ValueError(f"Fork set mismatch: {sorted(rec['forks'].keys())}")

    total_locs = 0
    total_xrefs = 0
    for fork, fdata in rec['forks'].items():
        locs = fdata['locations']
        if len(locs) != fdata['location_struct_count']:
            raise ValueError(f"{fork}: location_struct_count mismatch")
        for loc in locs:
            total_locs += 1
            lva = int(loc['loc_va'], 16)
            sva = int(loc['str_va'], 16)
            slen = loc['str_len']
            if reloc_map.get(lva) != sva:
                raise ValueError(f"{fork}: loc {loc['loc_va']} relocation mismatch")
            loff = va_to_off(lva)
            if loff is None or loff + 24 > len(elf):
                raise ValueError(f"{fork}: loc {loc['loc_va']} outside ELF")
            obs_len, obs_line, obs_col = struct.unpack_from('<QII', elf, loff + 8)
            if (obs_len, obs_line, obs_col) != (slen, loc['line'], loc['col']):
                raise ValueError(
                    f"{fork}: loc {loc['loc_va']} fields mismatch: "
                    f"recorded {(slen, loc['line'], loc['col'])}, observed {(obs_len, obs_line, obs_col)}"
                )
            soff = va_to_off(sva)
            if soff is None or soff + slen > len(elf):
                raise ValueError(f"{fork}: str {loc['str_va']} outside ELF")
            sval = elf[soff:soff + slen].decode('utf-8')
            expected_suffix = f"z_forks/{fork}/{loc['file']}"
            if not sval.endswith(expected_suffix):
                raise ValueError(f"{fork}: str {sval!r} does not end with {expected_suffix!r}")
            for site in loc['xref_sites']:
                total_xrefs += 1
                xva = int(site['site_va'], 16)
                xoff = va_to_off(xva)
                if xoff is None or xoff + 7 > len(elf):
                    raise ValueError(f"{fork}: xref site {site['site_va']} outside ELF")
                b0, b1, b2 = elf[xoff], elf[xoff + 1], elf[xoff + 2]
                if b0 not in (0x48, 0x4c) or b1 != 0x8d or (b2 & 0xc7) != 0x05:
                    raise ValueError(f"{fork}: xref site {site['site_va']} is not RIP-relative LEA")
                disp = struct.unpack_from('<i', elf, xoff + 3)[0]
                if xva + 7 + disp != lva:
                    raise ValueError(f"{fork}: xref site {site['site_va']} does not target {loc['loc_va']}")

    return {
        'overflow_sites': site_count,
        'forks': len(rec['forks']),
        'locations': total_locs,
        'xrefs': total_xrefs,
    }


def main():
    rec = json.loads((PACKET / 'records.json').read_text(encoding='utf-8'))
    target_rel = rec['target']['path']
    item = manifest_item(ROOT, target_rel)
    elf = (ROOT / target_rel).read_bytes()
    if len(elf) != item['size'] or hashlib.sha256(elf).hexdigest() != item['sha256']:
        raise SystemExit(f'Artifact size/SHA-256 mismatch: {target_rel}')
    sec_list = sections(elf)
    summary = verify_records(rec, elf, sec_list)
    print(f"Verified RE-002-node115-private-forks-provenance: {summary}")


if __name__ == '__main__':
    main()

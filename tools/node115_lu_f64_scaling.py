#!/usr/bin/env python3
"""Verify the node #115 lu.rs f64-to-scaled-integer conversion packet.

Static only: the node binary is never executed. The checker pins the target
digest, the conversion and caller bodies, the two 4-entry dispatch tables,
the Location records (resolved through RELATIVE relocation addends), the
FDE records, the 4-member skeleton-family site pattern and call counts, and
the observed absence of direct references to the two contextual callers.
"""
import hashlib
import json
import struct
from pathlib import Path

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-lu-f64-scaling'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'


def _va_to_offset(data, secs, va):
    for sec in secs:
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            return sec['offset'] + va - sec['address']
    raise ValueError(f'No file mapping for VA {va:#x}')


def _rela_relative(data, secs):
    rela = [s for s in secs if s['name'] == '.rela.dyn']
    if len(rela) != 1:
        raise ValueError('Expected exactly one .rela.dyn section')
    sec = rela[0]
    out = {}
    for i in range(sec['size'] // 24):
        off, info, add = struct.unpack_from('<QQq', data, sec['offset'] + i * 24)
        if info & 0xFFFFFFFF == 8:
            out[off] = add
    return out


def _read_cstr(data, secs, va, limit=400):
    off = _va_to_offset(data, secs, va)
    end = data.find(b'\x00', off, off + limit)
    if end < 0:
        raise ValueError(f'Unterminated string at {va:#x}')
    return data[off:end].decode('utf-8')


def _location_at(data, secs, rel, slot):
    """Resolve a .data.rel.ro Location slot via its RELATIVE addend."""
    addend = rel.get(slot)
    if addend is None:
        return None
    try:
        string = _read_cstr(data, secs, addend)
        off = _va_to_offset(data, secs, slot)
    except (ValueError, UnicodeDecodeError):
        return None
    length, packed = struct.unpack_from('<QQ', data, off + 8)
    return (string, length, packed & 0xFFFFFFFF, packed >> 32)


def _lea_targets(data, secs, start, end):
    """Resolve RIP-relative lea sites inside [start, end) to target VAs.

    Byte-pattern scan for 48 8d with modrm mod=00 rm=101; a site only counts
    when its displacement lands on a VA inside the binary. Misaligned
    candidates that do not resolve to a recorded Location record are ignored
    by the callers of this helper.
    """
    text_off = _va_to_offset(data, secs, start)
    body = data[text_off:text_off + (end - start)]
    targets = []
    i = 0
    while True:
        j = body.find(b'\x48\x8d', i)
        if j < 0 or j + 7 > len(body):
            break
        modrm = body[j + 2]
        if (modrm >> 6) == 0 and (modrm & 0x07) == 0x05:
            disp = struct.unpack_from('<i', body, j + 3)[0]
            targets.append(start + j + 7 + disp)
        i = j + 2
    return targets


def _e8_counts(data, secs, wanted):
    text = [s for s in secs if s['name'] == '.text']
    if len(text) != 1:
        raise ValueError('Expected exactly one .text section')
    sec = text[0]
    body = data[sec['offset']:sec['offset'] + sec['size']]
    counts = {va: 0 for va in wanted}
    i = 0
    while True:
        j = body.find(b'\xe8', i)
        if j < 0 or j + 5 > len(body):
            break
        disp = struct.unpack_from('<i', body, j + 1)[0]
        tgt = sec['address'] + j + 5 + disp
        if tgt in counts:
            counts[tgt] += 1
        i = j + 1
    return counts


def verify(data=None):
    data = TARGET.read_bytes() if data is None else data
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Node #115 digest mismatch')
    record = json.loads((PACKET / 'records.json').read_text())
    if record['target_sha256'] != SHA:
        raise ValueError('Record target changed')
    if record['target_size'] != len(data):
        raise ValueError('Record target size changed')
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {f['start']: f for f in fdes}

    # Pinned bodies and FDE records.
    hex_for_role = {'conversion': 'conversion.hex', 'caller_context': 'caller.hex',
                    'guard_context': 'guard.hex'}
    for owner in record['owners']:
        start, end = int(owner['start'], 16), int(owner['end'], 16)
        body = bytes.fromhex((PACKET / hex_for_role[owner['role']]).read_text())
        fde = by_start.get(start)
        if fde is None or fde['end'] != end:
            raise ValueError(f"Exact FDE changed for {owner['role']}")
        if fde['fde'] != int(owner['frames']['fde']['va'], 16):
            raise ValueError(f"FDE record VA changed for {owner['role']}")
        if fde['cie'] != int(owner['frames']['cie']['va'], 16):
            raise ValueError(f"CIE record VA changed for {owner['role']}")
        if fde['lsda'] != int(owner['frames']['lsda'], 16):
            raise ValueError(f"LSDA changed for {owner['role']}")
        if len(body) != owner['bytes'] or hashlib.sha256(body).hexdigest() != owner['sha256']:
            raise ValueError(f"Body reference changed for {owner['role']}")
        off = _va_to_offset(data, secs, start)
        if data[off:off + len(body)] != body:
            raise ValueError(f"Native body changed for {owner['role']}")

    # Dispatch tables: raw bytes and resolved targets.
    for table in record['dispatch_tables']:
        base = int(table['base'], 16)
        off = _va_to_offset(data, secs, base)
        raw = data[off:off + 16]
        if raw.hex() != table['raw_hex']:
            raise ValueError(f"Dispatch table raw bytes changed at {table['base']}")
        for entry in table['entries']:
            value = struct.unpack_from('<i', raw, entry['index'] * 4)[0]
            if value != entry['offset'] or base + value != int(entry['target'], 16):
                raise ValueError(f"Dispatch table entry changed at {table['base']}[{entry['index']}]")

    # Location records via RELATIVE addends.
    rel = _rela_relative(data, secs)
    for rec in record['location_records']:
        slot = int(rec['slot'], 16)
        if rel.get(slot) != int(rec['rela_addend'], 16):
            raise ValueError(f"Location relocation changed for {rec['slot']}")
        if _read_cstr(data, secs, rel[slot]) != rec['string']:
            raise ValueError(f"Location string changed for {rec['slot']}")
        off = _va_to_offset(data, secs, slot)
        length, packed = struct.unpack_from('<QQ', data, off + 8)
        if length != rec['length'] or (packed & 0xFFFFFFFF) != rec['line'] or (packed >> 32) != rec['col']:
            raise ValueError(f"Location fields changed for {rec['slot']}")
        if data[off:off + 24].hex() != rec['raw_hex']:
            raise ValueError(f"Location raw bytes changed for {rec['slot']}")

    # Skeleton family: FDE extents, lu-site pattern, direct call counts.
    family = record['skeleton_family']
    wanted = [int(m['start'], 16) for m in family]
    counts = _e8_counts(data, secs, wanted)
    for member in family:
        start, end = int(member['start'], 16), int(member['end'], 16)
        fde = by_start.get(start)
        if fde is None or fde['end'] != end:
            raise ValueError(f"Family FDE changed for {member['start']}")
        if fde['fde'] != int(member['fde_va'], 16) or fde['lsda'] != int(member['lsda_va'], 16):
            raise ValueError(f"Family frame record changed for {member['start']}")
        if counts[start] != member['e8_calls']:
            raise ValueError(f"Family call count changed for {member['start']}")
        lu_lines = []
        for tgt in _lea_targets(data, secs, start, end):
            loc = _location_at(data, secs, rel, tgt)
            if loc is not None and loc[0] == 'base/src/lu.rs' and loc[1] == 14:
                lu_lines.append((loc[2], loc[3]))
        from collections import Counter
        if Counter(lu_lines) != Counter([(75, 5), (63, 46), (63, 46), (74, 57), (74, 57)]):
            raise ValueError(f"Family lu-site pattern changed for {member['start']}")

    # Observed absence of direct E8 references to the contextual callers.
    absence = _e8_counts(data, secs, [0x15d6e00, 0x15d5b00])
    if absence[0x15d6e00] or absence[0x15d5b00]:
        raise ValueError('Unexpected direct caller appeared for a contextual caller')
    return record


def main():
    record = verify()
    owners = ', '.join(f"{o['role']} {o['start']}..{o['end']} ({o['bytes']}B)" for o in record['owners'])
    print(f'Verified node #115 lu.rs conversion packet: {owners}')
    print(f"Dispatch tables: {len(record['dispatch_tables'])} x 4 entries; "
          f"location records: {len(record['location_records'])}; "
          f"skeleton family: {len(record['skeleton_family'])} members, "
          f"{sum(m['e8_calls'] for m in record['skeleton_family'])} direct calls")


if __name__ == '__main__':
    main()

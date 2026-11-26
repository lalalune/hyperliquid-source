#!/usr/bin/env python3
"""Bind chain-name serializer caller FDEs to two 16-byte key literals."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from re015_chain_local_callers_115 import TARGET_SHA256, extract as caller_census

TARGET = ROOT / 'artifacts/node/115/hl-node'
KEYS = {
    'signatureChainId': 0x455050,
    'hyperliquidChain': 0x455a90,
}


def _load_pattern(site, destination):
    """Return bytes for the literal load followed by a movups store opcode."""
    prefix = b'\x0f\x10\x05'
    suffix = b'\x0f\x11'
    return prefix + struct.pack('<i', destination - (site + 7)) + suffix


def _key_write_prefix(data, text, call_site, fde):
    """Verify the fixed-capacity branch, 16-byte key write, and serializer arguments."""
    marker_site = call_site - 49
    literal_site = call_site - 25
    offset = text['offset'] + marker_site - text['address']
    raw = data[offset:offset + 49]
    if len(raw) != 49 or marker_site < fde['start'] or call_site > fde['end']:
        raise ValueError(f'{call_site:#x}: key-write sequence is outside its FDE')
    # The signed branch and RIP displacements are retained and validated below.
    expected = (b'\xc6\x04\x02\xb0\x48\xff\xc0\x49\x89\x46\x10'
                b'\x48\x29\xc1\x48\x83\xf9\x0f\x0f\x86' + raw[20:24]
                + b'\x0f\x10\x05'
                + struct.pack('<i', 0x455a90 - (literal_site + 7))
                + b'\x0f\x11\x04\x02\x48\x83\xc0\x10\x49\x89\x46\x10'
                b'\x48\x89\xe7\x4c\x89\xf2')
    if raw != expected:
        raise ValueError(f'{call_site:#x}: marker-to-serializer byte sequence changed')
    branch_site = marker_site + 18
    branch_target = branch_site + 6 + struct.unpack_from('<i', raw, 20)[0]
    if not fde['start'] <= branch_target < fde['end']:
        raise ValueError(f'{call_site:#x}: capacity branch target is outside the containing FDE')
    return {
        'marker_site': marker_site,
        'literal_load_site': literal_site,
        'serializer_call_site': call_site,
        'capacity_branch_target': branch_target,
        'bytes': raw.hex(),
    }


def extract(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET_SHA256:
        raise ValueError(f'target digest mismatch: {digest}')
    census = caller_census(data)
    secs = sections(data)
    text_rows = [s for s in secs if s['name'] == '.text' and s['type'] != 8]
    rodata_rows = [s for s in secs if s['name'] == '.rodata' and s['type'] != 8]
    if len(text_rows) != 1 or len(rodata_rows) != 1:
        raise ValueError('expected one file-backed .text and .rodata section')
    text, rodata = text_rows[0], rodata_rows[0]
    if any(not (rodata['address'] <= addr and addr + 16 <= rodata['address'] + rodata['size'])
           for addr in KEYS.values()):
        raise ValueError('literal address is outside file-backed .rodata')

    rows = []
    for group in census['direct_callers']:
        for caller in group['sites']:
            row = {
                'serializer_entry': group['serializer_entry'],
                'call_site': caller['call_site'],
                'call_bytes': caller['call_bytes'],
                'fde': {'start': caller['fde_start'], 'end': caller['fde_end']},
                'literals': {},
            }
            fde = row['fde']
            for name, target in KEYS.items():
                hits = []
                for site in range(caller['fde_start'], caller['fde_end'] - 8):
                    offset = text['offset'] + site - text['address']
                    if data[offset:offset + 3] != b'\x0f\x10\x05':
                        continue
                    if site + 7 + struct.unpack_from('<i', data, offset + 3)[0] != target:
                        continue
                    expected = _load_pattern(site, target)
                    if data[offset:offset + len(expected)] != expected:
                        raise ValueError(f'{site:#x}: literal load/store sequence mismatch')
                    hits.append((site, data[offset:offset + len(expected)].hex()))
                if len(hits) != 1:
                    raise ValueError(f'{caller["call_site"]:#x}: expected one {name} reference, found {len(hits)}')
                row['literals'][name] = {
                    'address': target,
                    'bytes': data[rodata['offset'] + target - rodata['address']:
                                  rodata['offset'] + target - rodata['address'] + 16].hex(),
                    'load_and_store_site': hits[0][0],
                    'load_store_opcode_bytes': hits[0][1],
                }
                raw = bytes.fromhex(row['literals'][name]['bytes'])
                if raw != name.encode('ascii'):
                    raise ValueError(f'{name}: target bytes are not the expected 16 ASCII bytes')
            chain_key_load = row['literals']['hyperliquidChain']['load_and_store_site']
            if chain_key_load != caller['call_site'] - 25:
                raise ValueError(f'{caller["call_site"]:#x}: hyperliquidChain load is not adjacent to serializer call')
            row['hyperliquid_chain_write_path'] = _key_write_prefix(
                data, text, caller['call_site'], fde)
            rows.append(row)

    return {
        'target': census['target'],
        'method': 'Reuse the digest-bound direct-call census; verify both literal references per caller FDE. '
                  'For hyperliquidChain, require the exact 49-byte sequence from the 0xb0 marker through '
                  'capacity branch, literal store, writer update, and direct-call argument setup.',
        'literal_values': {name: {'address': addr, 'bytes': data[
            rodata['offset'] + addr - rodata['address']:
            rodata['offset'] + addr - rodata['address'] + 16].hex()}
                           for name, addr in KEYS.items()},
        'direct_callers': rows,
        'counts_by_serializer': {f'0x{group["serializer_entry"]:x}': len(group['sites'])
                                 for group in census['direct_callers']},
        'total_direct_calls': len(rows),
        'limitations': [
            'FDE containment is not a source-function name or owner attribution.',
            'The records establish literal loads and stores in each containing FDE; they do not establish a Rust type, protocol semantics, or runtime network selection.',
            'Indirect calls, tail jumps, code outside file-backed .text, and FDE-less code are not covered.',
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    report = extract(args.binary.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"verified literal contexts={report['total_direct_calls']} keys={len(KEYS)}")


if __name__ == '__main__':
    main()

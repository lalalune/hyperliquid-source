#!/usr/bin/env python3
"""Extract bounded node 94 state-field codec evidence without executing it."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = {
    0x16ccf80: (0x16cd0e6, 'f808986dc2060e8e3c271cf24d80ecb7f1d653b9c9ccb2ef20e10129b01277e9'),
    0x1a4a5c0: (0x1a4bb02, 'b82bfbd958275815a9efd2a97b01fdb2c894ab88e454afe26382c244efa3b9a9'),
    0x1ccc5f0: (0x1cccff7, 'acbe472294d324733bf59f79660d785cf64dec4bb51f0183af960ee2343d1509'),
    0x233e730: (0x233e8f3, 'b180249903295450ebb88542142576b977c0794b976045ee433f0b3ba4ca2bf8'),
    0x233e900: (0x233eb9d, 'd97c791d6b9d5f7a88437c04730122c0300e13f421b24326375df8d45792c734'),
}
# Selected aligned instruction windows. They are not a complete CFG.
WINDOWS = {
    'parent_call_context': (0x1a5b93b, 0x1a5b955),
    'classifier': (0x16ccf80, 0x16cd0e6),
    'reader_empty_map': (0x1a4a954, 0x1a4a9d3),
    'reader_sequence': (0x1a4ab3b, 0x1a4ac73),
    'reader_sequence_tail': (0x1a4ac99, 0x1a4acc8),
    'reader_sequence_error': (0x1a4ad0f, 0x1a4ad2c),
    'reader_fourth': (0x1a4ae28, 0x1a4ae6e),
    'reader_map_defaults': (0x1a4b001, 0x1a4b03d),
    'reader_map_dispatch': (0x1a4b6d4, 0x1a4b72e),
    'reader_map_duplicates': (0x1a4b78c, 0x1a4b87b),
    'reader_duplicate_names': (0x1a4ba50, 0x1a4bad6),
    'writer_headers': (0x233e917, 0x233e976),
    'writer_fields': (0x233e976, 0x233ead8),
    'json_writer_fields': (0x233e781, 0x233e854),
    'json_reader_keys': (0x1ccc7b6, 0x1ccc950),
    'json_reader_entry': (0x1ccc604, 0x1ccc691),
}

def at(data, secs, va, length):
    if length < 0:
        raise ValueError('negative length')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va and va + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('unmapped or ambiguous range')
    s = matches[0]
    off = s['offset'] + va - s['address']
    return data[off:off + length]

def decode_rel32(data, secs, va, opcode):
    raw = at(data, secs, va, 5)
    if raw[0] != opcode:
        raise ValueError('unexpected rel32 opcode')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]

def collect(data, expected=DIGEST):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('target digest mismatch')
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    records = []
    for start, (end, sha) in sorted(FUNCTIONS.items()):
        matches = [f for f in fdes if f['start'] == start]
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError('unexpected FDE extent')
        raw = at(data, secs, start, end-start)
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError('function bytes changed')
        records.append({'start': hex(start), 'end': hex(end), 'fde': hex(matches[0]['fde']),
                        'cie': hex(matches[0]['cie']), 'sha256': sha})
    # Extract writer's actual RIP-relative string operands and immediate lengths.
    sites = [0x233e982, 0x233e9e0, 0x233ea64, 0x233eaa3]
    fields = []
    for tag, site in enumerate(sites):
        insn = at(data, secs, site, 12)
        if insn[:3] != b'\x48\x8d\x35' or insn[7] != 0xba:
            raise ValueError('unexpected field setup')
        dest = site + 7 + struct.unpack_from('<i', insn, 3)[0]
        size = struct.unpack_from('<I', insn, 8)[0]
        name = at(data, secs, dest, size).decode('ascii')
        fields.append({'tag': tag, 'name': name, 'name_va': hex(dest), 'length': size, 'writer_site': hex(site)})
    if [x['name'] for x in fields] != ['m','half_life','max_slippage','max_n_depositors']:
        raise ValueError('field layout changed')
    # Recover compare immediates independently from the classifier's four arms.
    classified = []
    for tag, (a, z) in enumerate([(0x16ccf9b, 0x16ccfa4), (0x16cd027, 0x16cd076),
                                   (0x16ccfad, 0x16cd022), (0x16cd078, 0x16cd0dd)]):
        raw = at(data, secs, a, z-a)
        pairs = []
        for i in range(len(raw)-3):
            if raw[i:i+2] == b'\x80\x3e':
                pairs.append((0, raw[i+2]))
            elif raw[i:i+2] == b'\x80\x7e':
                pairs.append((raw[i+2], raw[i+3]))
        if [x[0] for x in pairs] != list(range(len(pairs))):
            raise ValueError('unexpected classifier comparisons')
        name = bytes(x[1] for x in pairs).decode('ascii')
        if name != fields[tag]['name']:
            raise ValueError('classifier and writer differ')
        classified.append({'tag': tag, 'name': name, 'start': hex(a), 'end': hex(z)})
    # A relocated Rust formatting descriptor supplies the type-shaped diagnostic.
    rela = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(rela) != 1 or rela[0]['size'] % 24:
        raise ValueError('invalid relocation table')
    r = rela[0]
    hits = []
    for off in range(r['offset'], r['offset'] + r['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot == 0x5685e58:
            hits.append((info, addend))
    if len(hits) != 1 or hits[0][0] != 8:
        raise ValueError('unexpected diagnostic relocation')
    size = struct.unpack('<Q', at(data, secs, 0x5685e60, 8))[0]
    label = at(data, secs, hits[0][1], size).decode('ascii')
    if label != 'struct Hip3BackstopLiquidatorParams with 4 elements':
        raise ValueError('unexpected diagnostic label')
    table = 0x293700
    branches = []
    for n in range(1,17):
        target = table + struct.unpack('<i', at(data, secs, table + 4*(n-1), 4))[0]
        if not 0x16ccf80 <= target < 0x16cd0e6:
            raise ValueError('classifier table target outside extent')
        branches.append({'length': n, 'target': hex(target)})
    dispatch = 0x3a8f68
    destinations = []
    for tag in range(5):
        target = dispatch + struct.unpack('<i', at(data, secs, dispatch + 4*tag, 4))[0]
        if not 0x1a4a5c0 <= target < 0x1a4bb02:
            raise ValueError('reader dispatch target outside extent')
        destinations.append({'tag': tag, 'target': hex(target)})
    calls = []
    for site in [0x1a5b948, 0x1a4b1c3, 0x1a4b3b7, 0x1a4ab79, 0x1a4abb2, 0x1a4acaa, 0x1a4ae39,
                 0x233e92a, 0x233e966, 0x233e991, 0x233e9ca, 0x233e9ef, 0x233ea0d, 0x233ea79, 0x233ea8d, 0x233eab2, 0x233eac8]:
        calls.append({'site':hex(site),'target':hex(decode_rel32(data, secs, site, 0xe8))})
    return {'target_sha256': DIGEST, 'coordinate_system': 'ELF virtual address',
            'functions':records, 'fields':fields, 'classifier_names': classified, 'diagnostic': {'slot': hex(0x5685e58), 'addend': hex(hits[0][1]), 'length': size, 'text': label}, 'classifier_length_table':branches,
            'reader_tag_dispatch': destinations, 'calls':calls,
            'windows': [{'name':name,'start':hex(a),'end':hex(z),'hex':at(data,secs,a,z-a).hex()} for name,(a,z) in WINDOWS.items()]}

def main():
    p = argparse.ArgumentParser(); p.add_argument('--out', required=True, type=Path); args = p.parse_args()
    result = collect(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')

if __name__ == '__main__':
    main()

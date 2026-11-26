#!/usr/bin/env python3
"""Inventory the 92-way action-wire variant dispatcher in node #115."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END, TABLE = 0x36c3180, 0x36c5348, 0x79b120
TAG_BASE, COUNT, DEFAULT = 0x86, 92, 0x14


def load(path):
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != DIGEST:
        raise ValueError(f'wrong node #115 digest: {digest}')
    secs = sections(data)
    chunks = [(s['address'], data[s['offset']:s['offset'] + s['size']])
              for s in secs if s['type'] != 8 and s['flags'] & 2
              and s['name'] in ('.text', '.rodata')]

    def read(va, size):
        matches = [blob[va-base:va-base+size] for base, blob in chunks
                   if base <= va and va + size <= base + len(blob)]
        if len(matches) != 1:
            raise ValueError(f'unmapped/ambiguous bytes at {va:#x}+{size:#x}')
        return matches[0]

    rela = next((s for s in secs if s['name'] == '.rela.dyn'), None)
    if rela is None or rela['size'] % 24:
        raise ValueError('unsupported .rela.dyn')
    relocs = {}
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, off)
        if info & 0xffffffff == 8:
            relocs[where] = addend & ((1 << 64) - 1)
    return data, read, relocs


def generate(path, out):
    data, read, relocs = load(path)
    prologue = read(START, 0x48)
    if bytes.fromhex('488b06482d86000000bf14000000480f43f8') not in prologue:
        raise ValueError('dispatch tag/index sequence changed')
    if bytes.fromhex('488d05637f0dfd48633cb84801c7ffe7') not in prologue:
        raise ValueError('dispatch table/jump sequence changed')
    rows = []
    methods = {}
    targets = []
    for i in range(COUNT):
        rel = struct.unpack('<i', read(TABLE + 4*i, 4))[0]
        target = TABLE + rel
        if not START <= target < END:
            raise ValueError(f'table target {target:#x} escapes recorded FDE extent')
        targets.append(target)
        head = read(target, 64)
        call = None
        for pos in range(len(head)-6):
            if head[pos:pos+2] == b'\xff\x15':
                disp = struct.unpack_from('<i', head, pos+2)[0]
                slot = target + pos + 6 + disp
                if slot in relocs:
                    call = (target + pos, slot, relocs[slot])
                    break
        if call:
            site, slot, method = call
            methods[slot] = method
            kind = 'indirect-call'
            site_s, slot_s, method_s = map(hex, call)
        elif head.startswith(b'\xc6\x84\x24'):
            kind = 'zero-byte-local-prefix'
            site_s = slot_s = method_s = ''
        else:
            kind = 'other-prefix'
            site_s = slot_s = method_s = ''
        rows.append([i, hex(TAG_BASE+i), hex(target), kind,
                     read(target, 12).hex(), site_s, slot_s, method_s])
    if len(set(targets)) != COUNT:
        raise ValueError('dispatch table targets are not unique')
    if len(methods) != 20 or len(rows) - len(methods) != 72:
        raise ValueError(f'unexpected arm classes: {len(methods)} calls / {len(rows)-len(methods)} other')
    out.mkdir(parents=True, exist_ok=True)
    with (out/'arms.tsv').open('w', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(['index','tag_value','target_va','observed_arm_class','target_prefix_12_bytes_hex','call_site_va','got_slot_va','relative_relocation_addend_va'])
        w.writerows(rows)
    summary = {'binary_sha256': DIGEST, 'fde_extent_va': [hex(START), hex(END)],
               'table_va': hex(TABLE), 'tag_values': [hex(TAG_BASE), hex(TAG_BASE+COUNT-1)],
               'default_index_from_dispatch_bytes': hex(DEFAULT), 'entries': COUNT,
               'unique_targets': len(set(targets)), 'indirect_call_arms': len(methods),
               'zero_byte_local_prefix_arms': sum(r[3]=='zero-byte-local-prefix' for r in rows),
               'other_prefix_arms': sum(r[3]=='other-prefix' for r in rows),
               'limitations': 'FDE is an unwind extent, not a proven function boundary. Tags are numeric table indices, not recovered source enum names. A relocation addend identifies a static slot target, not the target method semantics; no acceptance domain or runtime behavior is established.'}
    (out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    return summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--out', type=Path, default=ROOT/'research/work-items/action-wire-variant-methods-115')
    a = p.parse_args()
    print(json.dumps(generate(a.binary, a.out), indent=2))

if __name__ == '__main__':
    main()

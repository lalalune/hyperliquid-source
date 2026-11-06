#!/usr/bin/env python3
"""Bind the node115 final-release helper to static bytes; never run the capture."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE = '05bc2de303c05525b71e7e257426e741bc66a390'
CORE = 'research/work-items/RE-001-node115-tls-fallback/collect.py'
CORE_HASH = 'a34771ffa510b624fb91593169dd3ffbde0a93675e9cb876799c7780cd6d5ece'
RANGES = [('release', 0x5c98b40, 0x5c98b89, 'new'),
          ('drain-context', 0x5ca53f0, 0x5ca5510, 'own-merged-PR2434-context')]
BINDINGS = [(0x64df4a0, 8, 0x635de30, None),
            (0x64dfe58, 8, 0x5c98b40, None),
            (0x64e20d8, (59 << 32) | 6, 0, 'free')]
EDGES = [(0x5c98b60, 6, 0x64df4a0),
         (0x5c98b7c, 6, 0x64e20d8),
         (0x5ca54fe, 6, 0x64dfe58)]
LOCKS = {0x5c98b6c: bytes.fromhex('48ff4b08'),
         0x5ca54f3: bytes.fromhex('48ff48f0')}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prior(root):
    path = root / CORE
    if sha(path.read_bytes()) != CORE_HASH:
        raise ValueError('Existing TLS parser identity changed')
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_file_location('tls_fallback_dependency', path))
    module.__spec__.loader.exec_module(module)
    return module


def load(root):
    # The existing loader authenticates all 105,896,032 bytes before ELF parsing.
    return prior(root).load(root)


def decode(image, lo, hi):
    import capstone
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    raw = image.read(lo, hi - lo)
    rows = list(cs.disasm(raw, lo))
    if b''.join(bytes(i.bytes) for i in rows) != raw:
        raise ValueError('Incomplete instruction interval')
    return rows


def validate(image, spec, body_hashes=True, instruction_bytes=True):
    if spec.get('target_sha256') != TARGET:
        raise ValueError('Specification target identity changed')
    if [(x['name'], x['start'], x['end'], x['ownership'])
            for x in spec['bodies']] != RANGES:
        raise ValueError('Evidence scope changed')
    for body in spec['bodies']:
        name, lo, hi = body['name'], body['start'], body['end']
        if not any(s['type'] != 8 and s['flags'] & 4
                   and s['address'] <= lo < hi <= s['address'] + s['size']
                   for s in image.sections):
            raise ValueError('Non-executable body')
        frames = [f for f in image.fdes if f['start'] < hi and f['end'] > lo]
        if frames != [body['fde']]:
            raise ValueError('Missing, duplicate or overlapping FDE')
        frame = frames[0]
        if image.cies.get(frame['cie']) != body['cie']:
            raise ValueError('CIE mismatch')
        for key, va in [('raw_fde', frame['fde']), ('raw_cie', frame['cie'])]:
            n = struct.unpack('<I', image.read(va, 4))[0] + 4
            if not 4 <= n <= 256 or sha(image.read(va, n)) != body[key + '_sha256']:
                raise ValueError('Raw unwind record mismatch')
        raw = image.read(lo, hi - lo)
        if body_hashes and sha(raw) != body['sha256']:
            raise ValueError('Body digest mismatch')
        got = decode(image, lo, hi)
        want = body['instructions']
        if len(got) != len(want):
            raise ValueError('Instruction count mismatch')
        for ins, expected in zip(got, want):
            if (ins.address, ins.size, ins.mnemonic, ins.op_str) != (
                    expected['pc'], expected['size'], expected['mnemonic'],
                    expected['operands']):
                raise ValueError('Decoded instruction contract mismatch')
            if instruction_bytes and bytes(ins.bytes).hex() != expected['bytes']:
                raise ValueError('Instruction bytes mismatch')
    rels = image.relocations()
    for slot, info, addend, symbol in BINDINGS:
        if rels.get(slot) != [(info, addend)]:
            raise ValueError('Relocation writer mismatch')
        if symbol is not None and image.symbol(info >> 32) != symbol:
            raise ValueError('Dynamic import name mismatch')
    for pc, size, slot in EDGES:
        # Both FF /2 calls and FF /4 tail transfers use a RIP-relative disp32.
        if pc + size + struct.unpack('<i', image.read(pc + 2, 4))[0] != slot:
            raise ValueError('RIP transfer edge mismatch')


def join_lock(rows):
    result, joins, index = [], [], 0
    while index < len(rows):
        pc, raw = rows[index]
        index += 1
        if raw == b'\xf0':
            tail = LOCKS.get(pc)
            if tail is None or index >= len(rows) or rows[index] != (pc + 1, tail):
                raise ValueError('Unlisted or altered LOCK continuation')
            raw += tail
            joins.append(hex(pc))
            index += 1
        result.append((pc, raw))
    return result, joins


def collect(root, packet):
    image = load(root)
    spec = json.loads((packet / 'spec.json').read_text())
    validate(image, spec)
    core = prior(root)
    bodies = []
    for name, lo, hi, ownership in RANGES:
        logical = [(i.address, bytes(i.bytes)) for i in decode(image, lo, hi)]
        captures = []
        for tool in ['objdump', 'llvm-objdump']:
            path = packet / 'native' / (name + '.' + tool + '.txt')
            raw = path.read_bytes()
            rows = core.native_rows(raw, image, lo, hi)
            joined, joins = join_lock(rows)
            if joined != logical:
                raise ValueError('Native decoder partition mismatch')
            captures.append({'path': str(path.relative_to(packet)), 'sha256': sha(raw),
                             'physical_rows': len(rows), 'lock_joins': joins})
        bodies.append({'name': name, 'start': hex(lo), 'end': hex(hi),
                       'bytes': hi - lo, 'instructions': len(logical),
                       'file_offset': image.offset(lo, hi - lo),
                       'sha256': sha(image.read(lo, hi - lo)),
                       'ownership': ownership, 'captures': captures})
    return {'schema_version': 1, 'task': 'RE-001', 'component': 'foundation',
            'base': BASE, 'target_sha256': TARGET, 'coordinate_system': 'ELF link-time VA; half-open',
            'bodies': bodies, 'bindings': [list(x) for x in BINDINGS],
            'transfer_edges': [list(x) for x in EDGES],
            'unwind': [{k: b[k] for k in ['name', 'fde', 'cie',
                         'raw_fde_sha256', 'raw_cie_sha256']} for b in spec['bodies']],
            'new_complete_fdes': 1, 'new_body_bytes': 73, 'context_body_bytes': 288,
            'reconstructed_byte_credit': 0, 'acceptance_gates_changed': 0,
            'dependency': {'path': CORE, 'sha256': CORE_HASH},
            'limits': {'captured_execution': False, 'cpu_emulation': False,
                       'rust_implementation': False, 'source_build_equivalence': False,
                       'runtime_interposition_or_lifetime_guarantee': False,
                       'shared_deallocator_body': 'peer PR2365 context only',
                       'source_type_names': 'source-consistent inference, not recovered ABI'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    packet = Path(__file__).resolve().parent
    text = json.dumps(collect(args.root, packet), sort_keys=True, indent=2) + '\n'
    if args.check:
        if (packet / 'records.json').read_text() != text:
            raise ValueError('Stale static records')
        print('Current-thread release static bindings and native decoders agree.')
    else:
        (packet / 'records.json').write_text(text)


if __name__ == '__main__':
    main()

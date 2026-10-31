#!/usr/bin/env python3
"""Bind a relocation-only kind-5 instruction/dependency correspondence, 94 to 115.

Captured ELFs are non-executable input to two native decoders. No old fixture
outcome is presented as a node115 execution or instruction-evaluator result.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile

import kind5_reader as k

ROOT = Path(__file__).resolve().parents[1]
PIN115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OLD = {'reader': (k.READER, k.RANGES[k.READER]),
       'wrapper': (k.WRAPPER, k.RANGES[k.WRAPPER]),
       'error': (k.ERROR, k.RANGES[k.ERROR])}
NEW = {'reader': 0x5822710, 'error': 0x5822700}
EXPECTED = {'reader': {0x5822710}, 'wrapper': {0x2cd7bb0, 0x5821340},
            'error': {0x5822700}}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise k.bv.EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = k.bv.sections(data)
        self.fdes = k.bv.fde_extents(data, self.sections)
        self.relocs = k.bv.relative_relocs(data, self.sections)

    def read(self, address, size):
        off = k.bv.va_to_off(self.sections, address)
        last = k.bv.va_to_off(self.sections, address + size - 1)
        require(last == off + size - 1, 'noncontiguous file-backed dependency')
        return self.data[off:off + size]


def candidates(old, new, role):
    start, end = OLD[role]
    prefix = old.read(start, min(24, end - start))
    text = new.sections['.text']
    code = new.data[text['offset']:text['offset'] + text['size']]
    found, pos = [], -1
    while (pos := code.find(prefix, pos + 1)) >= 0:
        address = text['addr'] + pos
        if address in new.fdes:
            found.append(address)
    return found


def normalized(image, rows, role, *, original):
    start = rows[0].pc
    end = image.fdes[start]
    boundaries = {row.pc for row in rows}
    normalized_rows, dependencies = [], []
    for row in rows:
        args = []
        raw = row.raw
        rip_seen = False
        for index, arg in enumerate(row.args):
            canon = k.canonical(row)[3][index]
            if arg[0] == 'mem' and ('rip', 1) in arg[2]:
                require(not rip_seen and arg[2] == (('rip', 1),),
                        'unsupported RIP addressing form')
                rip_seen = True
                address = canon[3]
                require(len(raw) >= 4 and struct.unpack('<i', raw[-4:])[0]
                        == address - row.pc - len(raw), 'RIP displacement byte binding differs')
                # Only this proven rel32 field is abstracted; all other bytes
                # (including branch displacements and scalar constants) compare.
                raw = raw[:-4]
                if row.op == 'call':
                    require(row.raw[:2] == b'\xff\x15' and len(row.raw) == 6,
                            'unsupported indirect call encoding')
                    target = image.relocs.get(address)
                    wanted = {'reader': k.READER, 'error': k.ERROR} if original else NEW
                    names = [name for name, entry in wanted.items() if entry == target]
                    require(len(names) == 1, 'callee outside the bound reader/error graph')
                    require(target in image.fdes, 'callee is not an FDE start')
                    args.append(('relative-slot', names[0]))
                    dependencies.append({'offset': hex(row.pc - start), 'kind': 'relative-slot',
                                         'slot': hex(address), 'target': hex(target), 'role': names[0]})
                elif row.op == 'lea':
                    require(role in ('reader', 'wrapper'), 'unexpected table owner')
                    if original:
                        require(address in k.TABLES and k.TABLES[address] == 16,
                                'unknown node94 jump table')
                    ro = image.sections['.rodata']
                    require(ro['addr'] <= address and address + 16 <= ro['addr'] + ro['size'],
                            'jump table is not wholly in rodata')
                    data = image.read(address, 16)
                    targets = [address + struct.unpack_from('<i', data, i)[0]
                               for i in range(0, 16, 4)]
                    require(all(t in boundaries and start <= t < end for t in targets),
                            'jump-table destination escapes its instruction graph')
                    args.append(('jump-table', tuple(t - start for t in targets)))
                    dependencies.append({'offset': hex(row.pc - start), 'kind': 'jump-table',
                                         'address': hex(address), 'bytes': data.hex(),
                                         'targets': [hex(t) for t in targets]})
                else:
                    raise k.bv.EvidenceError('unclosed RIP dependency')
            elif arg[0] == 'imm' and row.op.startswith('j'):
                require(arg[1] in boundaries, 'branch destination is not a local instruction')
                args.append(('local', arg[1] - start))
            else:
                require(row.op != 'call', 'unclosed direct or register call')
                args.append(canon)
        normalized_rows.append((row.pc - start, len(row.raw), raw.hex(), row.op, args))
    return normalized_rows, dependencies


def compare(old, new, old_path, new_path, role, start):
    old_start, old_end = OLD[role]
    require(old.fdes.get(old_start) == old_end, 'node94 FDE extent changed')
    require(start in new.fdes, 'node115 candidate is not an FDE start')
    end = new.fdes[start]
    a, an = k.native_pair(old_path, old.data, old.sections, old_start, old_end)
    b, bn = k.native_pair(new_path, new.data, new.sections, start, end)
    record = {'role': role, 'node94_fde': [hex(old_start), hex(old_end)],
              'node115_fde': [hex(start), hex(end)], 'node94_instructions': len(a),
              'node115_instructions': len(b), 'node94_bytes_sha256': sha(old.read(old_start, old_end-old_start)),
              'node115_bytes_sha256': sha(new.read(start, end-start))}
    try:
        require(end - start == old_end - old_start, 'FDE length differs')
        na, da = normalized(old, a, role, original=True)
        nb, db = normalized(new, b, role, original=False)
        require(na == nb, 'non-relocation instruction bytes/operands or table offsets differ')
        record.update(matched=True, node94_dependencies=da, node115_dependencies=db,
                      normalized_sha256=sha(json.dumps(na, sort_keys=True).encode()),
                      paired_instructions=len(a), paired_bytes=end-start)
    except k.bv.EvidenceError as error:
        record.update(matched=False, reason=str(error))
    return record, an, bn


def semantic_controls(old, new, old_path, new_path):
    """Mutate actual node115 bytes below the separate whole-image identity gate."""
    start = NEW['reader']
    rows, _ = k.native_pair(new_path, new.data, new.sections, start, new.fdes[start])
    literal = next(r for r in rows if r.raw == bytes.fromhex('be05000000'))
    table_row = next(r for r in rows if r.op == 'lea'
                     and any(a[0] == 'mem' and ('rip', 1) in a[2] for a in r.args))
    table = next(a[3] for a in k.canonical(table_row)[3] if a[0] == 'mem')
    call = next(r for r in rows if r.op == 'call')
    slot = next(a[3] for a in k.canonical(call)[3] if a[0] == 'mem')
    branch = next(r for r in rows if r.op in ('je', 'jne', 'ja', 'jae', 'jb', 'jbe')
                  and len(r.raw) == 2)
    rela = new.sections['.rela.dyn']
    entry = next(off for off in range(rela['offset'], rela['offset'] + rela['size'], 24)
                 if struct.unpack_from('<QQq', new.data, off) == (slot, 8, NEW['error']))
    table_off = k.bv.va_to_off(new.sections, table)
    table_bytes = new.read(table, 16)
    controls = [
        ('kind-literal', k.bv.va_to_off(new.sections, literal.pc) + 1, b'\x04'),
        ('table-order', table_off, table_bytes[4:8] + table_bytes[:4]),
        ('callee-relocation', entry + 16, struct.pack('<q', 0x58225c0)),
        ('table-RIP', k.bv.va_to_off(new.sections, table_row.pc) + len(table_row.raw) - 4,
         struct.pack('<i', 0x935c24 - table_row.pc - len(table_row.raw))),
        ('branch-byte', k.bv.va_to_off(new.sections, branch.pc) + 1,
         bytes([branch.raw[1] ^ 1])),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix='kind5-drift-controls-') as td:
        mutant_path = Path(td) / '115-mutant.elf'
        for name, off, changed in controls:
            mutated = bytearray(new.data)
            before = bytes(mutated[off:off + len(changed)])
            require(before != changed, 'ineffective corruption control')
            mutated[off:off + len(changed)] = changed
            require(sha(mutated) != PIN115, 'mutant passed the public identity gate')
            mutant_path.write_bytes(mutated)
            mutant_path.chmod(0o600)
            result, _, _ = compare(old, Image(mutated), old_path, mutant_path, 'reader', start)
            require(not result['matched'], 'semantic corruption was accepted: ' + name)
            results.append({'name': name, 'file_offset': hex(off), 'before': before.hex(),
                            'after': changed.hex(), 'sha256': sha(mutated),
                            'rejected': True, 'reason': result['reason'],
                            'global_identity_deliberately_bypassed': True})
    return results


def collect(paths, output, *, controls=False):
    require(not output.exists(), 'output exists; preserve it and choose a new directory')
    captures = [path.read_bytes() for path in paths]
    for data, digest, size in zip(captures, [k.bv.SHA256, PIN115], [91774280, 105896032]):
        require(len(data) == size and sha(data) == digest, 'wrong captured artifact identity')
    gnu, llvm = k.native_tools()
    require('LLVM' in subprocess.check_output([llvm, '--version'], text=True),
            'an identified LLVM decoder is required')
    old, new = map(Image, captures)
    output.mkdir(parents=True)
    records = []
    with tempfile.TemporaryDirectory(prefix='kind5-release-drift-') as td:
        snapshots = [Path(td) / (release + '.elf') for release in ['94', '115']]
        for path, data in zip(snapshots, captures):
            path.write_bytes(data)
            path.chmod(0o600)
        for role in OLD:
            for start in candidates(old, new, role):
                record, an, bn = compare(old, new, *snapshots, role, start)
                records.append(record)
                for release, native in [('94', an), ('115', bn)]:
                    for provider, text in zip(['gnu', 'llvm'], native):
                        (output / f'{role}-{start:x}-node{release}-{provider}.txt').write_text(text)
        for role, expected in EXPECTED.items():
            observed = {int(r['node115_fde'][0], 16) for r in records
                        if r['role'] == role and r['matched']}
            require(observed == expected, 'correspondence set changed: ' + role)
        corruptions = semantic_controls(old, new, *snapshots) if controls else []
    matched = [r for r in records if r['matched']]
    result = {'schema': 'hyperliquid.kind5-release-drift.v1',
              'node94_sha256': k.bv.SHA256, 'node115_sha256': PIN115,
              'discovery': 'all node115 text FDE starts with the selected node94 first24 bytes (14 for error)',
              'candidate_count': len(records), 'candidate_counts': dict(Counter(r['role'] for r in records)),
              'matched_count': len(matched), 'rejected_lookalikes': len(records)-len(matched),
              'paired_instructions': sum(r['paired_instructions'] for r in matched),
              'paired_bytes': sum(r['paired_bytes'] for r in matched),
              'comparisons': records, 'semantic_controls': corruptions,
              'captured_execution': False, 'node115_fixture_evaluation': False, 'gate_requested': False,
              'normalization': 'only resolved RIP rel32 fields; exact other machine bytes, local branch offsets, scalar constants and table destination offsets; RELATIVE targets checked per reference, including slot aliases',
              'limits': ['bounded static instruction/data correspondence, not target runtime equivalence',
                         'prefix census is not a census of all semantically equivalent implementations',
                         'node94 finite fixture results are not node115 measurements',
                         'no caller/source-type ownership, whole-node build or component gate']}
    (output / 'observations.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    versions = {'python': platform.python_version(), 'platform': platform.platform(),
                'gnu': subprocess.check_output([gnu, '--version'], text=True),
                'llvm': subprocess.check_output([llvm, '--version'], text=True)}
    (output / 'toolchain.json').write_text(json.dumps(versions, indent=2, sort_keys=True) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node94', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--node115', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    result = collect([args.node94, args.node115], args.output, controls=args.controls)
    print(json.dumps({name: result[name] for name in
                      ['candidate_count', 'matched_count', 'rejected_lookalikes',
                       'paired_instructions', 'paired_bytes', 'captured_execution']}))

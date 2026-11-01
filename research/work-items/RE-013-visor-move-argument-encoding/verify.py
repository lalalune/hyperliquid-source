#!/usr/bin/env python3
"""Check retained evidence, below-identity bindings and value certificates.

Native tools only disassemble an immutable copy. Mutant copies are never run.
No test establishes target behavior without the manual proof's premises.
"""
import argparse
import copy
import gzip
import json
from pathlib import Path
import struct
import tempfile
import collect as c
import algebra

def exports(data, directory, records):
    count = 0
    for group in ('ranges', 'context'):
        for name, row in records[group].items():
            a, b = int(row['start'], 16), int(row['end'], 16)
            c.require((a, b) == {**c.RANGES, **c.CONTEXT}[name], 'record extent')
            c.require(row['sha256'] == c.digest(c.read(data, a, b - a)), 'body digest')
            native = {}
            for provider, exp in row['exports'].items():
                stored = (directory / exp['file']).read_bytes()
                raw = gzip.decompress(stored) if provider == 'llvm' else stored
                c.require(c.digest(raw) == exp['raw_sha256'], 'export raw digest')
                c.require(c.digest(stored) == exp['stored_sha256'], 'export stored digest')
                native[provider] = c.native(data, raw.decode(), a, b)
                c.require(len(native[provider]) == row['rows'], 'export count')
            c.require([(v, raw) for v, raw, _ in native['gnu']] ==
                      [(v, raw) for v, raw, _ in native['llvm']], 'partition agreement')
            count += row['bytes']
    c.require(set(records['ranges']) == set(c.RANGES) and set(records['context']) == set(c.CONTEXT), 'complete scopes')
    return count

def run(regenerations):
    data = (c.ROOT / c.TARGET).read_bytes()
    c.require(len(data) == c.SIZE and c.digest(data) == c.SHA, 'target identity')
    observed = c.HERE / 'observed'
    records = json.loads((observed / 'records.json').read_text())
    c.require(records['target_sha256'] == c.SHA and records['target_bytes'] == c.SIZE, 'record identity')
    c.require(c.digest((c.HERE / 'pins.json').read_bytes()) == records['pins_sha256'], 'pins receipt')
    c.require(c.contract(data) == records['relocations'], 'retained relocations and import')
    c.require(c.fdes(data) == {k: r['unwind'] for k, r in records['ranges'].items()}, 'retained raw FDE/CIE')
    total = exports(data, observed, records)
    checks = []
    def reject(name, fn, category, coordinate=None):
        try:
            fn()
        except (ValueError, KeyError, IndexError, struct.error, UnicodeError) as e:
            checks.append({'name': name, 'category': category, 'rejected': str(e),
                           **({'coordinate': coordinate} if coordinate else {})})
        else:
            raise ValueError('control accepted:' + name)
    p = c.pins()
    # Bypass the whole-image SHA deliberately: these are actual operand/data
    # contracts, not mislabeled identity failures. They do not execute semantics.
    for group in ('instructions', 'data'):
        for name, row in p[group].items():
            va = int(row['va'], 16)
            delta = len(bytes.fromhex(row['hex'])) - 1 if group == 'instructions' else 0
            off = c.offset(data, va + delta)
            changed = bytearray(data)
            changed[off] ^= 1
            reject(group + ':' + name, lambda d=changed: c.contract(d),
                   'below-identity binding', {'va': hex(va + delta), 'file_offset': off})
    for row in records['relocations']:
        for label, delta in [('kind', 8), ('symbol', 12), ('addend', 16)]:
            changed = bytearray(data)
            off = row['file_offset'] + delta
            changed[off] ^= 1
            reject('RELA:' + row['slot'] + ':' + label, lambda d=changed: c.contract(d),
                   'below-identity relocation', {'file_offset': off})
    imp = next(r['import'] for r in records['relocations'] if 'import' in r)
    changed = bytearray(data)
    changed[imp['name_offset']] ^= 1
    reject('dynstr-memcpy', lambda: c.contract(changed), 'below-identity import')
    for name, row in records['ranges'].items():
        expected = row['unwind']
        for typ in ('fde', 'cie'):
            va = expected['record'][typ]
            # Last raw metadata byte: compare full records even if extent unchanged.
            off = c.offset(data, va) + len(bytes.fromhex(expected[typ + '_hex'])) - 1
            changed = bytearray(data)
            changed[off] ^= 1
            def metadata(d=changed):
                got = c.fdes(d)
                c.require(got == {k: r['unwind'] for k, r in records['ranges'].items()}, 'raw metadata changed')
            reject(typ + ':' + name, metadata, 'below-identity raw metadata', {'file_offset': off})
    a, b = c.RANGES['quote']
    original = (observed / 'quote.gnu.txt').read_text()
    lines = original.splitlines()
    instruction_line = next(i for i, line in enumerate(lines) if line.lstrip().startswith('651790:'))
    reject('native-row-removed', lambda: c.native(data, '\n'.join(lines[:instruction_line] + lines[instruction_line + 1:]), a, b), 'native partition')
    reject('native-byte-changed', lambda: c.native(data, original.replace('55 ', '54 ', 1), a, b), 'native bytes')
    stale = copy.deepcopy(records)
    stale['ranges']['quote']['rows'] -= 1
    reject('record-count-changed', lambda: exports(data, observed, stale), 'retained evidence')
    # Finite equations depend on extracted constants, not merely the pins SHA.
    for name in ['quote-raw-low', 'quote-raw-high', 'quote-not-double', 'quote-not-single', 'quote-double-escape-mask']:
        altered = copy.deepcopy(p)
        raw = bytearray.fromhex(altered['instructions'][name]['hex'])
        raw[2] ^= 1
        altered['instructions'][name]['hex'] = raw.hex()
        reject('algebra:' + name, lambda q=altered: algebra.certificate(q), 'value-level counterexample')
    altered = copy.deepcopy(p)
    raw = bytearray.fromhex(altered['data']['whitespace-table']['hex'])
    raw[0] ^= 2
    altered['data']['whitespace-table']['hex'] = raw.hex()
    reject('algebra:U2000-table-bit', lambda: algebra.certificate(altered), 'value-level counterexample')
    reject('grammar-NUL', lambda: algebra.segments(b'x\0y'), 'value-level domain')
    cert = algebra.certificate()
    regenerated = []
    fresh_mutants = []
    with tempfile.TemporaryDirectory(prefix='visor-move-check-') as tmp:
        root = Path(tmp)
        wrong = root / 'wrong.elf'
        changed = bytearray(data)
        changed[c.offset(data, 0x651775) + 2] ^= 1
        wrong.write_bytes(changed)
        reject('wrong-image', lambda: c.collect(wrong, root / 'wrong-out'), 'whole-image identity only')
        c.require(not (root / 'wrong-out').exists(), 'identity failure must not create output')
        reject('existing-output', lambda: c.collect(c.ROOT / c.TARGET, root), 'output safety')
        for label in ['move-zero-mode', 'collector-original-pointer', 'quote-nul-test', 'quote-raw-low', 'join-separator-store']:
            pin = p['instructions'][label]
            va = int(pin['va'], 16)
            delta = len(bytes.fromhex(pin['hex'])) - 1
            changed = bytearray(data)
            changed[c.offset(data, va + delta)] ^= 1
            image = root / (label + '.elf')
            image.write_bytes(changed)
            image.chmod(0o400)
            owner = next(k for k, (lo, hi) in c.RANGES.items() if lo <= va < hi)
            lo, hi = c.RANGES[owner]
            # Independent fresh decoding proves mutated bytes were presented;
            # the contract rejection remains a binding test, not execution.
            providers = []
            for provider, tool in [('gnu', c.GNU), ('llvm', c.LLVM)]:
                _, rows = c.decode(changed, image, tool, provider, lo, hi)
                row = next((raw, asm) for v, raw, asm in rows if v == va)
                c.require(row[0] != bytes.fromhex(pin['hex']), 'fresh mutant unchanged')
                providers.append({'provider': provider, 'instruction_hex': row[0].hex(), 'disassembly': row[1]})
            reject('fresh-native:' + label, lambda d=changed: c.contract(d), 'fresh native binding')
            fresh_mutants.append({'name': label, 'va': hex(va), 'file_offset': c.offset(data, va), 'decoders': providers})
        for i in range(regenerations):
            out = root / ('regeneration-' + str(i))
            result = c.collect(c.ROOT / c.TARGET, out)
            c.require(result == records, 'fresh records differ')
            expected = {q.name: c.digest(q.read_bytes()) for q in observed.iterdir()}
            actual = {q.name: c.digest(q.read_bytes()) for q in out.iterdir()}
            c.require(actual == expected, 'fresh exports differ')
            regenerated.append({'tree': i + 1, 'files': len(actual), 'identical': True})
    return {'target_sha256': c.SHA, 'full_fdes': len(c.RANGES), 'full_body_bytes': 4067,
            'full_body_rows': 1007, 'selected_context_bytes': total - 4067,
            'negative_controls': checks, 'negative_control_count': len(checks),
            'fresh_native_mutants': fresh_mutants, 'regenerations': regenerated,
            'algebra': cert, 'script_sha256': {f: c.digest((c.HERE / f).read_bytes()) for f in ['collect.py', 'verify.py', 'algebra.py', 'pins.json']},
            'limits': 'Static decoding/binding and mathematical checks. No target execution/emulation, original compiler/ABI inference, shell/argv or filesystem test; see PROOF.md premises.'}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--regenerations', type=int, choices=[0, 1, 2], default=2)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    c.require(not args.out.exists(), 'existing receipt refused')
    result = run(args.regenerations)
    args.out.write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
    print(json.dumps({'controls': result['negative_control_count'], 'regenerations': len(result['regenerations']), 'pass': True}))

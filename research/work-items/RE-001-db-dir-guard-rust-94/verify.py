#!/usr/bin/env python3
"""Authenticate retained static evidence and compare independently built Rust.

Only the new host-built library/harness run. Captured executables never run.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(PACKET))
import cases as spec
from elf_index import sections
from fde_extents import eh_frame_records

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SOURCE = ROOT / 'src' / spec.COMPONENT / 'lib.rs'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def dumped(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def bind(data, model):
    require(len(data) == 91774280 and sha(data) == SHA, 'wrong node94 capture')
    result = (getattr(model, 'build', None) or model.inspect)(data)
    result['vector_verifier'] = importlib.import_module('search_evidence').prove(data)
    image = importlib.import_module('evm_amount_scale').Image(data)
    cies, fdes = eh_frame_records(data, sections(data))
    owners = []
    for start in spec.OWNERS + [0x158ef30]:
        hits = [f for f in fdes if f['start'] == start]
        require(len(hits) == 1, 'missing or duplicate owner FDE')
        f = hits[0]
        require([x for x in fdes if x['start'] < f['end'] and start < x['end']] == hits,
                'overlapping owner FDE')
        owners.append({'fde': f, 'body_sha256': sha(image.read(start, f['end'] - start))})
    return {'target_sha256': SHA, 'source_tool_sha256': sha(Path(model.__file__).read_bytes()),
            'owners': owners, 'maintained_static_result': result,
            'captured_binaries_executed': False}


def listing_check(data, evidence):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    image = importlib.import_module('evm_amount_scale').Image(data)
    counts = []
    for owner in evidence['owners']:
        f = owner['fde']; start, end = f['start'], f['end']
        body = image.read(start, end - start)
        rows = [(i.address, bytes(i.bytes)) for i in Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, start)]
        require(b''.join(raw for _, raw in rows) == body, 'incomplete Capstone owner')
        cursor = start
        for address, raw in rows:
            require(address == cursor, 'noncontiguous Capstone owner'); cursor += len(raw)
        listing = (PACKET / f'{start:x}.llvm.txt').read_text()
        native = []
        lock_prefix = None
        for line in listing.splitlines():
            m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)', line)
            if m:
                address, raw = int(m[1], 16), bytes.fromhex(m[2])
                # LLVM renders LOCK as a separate line; Capstone attaches it.
                # Join only that contiguous display prefix. No bytes are masked.
                if raw == b'\xf0' and m[3].strip() == 'lock':
                    require(lock_prefix is None, 'consecutive standalone LOCK prefixes')
                    lock_prefix = address
                    continue
                if lock_prefix is not None:
                    require(address == lock_prefix + 1, 'noncontiguous LOCK instruction')
                    address, raw, lock_prefix = lock_prefix, b'\xf0' + raw, None
                native.append((address, raw))
        require(lock_prefix is None, 'unterminated LOCK prefix')
        require(native == rows, 'LLVM/Capstone bytes or instruction boundaries differ')
        counts.append({'start': hex(start), 'end_exclusive': hex(end),
                       'bytes': len(body), 'instructions': len(rows)})
    return counts


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepare', action='store_true')
    p.add_argument('--rustc', type=Path)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--controls', action='store_true')
    a = p.parse_args(); a.output.mkdir(parents=True, exist_ok=False)
    model = importlib.import_module(spec.MODEL)
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    evidence = bind(data, model)
    inputs, expected = spec.corpus(data, model)
    expected_text = '\n'.join(expected) + '\n'
    frozen = {'cases': len(expected), 'input_sha256': sha(inputs.encode()),
              'expected_sha256': sha(expected_text.encode()),
              'generator_sha256': sha((PACKET / 'cases.py').read_bytes())}
    (a.output / 'inputs.txt').write_text(inputs)
    (a.output / 'expected.txt').write_text(expected_text)
    if a.prepare:
        require(not SOURCE.exists(), 'freeze corpus before writing Rust implementation')
        (PACKET / 'evidence.json').write_text(dumped(evidence))
        (PACKET / 'corpus.json').write_text(dumped(frozen))
        print(dumped(frozen)); return
    require(evidence == json.loads((PACKET / 'evidence.json').read_text()), 'retained evidence differs')
    require(frozen == json.loads((PACKET / 'corpus.json').read_text()), 'frozen corpus differs')
    listings = listing_check(data, evidence)
    require(a.rustc is not None, 'explicit pinned compiler required')
    commands = []
    def run(command, **kwargs):
        command = list(map(str, command)); commands.append(command)
        r = subprocess.run(command, text=True, capture_output=True, **kwargs)
        (a.output / 'commands.json').write_text(dumped(commands))
        with (a.output / 'compiler-and-process.log').open('a') as log:
            log.write(dumped(command) + r.stderr)
        require(r.returncode == 0, 'command failed: ' + ' '.join(command) + '\n' + r.stderr)
        return r.stdout
    version = run([a.rustc, '--version', '--verbose'])
    require(version.startswith('rustc 1.94.1 '), 'expected rustc 1.94.1')
    def build(name, source, opt):
        directory = a.output / name; directory.mkdir()
        library = directory / 'libprojection.rlib'; runner = directory / 'compare'
        flags = ['--edition=2021', '-D', 'warnings', '-C', 'overflow-checks=on', '-C', f'opt-level={opt}']
        run([a.rustc, *flags, '--crate-name', 'projection', '--crate-type=rlib', source, '-o', library])
        run([a.rustc, *flags, PACKET / 'harness.rs', '--extern', f'projection={library}', '-o', runner])
        return library, runner
    comparisons, libraries = [], []
    for name, opt in [('debug', 0), ('optimized', 3), ('repeat', 3)]:
        library, runner = build(name, SOURCE, opt)
        actual = run([runner], input=inputs)
        (a.output / f'{name}.txt').write_text(actual)
        require(actual.splitlines() == expected, name + ' comparison mismatch')
        libraries.append(sha(library.read_bytes()))
        comparisons.append({'build': name, 'cases': len(expected), 'mismatches': 0,
                            'output_sha256': sha(actual.encode())})
    require(libraries[1] == libraries[2], 'own optimized library rebuild differs')
    unit = a.output / 'unit-tests'
    run([a.rustc, '--edition=2021', '--test', '-D', 'warnings', SOURCE, '-o', unit])
    (a.output / 'unit-tests.txt').write_text(run([unit]))
    controls = []
    if a.controls:
        source = SOURCE.read_text()
        for name, (old, new) in spec.MUTANTS.items():
            require(source.count(old) == 1, 'ambiguous mutation ' + name)
            mutated = a.output / (name + '.rs'); mutated.write_text(source.replace(old, new))
            _, runner = build(name, mutated, 3)
            actual = run([runner], input=inputs)
            (a.output / f'{name}.txt').write_text(actual)
            rows = actual.splitlines()
            require(len(rows) == len(expected), 'mutant did not complete normal protocol')
            mismatches = sum(x != y for x, y in zip(rows, expected))
            require(mismatches > 0, 'undetected mutation ' + name)
            controls.append({'name': name, 'mismatches': mismatches})
    result = {'rustc': version.splitlines(), 'corpus': frozen, 'listing_coverage': listings,
              'source_sha256': sha(SOURCE.read_bytes()),
              'harness_sha256': sha((PACKET / 'harness.rs').read_bytes()),
              'verifier_sha256': sha(Path(__file__).read_bytes()),
              'comparisons': comparisons, 'own_rlib_sha256': libraries,
              'controls': controls, 'captured_binaries_executed': False,
              'limits': 'Conditional static-derived projection, not target execution, original ABI or code identity.'}
    (a.output / 'results.json').write_text(dumped(result))
    print(dumped(result))


if __name__ == '__main__':
    main()

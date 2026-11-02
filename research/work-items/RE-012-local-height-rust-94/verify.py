#!/usr/bin/env python3
"""Bind existing node94 height evidence, build independent Rust, compare scalars.

Never launches captured code. No network, original node ABI, or binary-identity
comparison. The expected stream is computed outside the Rust process.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import random
import re
import subprocess
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import local_abci_gates_static as target
from elf_index import sections
from fde_extents import eh_frame_records

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODY = 'cc7958c8348146f55ce6e1be694987407e96b2142a737b136f03b87fea817b94'
BEGIN, END = 0x22689f0, 0x226b503
MAX = (1 << 64) - 1
SOURCE = ROOT / 'src/node94-local-height/lib.rs'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bind(data):
    require(len(data) == 91774280 and digest(data) == SHA, 'node94 identity mismatch')
    img = target.Image(data)
    require(digest(img.read(BEGIN, END - BEGIN)) == BODY, 'owner body differs')
    # Reuse the existing maintained byte locks and data/branch checks, rather
    # than adding an independent ELF parser or pretending to recover new facts.
    target.windows(img)
    selection = target.check_selection(img)
    status = target.check_status_log(img)
    gate = target.check_gate(img)
    _, fdes = eh_frame_records(data, sections(data))
    overlapping = [f for f in fdes if f['start'] < END and BEGIN < f['end']]
    require(len(overlapping) == 1 and overlapping[0]['start'] == BEGIN and
            overlapping[0]['end'] == END, 'owner FDE differs or overlaps')
    return {'target_sha256': SHA, 'owner_body_sha256': BODY,
            'owner_start': hex(BEGIN), 'owner_end_exclusive': hex(END),
            'fde': overlapping[0], 'selection': selection, 'status': status,
            'gate': gate, 'captured_binaries_executed': False}


def check_listings(data):
    img = target.Image(data)
    counts = {}
    for name, begin, end in [('selection', 0x226a53f, 0x226a6b8),
                             ('status-and-gate', 0x226a974, 0x226ab88)]:
        decoded = []
        for suffix in ('capstone', 'llvm'):
            rows, cursor = [], begin
            for line in (PACKET / f'{name}.{suffix}.txt').read_text().splitlines():
                if suffix == 'capstone':
                    match = re.match(r'^([0-9a-f]+): ([0-9a-f]+) ', line)
                else:
                    match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)', line)
                if not match:
                    continue
                address, raw = int(match[1], 16), bytes.fromhex(match[2])
                require(address == cursor and raw and address + len(raw) <= end,
                        'listing coverage differs')
                require(img.read(address, len(raw)) == raw, 'listing bytes differ')
                rows.append((address, raw))
                cursor += len(raw)
            require(cursor == end, 'incomplete listing')
            decoded.append(rows)
        require(decoded[0] == decoded[1], 'decoder instruction boundaries differ')
        counts[name] = {'bytes': end - begin, 'instructions': len(decoded[0])}
    return counts


def cases():
    """Independent order/arbitrary-precision oracle plus established models."""
    inputs, expected = [], []

    def selection(count, values):
        result = max(values) if len(values) > 1 or (len(values) == 1 and count == 1) else None
        require(result == target.select_heights(values, count), 'selection oracles disagree')
        inputs.append('S ' + str(count) + ''.join(f' {a} {b}' for a, b in values))
        expected.append('N' if result is None else f'S {result[0]} {result[1]}')

    def gate(local, initial, latest):
        # Derive the two target add arms using their carry and unsigned min,
        # then check against a separate unbounded-integer formulation.
        wrapped = (local + 20000) & MAX
        carry = local + 20000 > MAX
        bound = MAX if carry else wrapped
        code = 1 if bound <= latest else 2 if local < initial else 0
        oracle = 1 if min(local + 20000, MAX) <= latest else 2 if local < initial else 0
        require(code == oracle and (code == 1) == target.too_far_behind(local, latest),
                'gate oracles disagree')
        inputs.append(f'G {local} {initial} {latest}')
        expected.append(f'G {code}')

    points = [0, 1, 19999, 20000, 20001, (1 << 63) - 1, 1 << 63,
              MAX - 20001, MAX - 20000, MAX - 19999, MAX - 1, MAX]
    pairs = list(itertools.product(points, repeat=2))
    for count in (0, 1, 2, MAX):
        selection(count, [])
        for pair in pairs:
            selection(count, [pair])
    for a, b in itertools.product(pairs, repeat=2):
        selection(2, [a, b])
    for local, initial, latest in itertools.product(points, repeat=3):
        gate(local, initial, latest)
    # Exact adjacent decision boundaries, including the saturation crossover.
    for local in points:
        bound = min(local + 20000, MAX)
        for latest in {max(0, bound - 1), bound, min(MAX, bound + 1)}:
            for initial in {max(0, local - 1), local, min(MAX, local + 1)}:
                gate(local, initial, latest)
    rng = random.Random(0x226A53F)
    for _ in range(1000):
        selection(rng.randrange(1, 10), [tuple(rng.getrandbits(64) for _ in range(2))
                                       for _ in range(rng.randrange(10))])
        gate(*(rng.getrandbits(64) for _ in range(3)))
    return '\n'.join(inputs) + '\n', expected


def run(command, **kwargs):
    return subprocess.run([str(x) for x in command], check=True, text=True,
                          capture_output=True, **kwargs).stdout


def build(rustc, source, out, optimization):
    out.mkdir()
    library = out / 'libnode94_local_height.rlib'
    flags = ['--edition=2021', '-D', 'warnings', '-C', 'overflow-checks=on',
             '-C', f'opt-level={optimization}']
    run([rustc, *flags, '--crate-name', 'node94_local_height', '--crate-type=rlib',
         source, '-o', library])
    binary = out / 'compare'
    run([rustc, *flags, PACKET / 'harness.rs', '--extern',
         f'node94_local_height={library}', '-o', binary])
    return library, binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = bind((ROOT / 'artifacts/node/94/hl-node').read_bytes())
    retained = json.loads((PACKET / 'evidence.json').read_text())
    require(evidence == retained, 'retained evidence differs')
    listings = check_listings((ROOT / 'artifacts/node/94/hl-node').read_bytes())
    version = run([args.rustc, '--version', '--verbose'])
    require(version.startswith('rustc 1.94.1 '), 'use pinned research compiler 1.94.1')
    inputs, expected = cases()
    (args.output / 'inputs.txt').write_text(inputs)
    (args.output / 'expected.txt').write_text('\n'.join(expected) + '\n')
    comparisons, libraries = [], []
    for name, opt in [('debug', 0), ('release', 3), ('repeat', 3)]:
        library, binary = build(args.rustc, SOURCE, args.output / name, opt)
        actual = run([binary], input=inputs)
        require(actual.splitlines() == expected, name + ' Rust mismatch')
        (args.output / f'{name}.txt').write_text(actual)
        comparisons.append({'build': name, 'cases': len(expected), 'mismatches': 0,
                            'output_sha256': digest(actual.encode())})
        libraries.append(digest(library.read_bytes()))
    require(libraries[1] == libraries[2], 'own optimized library rebuild differs')
    unit = args.output / 'unit-tests'
    run([args.rustc, '--edition=2021', '--test', '-D', 'warnings', '-C',
         'overflow-checks=on', SOURCE, '-o', unit])
    unit_output = run([unit])
    (args.output / 'unit-tests.txt').write_text(unit_output)
    controls = []
    if args.controls:
        source = SOURCE.read_text()
        mutants = {
            'single_reply_without_single_peer': ('queried_peer_count != 1', 'queried_peer_count == 1'),
            'lexicographic_minimum': ('candidate >= selected', 'candidate <= selected'),
            'wrong_second_field': ('selected = candidate;', 'selected.initial = candidate.initial;'),
            'coordinatewise_maximum': ('selected = candidate;',
                'selected = Heights { initial: core::cmp::max(selected.initial, candidate.initial), '
                'latest: core::cmp::max(selected.latest, candidate.latest) };'),
            'wrapping_addition': ('local.saturating_add(20_000)', 'local.wrapping_add(20_000)'),
            'exclusive_latest_boundary': ('<= peer.latest', '< peer.latest'),
            'inclusive_hardfork_boundary': ('local < peer.initial', 'local <= peer.initial'),
            'wrong_lag_constant': ('saturating_add(20_000)', 'saturating_add(200)'),
        }
        for name, (old, new) in mutants.items():
            require(source.count(old) == 1, 'ambiguous mutant ' + name)
            mutated = args.output / f'{name}.rs'
            mutated.write_text(source.replace(old, new))
            _, binary = build(args.rustc, mutated, args.output / name, 3)
            actual = run([binary], input=inputs).splitlines()
            require(len(actual) == len(expected), 'mutant output length differs')
            mismatches = sum(a != b for a, b in zip(actual, expected))
            require(mismatches > 0, 'undetected mutant ' + name)
            controls.append({'mutant': name, 'mismatches': mismatches})
    result = {'rustc': version.splitlines(), 'source_sha256': digest(SOURCE.read_bytes()),
              'input_sha256': digest(inputs.encode()),
              'expected_sha256': digest(('\n'.join(expected) + '\n').encode()),
              'listing_coverage': listings,
              'comparisons': comparisons, 'own_rlib_sha256': libraries,
              'controls': controls, 'captured_binaries_executed': False,
              'limits': 'Static-derived scalar comparison, not original execution or binary equivalence.'}
    (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

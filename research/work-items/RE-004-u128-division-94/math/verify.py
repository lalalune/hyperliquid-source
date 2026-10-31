#!/usr/bin/env python3
"""Check quotient arithmetic queries and finite decoder/translation bindings.

This does not formalize x86 semantics or independently check a solver proof object.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
PACKET = HERE.parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import u128_division as u

QUERIES = (
    'normalization', 'normalized-div-safe', 'floor-composition', 'estimate-error',
    'estimate-not-below', 'estimate-at-most-one-above', 'wide-product-safe', 'limb-division',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--z3', default=shutil.which('z3'))
    args = parser.parse_args()
    require(args.z3, 'an existing Z3 executable is required')
    gnu = shutil.which('gobjdump') or shutil.which('objdump')
    llvm = os.environ.get('LLVM_OBJDUMP') or shutil.which('llvm-objdump')
    require(gnu and llvm, 'existing GNU and LLVM decoders are required')
    versions = {name: subprocess.check_output([tool, flag], text=True)
                for name, tool, flag in [('z3', args.z3, '-version'),
                                         ('gnu', gnu, '--version'), ('llvm', llvm, '--version')]}
    require(versions['z3'].startswith('Z3 version ') and 'GNU objdump' in versions['gnu']
            and 'LLVM' in versions['llvm'], 'identified Z3, GNU and LLVM tools required')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sources = [ROOT / 'tools/u128_division.py', ROOT / 'tools/spot_wei_scale.py',
               Path(__file__).resolve(), HERE / 'PROOF.md', PACKET / 'evidence.json',
               PACKET / 'helper.gnu-objdump.txt', PACKET / 'helper.llvm-objdump.txt']
    sources += [HERE / (name + '.smt2') for name in QUERIES]
    inputs = {p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in sources}
    query_texts = {name: (HERE / (name + '.smt2')).read_text() for name in QUERIES}
    results = []

    def solve(name, text, expected):
        path = output / (name + '.smt2')
        path.write_text(text)
        completed = subprocess.run([args.z3, '-smt2', str(path)], capture_output=True,
                                   text=True, timeout=15)
        (output / (name + '.txt')).write_text(completed.stdout + completed.stderr)
        require(completed.returncode == 0 and not completed.stderr
                and completed.stdout.strip() == expected,
                f'{name}: expected {expected}, got {completed.stdout!r} / {completed.stderr!r}')
        results.append({'name': name, 'result': expected, 'query_sha256': sha(text.encode())})

    for name, text in query_texts.items():
        require(text.count('(check-sat)') == 1, 'one query expected per file')
        solve(name, text, 'unsat')
        lines = text.splitlines()
        last_assertion = max(i for i, line in enumerate(lines) if line.startswith('(assert '))
        require(lines[-2].startswith('(assert '), 'negated conclusion must be the final assertion')
        assumptions = '\n'.join(lines[:last_assertion] + ['(check-sat)']) + '\n'
        solve(name + '-assumptions', assumptions, 'sat')

    core = query_texts['estimate-error']
    controls = {
        'numerator-range': '(assert (< n (* m m)))',
        'denominator-normalization': '(assert (>= t (* m h)))',
        'truncation-remainder': '(assert (<= delta (- (* 2 h) 1)))',
    }
    for name, assertion in controls.items():
        require(core.count(assertion) == 1, 'mathematical control anchor changed')
        solve('weaken-' + name, core.replace(assertion, '', 1), 'sat')

    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    u.check_digest(data)
    image = u.Image(data)
    extent = u.Fdes(image).range_of(u.ENTRY)
    require((extent['start'], extent['end']) == (u.ENTRY, u.END), 'helper FDE changed')
    require(image.relative_relocs()[u.SLOT] == u.ENTRY, 'helper slot binding changed')
    expected = json.loads((PACKET / 'evidence.json').read_text())
    require(sha(image.read(u.ENTRY, u.END - u.ENTRY)) == expected['raw_window_sha256'],
            'helper bytes differ from original evidence')
    decoded = []
    listing_hashes = {}
    with tempfile.TemporaryDirectory(prefix='node94-division-proof-') as directory:
        snapshot = Path(directory) / 'node94.elf'
        with snapshot.open('xb') as stream:
            stream.write(data)
        snapshot.chmod(0o400)
        for name, tool in [('gnu', gnu), ('llvm', llvm)]:
            listing = u.disassemble(snapshot, tool)
            decoded.append(u.decode(listing, image))
            retained_listing = listing.replace(str(snapshot), 'node94.elf')
            (output / (name + '.txt')).write_text(retained_listing)
            listing_hashes[name] = sha(retained_listing.encode())
        require(sha(snapshot.read_bytes()) == u.SHA256, 'owned snapshot changed')
    require(decoded[0] == decoded[1] and len(decoded[0]) == 71, 'native helper decodes disagree')

    # Finite checks of the manual translation; these are not the universal proof.
    m = 1 << 64
    counts = Counter()
    witnesses = []
    machine = u.Machine(decoded[0])
    for k in range(64):
        h = 1 << k
        for dh in sorted({h, 2 * h - 1}):
            for dl in (0, 1, m - 1):
                d = dh * m + dl
                for n in sorted({0, 1, d - 1, d, d + 1, m * m - 1, m * m - m}):
                    if not 0 <= n < m * m:
                        continue
                    a = d >> (k + 1)
                    t = a * (2 * h)
                    e, q = n // t, n // d
                    q0 = max(e - 1, 0)
                    observed, pc = machine.run(n, d)
                    native_q0, known = machine.get('r10')
                    require(observed == q and pc == 0x565f61d
                            and known == u.MASK and native_q0 == q0
                            and e in (q, q + 1) and q - q0 in (0, 1),
                            'finite decoder/normalization translation mismatch')
                    counts['estimate_excess_' + str(e - q)] += 1
                    counts['final_increment_' + str(q - q0)] += 1
                    counts['clamped_estimates'] += e == 0
                    witnesses.append({'k': k, 'n': hex(n), 'd': hex(d), 'estimate': hex(e),
                                      'decremented': hex(q0), 'quotient': hex(q)})
    require(all(counts[key] for key in ['estimate_excess_0', 'estimate_excess_1',
                                      'final_increment_0', 'final_increment_1', 'clamped_estimates']),
            'translation witnesses missed a required boundary')
    require(all(sha((ROOT / name).read_bytes()) == digest for name, digest in inputs.items()),
            'proof source changed during verification')
    (output / 'translation-witnesses.json').write_text(json.dumps(witnesses, indent=2) + '\n')
    report = {'target_sha256': u.SHA256, 'helper_sha256': expected['raw_window_sha256'],
              'native_instructions': 71, 'arithmetic_queries_unsat': 8,
              'assumption_queries_sat': 8, 'weakened_hypothesis_queries_sat': 3,
              'solver_results': results, 'translation_cases': len(witnesses),
              'translation_counts': dict(counts), 'inputs': inputs, 'versions': versions,
              'decoder_listing_sha256': listing_hashes,
              'tool_executable_sha256': {
                  name: sha(Path(tool).resolve().read_bytes())
                  for name, tool in [('z3', args.z3), ('gnu', gnu), ('llvm', llvm)]},
              'captured_execution': False, 'gate_requested': False,
              'formal_isa_verification': False, 'independent_proof_object_check': False,
              'limit': 'Polynomial arithmetic lemmas; the documented ISA translation remains a manual review obligation.'}
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['arithmetic_queries_unsat',
                     'assumption_queries_sat', 'weakened_hypothesis_queries_sat', 'translation_cases',
                     'formal_isa_verification', 'captured_execution']}))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Prove the admitted limb recurrence's bounded field identity with Z3.

Optional research dependency: z3-solver==4.15.4.0. No target execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

import z3
from collect import B, C, P, ROOT, TARGET_SHA, MANIFEST_SHA, admit_target, public_inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        raise ValueError('Output already exists')
    if z3.get_version_string() != '4.15.4':
        raise ValueError('Expected the pinned Z3 4.15.4 research solver')
    public_inputs()
    binary = args.binary.read_bytes()
    admit_target(binary)
    a = [z3.BitVec('a' + str(i), 64) for i in range(5)]
    high = z3.LShR(a[4], 48)
    current = a[0] + high * C
    out = [current & (B - 1)]
    for limb in a[1:4]:
        current = limb + z3.LShR(current, 52)
        out.append(current & (B - 1))
    out.append((a[4] & ((1 << 48) - 1)) + z3.LShR(current, 52))

    def integer_image(words):
        # All possible five-u64 representations are below 2^273. Thus these
        # 320-bit sums are exact integer embeddings, with no hidden wrap.
        return sum(z3.ZeroExt(256, word) << (52 * i) for i, word in enumerate(words))

    difference = integer_image(out) != integer_image(a) - z3.ZeroExt(256, high) * P
    bounds = [z3.ULE(x, 64 * (B - 1)) for x in a[:4]]
    bounds.append(z3.ULE(a[4], 64 * ((1 << 48) - 1)))
    solver = z3.Solver(); solver.set(timeout=30000)
    solver.add(*bounds)
    solver.add(z3.Or(difference, z3.UGE(out[4], 1 << 49),
                     *[z3.UGE(x, B) for x in out[:4]]))
    result = str(solver.check())
    if result != 'unsat':
        raise ValueError('Bounded identity/bounds proof did not succeed: ' + result)
    # Removing the source's magnitude premises must expose a counterexample.
    control = z3.Solver(); control.set(timeout=30000)
    control.add(difference)
    status = str(control.check())
    if status != 'sat':
        raise ValueError('Out-of-contract control did not produce SAT: ' + status)
    model = control.model()
    witness = [model.eval(x, model_completion=True).as_long() for x in a]
    native = [model.eval(x, model_completion=True).as_long() for x in out]
    numeric = lambda words: sum(x << (52 * i) for i, x in enumerate(words))
    if numeric(native) == numeric(witness) - (witness[4] >> 48) * P:
        raise ValueError('SAT model does not reproduce as an integer counterexample')
    record = {'solver': z3.get_version_string(), 'target_sha256': TARGET_SHA,
              'source_manifest_sha256': MANIFEST_SHA,
              'proof_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'bounded_field_identity_and_output_bounds': result,
              'domain': {'lower_bound': 0, 'first_four_upper_bound': 64 * (B - 1),
                         'high_upper_bound': 64 * ((1 << 48) - 1)},
              'unbounded_identity_control': status,
              'counterexample_inputs': witness, 'counterexample_native_outputs': native,
              'captured_code_executed': False,
              'limit': 'Proof of admitted equations and stated source-domain assumptions; caller invariants and compiler correctness are not independently proved.'}
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'bounded': result, 'removed_bounds_control': status}))


if __name__ == '__main__':
    main()

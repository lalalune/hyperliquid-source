#!/usr/bin/env python3
"""Prove the admitted node115 recurrence's canonical field result, statically.

Optional research dependency: z3-solver==4.15.4.0. No target/object execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

import z3
from collect import B, C, P, MASK48, MASK64, ROOT, TARGET_SHA, SOURCE_SHA, admit_target, public_source


def require(ok, message):
    if not ok:
        raise ValueError(message)


def native(words, threshold_delta=0):
    """The admitted branchless integer projection, as 64-bit equations."""
    current = words[0] + z3.LShR(words[4], 48) * C
    weak = [current & (B - 1)]
    for limb in words[1:4]:
        current = limb + z3.LShR(current, 52)
        weak.append(current & (B - 1))
    weak.append((words[4] & MASK48) + z3.LShR(current, 52))
    threshold = z3.And(weak[4] == MASK48, weak[1] & weak[2] & weak[3] == B - 1,
                       z3.UGE(weak[0], B - C + threshold_delta))
    reduction = z3.LShR(weak[4], 48) | z3.If(threshold, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
    current = weak[0] + (-reduction & C)
    out = [current & (B - 1)]
    for limb in weak[1:4]:
        current = limb + z3.LShR(current, 52)
        out.append(current & (B - 1))
    out.append((weak[4] + z3.LShR(current, 52)) & MASK48)
    return out, reduction


def integer_image(words):
    # Five u64 limbs encode less than 2^273; 320 bits suffice for exact
    # integer embeddings and every signed identity difference used here.
    return sum(z3.ZeroExt(256, word) << (52 * i) for i, word in enumerate(words))


def number(words):
    return sum(word << (52 * i) for i, word in enumerate(words))


def concrete(words, threshold_delta=0):
    current = (words[0] + (words[4] >> 48) * C) & MASK64
    weak = [current & (B - 1)]
    for limb in words[1:4]:
        current = (limb + (current >> 52)) & MASK64
        weak.append(current & (B - 1))
    weak.append((words[4] & MASK48) + (current >> 52))
    reduction = (weak[4] >> 48) | int(weak[4] == MASK48 and
        weak[1] & weak[2] & weak[3] == B - 1 and weak[0] >= B - C + threshold_delta)
    current = (weak[0] + (-reduction & C)) & MASK64
    out = [current & (B - 1)]
    for limb in weak[1:4]:
        current = (limb + (current >> 52)) & MASK64
        out.append(current & (B - 1))
    out.append((weak[4] + (current >> 52)) & MASK48)
    return out, reduction


def check_solver(solver, expected, label):
    solver.set(timeout=30000)
    status = str(solver.check())
    require(status == expected, label + ': expected ' + expected + ', got ' + status)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not os.path.lexists(args.output), 'Output exists')
    corners_path = args.output.with_suffix('.corners.tsv')
    require(not os.path.lexists(corners_path), 'Corner output exists')
    require(z3.get_version_string() == '4.15.4', 'Expected Z3 4.15.4')
    public_source(); admit_target(args.binary.read_bytes())
    words = [z3.BitVec('a' + str(i), 64) for i in range(5)]
    out, reduction = native(words)
    quotient = z3.ZeroExt(256, z3.LShR(words[4], 48)) + z3.ZeroExt(256, reduction)
    difference = integer_image(out) != integer_image(words) - quotient * P
    noncanonical = z3.UGE(integer_image(out), z3.BitVecVal(P, 320))
    bounds = [z3.ULE(word, 64 * (B - 1)) for word in words[:4]]
    bounds.append(z3.ULE(words[4], 64 * MASK48))
    solver = z3.Solver(); solver.add(*bounds, z3.Or(difference, noncanonical))
    bounded = check_solver(solver, 'unsat', 'Bounded canonical theorem')
    range_solver = z3.Solver(); range_solver.add(noncanonical)
    range_status = check_solver(range_solver, 'unsat', 'Unbounded canonical output range')
    # This bit-mask multiplication rewrite is valid even without magnitude
    # assumptions; its arithmetic inputs already force reduction to 0 or 1.
    bool_solver = z3.Solver(); bool_solver.add(z3.UGT(reduction, 1))
    bool_status = check_solver(bool_solver, 'unsat', 'Unbounded selector range')
    control = z3.Solver(); control.add(difference)
    control_status = check_solver(control, 'sat', 'Removed magnitude bounds')
    witness = [control.model().eval(x, model_completion=True).as_long() for x in words]
    witness_out, witness_reduction = concrete(witness)
    require(witness_out == [control.model().eval(x, model_completion=True).as_long() for x in out],
            'Concrete recurrence does not replay solver model')
    require(number(witness_out) % P != number(witness) % P, 'Off-domain witness is not modularly different')
    # Advancing the unsigned threshold by one loses reduction at exactly p.
    mutant, _ = native(words, threshold_delta=1)
    prime = [(P >> (52 * i)) & (B - 1) for i in range(5)]
    mutation = z3.Solver(); mutation.add(*[word == value for word, value in zip(words, prime)])
    mutation.add(z3.UGE(integer_image(mutant), z3.BitVecVal(P, 320)))
    mutation_status = check_solver(mutation, 'sat', 'Threshold mutation at p')
    require(concrete(prime)[0] == [0] * 5 and concrete(prime, 1)[0] == prime,
            'Threshold counterexample replay differs')
    finite = []
    for magnitude in (0, 1, 2, 16, 32):
        limits = [2 * magnitude * (B - 1)] * 4 + [2 * magnitude * MASK48]
        for bits in range(32):
            vector = [limit if bits & (1 << i) else 0 for i, limit in enumerate(limits)]
            result, x = concrete(vector)
            require(number(result) == number(vector) % P, 'Corner control is not canonical')
            finite.append([len(finite), magnitude, *vector, *result, x])
    boundaries = []
    for value in (0, 1, P - 1, P, P + 1, 2 * P - 1, 2 * P, (1 << 256) - 1, 1 << 256):
        vector = [(value >> (52 * i)) & (B - 1) for i in range(4)] + [value >> 208]
        result, x = concrete(vector)
        require(number(result) == value % P, 'Boundary control is not canonical')
        boundaries.append({'integer': value, 'input': vector, 'output': result, 'final_selector': x})
    corner_header = ['case', 'magnitude', *['a' + str(i) for i in range(5)],
                     *['o' + str(i) for i in range(5)], 'final_selector']
    corners = ('\t'.join(corner_header) + '\n' +
               ''.join('\t'.join(map(str, row)) + '\n' for row in finite)).encode()
    record = {'target_sha256': TARGET_SHA, 'source_manifest_sha256': SOURCE_SHA,
              'proof_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'solver': z3.get_version_string(), 'timeout_ms_each': 30000,
              'bounded_canonical_range_and_identity': bounded, 'unbounded_selector_is_boolean': bool_status,
              'unbounded_canonical_output_range': range_status,
              'domain': {'first_four_upper_bound': 64 * (B - 1), 'high_upper_bound': 64 * MASK48, 'lower_bound': 0},
              'removed_bounds_control': control_status,
              'off_domain_witness': {'input': witness, 'output': witness_out, 'final_selector': witness_reduction,
                                     'input_mod_p': number(witness) % P, 'output_mod_p': number(witness_out) % P},
              'threshold_plus_one_control': mutation_status,
              'threshold_witness': {'input': prime, 'correct_output': [0] * 5, 'mutated_output': prime},
              'corner_controls': {'format': 'TSV with header, adjacent .corners.tsv file',
                                  'cases': len(finite),
                                  'unique_inputs': len({tuple(row[2:7]) for row in finite}),
                                  'sha256': hashlib.sha256(corners).hexdigest()},
              'boundary_cases': boundaries,
              'captured_or_compiled_code_executed': False,
              'limits': 'Theorem of the admitted numeric equations. Not a formal ISA decoder/compiler proof, caller invariant proof or target execution result.'}
    corners_path.write_bytes(corners)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'canonical_theorem': bounded, 'selector_range': bool_status,
                      'all_u64_output_range': range_status,
                      'removed_bounds': control_status, 'threshold_control': mutation_status,
                      'corner_cases': len(finite), 'boundary_cases': len(boundaries)}))


if __name__ == '__main__':
    main()

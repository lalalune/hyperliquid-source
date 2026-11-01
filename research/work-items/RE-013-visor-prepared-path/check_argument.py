#!/usr/bin/env python3
"""Bind the manual argument and check its abstract truth table; no CPU evaluator."""
import argparse
import copy
import itertools
import json
from pathlib import Path
from survey import DATA, Image, InvalidEvidence, format_events, json_bytes, require, sha

# Exact bytes cited by PROOF.md. This check does not interpret instructions.
ANCHORS = {
    0x39a750: '4889f0488b7708488b57104889c7ff25eca44400',
    0x32cf10: '4889f0488b37488b57084889c7ff252d7d4b00',
    0x3a1823: 'ff15f7334400',
    0x3a18cf: '84c00f8554010000',
    0x3a18f5: '4885c00f842d010000',
    0x3a190e: '488d44245048894424704c89642478',
    0x3a1933: 'ff15e7324400',
    0x3a19d2: '84c0757b',
    0x3a19f4: '4885c07458',
    0x3a1a2b: '488b442460488943100f284424500f1103',
    0x3a1a51: '4c89234c897b084c897310',
    0x3a1a7f: '488b6c24104c8b6c2418e92effffff',
    0x3a0d9e: '84c07523',
    0x3a0dc0: '4885c0750a',
    0x3a0dc5: '31c0',
    0x3d8e1e: '4989c74885c0744f',
}


def bind(image):
    for address, expected in ANCHORS.items():
        raw = bytes.fromhex(expected)
        require(image.at(address, len(raw)) == raw,
                'Manual-proof anchor differs: ' + hex(address))
    for label, (address, expected) in DATA.items():
        require(image.at(address, len(expected)) == expected,
                'Manual-proof data differs: ' + label)
    image.relocations()


def requests(events, args):
    # Data-record substitution only. No target callback or target code is run.
    return b''.join(bytes.fromhex(e['bytes']) if e['kind'] == 'literal'
                    else args[e['index']] for e in events)


def selected(a, u_zero, b, v_zero):
    """Abstract normal-return choice from the addressed manual argument."""
    if a or u_zero:
        return 'P'
    if b or v_zero:
        return 'Q'
    return 'P'


def run(binary):
    image = Image(binary.read_bytes())
    bind(image)
    primary = format_events(image.at(DATA['primary-format-window'][0], 8), 3)
    fallback = format_events(image.at(DATA['fallback-format-window'][0], 8), 1)
    require([e['index'] for e in primary if e['kind'] == 'argument'] == [0, 1, 2],
            'Primary request order differs')
    require([e['index'] for e in fallback if e['kind'] == 'argument'] == [0],
            'Fallback request differs')
    fixtures = [
        (b'root', b'shell_rs_out/x', b'root/tmp/shell_rs_out/x',
         b'/tmp/root/tmp/shell_rs_out/x'),
        (b'', b'\x00', b'/tmp/\x00', b'/tmp//tmp/\x00'),
        (b'base/', b'', b'base//tmp/', b'/tmp/base//tmp/'),
    ]
    for g, x, expected_p, expected_q in fixtures:
        p = requests(primary, [g, b'tmp', x])
        q = requests(fallback, [p])
        require((p, q) == (expected_p, expected_q), 'Byte-construction fixture differs')
    inputs = list(itertools.product((False, True), repeat=4))
    # Explicit table in order (a,u_zero,b,v_zero); don't-cares retained.
    expected = list('PQQQPPPPPPPPPPPP')
    results = [selected(*row) for row in inputs]
    require(results == expected, 'Abstract choice differs from manual truth table')
    formula = ['Q' if not a and not u and (b or v) else 'P'
               for a, u, b, v in inputs]
    require(formula == expected, 'Independent boolean formula differs')
    mutants = {
        'always-use-fallback-after-first-failure':
            lambda a, u, b, v: 'Q' if not a and not u else 'P',
        'ignore-first-attempt': lambda a, u, b, v: 'Q' if b or v else 'P',
        'invert-second-preparation-zero-test':
            lambda a, u, b, v: 'Q' if not a and not u and (b or not v) else 'P',
    }
    witnesses = {}
    for name, mutant in mutants.items():
        bad = [i for i, row in enumerate(inputs) if mutant(*row) != expected[i]]
        require(bad, 'Abstract mutant survived table: ' + name)
        i = bad[0]
        witnesses[name] = {'input': list(inputs[i]), 'expected': expected[i],
                           'mutant': mutant(*inputs[i])}
    guards = []
    for name, address in [
        ('first-predicate-branch', 0x3a18d1),
        ('second-preparation-branch', 0x3a19f7),
        ('primary-output-copy', 0x3a1a2b),
        ('fallback-record-source', 0x3a1912),
        ('slice-callback', 0x32cf10),
        ('primary-stream', 0x65d22),
        ('fallback-stream', 0x62043),
        ('tmp-literal', 0x795ee),
    ]:
        offsets = [o + address - va for o, va, size in image.loads
                   if va <= address < va + size]
        require(len(offsets) == 1, 'Control lacks a unique file mapping')
        changed = bytearray(image.data)
        changed[offsets[0]] ^= 1
        lower = copy.copy(image)
        lower.data = bytes(changed)  # Deliberately below the image-identity guard.
        try:
            bind(lower)
        except InvalidEvidence:
            guards.append({'case': name, 'result': 'binding corruption refused'})
        else:
            raise InvalidEvidence('Lower-level mutation accepted: ' + name)
    return {
        'targetSha256': sha(image.data), 'anchorCount': len(ANCHORS),
        'byteFixtures': len(fixtures),
        'abstractRows': [{'input': list(row), 'choice': choice}
                         for row, choice in zip(inputs, expected)],
        'abstractMutantWitnesses': witnesses, 'bindingControls': guards,
        'capturedExecution': False, 'instructionEvaluation': False,
        'limits': 'Data binding and abstract algebra support the manual proof. '
                  'They do not execute instructions or prove filesystem/helper/storage premises.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    try:
        require(not args.receipt or not args.receipt.exists(), 'Preserve existing receipt')
        result = run(args.binary)
        if args.receipt:
            args.receipt.write_bytes(json_bytes(result))
        print(json.dumps(result))
    except (InvalidEvidence, OSError, UnicodeError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()

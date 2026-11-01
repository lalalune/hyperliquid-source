#!/usr/bin/env python3
"""Compile a pinned public C function and compare its whole code to node94.

No captured code, newly compiled code, or archive build hook is executed.
This is an isolated source-compilation witness, not a secp crate/node build.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from libcore_fmt_correspondence import Elf
from foundation_multi_limb_multiply_accumulate import analyze as admit_target

MANIFEST_SHA = 'd5f8444ef4e39c446d7b7807613495cf1e4cb6d98dcbb0671cacbbe4693c30df'
TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
NAME = 'rustsecp256k1_v0_10_0_fe_impl_normalize_weak'
BEGIN, SIZE = 0x56327f0, 123
B, C, P = 1 << 52, (1 << 32) + 977, (1 << 256) - (1 << 32) - 977


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def public_inputs():
    manifest = (HERE / 'SOURCES.json').read_bytes()
    require(sha(manifest) == MANIFEST_SHA, 'Source manifest identity differs')
    records = json.loads(manifest)
    sources = {}
    for row in records['files']:
        raw = (HERE / 'third_party' / row['file']).read_bytes()
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'],
                'Public source identity differs: ' + row['file'])
        require(hashlib.sha1(('blob ' + str(len(raw)) + '\0').encode() + raw).hexdigest()
                == row['git_blob'], 'Public Git blob identity differs')
        sources[row['file']] = raw
    text = sources['field_5x52_impl.h'].decode()
    start = text.index('static void ' + NAME + '(')
    end = text.index('\n}', start) + 2
    function = text[start:end]
    require(text.count('static void ' + NAME + '(') == 1, 'Ambiguous source selection')
    # These are the actual non-VERIFY expansions, witnessed in field.h/util.h.
    require('#  define SECP256K1_FE_VERIFY_FIELDS\n#endif' in sources['field.h'].decode(),
            'Non-VERIFY field expansion differs')
    require('#define VERIFY_CHECK(cond)\n#endif' in sources['util.h'].decode(),
            'Non-VERIFY assertion expansion differs')
    unit = ('#define SECP256K1_FE_VERIFY_FIELDS\n#include "field_5x52.h"\n'
            '#define VERIFY_CHECK(cond)\n' + function + '\n').encode()
    return sources, unit, {'source_byte_interval': [start, end],
                           'selected_source_sha256': sha(function.encode()),
                           'translation_unit_sha256': sha(unit),
                           'non_verify_macro_expansions': ['SECP256K1_FE_VERIFY_FIELDS',
                                                           'VERIFY_CHECK(cond)']}


def compiled_body(raw):
    image = Elf(raw, 1)
    named = [s for t in image.sections if t['type'] == 2 for s in image.symbols(t['index'])
             if s['name'] == NAME and s['section'] != 0]
    require(len(named) == 1, 'Missing or ambiguous named object function')
    symbol = image.function(named[0]['section'], NAME)
    require(symbol['info'] == 2, 'Expected a local FUNC')
    section = image.section(symbol['section'])
    require(section['flags'] & 2, 'Function section is not allocated')
    require(not image.relocations(section['index']), 'Code has relocations')
    require(not any(s['type'] == 9 and s['info'] == section['index'] for s in image.sections),
            'Unsupported source REL code relocation')
    body = image.section_bytes(section['index'])
    return body, {'symbol': symbol, 'section': section, 'body_sha256': sha(body),
                  'object_sha256': sha(raw), 'object_bytes': len(raw),
                  'code_relocations': []}


def comparison(target, source):
    return {'target_bytes': len(target), 'source_bytes': len(source),
            'extent_equal': len(target) == len(source), 'raw_equal': target == source,
            'common_prefix_compared_bytes': min(len(target), len(source)),
            'differing_offsets': [i for i, (a, b) in enumerate(zip(target, source)) if a != b],
            'normalization_fields': []}


def numeric_controls():
    # The independently established target recurrence; no execution/emulation.
    def fold(a):
        out, carry = [], (a[4] >> 48) * C
        for limb in a[:4]:
            total = (limb + carry) & ((1 << 64) - 1)
            out.append(total & (B - 1)); carry = total >> 52
        return out + [(a[4] & ((1 << 48) - 1)) + carry]

    def number(a):
        return sum(v << (52 * i) for i, v in enumerate(a))

    cases = []
    for magnitude in (0, 1, 2, 16, 32):
        bounds = [2 * magnitude * (B - 1)] * 4 + [2 * magnitude * ((1 << 48) - 1)]
        for bits in range(32):
            a = [bound if bits & (1 << i) else 0 for i, bound in enumerate(bounds)]
            result = fold(a); x = a[4] >> 48
            require(number(result) == number(a) - x * P, 'Bounded field identity failed')
            require(all(v < B for v in result[:4]) and result[4] < (1 << 49),
                    'Weak output bounds failed')
            cases.append({'magnitude': magnitude, 'inputs': a, 'outputs': result,
                          'subtracted_modulus_multiples': x})
    prime = [P >> (52 * i) & (B - 1) for i in range(5)]
    require(fold(prime) == prime and number(prime) == P, 'Prime witness differs')
    oversized = [(1 << 64) - 1, 0, 0, 0, 1 << 48]
    require(number(fold(oversized)) % P != number(oversized) % P,
            'Out-of-contract overflow counterexample disappeared')
    return {'bounded_corner_cases': cases,
            'not_canonical': {'input': prime, 'output': fold(prime), 'canonical_residue': 0},
            'outside_magnitude_contract': {'input': oversized, 'output': fold(oversized),
                                         'input_mod_p': number(oversized) % P,
                                         'output_mod_p': number(fold(oversized)) % P},
            'qualification': 'Finite controls of admitted equations; all-input bound proof is in PROOF.md.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--gcc', default='gcc')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not os.path.lexists(args.output), 'Output already exists')
    gcc = shutil.which(args.gcc)
    require(gcc is not None, 'GCC is unavailable')
    sources, unit, selection = public_inputs()
    target = args.binary.read_bytes()
    require(sha(target) == TARGET_SHA, 'Full target identity differs')
    admission = admit_target(target)
    native, mapping = Elf(target, 3).va_bytes(BEGIN, SIZE, executable=True)
    args.output.mkdir(parents=True)
    (args.output / 'target.bin').write_bytes(native)
    rows, objects = [], []
    variants = [('build-a', ['-O2', '-fcf-protection=none'], unit),
                ('build-b', ['-O2', '-fcf-protection=none'], unit),
                ('cet-control', ['-O2', '-fcf-protection=branch'], unit),
                ('constant-control', ['-O2', '-fcf-protection=none'],
                 unit.replace(b'0x1000003D1ULL', b'0x1000003D0ULL'))]
    for name, options, code in variants:
        directory = args.output / name; directory.mkdir()
        (directory / 'probe.c').write_bytes(code)
        (directory / 'field_5x52.h').write_bytes(sources['field_5x52.h'])
        command = [gcc, '-std=c99', *options, '-fkeep-static-functions',
                   '-c', 'probe.c', '-o', 'probe.o']
        process = subprocess.run(command, cwd=directory, capture_output=True)
        (directory / 'compiler.stdout').write_bytes(process.stdout)
        (directory / 'compiler.stderr').write_bytes(process.stderr)
        require(process.returncode == 0, 'Source compilation failed: ' + name)
        raw = (directory / 'probe.o').read_bytes(); body, metadata = compiled_body(raw)
        (directory / 'code.bin').write_bytes(body)
        objects.append(raw)
        rows.append({'variant': name, 'command': command, 'exit': process.returncode,
                     'translation_unit_sha256': sha(code), **metadata,
                     'comparison': comparison(native, body)})
    require(objects[0] == objects[1], 'Independent object builds differ')
    require(all(r['comparison']['raw_equal'] for r in rows[:2]), 'Positive raw comparison failed')
    require(not any(r['comparison']['raw_equal'] for r in rows[2:]), 'Build control matched')
    bad = bytearray(target); bad[mapping['file_offset'] + 0x13] ^= 1
    try:
        admit_target(bytes(bad))
    except ValueError as error:
        target_control = True
        target_control_reason = str(error)
    else:
        raise ValueError('Corrupted target admitted')
    corrupted_comparison = comparison(
        bytes(bad[mapping['file_offset']:mapping['file_offset'] + SIZE]),
        (args.output / 'build-a/code.bin').read_bytes())
    require(not corrupted_comparison['raw_equal'],
            'Unmasked captured byte corruption matched')
    record = {'target_sha256': TARGET_SHA, 'target_bytes': len(target), 'mapping': mapping,
              'existing_target_admission': admission, 'selection': selection,
              'compiler_version': subprocess.check_output([gcc, '--version'], text=True).splitlines()[0],
              'compiler_sha256': sha(Path(gcc).read_bytes()),
              'compiler_target': subprocess.check_output([gcc, '-dumpmachine'], text=True).strip(),
              'builds': rows, 'two_complete_objects_equal': True,
              'target_digest_control_rejected': target_control,
              'target_corruption': {'origin': 'UNQUALIFIED_COUNTERFACTUAL',
                                    'relative_offset': 0x13, 'xor': 1,
                                    'full_input_sha256': sha(bytes(bad)),
                                    'admission_error': target_control_reason,
                                    'unmasked_comparison': corrupted_comparison},
              'captured_or_compiled_code_executed': False, 'progress_gate_requested': False,
              'limits': 'One isolated licensed C function; no full crate/node build, original compiler, ABI or historical-source uniqueness claim.'}
    (args.output / 'record.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    (args.output / 'numeric-controls.json').write_text(json.dumps(numeric_controls(), sort_keys=True, indent=2) + '\n')
    print(json.dumps({'raw_equal_bytes': SIZE, 'independent_equal_builds': 2,
                      'compiled_negative_controls': 2, 'target_corruption_rejected': target_control}))


if __name__ == '__main__':
    main()

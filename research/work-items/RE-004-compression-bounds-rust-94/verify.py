#!/usr/bin/env python3
"""Static target binding and host-native Rust value checks, never target execution."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import random
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
SOURCE = ROOT / 'src/node94-compression-bounds'
sys.path.insert(0, str(ROOT / 'tools'))
import foundation_compression_bounds as original
from elf_index import sections
from fde_extents import eh_frame_records

CRATE = 'node94_compression_bounds'
COMPILER_SHA256 = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
COMPILER_COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
LIMIT = 0x7e000000
MODULUS = 1 << 64


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def target_binding():
    data = original.TARGET.read_bytes()
    require(len(data) == original.SIZE and sha(data) == original.SHA256,
            'Captured node #94 identity differs')
    # The existing checker locks complete bodies, padding, CIE/FDE records,
    # direct-call candidates and immediate operands against the actual ELF.
    checked = original.analyze(data)
    secs = sections(data)
    cies, fdes = eh_frame_records(data, secs)

    def read(va, size):
        mapped = [s for s in secs if s['type'] != 8 and s['address'] <= va
                  and va + size <= s['address'] + s['size']]
        require(len(mapped) == 1, 'VA mapping is not unique and file backed')
        offset = mapped[0]['offset'] + va - mapped[0]['address']
        return offset, data[offset:offset + size]

    frame = next(s for s in secs if s['name'] == '.eh_frame')
    relocations = []
    for section in secs:
        if section['type'] == 4:  # SHT_RELA
            require(section['size'] % 24 == 0, 'Partial RELA record')
            for offset in range(section['offset'], section['offset'] + section['size'], 24):
                relocations.append(struct.unpack_from('<QQq', data, offset))
        require(section['type'] != 9, 'Unreviewed SHT_REL section')
    windows = {}
    for name, window in [('snappy', original.SNAPPY), ('lz4', original.LZ4)]:
        lo, hi = window['start'], window['end']
        matches = [f for f in fdes if f['start'] == lo]
        require(len(matches) == 1 and matches[0]['end'] == hi,
                'Decoded FDE does not establish the selected extent')
        fde = matches[0]
        require(fde['lsda'] is None, 'Unexpected leaf exception metadata')
        file_offset, body = read(lo, hi - lo)
        sites = [r for r in relocations if lo <= r[0] < hi]
        require(not sites, 'Relocation patches the selected instruction body')
        windows[name] = {
            'start_va': hex(lo), 'end_va_exclusive': hex(hi),
            'file_offset': hex(file_offset), 'body_hex': body.hex(),
            'body_sha256': sha(body), 'decoded_fde': fde,
            'fde_hex': read(fde['fde'], len(window['fde']))[1].hex(),
            'cie': cies[fde['cie']],
            'cie_hex': read(fde['cie'], len(original.CIE))[1].hex(),
            'padding_hex': read(hi, window['pad_end'] - hi)[1].hex(),
            'next_fde_hex': read(frame['address'] + window['next_fde_offset'],
                                 len(window['next_fde']))[1].hex(),
            'direct_e8_candidates': checked[name]['direct_callers'],
            'relocations_patching_body': sites,
        }
    return {'target_sha256': original.SHA256, 'target_bytes': len(data),
            'windows': windows,
            'data_dependency': 'All arithmetic constants are immediate operands; '
                               'lea computes addresses without reading memory. '
                               'Only ret reads the valid return stack.',
            'original_checker_sha256': sha((ROOT / 'tools/foundation_compression_bounds.py').read_bytes()),
            'prior_evidence_sha256': sha((ROOT / 'research/work-items/foundation-compression-bounds-94/evidence.json').read_bytes())}


def fixtures():
    # Arbitrary-precision rational floors, separately derived from the byte-bound
    # proof. No Rust results, instruction evaluator or captured execution is used.
    wrap_start = (6 * (MODULUS - 32) + 6) // 7
    snappy = set()
    for anchor in [0, 6, 12, 65536, 1 << 32, 1 << 63, wrap_start, MODULUS - 1]:
        for delta in range(-12, 13):
            if 0 <= anchor + delta < MODULUS:
                snappy.add(anchor + delta)
        quotient = anchor // 6
        snappy.update(6 * quotient + r for r in range(6) if 6 * quotient + r < MODULUS)
    lz4 = set()
    for quotient in [0, 1, 256, 65536, LIMIT // 255]:
        lz4.update(255 * quotient + r for r in range(255))
    for anchor in [65536, 1 << 24, LIMIT, 1 << 31, (1 << 32) - 1]:
        lz4.update(anchor + delta for delta in range(-12, 13)
                   if 0 <= anchor + delta < 1 << 32)
    lz4.update(LIMIT + 1 + ((1 << 32) - LIMIT - 2) * i // 127 for i in range(128))
    rng = random.Random(0x546af50546e280)
    snappy.update(rng.getrandbits(64) for _ in range(1024))
    lz4.update(rng.getrandbits(32) for _ in range(1024))
    inputs, expected = [], []
    counts = {}
    for operation, numbers in [('snappy', snappy), ('lz4', lz4)]:
        counts[operation] = len(numbers)
        for index, n in enumerate(sorted(numbers)):
            identifier = f'{operation}_{index:04d}'
            answer = ((7 * n + 192) // 6) % MODULUS if operation == 'snappy' else (
                (256 * n + 4080) // 255 if n <= LIMIT else 0)
            inputs.append(f'{identifier} {operation} {n:016x}\n')
            expected.append(f'{identifier} {answer:016x}\n')
    return ''.join(inputs).encode(), ''.join(expected).encode(), {
        'counts': counts, 'first_wrapping_u64': wrap_start,
        'snappy_residues': sorted({n % 6 for n in snappy}),
        'lz4_admitted_residues': sorted({n % 255 for n in lz4 if n <= LIMIT}),
        'snappy_wrapping_cases': sum((7 * n + 192) // 6 >= MODULUS for n in snappy),
        'lz4_rejected_cases': sum(n > LIMIT for n in lz4),
        'formulas': {'snappy': 'floor((7*n + 192)/6) mod 2^64',
                     'lz4': 'floor((256*n + 4080)/255) if n <= 0x7e000000, else 0'},
        'oracle_kind': 'Exact unbounded-integer expectations from static proof; not target observations',
    }


def differences(actual, expected):
    rows, wanted = actual.splitlines(), expected.splitlines()
    require(len(rows) == len(wanted), 'Native output row count differs')
    mismatches = []
    for row, answer in zip(rows, wanted):
        fields, correct = row.split(), answer.split()
        require(len(fields) == 2 and fields[0] == correct[0], 'Native case identity/order differs')
        require(len(fields[1]) == 16 and all(c in b'0123456789abcdef' for c in fields[1]),
                'Native answer is not a canonical u64 hex value')
        if row != answer:
            mismatches.append({'id': fields[0].decode(), 'actual': fields[1].decode(),
                               'expected': correct[1].decode()})
    return mismatches


MUTATIONS = [
    ('snappy_divisor', 'input_len / 6', 'input_len / 7'),
    ('snappy_saturating', 'input_len.wrapping_add(input_len / 6).wrapping_add(32)',
     'input_len.saturating_add(input_len / 6).saturating_add(32)'),
    ('snappy_narrowed', 'input_len.wrapping_add', '(input_len as u32 as u64).wrapping_add'),
    ('snappy_constant', '.wrapping_add(32)', '.wrapping_add(31)'),
    ('lz4_exclusive_limit', 'input_bits > 0x7e00_0000', 'input_bits >= 0x7e00_0000'),
    ('lz4_signed_guard', 'input_bits > 0x7e00_0000', '(input_bits as i32) > 0x7e00_0000'),
    ('lz4_divisor', 'input_bits / 255', 'input_bits / 256'),
    ('lz4_constant', 'input_bits / 255 + 16', 'input_bits / 255 + 15'),
]


def qualify(output, rustc, cc):
    require(not output.exists(), 'Use a fresh output directory')
    binding = target_binding()
    inputs, expected, coverage = fixtures()
    frozen = {'target-binding.json': json_bytes(binding), 'inputs.txt': inputs,
              'expected.txt': expected, 'coverage.json': json_bytes(coverage)}
    for name, raw in frozen.items():
        require((PACKET / name).read_bytes() == raw, f'Frozen {name} differs from revalidation')
    require(sha(rustc.read_bytes()) == COMPILER_SHA256, 'Actual rustc binary differs from pin')
    output.mkdir(parents=True)
    calls = []

    def execute(label, argv, stimulus=None):
        args = list(map(str, argv))
        result = subprocess.run(args, cwd=ROOT, input=stimulus, capture_output=True)
        logs = {}
        for kind, raw in [('stdout', result.stdout), ('stderr', result.stderr)]:
            name = f'{label}.{kind}'
            (output / name).write_bytes(raw)
            logs[kind] = {'path': name, 'bytes': len(raw), 'sha256': sha(raw)}
        calls.append({'label': label, 'argv': [a.replace(str(ROOT), '<repo>').replace(str(rustc), '<rustc>') for a in args],
                      'exit_code': result.returncode, 'logs': logs,
                      'stdin_sha256': None if stimulus is None else sha(stimulus)})
        (output / 'calls.json').write_bytes(json_bytes(calls))
        require(result.returncode == 0, f'{label} failed; raw output retained')
        return result.stdout

    version = execute('compiler', [rustc, '-vV']).decode()
    require('release: 1.94.1\n' in version and f'commit-hash: {COMPILER_COMMIT}\n' in version
            and 'host: aarch64-apple-darwin\n' in version, 'Research compiler identity differs')
    linker_version = execute('linker', [cc, '--version']).decode()
    source_text = (SOURCE / 'lib.rs').read_text()
    source_hashes = {p.name: sha(p.read_bytes()) for p in SOURCE.glob('*.rs')}

    def build(folder, source, optimization):
        directory = output / folder
        directory.mkdir()
        library, program = directory / f'lib{CRATE}.rlib', directory / 'client'
        flags = ['--edition=2021', '--target=aarch64-apple-darwin', '-Dwarnings',
                 '-Ccodegen-units=1', f'-Copt-level={optimization}', '-Coverflow-checks=on',
                 f'-Clinker={cc}', '--remap-path-prefix', f'{ROOT}=/reconstruction']
        execute(folder + '-library', [rustc, '--crate-name', CRATE, '--crate-type=rlib', source,
                                     '-Cmetadata=compression_bounds94', *flags, '-o', library])
        execute(folder + '-client', [rustc, '--crate-name', 'compression_bounds_client',
                                    SOURCE / 'input_only_driver.rs', '--extern', f'{CRATE}={library}',
                                    *flags, '-o', program])
        actual = execute(folder + '-run', [program], inputs)
        return library, program, actual, flags

    comparisons, rebuilds, controls = [], [], []
    for optimization in [0, 3]:
        name = f'opt{optimization}'
        library, program, actual, flags = build(name, SOURCE / 'lib.rs', optimization)
        require(not differences(actual, expected), f'{name} production mismatch')
        unit = output / name / 'unit-tests'
        execute(name + '-unit-build', [rustc, '--crate-name', CRATE, '--test', SOURCE / 'lib.rs',
                                      *flags, '-o', unit])
        unit_stdout = execute(name + '-unit-run', [unit, '--test-threads=1'])
        require(b'3 passed; 0 failed' in unit_stdout, 'Ordinary Rust unit tests did not pass')
        library2, program2, actual2, _ = build(name + '-repeat', SOURCE / 'lib.rs', optimization)
        require(actual2 == expected, 'Repeat native output differs')
        for kind, first, second in [('rlib', library, library2), ('client', program, program2)]:
            same = first.read_bytes() == second.read_bytes()
            require(same, f'{name} repeated {kind} is not byte-identical')
            rebuilds.append({'profile': name, 'artifact': kind, 'bytes': first.stat().st_size,
                             'sha256': sha(first.read_bytes()), 'raw_equal': same, 'normalization': 'none'})
        comparisons.append({'profile': name, 'native_cases': sum(coverage['counts'].values()),
                            'mismatches': 0, 'stdout_sha256': sha(actual), 'unit_tests_passed': 3})
        for label, needle, replacement in MUTATIONS:
            require(source_text.count(needle) == 1, f'{label} mutation is not unique')
            mutant = output / f'{label}.rs'
            mutated = source_text.replace(needle, replacement)
            if label == 'lz4_signed_guard':
                # Keep this deliberately wrong guard runnable over all u32s;
                # detect wrong values, rather than relying on overflow panic.
                mutated = mutated.replace('input_bits + input_bits / 255 + 16',
                    'input_bits.wrapping_add(input_bits / 255).wrapping_add(16)')
            mutant.write_text(mutated)
            _, _, wrong, _ = build(f'{name}-{label}', mutant, optimization)
            mismatches = differences(wrong, expected)
            require(mismatches, f'Native wrong implementation survived: {label}')
            controls.append({'profile': name, 'mutation': label, 'mismatches': len(mismatches),
                             'first_witness': mismatches[0], 'source_sha256': sha(mutant.read_bytes())})
    # Comparator controls distinguish semantic disagreement from broken framing.
    corrupt = expected.splitlines(keepends=True)
    corrupt[0] = corrupt[0].split()[0] + b' ffffffffffffffff\n'
    require(len(differences(b''.join(corrupt), expected)) == 1, 'Changed-answer control survived')
    for broken in [b'\n'.join(expected.splitlines()[:-1]) + b'\n',
                   b'\n'.join(reversed(expected.splitlines())) + b'\n']:
        try:
            differences(broken, expected)
        except ValueError:
            pass
        else:
            raise ValueError('Missing/reordered-output control survived')
    require(source_hashes == {p.name: sha(p.read_bytes()) for p in SOURCE.glob('*.rs')},
            'Component source changed during qualification')
    require(sha(rustc.read_bytes()) == COMPILER_SHA256, 'Compiler changed during qualification')
    record = {'target_sha256': original.SHA256, 'compiler_sha256': COMPILER_SHA256,
              'compiler_version': version, 'linker_sha256': sha(cc.read_bytes()),
              'linker_version': linker_version, 'python': platform.python_version(),
              'platform': platform.platform(), 'source_sha256': source_hashes,
              'fixtures_sha256': {name: sha(raw) for name, raw in frozen.items()},
              'comparisons': comparisons, 'own_rebuilds': rebuilds,
              'native_wrong_implementation_controls': controls,
              'comparator_controls': ['changed answer detected', 'missing row rejected', 'reordered rows rejected'],
              'target_executed': False, 'instruction_emulator_executed': False,
              'target_compiled_byte_comparison': 'not performed; no original ABI or build identity claim'}
    (output / 'results.json').write_bytes(json_bytes(record))
    print(json.dumps({'comparisons': comparisons, 'native_controls_rejected': len(controls),
                      'own_rebuilds_equal': len(rebuilds)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', action='store_true', help='create new frozen files; refuses overwrite')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--rustc', type=Path)
    parser.add_argument('--cc', type=Path, default=Path('/usr/bin/cc'))
    args = parser.parse_args()
    if args.freeze:
        inputs, expected, coverage = fixtures()
        files = {'target-binding.json': json_bytes(target_binding()), 'inputs.txt': inputs,
                 'expected.txt': expected, 'coverage.json': json_bytes(coverage)}
        require(all(not (PACKET / name).exists() for name in files), 'Freeze refuses to overwrite evidence')
        for name, raw in files.items():
            (PACKET / name).write_bytes(raw)
        print(json.dumps(coverage['counts']))
    else:
        require(args.out is not None and args.rustc is not None, '--out and actual --rustc required')
        qualify(args.out.absolute(), args.rustc.resolve(), args.cc.resolve())


if __name__ == '__main__':
    main()

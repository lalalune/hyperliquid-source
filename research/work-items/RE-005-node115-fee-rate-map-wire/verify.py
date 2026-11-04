"""Reproduce the bounded Node115 fee-rate encoder contract without target execution."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LIB = ROOT / 'src/node115-fee-rate-map-codec/src/lib.rs'
TARGET_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CAPTURED = {TARGET_SHA, '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents


def need(condition, message):
    if not condition:
        raise ValueError(message)


def certificate(data, record):
    secs = sections(data)

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        need(len(matches) == 1, 'selected ELF virtual address is ambiguous/unmapped')
        s = matches[0]
        offset = s['offset'] + va - s['address']
        return data[offset:offset + size]

    def exact(va, encoded, label):
        need(read(va, len(bytes.fromhex(encoded))).hex() == encoded, label)

    def call(va, target):
        instruction = read(va, 5)
        need(instruction[0] == 0xe8 and va + 5 + struct.unpack('<i', instruction[1:])[0] == target,
             'selected direct call differs')

    _, fdes, _ = fde_extents(data)
    bodies = []
    for span in record['ranges']:
        lo, hi = int(span['startELFVA'], 16), int(span['endELFVA'], 16)
        need(any(f['start'] == lo and f['end'] == hi for f in fdes), 'selected FDE extent differs')
        bodies.append({'name': span['name'], 'length': hi - lo,
                       'bodySHA256': hashlib.sha256(read(lo, hi - lo)).hexdigest()})
    exact(0x2764d07, '410f1007', 'first caller input load differs')
    exact(0x2764d0f, '410f104710', 'second caller input load differs')
    exact(0x2764d0b, '0f290424', 'first caller stack copy differs')
    exact(0x2764d14, '0f29442410', 'second caller stack copy differs')
    exact(0x2764d25, '4989e0', 'caller does not bind R8 to copied words')
    ref = read(0x2764d19, 7)
    need(ref[:3] == bytes.fromhex('488d15'), 'caller type reference differs')
    target = 0x2764d20 + struct.unpack('<i', ref[3:])[0]
    need(read(target, 15) == b'FeeRateMapSerde', 'caller type literal differs')
    exact(0x2764d28, 'b90f000000', 'concrete type-name length differs')
    call(0x2764d30, 0x2276490)
    exact(0x22764ad, '4883f90a', 'special type-name length guard differs')
    # Concrete length15 bypasses the special length10 _ExtStruct branch.
    prefixes = [read(va, 4) for va in (0x22764ef, 0x227650d)]
    need(all(p[:3] == bytes.fromhex('c60430') for p in prefixes), 'array-marker stores differ')
    need(prefixes[0][3] == prefixes[1][3] == 0x94, 'ordinary branches do not both write array4')
    exact(0x22764db, '4d8b20', 'mode2 first word load differs')
    exact(0x2276518, '4d8b20', 'ordinary first word load differs')
    exact(0x227654e, '4d8b6008', 'second word displacement differs')
    exact(0x2276589, '4d8b6010', 'third word displacement differs')
    exact(0x22765c4, 'f2410f104018', 'fourth word displacement differs')
    float_prefixes = [read(va, 4) for va in (0x2276527, 0x2276562, 0x227659d, 0x25e8505)]
    need(all(p[:3] == bytes.fromhex('c60430') and p[3] == 0xcb for p in float_prefixes),
         'float64 marker differs')
    for va in (0x227653f, 0x227657a, 0x22765b5):
        exact(va, '490fcc', 'first-three byte-swap differs')
    call(0x22765cd, 0x25e84f0)
    exact(0x25e8519, '66480f7ec1', 'fourth word raw XMM bit move differs')
    exact(0x25e851e, '480fc9', 'fourth word byte-swap differs')
    exact(0x25e8521, '48890c30', 'fourth word store differs')
    exact(0x25e852d, 'b802000000', 'float writer success value differs')
    exact(0x22765d2, '4883f802', 'float writer success guard differs')
    exact(0x22764a3, '49bf0000000000000080', 'writer sentinel differs')
    exact(0x22765d8, '4c897c2408', 'finalizer state sentinel binding differs')
    exact(0x22765fc, '488d742408', 'finalizer state address differs')
    call(0x2276604, 0x22999e0)
    exact(0x22999f1, '49be0000000000000080', 'finalizer return sentinel differs')
    exact(0x22999fb, '488b0e4889c848f7d8', 'finalizer state load/negation differs')
    branch = read(0x2299a04, 6)
    need(branch[:2] == bytes.fromhex('0f80') and 0x2299a0a + struct.unpack('<i', branch[2:])[0] == 0x2299aa2,
         'min-i64 negation overflow does not reach direct return')
    exact(0x2299aa2, '4983c6044c89334889d84883c4185b415c415d415e415f5dc3',
          'direct return block has changed effects')
    return {'arrayMarker': prefixes[0][3], 'floatMarkers': [p[3] for p in float_prefixes],
            'wordOffsets': [0, 8, 16, 24], 'byteOrder': 'big',
            'finalizerAddsPayload': False, 'selectedBodies': bodies}


def structural_controls(data, record):
    # Deliberate in-memory corruption after the input identity gate; no target is run.
    locations = [(0x22764f2, 0x93, 'array-marker'), (0x2276551, 0x10, 'word-displacement'),
                 (0x25e8508, 0xca, 'fourth-marker'), (0x25e8520, 0xc8, 'fourth-byte-swap'),
                 (0x2299a05, 0x81, 'finalizer-overflow-branch'),
                 (0x2764d29, 14, 'caller-type-name-length')]
    secs = sections(data)
    rejected = []
    for va, value, name in locations:
        s = next(s for s in secs if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        offset = s['offset'] + va - s['address']
        changed = bytearray(data)
        changed[offset] = value
        try:
            certificate(changed, record)
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('structural counterfactual accepted: ' + name)
    return rejected


def trusted_tool(value):
    path = Path(shutil.which(str(value)) or value).resolve()
    need(hashlib.sha256(path.read_bytes()).hexdigest() not in CAPTURED,
         'captured node/visor cannot be used as an analysis/compiler tool')
    return str(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--rustc', required=True)
    parser.add_argument('--objdump', required=True)
    parser.add_argument('--linker')
    parser.add_argument('--linker-flavor')
    parser.add_argument('--self-contained', action='store_true')
    parser.add_argument('--linux-lib', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = args.target.read_bytes()
    need(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == TARGET_SHA,
         'pinned Node115 identity required before tools or outputs')
    rustc, objdump = trusted_tool(args.rustc), trusted_tool(args.objdump)
    linker = trusted_tool(args.linker) if args.linker else None
    record = json.loads((HERE / 'observed/records.json').read_text(encoding='utf-8'))
    need(record['targetSHA256'] == TARGET_SHA, 'record identity differs')
    contract = certificate(data, record)
    version = subprocess.check_output([rustc, '-vV'], stderr=subprocess.STDOUT).decode()
    need(version.startswith('rustc 1.95.0 '), 'this comparison pins Rust1.95.0')
    native_version = subprocess.check_output([objdump, '--version'], stderr=subprocess.STDOUT).decode().splitlines()[0]
    need('GNU objdump' in native_version, 'GNU objdump required')
    for span in record['ranges']:
        raw = HERE / 'observed' / (span['name'] + '.objdump.txt')
        need(hashlib.sha256(raw.read_bytes()).hexdigest() == span['rawSHA256'], 'retained native export changed')
        # Full ranges, with original bytes; symbols are not inferred source names.
        output = subprocess.check_output([objdump, '-d', '-M', 'intel',
                    '--start-address=' + span['startELFVA'], '--stop-address=' + span['endELFVA'],
                    str(args.target)], cwd=ROOT, stderr=subprocess.STDOUT).decode()
        need(re.search(r'^\s*' + span['startELFVA'][2:] + r':\s', output, re.M),
             'native selected entry boundary missing')
    frozen = json.loads((HERE / 'PRE-RUST-FREEZE.json').read_text(encoding='utf-8'))
    need(hashlib.sha256((HERE / 'vectors.tsv').read_bytes()).hexdigest() == frozen['vectorsSHA256'],
         'pre-Rust corpus changed')
    with (HERE / 'vectors.tsv').open(encoding='utf-8', newline='') as handle:
        rows = list(csv.DictReader(handle, delimiter='\t'))
    expected = [r['expected_hex'] for r in rows]
    for r in rows:
        words = [int(r['bits' + str(i)], 16) for i in range(4)]
        predicted = bytes([contract['arrayMarker']]) + b''.join(bytes([tag]) + struct.pack('>Q', word)
                      for tag, word in zip(contract['floatMarkers'], words))
        need(predicted.hex() == r['expected_hex'], 'decoded contract and frozen corpus differ')
    need(not args.output.exists(), 'use a fresh comparison output; preserve prior results')
    args.output.mkdir(parents=True)
    commands = []

    def run(command, name, stdin=None):
        process = subprocess.run(command, cwd=ROOT, input=stdin, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=180)
        (args.output / (name + '.log')).write_bytes(process.stdout)
        commands.append({'name': name, 'command': command, 'exitCode': process.returncode})
        need(process.returncode == 0, 'comparison command failed: ' + name)
        return process.stdout

    flags = []
    if linker:
        flags += ['-C', 'linker=' + linker]
    if args.linker_flavor:
        flags += ['-C', 'linker-flavor=' + args.linker_flavor]
    if args.self_contained:
        flags += ['-C', 'link-self-contained=yes']
    stdin = ('\n'.join(' '.join(r['bits' + str(i)] for i in range(4)) for r in rows) + '\n').encode()
    builds = []

    def build(source, name, optimized):
        directory = args.output / name
        directory.mkdir()
        library = directory / 'libnode115_fee_rate_map_codec.rlib'
        executable = directory / ('compare.exe' if sys.platform == 'win32' else 'compare')
        optimize = ['-C', 'opt-level=3' if optimized else 'opt-level=0']
        run([rustc, '--edition=2021', '--crate-name', 'node115_fee_rate_map_codec',
             '--crate-type=rlib', *optimize, str(source), '-o', str(library)], name + '-library')
        run([rustc, '--edition=2021', *flags, *optimize, str(HERE / 'runner.rs'),
             '--extern', 'node115_fee_rate_map_codec=' + str(library), '-o', str(executable)], name + '-runner')
        actual = run([str(executable)], name + '-execute', stdin).decode().splitlines()
        return {'name': name, 'matched': actual == expected,
                'differingRows': sum(a != b for a, b in zip(actual, expected)) + abs(len(actual) - len(expected)),
                'outputSHA256': hashlib.sha256(('\n'.join(actual) + '\n').encode()).hexdigest(),
                'librarySHA256': hashlib.sha256(library.read_bytes()).hexdigest(),
                'executableSHA256': hashlib.sha256(executable.read_bytes()).hexdigest()}

    for name, optimized in [('debug', False), ('optimized', True), ('optimized-repeat', True)]:
        result = build(LIB, name, optimized)
        need(result['matched'], 'independent Rust differs from frozen contract: ' + name)
        builds.append(result)
    mutations = []
    controls = []
    if args.self_test:
        controls = structural_controls(data, record)
        production = LIB.read_text(encoding='utf-8')
        edits = [('array3', 'output[0] = 0x94;', 'output[0] = 0x93;'),
                 ('little-endian', 'word.to_be_bytes()', 'word.to_le_bytes()'),
                 ('float32-marker', 'output[start] = 0xcb;', 'output[start] = 0xca;'),
                 ('fourth-alias', 'let start = 1 + slot * 9;',
                  'let word = if slot == 3 { words[0] } else { word };\n        let start = 1 + slot * 9;')]
        for name, old, new in edits:
            need(production.count(old) == 1, 'production mutation site differs: ' + name)
            source = args.output / ('mutant-' + name + '.rs')
            source.write_text(production.replace(old, new), encoding='utf-8')
            result = build(source, 'mutant-' + name, True)
            need(not result['matched'] and result['differingRows'] > 0,
                 'wrong production implementation was accepted: ' + name)
            mutations.append(result)
    if args.linux_lib:
        run([rustc, '--edition=2021', '--crate-name', 'node115_fee_rate_map_codec',
             '--target', 'x86_64-unknown-linux-gnu', '--crate-type=rlib', '-C', 'opt-level=3',
             str(LIB), '-o', str(args.output / 'linux-source-built.rlib')], 'linux-library')
    report = {'targetSHA256': TARGET_SHA, 'rustcVersion': version, 'nativeToolVersion': native_version,
              'productionSourceSHA256': hashlib.sha256(LIB.read_bytes()).hexdigest(),
              'inputSHA256': {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in {
                  'production': LIB, 'runner': HERE / 'runner.rs', 'verifier': Path(__file__),
                  'vectors': HERE / 'vectors.tsv', 'record': HERE / 'observed/records.json',
                  'freeze': HERE / 'PRE-RUST-FREEZE.json'}.items()},
              'toolSHA256': {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                            for name, path in [('rustc', rustc), ('objdump', objdump)] +
                            ([('linker', linker)] if linker else [])},
              'frozenCorpusSHA256': frozen['vectorsSHA256'], 'contract': contract,
              'vectors': len(rows), 'builds': builds, 'productionMutantsRejected': mutations,
              'postIdentityStructuralControlsRejected': controls, 'commands': commands,
              'linuxLibraryBuilt': args.linux_lib, 'capturedExecutedOrEmulated': False,
              'claim': 'Bounded encoder bytes from decoded static predicates; no decoder/native ABI/whole-ELF equivalence or gate.'}
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'vectors': len(rows), 'positiveBuilds': len(builds), 'rejectedProductionMutants': len(mutations),
                      'rejectedStructuralControls': len(controls), 'linuxLibraryBuilt': args.linux_lib}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print('fee-rate encoder verification: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
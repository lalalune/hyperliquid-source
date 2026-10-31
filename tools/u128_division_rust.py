#!/usr/bin/env python3
"""Compare new Rust limb division to fresh authenticated node94 static results.

Only analysis tools and newly authored Rust execute; the captured ELF is data.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

import u128_division as u

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / 'src/node94-u128-division'
PACKET = ROOT / 'research/work-items/RE-004-u128-division-94'
BINARY = ROOT / 'artifacts/node/94/hl-node'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    cargo = shutil.which('cargo')
    gnu = shutil.which('gobjdump') or shutil.which('objdump')
    llvm = os.environ.get('LLVM_OBJDUMP') or shutil.which('llvm-objdump')
    require(cargo and gnu and llvm, 'existing Cargo, GNU objdump and LLVM objdump required')
    require('GNU objdump' in subprocess.check_output([gnu, '--version'], text=True),
            'GNU decoder required')
    require('LLVM' in subprocess.check_output([llvm, '--version'], text=True),
            'LLVM decoder required')
    commands = []
    environment = dict(os.environ)
    environment['CARGO_TARGET_DIR'] = str(output / 'target-tests')
    environment['RUSTFLAGS'] = f'--remap-path-prefix={ROOT}=<repository>'

    def run(label, command, *, env=None, expected=0):
        result = subprocess.run(command, cwd=ROOT, env=env or environment,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True)
        log = result.stdout.replace(str(ROOT), '<repository>')
        (output / (label + '.log')).write_text(log)
        commands.append({'label': label,
                         'argv': [str(x).replace(str(ROOT), '<repository>') for x in command],
                         'exit_code': result.returncode})
        require(result.returncode == expected, f'{label}: exit {result.returncode}, expected {expected}')
        return log

    data = BINARY.read_bytes()
    u.check_digest(data)
    image = u.Image(data)
    with tempfile.TemporaryDirectory(prefix='node94-u128-static-') as directory:
        snapshot = Path(directory) / 'node94.elf'
        with snapshot.open('xb') as stream:
            stream.write(data)
        snapshot.chmod(0o400)
        reports = []
        decoded = []
        for name, tool in [('gnu', gnu), ('llvm', llvm)]:
            listing = u.disassemble(snapshot, tool)
            (output / (name + '.txt')).write_text(listing.replace(str(snapshot), 'node94.elf'))
            decoded.append(u.decode(listing, image))
            report = u.produce(snapshot, listing)
            require(report == json.loads((PACKET / 'evidence.json').read_text()),
                    f'{name}: fresh static evidence differs from retained packet')
            reports.append(report)
        require(decoded[0] == decoded[1], 'native helper decodes disagree')
        require(reports[0] == reports[1], 'native static results disagree')
        require(digest(snapshot) == u.SHA256, 'owned target snapshot changed')

        # Rebind the original full incoming caller, including its real ff15 slot.
        extent = u.Fdes(image).range_of(0x333e310)
        require((extent['start'], extent['end']) == (0x333e310, 0x333e441),
                'incoming caller FDE changed')
        listing = subprocess.check_output(
            [gnu, '-d', '-M', 'intel', '--insn-width=16',
             '--start-address=0x333e310', '--stop-address=0x333e441', str(snapshot)], text=True)
        caller = u.decode(listing, image, start=extent['start'], end=extent['end'])
        require(caller == u.decode((PACKET / 'caller.gnu-objdump.txt').read_text(), image,
                                  start=extent['start'], end=extent['end']),
                'fresh incoming caller differs from retained decoded bytes')
        call = next(row for row in caller if row[0] == 0x333e361)
        require(call[1][:2] == b'\xff\x15'
                and call[0] + 6 + struct.unpack('<i', call[1][2:])[0] == u.SLOT,
                'incoming call slot changed')
        require(image.relative_relocs()[u.SLOT] == u.ENTRY, 'helper RELATIVE binding changed')
        (output / 'caller-gnu.txt').write_text(listing.replace(str(snapshot), 'node94.elf'))

        vectors = output / 'vectors.txt'
        machine = u.Machine(decoded[0])
        count = 0
        with vectors.open('w', encoding='ascii', newline='\n') as stream:
            for numerator, denominator in u.vectors():
                observed, _ = machine.run(numerator, denominator)
                require(observed == numerator // denominator, 'independent Python quotient differs')
                stream.write(f'{numerator:032x}/{denominator:032x}={observed:032x}\n')
                count += 1
        require(count == reports[0]['vectors'] == 159431, 'fixture count changed')
        require(digest(vectors) == reports[0]['vector_result_sha256'], 'fresh fixture stream changed')

    (output / 'static-evidence.json').write_text(json.dumps(reports[0], indent=2) + '\n')
    environment['NODE94_U128_VECTORS'] = str(vectors)
    manifest = str(COMPONENT / 'Cargo.toml')
    run('format', [cargo, 'fmt', '--manifest-path', manifest, '--', '--check'])
    run('clippy', [cargo, 'clippy', '--manifest-path', manifest, '--offline', '--locked',
                   '--all-targets', '--', '-D', 'warnings'])
    profiles = {}
    for profile in ['debug', 'release']:
        command = [cargo, 'test', '--manifest-path', manifest, '--offline', '--locked']
        if profile == 'release':
            command.append('--release')
        log = run(profile + '-tests', command + ['--', '--include-ignored', '--nocapture'])
        require('5 passed; 0 failed; 0 ignored' in log
                and 'authenticated nonzero-divisor cases: 159431' in log,
                f'{profile}: complete corpus did not run')
        profiles[profile] = {'cases': count, 'tests_passed': 5, 'ignored': 0}

    archives = []
    (output / 'build-archives').mkdir()
    (output / 'llvm-ir').mkdir()
    for name in ['a', 'b']:
        target = output / ('target-release-' + name)
        build_env = dict(environment, CARGO_TARGET_DIR=str(target))
        run('release-build-' + name,
            [cargo, 'rustc', '--manifest-path', manifest, '--offline', '--locked',
             '--release', '--lib', '--', '--emit=llvm-ir,link'], env=build_env)
        library = target / 'release/libhyperliquid_node94_u128_division.rlib'
        retained = output / 'build-archives' / (name + '.rlib')
        shutil.copyfile(library, retained)
        ir_files = list((target / 'release/deps').glob('*.ll'))
        require(len(ir_files) == 1, 'expected one component LLVM IR file')
        ir = ir_files[0].read_text()
        require(re.search(r'define[^\n]*quotient', ir), 'component quotient definition missing from IR')
        require(not re.search(r'\b(?:u|s)(?:div|rem)\s+i128\b|@__(?:u?div|u?mod|u?divmod)ti[34]\b', ir),
                'component IR depends on a 128-bit division primitive')
        shutil.copyfile(ir_files[0], output / 'llvm-ir' / (name + '.ll'))
        archives.append({'name': name, 'bytes': retained.stat().st_size,
                         'sha256': digest(retained), 'retained_archive': f'build-archives/{name}.rlib',
                         'llvm_ir_sha256': digest(ir_files[0]), 'retained_ir': f'llvm-ir/{name}.ll'})
        shutil.rmtree(target)
    require(archives[0]['sha256'] == archives[1]['sha256'], 'clean release archives differ')

    controls = []
    mutations = {
        'bit-order': ('for bit in (0..128).rev()', 'for bit in 0..128'),
        'missing-top-bit': ('for bit in (0..128).rev()', 'for bit in (0..127).rev()'),
        'strict-low-comparison': ('remainder.low >= divisor.low', 'remainder.low > divisor.low'),
        'borrow-propagation': ('.wrapping_sub(u64::from(borrow))', '.wrapping_sub(u64::from(!borrow))'),
        'cross-limb-shift': ('| (remainder.low >> 63)', '| (remainder.low >> 62)'),
        'quotient-high-limb': ('result.high |= 1 << (bit - 64)', 'result.high |= 0 << (bit - 64)'),
        'denominator-high-limb': ('let divisor = denominator.0;',
                                  'let divisor = Words { low: denominator.0.low, high: 0 };'),
        'zero-boundary': ('words.low == 0 && words.high == 0', 'words.low == 0 || words.high == 0'),
    }
    if args.controls:
        source = (COMPONENT / 'src/lib.rs').read_text()
        for name, (before, after) in mutations.items():
            require(source.count(before) == 1, f'{name}: mutation anchor changed')
            mutant = output / 'mutants' / name
            shutil.copytree(COMPONENT, mutant, ignore=shutil.ignore_patterns('target'))
            (mutant / 'src/lib.rs').write_text(source.replace(before, after, 1))
            target = output / ('target-mutant-' + name)
            mutant_env = dict(environment, CARGO_TARGET_DIR=str(target))
            command = [cargo, 'test', '--manifest-path', str(mutant / 'Cargo.toml'), '--offline', '--locked']
            run('mutation-' + name + '-compile', command + ['--no-run'], env=mutant_env)
            run('mutation-' + name, command + ['--', '--include-ignored'], env=mutant_env, expected=101)
            controls.append({'name': name, 'compiled': True, 'test_exit_code': 101})
            shutil.rmtree(target)

    versions = {name: subprocess.check_output(command, text=True).replace(str(ROOT), '<repository>')
                for name, command in [('cargo', [cargo, '--version']),
                                      ('rustc', [environment.get('RUSTC', 'rustc'), '--version', '--verbose']),
                                      ('gnu', [gnu, '--version']), ('llvm', [llvm, '--version'])]}
    (output / 'toolchain.json').write_text(json.dumps(versions, indent=2) + '\n')
    report = {'target_sha256': u.SHA256, 'fixture_count': count,
              'fixture_sha256': digest(vectors), 'fresh_static_matches_retained': True,
              'profiles': profiles, 'clean_release_builds': archives, 'raw_archive_equal': True,
              'i128_division_primitive_in_component_ir': False, 'rust_source_controls': controls,
              'commands': commands, 'captured_execution': False, 'gate_requested': False,
              'limits': ['new checked nonzero interface, not native ABI or zero-fault behavior',
                         'binary long division, not target instruction paths or performance',
                         'finite static comparison, not a universal proof or captured execution',
                         'macOS arm64 component builds, not target Linux builds']}
    (output / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    shutil.rmtree(output / 'target-tests')
    print(json.dumps({'fixture_count': count, 'profiles': profiles,
                      'compiled_source_controls_rejected': len(controls), 'raw_archive_equal': True}))


if __name__ == '__main__':
    main()

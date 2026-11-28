#!/usr/bin/env python3
"""Verify the node #115 linker stamp and replay a data-only Linux ELF fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections

NODE_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ARCHIVE_SHA = '8426a3d170a5879f5682f5fbdd024a1779b3951e7baba685af2d6dc32a6dfc15'
LINUX_LINKER_SHA = '60f305b55da767671e895b231e0c78e87f4ccbf790d7181842039c53bb60281c'
TARGET = 'x86_64-unknown-linux-gnu'
MEMBER = f'rustc-1.95.0-{TARGET}/rustc/lib/rustlib/{TARGET}/bin/rust-lld'
RUST = {
    '1.95.0': ('59807616e1fa2540724bfbac14d7976d7e4a3860', '22.1.2',
               '1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e'),
    '1.94.1': ('e408947bfd200af42db322daf0fadfe7e26d3bd1', '21.1.8',
               '00d23d10dc48c6bb9d57ba96d4a748d85d77d0c7'),
}
OVERRIDE = 'RE-002 link fixture control'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(test, message):
    if not test:
        raise ValueError(message)


def section(data, name):
    rows = [s for s in sections(data) if s['name'] == name]
    require(len(rows) == 1 and rows[0]['type'] != 8, f'Expected one file-backed {name}')
    row = rows[0]
    return row, data[row['offset']:row['offset'] + row['size']]


def build_id(data):
    row, note = section(data, '.note.gnu.build-id')
    # The measured files each contain exactly one 20-byte GNU NT_GNU_BUILD_ID.
    require(row['type'] == 7 and len(note) == 36 and
            note[:16] == struct.pack('<III', 4, 20, 3) + b'GNU\0', 'Unexpected GNU build-id note')
    return note[16:].hex()


def c_strings(data):
    require(data.endswith(b'\0'), 'Unterminated string section')
    offset = 0
    for value in data[:-1].split(b'\0'):
        if value:
            yield offset, value.decode('ascii')
        offset += len(value) + 1


def capture(path):
    data = path.read_bytes()
    require(digest(data) == NODE_SHA, 'Node #115 SHA-256 mismatch')
    row, blob = section(data, '.comment')
    stamps = [(off, name) for off, name in c_strings(blob) if name.startswith('Linker: ')]
    require(len(stamps) == 1, 'Expected a unique node linker stamp')
    offset, stamp = stamps[0]
    return dict(sha256=NODE_SHA, gnu_build_id=build_id(data), stamp=stamp,
                comment_file_offset=row['offset'], stamp_file_offset=row['offset'] + offset)


def linux_candidate(path, stamp):
    with path.open('rb') as archive:
        checksum = hashlib.file_digest(archive, 'sha256').hexdigest()
        require(checksum == ARCHIVE_SHA, 'Linux compiler archive SHA-256 mismatch')
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode='r|xz') as tar:
            for member in tar:
                if member.name == MEMBER:
                    require(member.isfile(), 'Expected a regular linker file')
                    with tar.extractfile(member) as source:
                        data = source.read()
                    break
            else:
                raise ValueError('Missing Linux linker archive member')
    require(digest(data) == LINUX_LINKER_SHA, 'Linux linker member SHA-256 mismatch')
    require(struct.unpack_from('<H', data, 18)[0] == 62, 'Expected x86-64 Linux linker')
    row, blob = section(data, '.rodata')
    require(row['type'] == 1 and row['flags'] & 7 == 2, 'Expected allocated read-only data')
    prefix = 'Linker: '
    require(stamp.startswith(prefix), 'Unexpected node linker prefix')
    offsets = {}
    for name, text in [('prefix', prefix), ('version', stamp[len(prefix):]), ('override_variable', 'LLD_VERSION')]:
        pattern = b'\0' + text.encode('ascii') + b'\0'
        require(blob.count(pattern) == 1, f'Expected a unique {name} literal in linker .rodata')
        offsets[name] = row['offset'] + blob.index(pattern) + 1
    return dict(archive_sha256=checksum, member=MEMBER, member_sha256=LINUX_LINKER_SHA,
                member_size=len(data), rodata_file_offsets=offsets,
                version=stamp[len(prefix):], prefix=prefix)


def command(args, **kw):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, **kw).stdout.strip()


def toolchain(version):
    driver = ['rustup', 'run', version, 'rustc']
    info = dict(line.split(': ', 1) for line in command(driver + ['-vV']).splitlines() if ': ' in line)
    commit, llvm, revision = RUST[version]
    require((info['release'], info['commit-hash'], info['LLVM version']) == (version, commit, llvm),
            f'Unexpected Rust {version} toolchain')
    linker = Path(command(driver + ['--print', 'sysroot'])) / 'lib/rustlib' / info['host'] / 'bin/rust-lld'
    banner = command([linker, '-flavor', 'gnu', '--version'])
    match = re.fullmatch(r'(LLD ([\d.]+) \((\S+) ([0-9a-f]{40})\)) \(compatible with GNU linkers\)', banner)
    require(match and (match[2], match[4]) == (llvm, revision), 'Unexpected linker revision')
    linker_hash = digest(linker.read_bytes())
    if version == '1.95.0' and info['host'] == TARGET:
        require(linker_hash == LINUX_LINKER_SHA, 'Installed Linux linker differs from authenticated archive')
    return linker, dict(host=info['host'], rustc_commit=commit, rust_lld_sha256=linker_hash,
                        llvm_revision=revision, version=match[1])


def link_cases(directory, assembler):
    env = {key: os.environ[key] for key in ('PATH', 'TMPDIR', 'SYSTEMROOT') if key in os.environ}
    env['LC_ALL'] = 'C'
    source = (HERE / 'fixture.s').read_bytes()
    require(source.count(b'"RE002"') == 1, 'Expected one fixture constant')
    cases = [('current_a', '1.95.0', False, False), ('current_b', '1.95.0', False, False),
             ('changed_input', '1.95.0', True, False), ('changed_stamp', '1.95.0', False, True),
             ('older', '1.94.1', False, False)]
    toolchains = {v: toolchain(v) for v in RUST}
    results = {}
    original_obj = None
    changed_offset = None
    for label, version, changed, override in cases:
        work = directory / label
        work.mkdir()
        (work / 'fixture.s').write_bytes(source.replace(b'"RE002"', b'"RE003"') if changed else source)
        command([assembler, '--target=' + TARGET, '-c', 'fixture.s', '-o', 'fixture.o'], cwd=work, env=env)
        obj = (work / 'fixture.o').read_bytes()
        require(struct.unpack_from('<HH', obj, 16) == (1, 62), 'Expected x86-64 relocatable object')
        require(not any(s['size'] and (s['name'] == '.comment' or s['flags'] & 4)
                        for s in sections(obj)), 'Input contains a producer stamp or code')
        require(section(obj, '.rodata')[1] == (b'RE003\0' if changed else b'RE002\0'), 'Unexpected fixture data')
        if label == 'current_a':
            original_obj = obj
        elif changed:
            diffs = [i for i, (a, b) in enumerate(zip(original_obj, obj)) if a != b]
            require(len(original_obj) == len(obj) and len(diffs) == 1, 'Expected one changed input object byte')
            changed_offset = diffs[0]
        linker, info = toolchains[version]
        link_env = dict(env, LLD_VERSION=OVERRIDE) if override else env
        command([linker, '-flavor', 'gnu', '-shared', '--build-id=sha1', '-o', 'fixture.so', 'fixture.o'],
                cwd=work, env=link_env)
        data = (work / 'fixture.so').read_bytes()
        require(struct.unpack_from('<HH', data, 16) == (3, 62), 'Expected x86-64 ELF shared object')
        require(section(data, '.rodata')[1] == section(obj, '.rodata')[1], 'Output payload changed')
        stamp = OVERRIDE if override else 'Linker: ' + info['version']
        require([s for _, s in c_strings(section(data, '.comment')[1])] == [stamp], 'Unexpected output stamp')
        results[label] = dict(release=version, object_sha256=digest(obj), elf_sha256=digest(data),
                              gnu_build_id=build_id(data), stamp=stamp)
    return dict(assembler=command([assembler, '--version']).splitlines()[0], fixture_sha256=digest(source),
                changed_object_file_offset=changed_offset, toolchains={v: info for v, (_, info) in toolchains.items()}, cases=results)


def check_controls(result):
    cases = result['fixture']['cases']
    current = cases['current_a']
    require(cases['current_b'] == current, 'Repeat link differs')
    for label in ('older', 'changed_stamp'):
        require(cases[label]['object_sha256'] == current['object_sha256'], f'Changed input object in {label}')
        require(cases[label]['stamp'] != current['stamp'], f'Missing stamp contrast in {label}')
    changed = cases['changed_input']
    require(changed['object_sha256'] != current['object_sha256'] and changed['stamp'] == current['stamp'],
            'Missing single-byte input contrast')
    require(cases['changed_stamp']['stamp'] == OVERRIDE, 'Unexpected override marker')
    for key in ('elf_sha256', 'gnu_build_id'):
        require(len({row[key] for row in cases.values()}) == 4, f'Missing {key} contrast')
    candidate = result['linux_distribution']
    capture_stamp = result['capture']['stamp']
    require(candidate['prefix'] + candidate['version'] == capture_stamp, 'Linux candidate stamp differs')
    for version, info in result['fixture']['toolchains'].items():
        commit, llvm, revision = RUST[version]
        require((info['rustc_commit'], info['llvm_revision']) == (commit, revision), 'Incorrect toolchain pins')
        label = 'current_a' if version == '1.95.0' else 'older'
        require(cases[label]['stamp'] == 'Linker: ' + info['version']
                and info['version'].startswith('LLD ' + llvm + ' (') and info['version'].endswith(' ' + revision + ')'),
                f'Incorrect native linker stamp for {version}')
    current_tool = result['fixture']['toolchains']['1.95.0']
    if current_tool['host'] == TARGET:
        require(current_tool['rust_lld_sha256'] == LINUX_LINKER_SHA and current['stamp'] == capture_stamp,
                'Linux-hosted link differs from distribution candidate')
    require(result['capture']['gnu_build_id'] not in {c['gnu_build_id'] for c in cases.values()},
            'Unexpected equality with node build ID')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--archive', type=Path, help='Pinned official Linux rustc 1.95.0 archive')
    parser.add_argument('--replay', action='store_true', help='Perform five fresh fixture links')
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--output', type=Path, help='Write replay evidence')
    args = parser.parse_args()
    retained = json.loads((HERE / 'result.json').read_text()) if not args.replay else None
    target = capture(args.node)
    if args.replay:
        require(args.archive is not None, 'Replay requires --archive')
        candidate = linux_candidate(args.archive, target['stamp'])
        with tempfile.TemporaryDirectory(prefix='re002-lld-') as tmp:
            fixture = link_cases(Path(tmp), args.clang)
        result = dict(capture=target, linux_distribution=candidate, fixture=fixture)
        check_controls(result)
        encoded = json.dumps(result, indent=2) + '\n'
        if args.output:
            args.output.write_text(encoded)
        else:
            print(encoded, end='')
    else:
        require(args.output is None, '--output requires --replay')
        require(retained['capture'] == target, 'Changed capture evidence')
        require(retained['fixture']['fixture_sha256'] == digest((HERE / 'fixture.s').read_bytes()), 'Changed fixture')
        require(retained['linux_distribution']['archive_sha256'] == ARCHIVE_SHA
                and retained['linux_distribution']['member_sha256'] == LINUX_LINKER_SHA, 'Changed archive pins')
        if args.archive:
            require(linux_candidate(args.archive, target['stamp']) == retained['linux_distribution'],
                    'Changed distribution evidence')
        check_controls(retained)
        print('Verified node #115 capture and retained linker controls.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        sys.exit(str(exc))

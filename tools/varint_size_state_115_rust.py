"""Replay new node115 native size-state evidence, then compare independently authored Rust."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-005-varint-size-state-rust-115'
COMPONENT = ROOT / 'src/node115-varint-size-state'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def build(rustc, output):
    need(not output.exists(), 'output must be new')
    output.mkdir(parents=True)
    replay = output / 'native-replay'
    subprocess.run([sys.executable, str(ROOT / 'tools/varint_size_state_115_freeze.py'), str(replay)], check=True)
    for file in ('owners.json', 'native-controls.json'):
        need((replay / file).read_bytes() == (PACKET / file).read_bytes(), 'native evidence differs: ' + file)
    freeze = json.loads((PACKET / 'FREEZE.json').read_text())
    need(not freeze['new115_source_exists'], 'expected pre115source freeze')
    current = json.loads((replay / 'FREEZE.json').read_text())
    for field in freeze:
        if field != 'new115_source_exists':
            need(current[field] == freeze[field], 'freeze differs: ' + field)
    inputs = (replay / 'inputs.tsv').read_bytes(); expected = (replay / 'expected.tsv').read_bytes()
    need(sha(inputs) == freeze['input_sha256'] and sha(expected) == freeze['expected_sha256'], 'frozen corpus differs')
    version = subprocess.check_output([str(rustc), '-Vv'], text=True)
    need(version.startswith('rustc 1.94.1 ('), 'pinned compiler required')
    commands = []

    def run(argv, **kw):
        argv = list(map(str, argv)); commands.append(argv)
        return subprocess.run(argv, capture_output=True, text=True, **kw)

    def compile_library(source, folder, opt):
        folder.mkdir()
        lib = folder / 'libnode115_varint_size_state.rlib'
        p = run([rustc, '--edition=2021', '--crate-name', 'node115_varint_size_state', '--crate-type', 'rlib',
                 '-C', f'opt-level={opt}', '-C', 'codegen-units=1', '-C', 'overflow-checks=on',
                 '-D', 'warnings', source, '-o', lib])
        need(p.returncode == 0, p.stderr)
        exe = folder / 'driver'
        p = run([rustc, '--edition=2021', '-D', 'warnings', COMPONENT / 'input_only_driver.rs',
                 '--extern', f'node115_varint_size_state={lib}', '-o', exe])
        need(p.returncode == 0, p.stderr)
        p = run([exe], input=inputs.decode()); need(p.returncode == 0, p.stderr)
        (folder / 'stdout.tsv').write_text(p.stdout)
        return lib, p.stdout.encode()

    def smoke(source, folder):
        exe = folder / 'smoke'
        p = run([rustc, '--edition=2021', '--test', '-D', 'warnings', source, '-o', exe])
        need(p.returncode == 0, p.stderr)
        p = run([exe]); (folder / 'smoke-output.txt').write_text(p.stdout + p.stderr)
        return p.returncode

    profiles = {}
    for opt in (0, 3):
        folder = output / f'o{opt}'; lib, answer = compile_library(COMPONENT / 'lib.rs', folder, opt)
        need(answer == expected, 'compiled Rust differs')
        need(smoke(COMPONENT / 'lib.rs', folder) == 0, 'native smoke failed')
        profiles[str(opt)] = {'rows': freeze['rows'], 'match': True, 'stdout_sha256': sha(answer)}
    source = (COMPONENT / 'lib.rs').read_text(); controls = []
    for name, before, after in [
        ('marker-precommit', '    *counter = marked;', '    // omit marker precommit'),
        ('payload-charge', 'marked.checked_add(length - 1)', 'marked.checked_add(length)'),
        ('marker-charge', 'counter.checked_add(1)', 'counter.checked_add(0)'),
        ('threshold', 'value < 251', 'value < 250')]:
        need(source.count(before) == 1, 'compiled mutation binding')
        folder = output / ('mutant-' + name); folder.mkdir()
        changed = folder / 'lib.rs'; changed.write_text(source.replace(before, after))
        (folder / 'target-smoke.tsv').write_bytes((COMPONENT / 'target-smoke.tsv').read_bytes())
        _, answer = compile_library(changed, folder / 'build', 3)
        actual = answer.splitlines(); wanted = expected.splitlines()
        mismatch = sum(a != b for a, b in zip(actual, wanted))
        need(len(actual) == len(wanted) and mismatch > 0, 'compiled mutant escaped')
        code = smoke(changed, folder); need(code != 0, 'compiled mutant passed frozen smoke')
        controls.append({'name': name, 'mismatches': mismatch, 'smoke_exit': code})
    repeat, answer = compile_library(COMPONENT / 'lib.rs', output / 'o3-repeat', 3)
    raw = (output / 'o3/libnode115_varint_size_state.rlib').read_bytes()
    need(raw == repeat.read_bytes() and answer == expected, 'own repeat differs')
    report = {'freeze_commit': 'a45e9f33', 'profiles': profiles, 'compiled_mutants': controls,
              'raw_own_rlib_equal': True, 'source_sha256': sha(source.encode()), 'rlib_sha256': sha(raw),
              'rustc': version, 'commands': commands, 'captured_process_executed': False, 'helper_calls': 0}
    (output / 'build-result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('profiles', 'compiled_mutants', 'raw_own_rlib_equal')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build(args.rustc, args.output)

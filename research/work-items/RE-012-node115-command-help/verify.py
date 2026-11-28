"""Compare source-built, offline command help to the pinned node 115 descriptors."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from entry_start_static import TARGET, read, rip_target
from fde_extents import eh_frame_records

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
PACKETS = ROOT / 'research/work-items'
FACTORY = 'RE-012-node115-cli-command-factory'
COMMON = 'RE-012-node115-cli-common-settings'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def records(packet):
    record = json.loads((PACKETS / packet / 'records.json').read_text())
    require(record['targetSHA256'] == SHA, f'{packet}: different target')
    return record


def target_evidence():
    data = TARGET.read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA, 'different #115 capture')
    _, fdes = eh_frame_records(data)
    require(any(r['start'] == 0x1637ae0 and r['end'] == 0x16382b7 for r in fdes),
            'missing help builder FDE')
    for site, opcode, dest, literal in [
        (0x1637c55, '48 8d 0d', 0x46cb8a, b'Prints help information'),
        (0x16380dd, '48 8d 05', 0x46cbd2, b'Prints this message or the help of the given subcommand(s)'),
    ]:
        require(read(data, site, 3)[1] == bytes.fromhex(opcode) and rip_target(data, site, 3) == dest,
                f'changed description reference at {site:#x}')
        require(read(data, dest, len(literal))[1] == literal, f'changed help descriptor at {dest:#x}')
    for site, raw in [
        (0x1637c5c, 'ba 17 00 00 00'),                          # first description length
        (0x163801e, 'c7 00 68 65 6c 70'),                       # generated command name "help"
        (0x16380e4, '48 89 84 24 98 02 00 00'),                 # second description pointer
        (0x16380ec, '48 c7 84 24 a0 02 00 00 3a 00 00 00'),     # second length, 58
    ]:
        expected = bytes.fromhex(raw)
        require(read(data, site, len(expected))[1] == expected, f'changed builder at {site:#x}')


def source_binary(tree):
    args = ['cargo', 'build', '--offline', '--locked', '--manifest-path',
            str(tree / 'src/hl-node/Cargo.toml'), '--bin', 'hl-node', '--message-format=json']
    result = subprocess.run(args, cwd=tree, stdout=subprocess.PIPE, text=True, check=True)
    reports = [json.loads(line) for line in result.stdout.splitlines()]
    files = [r['executable'] for r in reports if r['reason'] == 'compiler-artifact'
             and r['target']['name'] == 'hl-node' and r.get('executable')]
    require(len(files) == 1, 'no unique Cargo-built hl-node executable')
    return files[0]


def option_lines(output):
    return {line.strip() for line in output.splitlines() if line.startswith('    -')}


def expected_line(name, raw):
    return '--' + name + {'0x404': '', '0x424': ' <VALUE>', '0x425': ' <VALUE> (required)'}[raw]


def audit(binary, factory, common):
    commands = [row['name'] for row in factory['commands']]
    required = {name: {'-h, --help', '-V, --version'} for name in commands}
    for row in factory['arguments']:
        required[row['command']].add(expected_line(row['argument'], row['rawFlags']))
    for name in ('run-validator', 'run-non-validator'):
        required[name].update(expected_line(row['longName'], row['initialFlags'])
                              for row in common['options'])
        # These three switches belong to the reconstructed workspace.
        required[name].update({'--dry-run', '--http-bind <VALUE>', '--data-dir <VALUE>'})
    equal = matches = 0
    for name in commands:
        args = [(name, '--help'), (name, '-h'), ('help', name)]
        outputs = [subprocess.run([binary, *tokens], capture_output=True, text=True)
                   for tokens in args]
        good = all(p.returncode == 0 and not p.stderr for p in outputs)
        same = good and len({p.stdout for p in outputs}) == 1
        equal += int(same)
        matches += sum(p.returncode == 0 and not p.stderr and
                       option_lines(p.stdout) == required[name] for p in outputs)
    total = len(commands)
    print(f'commands with three identical successful help forms: {equal}/{total}')
    print(f'help outputs with exactly the selected descriptor set: {matches}/{3 * total}')
    require(len(factory['arguments']) == 24 and len(common['options']) == 14 and total == 14,
            'command descriptor denominator changed')
    require(equal == total and matches == 3 * total, 'rendered help differs from descriptors')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-tree', type=Path, default=ROOT,
                        help='repository root or extracted src tree containing src/hl-node/Cargo.toml')
    args = parser.parse_args()
    target_evidence()
    audit(source_binary(args.source_tree.resolve()), records(FACTORY), records(COMMON))

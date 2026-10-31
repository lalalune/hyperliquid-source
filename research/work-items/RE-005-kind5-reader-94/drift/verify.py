#!/usr/bin/env python3
"""Check packet/source bindings and retain a fresh two-decoder drift comparison."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
PACKET = HERE.parent
ROOT = HERE.parents[3]
SOURCES = {
    'tools/kind5_release_drift.py', 'tools/kind5_reader.py', 'tools/bincode_varint.py',
    'tests/test_kind5_release_drift.py',
    'research/work-items/RE-005-kind5-reader-94/drift/README.md',
    'research/work-items/RE-005-kind5-reader-94/drift/verify.py',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.is_relative_to(PACKET), 'fresh output must be outside the retained packet')
    members = {}
    for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
        expected, name = line.split('  ', 1)
        path = PACKET / name
        require(name not in members and not Path(name).is_absolute() and '..' not in Path(name).parts,
                'invalid or duplicate packet member')
        require(path.is_file() and not path.is_symlink() and digest(path) == expected,
                'packet member differs: ' + name)
        members[name] = expected
    actual = {p.relative_to(PACKET).as_posix() for p in PACKET.rglob('*') if p.is_file()}
    require(actual == set(members) | {'MANIFEST.sha256'}, 'packet membership differs')
    sources = json.loads((HERE / 'source-sha256.json').read_text())
    require(set(sources) == SOURCES, 'compared source set differs')
    for name, expected in sources.items():
        require(digest(ROOT / name) == expected, 'compared source differs: ' + name)
    subprocess.run([sys.executable, '-B', str(ROOT / 'tools/kind5_release_drift.py'),
                    '--controls', '--output', str(output)], cwd=ROOT, check=True)
    require((output / 'observations.json').read_bytes() == (HERE / 'observations.json').read_bytes(),
            'fresh correspondence/control observations differ')
    print(json.dumps({'packet_members': len(members), 'source_bindings': 'verified',
                      'fresh_observations': 'equal', 'raw_fresh_output': str(output.relative_to(ROOT))
                      if output.is_relative_to(ROOT) else str(output), 'captured_execution': False}))


if __name__ == '__main__':
    main()

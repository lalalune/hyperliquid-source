#!/usr/bin/env python3
"""Verify a closed manifest whitelist and regenerate the static certificate."""
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_sub256_inplace_borrow as subject

# Fixed names, no glob expansion, manifest-driven imports or arbitrary paths.
WHITELIST = {
    'README.md': HERE / 'README.md',
    'records.json': HERE / 'records.json',
    'verify.py': HERE / 'verify.py',
    'tools/node115_sub256_inplace_borrow.py': ROOT / 'tools/node115_sub256_inplace_borrow.py',
    'tests/test_node115_sub256_inplace_borrow.py': ROOT / 'tests/test_node115_sub256_inplace_borrow.py',
    'tools/elf_index.py': ROOT / 'tools/elf_index.py',
    'tools/fde_extents.py': ROOT / 'tools/fde_extents.py',
}


def check_manifest(text, whitelist=WHITELIST):
    seen = set()
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        subject.demand(match is not None, 'malformed manifest row')
        sha, name = match.groups()
        subject.demand(name in whitelist and name not in seen, 'manifest whitelist violation')
        seen.add(name)
        path = whitelist[name]
        subject.demand(path.is_file() and not path.is_symlink(), 'missing or symlinked manifest file')
        subject.demand(hashlib.sha256(path.read_bytes()).hexdigest() == sha, 'manifest digest mismatch')
    subject.demand(seen == set(whitelist), 'incomplete manifest whitelist')


def check_readme_counts(record, readme):
    marker = '<!-- counts-from-records -->'
    end = '<!-- end-counts -->'
    subject.demand(readme.count(marker) == readme.count(end) == 1, 'README counts markers')
    table = readme.split(marker)[1].split(end)[0].strip()
    expected = '| Metric | Count |\n| --- | ---: |\n' + subject.readme_counts(record)
    subject.demand(table == expected, 'README counts differ from JSON')


def main():
    allowed = {'README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'}
    subject.demand({p.name for p in HERE.iterdir()} == allowed, 'unexpected packet file')
    check_manifest((HERE / 'MANIFEST.sha256').read_text(encoding='utf-8'))
    with tempfile.TemporaryDirectory() as folder:
        record = subject.generate(subject.TARGET, Path(folder))
        subject.demand((Path(folder) / 'records.json').read_bytes() == (HERE / 'records.json').read_bytes(),
                       'regenerated semantic records differ')
    check_readme_counts(record, (HERE / 'README.md').read_text(encoding='utf-8'))
    print('Verified whitelist, input digest, byte-identical records and README counts.')


if __name__ == '__main__':
    main()

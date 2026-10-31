#!/usr/bin/env python3
"""Stdlib-only whitelist, manifest, target facts and regeneration (MIT)."""
import hashlib
import importlib.util
import mmap
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MANIFEST = frozenset({'README.md', 'RESULT.md', 'inventory.json', 'instructions.json', 'verify.py'})
EXPECTED_LOCATIONS = (('0x566a8e8', 24, 67),
 ('0x566a900', 34, 13),
 ('0x566a918', 41, 48),
 ('0x566a930', 15, 71),
 ('0x566a948', 60, 10),
 ('0x566a960', 51, 22),
 ('0x566a978', 44, 16),
 ('0x566c5d8', 24, 67),
 ('0x566c5f0', 34, 13),
 ('0x566c608', 41, 48),
 ('0x566c620', 15, 71),
 ('0x566c638', 60, 10),
 ('0x566c650', 51, 22),
 ('0x566c668', 44, 16),
 ('0x566d568', 24, 67),
 ('0x566d580', 34, 13),
 ('0x566d598', 41, 48),
 ('0x566d5b0', 15, 71),
 ('0x566d5c8', 60, 10),
 ('0x566d5e0', 51, 22),
 ('0x566d5f8', 44, 16))
EXPECTED_FDES = (('0x1449410', '0x1449a79'),
 ('0x1457070', '0x145964f'),
 ('0x1479330', '0x1479999'),
 ('0x1479d30', '0x147bfb3'),
 ('0x14abd40', '0x14ac3a9'),
 ('0x14b23d0', '0x14b4b89'))
EXPECTED_EDGES = (('0x14586cf', '0x1457070', '0x1449410'),
 ('0x145935c', '0x1457070', '0x1449410'),
 ('0x147b2e9', '0x1479d30', '0x1479330'),
 ('0x147bbb9', '0x1479d30', '0x1479330'),
 ('0x14b3951', '0x14b23d0', '0x14abd40'),
 ('0x14b3c2d', '0x14b23d0', '0x14abd40'))
EXPECTED_METRICS = {'constants_bound': 0,
 'constants_unresolved': 2,
 'decoded_instructions': 6272,
 'diagnostics_absent': 3,
 'diagnostics_bound': 5,
 'diagnostics_probed': 12,
 'diagnostics_unresolved': 4,
 'indirect_calls_unresolved': 382,
 'indirect_jumps_unresolved': 17,
 'internal_rel32_calls': 0,
 'internal_rel32_jumps': 331,
 'location_leas': 27,
 'locations': 21,
 'pointer_length_anchors': 15,
 'scoped_fde_bytes': 33622,
 'scoped_fdes': 6,
 'scoped_rel32_calls': 6,
 'scoped_rel32_jumps': 0,
 'unique_line_column': 7,
 'unresolved_external_rel32_calls': 224,
 'unresolved_external_rel32_jumps': 0}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def verify_manifest(here):
    actual = set()
    for path in here.iterdir():
        check(not path.is_symlink(), f'symlink in packet: {path.name}')
        # Python import cache is transient and contains no packet evidence.
        if path.name == '__pycache__' and path.is_dir():
            check(all(p.is_file() and not p.is_symlink() and p.suffix == '.pyc' for p in path.iterdir()),
                  'unexpected import cache contents')
            continue
        check(path.is_file(), f'unexpected directory: {path.name}')
        actual.add(path.name)
    check(actual == MANIFEST | {'MANIFEST.sha256'}, 'packet file whitelist differs')
    raw = (here/'MANIFEST.sha256').read_text(encoding='ascii')
    check(raw.endswith('\n'), 'manifest lacks final newline')
    entries = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        check(match is not None, 'malformed manifest entry')
        digest, name = match.groups()
        check(name in MANIFEST and name not in entries, 'unexpected or duplicate manifest member')
        entries[name] = digest
    check(set(entries) == MANIFEST, 'manifest omits required file')
    for name, digest in entries.items():
        check(hashlib.sha256((here/name).read_bytes()).hexdigest() == digest, f'manifest mismatch: {name}')


def load_tool():
    spec = importlib.util.spec_from_file_location('slack_alert_inventory', ROOT/'tools/slack_alert_inventory.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def verify_docs(here, tool, evidence):
    tables = tool.evidence_tables(evidence)
    expected = {'README.md': ('METRICS', 'LOCATIONS', 'FDES'),
                'RESULT.md': ('METRICS', 'LITERALS', 'EDGES', 'CONSTANTS')}
    for name, tags in expected.items():
        text = (here/name).read_text(encoding='utf-8')
        blocks = re.findall(r'<!-- BEGIN GENERATED ([A-Z]+) -->.*?<!-- END GENERATED \1 -->', text, re.S)
        check(blocks == list(tags), f'derived report blocks differ: {name}')
        for tag in tags:
            blocks = re.findall(f'<!-- BEGIN GENERATED {tag} -->.*?<!-- END GENERATED {tag} -->', text, re.S)
            check(blocks == [tables[tag]], f'derived metrics/facts differ: {name}/{tag}')


def verify_facts(evidence):
    actual = tuple((x['va'], x['line'], x['column']) for x in evidence['locations'])
    check(actual == EXPECTED_LOCATIONS, 'pinned Location layout differs')
    check(evidence['scope_rule'] == 'base/src/slack_alert.rs', 'scope differs')
    check(evidence['metrics'] == EXPECTED_METRICS, 'pinned counts differ')
    check(tuple((f['start'], f['end_exclusive']) for f in evidence['fdes']) == EXPECTED_FDES,
          'pinned FDE ranges differ')
    check(tuple((e['instruction']['va'], e['caller'], e['callee']) for e in evidence['call_edges']) == EXPECTED_EDGES,
          'pinned call edges differ')
    check(evidence['method']['all_fde_records_checked'] == 121299, 'FDE inventory differs')
    for edge in evidence['call_edges']:
        check(edge['caller'] in {f['start'] for f in evidence['fdes']} and
              edge['callee'] in {f['start'] for f in evidence['fdes']}, 'edge endpoint differs')


def verify_outputs(here, tool, result):
    for name in tool.OUTPUTS:
        check(tool.render(result[name]) == (here/name).read_bytes(), f'regeneration differs: {name}')
    verify_facts(result['inventory.json'])
    verify_docs(here, tool, result['inventory.json'])


def main():
    verify_manifest(HERE)
    tool = load_tool()
    with (ROOT/tool.TARGET).open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result = tool.build(data)
    verify_outputs(HERE, tool, result)
    print('PASS: whitelist, manifest, node #94 digest, exact regeneration, target facts and derived report counts')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        sys.exit(f'FAIL: {exc}')

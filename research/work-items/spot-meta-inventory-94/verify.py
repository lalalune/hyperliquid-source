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
EXPECTED_LOCATIONS = (('0x5690308', 565, 25), ('0x56bb188', 565, 25), ('0x56bd208', 565, 25), ('0x56d4e10', 565, 25), ('0x56df828', 565, 25), ('0x56f1fd8', 565, 25), ('0x56f21f0', 113, 33), ('0x56f2208', 119, 37), ('0x56f2240', 1005, 69), ('0x56f2258', 984, 9), ('0x56f2270', 1199, 57), ('0x5714c70', 565, 25), ('0x571ca98', 565, 25), ('0x571fd18', 565, 25), ('0x573dfc8', 565, 25), ('0x5742350', 565, 25), ('0x5744640', 565, 25))


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
    spec = importlib.util.spec_from_file_location('spot_meta_inventory', ROOT/'tools/spot_meta_inventory.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def verify_docs(here, tool, metrics):
    for name in ('README.md', 'RESULT.md'):
        text = (here/name).read_text(encoding='utf-8')
        blocks = re.findall(r'<!-- BEGIN GENERATED METRICS -->.*?<!-- END GENERATED METRICS -->', text, re.S)
        check(blocks == [tool.metric_table(metrics)], f'derived metrics differ: {name}')


def verify_facts(evidence):
    actual = tuple((x['va'], x['line'], x['column']) for x in evidence['locations'])
    check(actual == EXPECTED_LOCATIONS, 'pinned Location layout differs')
    check(evidence['scope_rule'] == 'l1/src/spot_meta.rs', 'scope differs')
    metrics = evidence['metrics']
    expected = {'locations': 17, 'location_leas': 599, 'scoped_fdes': 333,
                'diagnostics_bound': 8, 'diagnostics_unresolved': 2, 'diagnostics_absent': 2,
                'constants_bound': 0, 'constants_unresolved': 6,
                'scoped_rel32_calls': 269, 'scoped_rel32_jumps': 1}
    check(all(metrics[k] == v for k, v in expected.items()), 'pinned counts differ')
    check(evidence['method']['all_fde_records_checked'] == 121299, 'FDE inventory differs')
    for edge in evidence['call_edges']:
        check(edge['caller'] in {f['start'] for f in evidence['fdes']} and
              edge['callee'] in {f['start'] for f in evidence['fdes']}, 'edge endpoint differs')


def verify_outputs(here, tool, result):
    for name in tool.OUTPUTS:
        check(tool.render(result[name]) == (here/name).read_bytes(), f'regeneration differs: {name}')
    verify_facts(result['inventory.json'])
    verify_docs(here, tool, result['inventory.json']['metrics'])


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

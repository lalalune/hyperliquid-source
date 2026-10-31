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
EXPECTED_LOCATIONS = (
    ('0x569ed68', 58, 22), ('0x569ed80', 93, 13), ('0x569ed98', 98, 40),
    ('0x571d1b0', 311, 5), ('0x571d1c8', 223, 13), ('0x571d1e0', 219, 108),
    ('0x571d1f8', 144, 93), ('0x571d210', 198, 45), ('0x571d228', 187, 37),
    ('0x571d240', 262, 21), ('0x571d258', 287, 17), ('0x571d270', 279, 108),
    ('0x572f088', 223, 13), ('0x572f0a0', 219, 108), ('0x572f0b8', 138, 93),
    ('0x572f0d0', 144, 93), ('0x572f0e8', 198, 45), ('0x572f100', 187, 37),
    ('0x572f118', 179, 47), ('0x5738770', 311, 18), ('0x5738788', 324, 21),
    ('0x57387a0', 223, 13), ('0x57387b8', 219, 108), ('0x57387d0', 138, 93),
    ('0x57387e8', 144, 93), ('0x5738800', 198, 45), ('0x5738818', 187, 37),
    ('0x5738830', 179, 47),
)
EXPECTED_EDGES = (
    ('0x439baf0', '0x439c9b2', 'e8e932fcff', '0x435fca0'),
    ('0x439baf0', '0x439d2e9', 'e882bdfeff', '0x4389070'),
    ('0x4759970', '0x475aebd', 'e8aee1c2ff', '0x4389070'),
    ('0x4759970', '0x475fa08', 'e89302c0ff', '0x435fca0'),
    ('0x4b3c880', '0x4b3d37f', 'e81c2982ff', '0x435fca0'),
    ('0x4b3c880', '0x4b3db72', 'e8f9b484ff', '0x4389070'),
)


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
    spec = importlib.util.spec_from_file_location('nv_stream_inventory', ROOT/'tools/nv_stream_inventory.py')
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
    check(evidence['scope_rule'] == 'node/src/nv_stream.rs', 'scope differs')
    actual = tuple((e['caller'], e['instruction']['va'], e['instruction']['bytes'], e['callee'])
                   for e in evidence['call_edges'])
    check(actual == EXPECTED_EDGES, 'pinned rel32 edges differ')
    check(evidence['metrics']['location_leas'] == 40 and evidence['metrics']['scoped_fdes'] == 10,
          'LEA/FDE census differs')
    check(evidence['method']['all_fde_records_checked'] == 121299, 'FDE inventory differs')
    check({c['value'] for c in evidence['constants'] if c['status'] == 'bound'} == {5000, 8000000},
          'constant binding changed')
    check({d['probe'] for d in evidence['diagnostics'] if d['status'] == 'absent'} == {
        'got client blocks', 'no client blocks returned', 'nv stream execution state unavailable',
        'client block parent round mismatch'}, 'negative diagnostic probes changed')


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

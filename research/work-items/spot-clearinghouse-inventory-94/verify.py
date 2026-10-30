#!/usr/bin/env python3
"""Fail-closed packet whitelist, manifest, regeneration and target fact checks."""
import hashlib
import importlib.util
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MANIFEST = frozenset({'README.md', 'RESULT.md', 'inventory.json', 'disassembly.json', 'verify.py'})
EXPECTED_METRICS = {
    'constants_bound': 1, 'constants_unresolved': 1,
    'counted_prefix_anchors': 1, 'diagnostics_bound': 2, 'diagnostics_unresolved': 12,
    'location_leas': 27, 'locations': 17,
    'locations_by_basename': {'cl_trait.rs': 12, 'impl_outcome.rs': 3,
                             'spot_clearinghouse.rs': 1, 'types.rs': 1},
    'ptr_length_anchors': 8, 'ptr_length_anchors_with_same_call_scoped_location': 7,
    'reference_diagnostics_bound': 1, 'reference_diagnostics_probed': 12,
    'scoped_fde_bytes': 30475, 'scoped_fdes': 15, 'scoped_rel32_edges': 3,
    'unique_path_line_column': 16, 'unowned_location_lea_candidates': 0,
}
EXPECTED_EDGES = (
    ('0x3721780', '0x3721beb', 'e830b5ffff', '0x371d120'),
    ('0x372b9d0', '0x372c196', 'e805574d00', '0x3c018a0'),
    ('0x372e0a0', '0x372e392', 'e809354d00', '0x3c018a0'),
)


def check(condition, message):
    if not condition:
        raise ValueError(message)


def verify_manifest(here):
    actual = set()
    for path in here.iterdir():
        check(not path.is_symlink(), f'symlink in packet: {path.name}')
        if path.name == '__pycache__' and path.is_dir():
            continue
        check(path.is_file(), f'unexpected directory: {path.name}')
        actual.add(path.name)
    check(actual == MANIFEST | {'MANIFEST.sha256'}, 'packet file whitelist differs')
    raw = (here / 'MANIFEST.sha256').read_text(encoding='ascii')
    check(raw.endswith('\n'), 'manifest lacks final newline')
    entries = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        check(match is not None, 'malformed manifest entry')
        digest, name = match.groups()
        check(name in MANIFEST and name not in entries, f'unexpected/duplicate manifest member: {name}')
        entries[name] = digest
    check(set(entries) == MANIFEST, 'manifest omits required file')
    for name, digest in entries.items():
        check(hashlib.sha256((here / name).read_bytes()).hexdigest() == digest,
              f'manifest mismatch: {name}')


def load_tool():
    spec = importlib.util.spec_from_file_location('spot_clearinghouse_inventory', ROOT / 'tools/spot_clearinghouse_inventory.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def verify_facts(evidence):
    check(evidence['metrics'] == EXPECTED_METRICS, 'pinned metrics differ')
    check(evidence['method']['all_fde_records_checked'] == 121299, 'FDE inventory differs')
    check(evidence['scope_rule'] == 'l1/src/spot_clearinghouse/*', 'scope differs')
    actual = tuple((e['caller'], e['instruction']['va'], e['instruction']['bytes'], e['callee'])
                   for e in evidence['call_edges'])
    check(actual == EXPECTED_EDGES, 'pinned rel32 edges differ')
    diagnostics = {d['id']: d for d in evidence['diagnostics']}
    prefix = diagnostics['balance_total']['anchors']
    check(len(prefix) == 1 and prefix[0]['site']['va'] == '0x3308cd3'
          and prefix[0]['anchor'] == '0x1f5631' and prefix[0]['length'] == 56,
          'counted diagnostic prefix differs')
    check({d['id'] for d in evidence['diagnostics'] if d['status'] == 'bound'} ==
          {'balance_total', 'result_unwrap'}, 'diagnostic claim expanded')
    constant = evidence['constants'][0]
    check(constant['value'] == 1.01 and len(constant['occurrences']) == 1
          and constant['occurrences'][0]['va'] == '0x20a528'
          and len(constant['scoped_operands']) == 7, 'unique constant binding differs')
    check(evidence['constants'][1]['status'] == 'unresolved'
          and len(evidence['constants'][1]['occurrences']) == 11, 'nonunique constant promoted')


def main():
    verify_manifest(HERE)
    tool = load_tool()
    results = tool.build((ROOT / tool.TARGET).read_bytes())
    for name in tool.OUTPUTS:
        check(tool.render(results[name]) == (HERE / name).read_bytes(), f'regeneration differs: {name}')
    verify_facts(results['inventory.json'])
    print('PASS: manifest whitelist, node #94 digest, byte-identical regeneration, pinned census/anchors/edges')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        sys.exit(f'FAIL: {exc}')

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
EXPECTED_LOCATIONS = (('0x5692d40', 16, 17), ('0x5692d58', 96, 9), ('0x5692d70', 60, 25), ('0x5692d88', 102, 89), ('0x569e7f8', 168, 88), ('0x569e810', 118, 9), ('0x569e828', 115, 17), ('0x569e840', 134, 17), ('0x569e858', 151, 13), ('0x571d018', 168, 88), ('0x571d030', 118, 9), ('0x571d048', 115, 17), ('0x571d060', 134, 17), ('0x571d078', 151, 13), ('0x572ee48', 168, 88), ('0x572ee60', 118, 9), ('0x572ee78', 115, 17), ('0x572ee90', 134, 17), ('0x572eea8', 151, 13), ('0x57385d8', 168, 88), ('0x57385f0', 118, 9), ('0x5738608', 115, 17), ('0x5738620', 134, 17), ('0x5738638', 151, 13))
EXPECTED_EDGES = (('0x1fd6300', '0x1fd64d8', 'e833130000', '0x1fd7810'), ('0x1fd6300', '0x1fd70a9', 'e862070000', '0x1fd7810'))


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
    spec = importlib.util.spec_from_file_location('evm_kvs_inventory', ROOT/'tools/evm_kvs_inventory.py')
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
    check(evidence['scope_rule'] == 'node/src/evm_kvs.rs', 'scope differs')
    actual = tuple((e['caller'], e['instruction']['va'], e['instruction']['bytes'], e['callee'])
                   for e in evidence['call_edges'])
    check(actual == EXPECTED_EDGES, 'pinned rel32 edges differ')
    check(evidence['metrics']['location_leas'] == 38 and evidence['metrics']['scoped_fdes'] == 7,
          'LEA/FDE census differs')
    check(evidence['method']['all_fde_records_checked'] == 121299, 'FDE inventory differs')
    check({d['probe'] for d in evidence['diagnostics'] if d['status'] == 'absent'} == {'rocksdb bug'}, 'negative diagnostic probes changed')
    check(not any(c['status'] == 'bound' for c in evidence['constants']), 'constant binding changed')


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

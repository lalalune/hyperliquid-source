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
EXPECTED_LOCATIONS = (('0x571d090', 248, 108),
 ('0x572eef0', 90, 61),
 ('0x572ef08', 103, 66),
 ('0x572ef20', 106, 56),
 ('0x572ef38', 115, 66),
 ('0x572ef50', 119, 17),
 ('0x5738698', 203, 31),
 ('0x57386b0', 184, 109),
 ('0x57386c8', 119, 30))
EXPECTED_FDES = (('0x43848f0', '0x4386a36'),
 ('0x47b05f0', '0x47b0b43'),
 ('0x47b3f50', '0x47b494c'),
 ('0x4b33eb0', '0x4b363ae'))
EXPECTED_EDGES = (('0x4b35337', '0x4b33eb0', '0x43848f0'),)
EXPECTED_METRICS = {'constants_bound': 0,
 'constants_unresolved': 2,
 'decoded_instructions': 4024,
 'diagnostics_absent': 0,
 'diagnostics_bound': 14,
 'diagnostics_probed': 22,
 'diagnostics_unresolved': 8,
 'indirect_calls_unresolved': 238,
 'indirect_jumps_unresolved': 21,
 'internal_rel32_calls': 0,
 'internal_rel32_jumps': 208,
 'location_leas': 14,
 'locations': 9,
 'pointer_length_anchors': 14,
 'scoped_fde_bytes': 21907,
 'scoped_fdes': 4,
 'scoped_rel32_calls': 1,
 'scoped_rel32_jumps': 0,
 'unique_line_column': 9,
 'unresolved_external_rel32_calls': 119,
 'unresolved_external_rel32_jumps': 0}
EXPECTED_SEEDS = (('0x43848f0', True, True),
 ('0x4553910', True, False),
 ('0x4553eb0', True, False),
 ('0x47b05f0', True, True),
 ('0x47b3f50', True, True),
 ('0x4b33eb0', True, True))
EXPECTED_DIAGNOSTICS = (('make_rpc_request_get_node_ip', 'bound', ('0x4384b27',)),
 ('node_rpc_request', 'bound', ('0x4384cf9',)),
 ('BUG: unknown validator: ', 'present-but-unbound', ()),
 ('client blocks first=', 'present-but-unbound', ()),
 ('@@ finished bootstrap @@ [start_round: ', 'present-but-unbound', ()),
 ('rpc_clone_main_validators', 'bound', ('0x4b3435e',)),
 ('Peer response', 'bound', ('0x4b35b11',)),
 ('Peer timed out', 'bound', ('0x4b3566a',)),
 ('rpc_task_get_peers', 'bound', ('0x4b348da',)),
 ('Rpc task inbound', 'bound', ('0x4b34126',)),
 ('Rpc task outbound', 'bound', ('0x4b33f58',)),
 ('Rpc task response', 'bound', ('0x4b35d42',)),
 ('Rpc task size stats', 'bound', ('0x47b42fd',)),
 ('hash_to_tx', 'bound', ('0x47b4318',)),
 ('hash_to_block', 'bound', ('0x47b4340',)),
 ('ask_peer', 'bound', ('0x4b3507f',)),
 ('Rpc task failed to send response', 'bound', ('0x4b35f35',)),
 ('Incoming tcp stream', 'present-but-unbound', ()),
 ('Received rpc request', 'present-but-unbound', ()),
 ('send consensus rpc resp', 'present-but-unbound', ()),
 ('Failed to receive response from rpc task', 'present-but-unbound', ()),
 ('/override_consensus_rpc_c_signers.json', 'present-but-unbound', ()))

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
    spec = importlib.util.spec_from_file_location('consensus_rpc_inventory', ROOT/'tools/consensus_rpc_inventory.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def verify_docs(here, tool, evidence):
    tables = tool.evidence_tables(evidence)
    expected = {'README.md': ('METRICS', 'LOCATIONS', 'FDES'),
                'RESULT.md': ('METRICS', 'LITERALS', 'ANCHORS', 'EDGES', 'CONSTANTS')}
    for name, tags in expected.items():
        text = (here/name).read_text(encoding='utf-8')
        blocks = re.findall(r'<!-- BEGIN GENERATED ([A-Z]+) -->.*?<!-- END GENERATED \1 -->', text, re.S)
        check(blocks == list(tags), f'derived report blocks differ: {name}')
        for tag in tags:
            blocks = re.findall(f'<!-- BEGIN GENERATED {tag} -->.*?<!-- END GENERATED {tag} -->', text, re.S)
            check(blocks == [tables[tag]], f'derived metrics/facts differ: {name}/{tag}')


def tool_seeds():
    return load_tool().SEEDS


def verify_facts(evidence):
    actual = tuple((x['va'], x['line'], x['column']) for x in evidence['locations'])
    check(actual == EXPECTED_LOCATIONS, 'pinned Location layout differs')
    check(evidence['scope_rule'] == 'node/src/consensus/rpc.rs', 'scope differs')
    check(evidence['metrics'] == EXPECTED_METRICS, 'pinned counts differ')
    check(tuple((f['start'], f['end_exclusive']) for f in evidence['fdes']) == EXPECTED_FDES,
          'pinned FDE ranges differ')
    check(tuple((e['instruction']['va'], e['caller'], e['callee']) for e in evidence['call_edges']) == EXPECTED_EDGES,
          'pinned call edges differ')
    check(tuple((x['address'], x['fde_start'], x['references_scoped_location'])
                for x in evidence['seed_checks']) == EXPECTED_SEEDS, 'seed checks differ')
    check(tuple((x['probe'], x['status'], tuple(a['lea']['va'] for a in x['anchors']))
                for x in evidence['diagnostics']) == EXPECTED_DIAGNOSTICS, 'diagnostic anchors differ')
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

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
EXPECTED_LOCATIONS = (('0x5692de8', 535, 18),
 ('0x5692e00', 543, 50),
 ('0x5692e18', 220, 48),
 ('0x5692e30', 225, 29),
 ('0x569ec90', 535, 5),
 ('0x569eca8', 69, 40),
 ('0x569ecc0', 76, 42),
 ('0x569ecd8', 41, 76),
 ('0x569ecf0', 37, 49),
 ('0x569ed08', 201, 45),
 ('0x569ed20', 192, 65),
 ('0x569ed38', 220, 48),
 ('0x569ed50', 225, 29),
 ('0x56be198', 205, 30),
 ('0x571d0a8', 579, 5),
 ('0x571d0c0', 114, 57),
 ('0x571d0d8', 153, 55),
 ('0x571d0f0', 178, 58),
 ('0x571d108', 302, 52),
 ('0x571d120', 360, 25),
 ('0x571d138', 458, 54),
 ('0x571d150', 463, 36),
 ('0x571d168', 466, 17),
 ('0x572efb0', 114, 57),
 ('0x572efc8', 153, 55),
 ('0x572efe0', 178, 58),
 ('0x572eff8', 302, 52),
 ('0x572f010', 306, 38),
 ('0x572f028', 308, 67),
 ('0x572f040', 360, 25),
 ('0x572f058', 458, 54),
 ('0x572f070', 466, 17),
 ('0x5738710', 579, 18),
 ('0x5738728', 591, 42),
 ('0x5738740', 466, 30))
EXPECTED_FDES = (('0x1fd7d00', '0x1fd85e1'),
 ('0x1fd85f0', '0x1fd8998'),
 ('0x203d330', '0x203e0f8'),
 ('0x226c2d0', '0x22713e1'),
 ('0x227c0c0', '0x227c868'),
 ('0x227c870', '0x227cf46'),
 ('0x22be860', '0x22bf216'),
 ('0x27d6c70', '0x27d6fd0'),
 ('0x435e3d0', '0x435e67a'),
 ('0x438cb90', '0x438d2a7'),
 ('0x4391840', '0x4392387'),
 ('0x43965b0', '0x43988c4'),
 ('0x4399360', '0x4399e76'),
 ('0x4399e80', '0x439a8af'),
 ('0x47b12d0', '0x47b192a'),
 ('0x47b1930', '0x47b1c5e'),
 ('0x47b1ef0', '0x47b3b78'),
 ('0x47b6f90', '0x47b75d1'),
 ('0x47b75e0', '0x47b7cf1'),
 ('0x4b363b0', '0x4b39004'),
 ('0x4b39010', '0x4b39991'))
EXPECTED_EDGES = (('0x203d8ea', '0x203d330', '0x227c870'),
 ('0x203dbc2', '0x203d330', '0x227c0c0'),
 ('0x22beae5', '0x22be860', '0x227c870'),
 ('0x22bedb3', '0x22be860', '0x227c0c0'))
EXPECTED_METRICS = {'constants_bound': 0,
 'constants_unresolved': 3,
 'decoded_instructions': 15212,
 'diagnostics_absent': 0,
 'diagnostics_bound': 19,
 'diagnostics_probed': 26,
 'diagnostics_unresolved': 7,
 'indirect_calls_unresolved': 772,
 'indirect_jumps_unresolved': 41,
 'internal_rel32_calls': 0,
 'internal_rel32_jumps': 518,
 'location_leas': 54,
 'locations': 35,
 'pointer_length_anchors': 22,
 'scoped_fde_bytes': 81294,
 'scoped_fdes': 21,
 'scoped_rel32_calls': 4,
 'scoped_rel32_jumps': 0,
 'unique_line_column': 26,
 'unresolved_external_rel32_calls': 548,
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
    spec = importlib.util.spec_from_file_location('consensus_server_inventory', ROOT/'tools/consensus_server_inventory.py')
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


def tool_seeds():
    return load_tool().SEEDS


def verify_facts(evidence):
    actual = tuple((x['va'], x['line'], x['column']) for x in evidence['locations'])
    check(actual == EXPECTED_LOCATIONS, 'pinned Location layout differs')
    check(evidence['scope_rule'] == 'node/src/consensus/server.rs', 'scope differs')
    check(evidence['metrics'] == EXPECTED_METRICS, 'pinned counts differ')
    check(tuple((f['start'], f['end_exclusive']) for f in evidence['fdes']) == EXPECTED_FDES,
          'pinned FDE ranges differ')
    check(tuple((e['instruction']['va'], e['caller'], e['callee']) for e in evidence['call_edges']) == EXPECTED_EDGES,
          'pinned call edges differ')
    check(all(x['fde_start'] and x['references_scoped_location'] for x in evidence['seed_checks']) and tuple(x['address'] for x in evidence['seed_checks']) == tuple(map(hex, tool_seeds())), 'seed checks differ')
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

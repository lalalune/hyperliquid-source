#!/usr/bin/env python3
"""Offline whitelist, digest, fact and exact-regeneration checks; stdlib only (MIT)."""
import hashlib
import importlib.util
import mmap
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MANIFEST = frozenset({'README.md', 'RESULT.md', 'inventory.json', 'instructions.json', 'verify.py'})
EXPECTED_LOCATIONS = (('0x569dbe8', 368, 25, ('0x220bc1c',)),
 ('0x569dc00', 142, 13, ('0x220b885',)),
 ('0x569dc18', 143, 13, ('0x220b8b0',)),
 ('0x569dc30', 144, 13, ('0x220b8ce',)),
 ('0x569dc48', 147, 17, ('0x220b8f3',)),
 ('0x569dc60', 141, 13, ('0x220b89e',)),
 ('0x569dc88', 259, 41, ('0x220c112',)),
 ('0x569dcb8', 224, 17, ('0x220b91e',)),
 ('0x56e8ae0', 503, 17, ('0x330863b',)),
 ('0x56f3b18', 460, 35, ('0x37e35a4',)),
 ('0x571c860', 368, 25, ('0x42e5b37', '0x42e71d7')),
 ('0x571c878', 142, 13, ('0x42e5863', '0x42e6ef3')),
 ('0x571c890', 143, 13, ('0x42e588e', '0x42e6f1e')),
 ('0x571c8a8', 144, 13, ('0x42e58ac', '0x42e6f3c')),
 ('0x571c8c0', 147, 17, ('0x42e58d1', '0x42e6f61')),
 ('0x571c8d8', 141, 13, ('0x42e587c', '0x42e6f0c')),
 ('0x571c900', 259, 41, ('0x42e760a', '0x42e7bba')),
 ('0x571c930', 286, 17, ('0x432f443',)),
 ('0x571c948', 279, 25, ('0x432f3cc',)),
 ('0x571c960', 224, 17, ('0x42e4d66', '0x42e6430')))
EXPECTED_FDES = (('0x2209d40', '0x220becb', 'e122415e04d22033a6d4e051e9639e93c407e95e7fa583c878cedb2907983105'),
 ('0x220bed0', '0x220c477', '5d012f851027ae4d6b1adedb7bd494d4de7301c0dcb8d115903d3c1ed02dd897'),
 ('0x33084a0', '0x33086f3', '77aa93933a93ddabe2993c106e2ffcd31ca117c65747212c450554799f4b1e45'),
 ('0x37e2960', '0x37e3a6b', '7fc7855c17899fc24fa9c0f37c2af2d23fe113666a91017f352eae2742aebe41'),
 ('0x42e4600', '0x42e5d3b', 'b57a94b6b038af95652e4cb090a35d343c6e1335d632d35b1101ab9027f7a2e5'),
 ('0x42e5d40', '0x42e73ce', 'f27c6f57dec13d44007e7a1acafb0bee2253eb15aa38f00c71ce351107058b4a'),
 ('0x42e73d0', '0x42e797d', '65392f8ad976017d9d1d2f09f53732261e2e08319a466328023e14747714ed9a'),
 ('0x42e7980', '0x42e7f2d', '5d6f8fedb6a0ddbf77e648dd390776e77f4d639abca767c637de6ef9c6203656'),
 ('0x432f310', '0x432f5ed', '2bc1cee7929de30afb2d6d383af783abd5e0d074216ad1a0b42293989de25a00'))
EXPECTED_METRICS = {'anchors_with_local_engine_location': 15,
 'call_edges': 4,
 'constants_bound': 0,
 'constants_unresolved': 5,
 'counted_fragment_anchors': 12,
 'decoded_instructions': 6032,
 'diagnostics_absent': 7,
 'diagnostics_bound': 18,
 'diagnostics_probed': 27,
 'diagnostics_unresolved': 2,
 'location_leas': 28,
 'locations': 20,
 'pointer_length_anchors': 24,
 'prior_owner_overlaps': 5,
 'scoped_fde_bytes': 30352,
 'scoped_fdes': 9,
 'shared_first_party_fdes': 6,
 'tail_edges': 0,
 'unique_line_column': 12}
EXPECTED_EDGES = (('0x220b708', '0x2209d40', '0x220bed0', 'e8c3070000'),
 ('0x37e31cc', '0x37e2960', '0x3bade80', 'e8afac3c00'),
 ('0x42e56bb', '0x42e4600', '0x42e73d0', 'e8101d0000'),
 ('0x42e6d7b', '0x42e5d40', '0x42e7980', 'e8000c0000'))
EXPECTED_DIAGNOSTICS = (('reference-line-33', 'bound', ('0x3308584',)),
 ('reference-line-34', 'bound', ('0x220bf56', '0x42e7456', '0x42e7a06')),
 ('reference-line-35', 'bound', ('0x220bf6c', '0x42e7464', '0x42e7a14')),
 ('reference-line-110', 'absent', ()),
 ('reference-line-111', 'bound', ('0x220b897', '0x42e5875', '0x42e6f05')),
 ('reference-line-405', 'absent', ()),
 ('reference-line-495', 'bound', ('0x220b87e', '0x42e585c', '0x42e6eec')),
 ('reference-line-496', 'absent', ()),
 ('reference-line-497', 'absent', ()),
 ('reference-line-498', 'absent', ()),
 ('reference-line-499', 'absent', ()),
 ('reference-line-509', 'absent', ()),
 ('binary-1', 'bound', ('0x220b8ec', '0x42e58ca', '0x42e6f5a')),
 ('binary-2', 'present-but-unbound', ()),
 ('binary-3', 'bound', ('0x220bb27', '0x42e5a41', '0x42e70e1')),
 ('binary-4', 'bound', ('0x220bb58', '0x42e5a73', '0x42e7113')),
 ('binary-5', 'bound', ('0x220bc15', '0x42e5b30', '0x42e71d0')),
 ('binary-6', 'bound', ('0x220ae9b', '0x42e4e77', '0x42e6541')),
 ('binary-7', 'bound', ('0x220acb4',)),
 ('binary-8', 'bound', ('0x330862f',)),
 ('binary-9', 'bound', ('0x37e3723',)),
 ('binary-10', 'bound', ('0x432f3c5',)),
 ('binary-11', 'bound', ('0x432f43c',)),
 ('binary-12', 'bound', ('0x37e310e',)),
 ('binary-13', 'bound', ('0x37e3141',)),
 ('binary-14', 'bound', ('0x37e3174',)),
 ('binary-15', 'present-but-unbound', ()))


def check(ok, message):
    if not ok: raise ValueError(message)


def verify_manifest(here):
    actual = set()
    for path in here.iterdir():
        check(not path.is_symlink(), 'packet symlink: '+path.name)
        if path.name == '__pycache__' and path.is_dir():
            check(all(p.is_file() and not p.is_symlink() and p.suffix == '.pyc' for p in path.iterdir()), 'unexpected cache content')
            continue
        check(path.is_file(), 'unexpected directory: '+path.name)
        actual.add(path.name)
    check(actual == MANIFEST | {'MANIFEST.sha256'}, 'packet whitelist differs')
    text = (here/'MANIFEST.sha256').read_text(encoding='ascii')
    check(text.endswith('\n'), 'manifest missing final newline')
    entries = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        check(match is not None, 'malformed manifest entry')
        digest, name = match.groups()
        check(name in MANIFEST and name not in entries, 'unexpected/duplicate manifest member')
        entries[name] = digest
    check(set(entries) == MANIFEST, 'manifest omits required file')
    for name, digest in entries.items():
        check(hashlib.sha256((here/name).read_bytes()).hexdigest() == digest, 'manifest hash mismatch: '+name)


def load_tool():
    spec = importlib.util.spec_from_file_location('abci_engine_inventory', ROOT/'tools/abci_engine_inventory.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def verify_facts(e):
    check(e['target']['sha256'] == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f', 'target mismatch')
    check(e['scope_rule'] == 'l1/src/abci/engine.rs', 'scope mismatch')
    check(tuple((x['va'],x['line'],x['column'],tuple(x['lea_sites'])) for x in e['locations']) == EXPECTED_LOCATIONS, 'Location census differs')
    check(tuple((x['start'],x['end_exclusive'],x['code_sha256']) for x in e['fdes']) == EXPECTED_FDES, 'FDE facts differ')
    check(e['metrics'] == EXPECTED_METRICS, 'counts differ')
    check(tuple((x['instruction']['va'],x['caller'],x['callee'],x['instruction']['bytes']) for x in e['call_edges']) == EXPECTED_EDGES, 'entry edges differ')
    check(tuple((x['id'],x['status'],tuple(a['lea']['va'] for a in x['anchors'])) for x in e['diagnostics']) == EXPECTED_DIAGNOSTICS, 'diagnostics differ')
    check(all(c['status'] == 'unresolved' and not c['anchors'] for c in e['constants']), 'constants incorrectly promoted')
    check(e['method']['all_fde_records_checked'] == 121299, 'FDE inventory differs')


def verify_docs(here, tool, e):
    expected = {'README.md': ('METRICS', 'LOCATIONS', 'FDES'),
                'RESULT.md': ('METRICS', 'DIAGNOSTICS', 'ANCHORS', 'EDGES', 'TRANSFERS', 'CONSTANTS')}
    tables = tool.evidence_tables(e)
    for name, tags in expected.items():
        text = (here/name).read_text(encoding='utf-8')
        actual = re.findall(r'<!-- BEGIN GENERATED ([A-Z]+) -->.*?<!-- END GENERATED \1 -->', text, re.S)
        check(actual == list(tags), 'report block membership differs: '+name)
        for tag in tags:
            blocks = re.findall(f'<!-- BEGIN GENERATED {tag} -->.*?<!-- END GENERATED {tag} -->', text, re.S)
            check(blocks == [tables[tag]], 'report facts/counts differ: '+name+'/'+tag)


def verify_outputs(here, tool, result):
    for name in tool.OUTPUTS:
        check(tool.render(result[name]) == (here/name).read_bytes(), 'byte-identical regeneration differs: '+name)
    verify_facts(result['inventory.json'])
    verify_docs(here, tool, result['inventory.json'])


def main():
    verify_manifest(HERE)
    tool = load_tool()
    with (ROOT/tool.TARGET).open('rb') as h, mmap.mmap(h.fileno(),0,access=mmap.ACCESS_READ) as data:
        result = tool.build(data)
    verify_outputs(HERE, tool, result)
    print('PASS: whitelist, hashes, node #94 digest, byte-identical regeneration, pinned facts and derived report counts')


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError) as exc: sys.exit(f'FAIL: {exc}')

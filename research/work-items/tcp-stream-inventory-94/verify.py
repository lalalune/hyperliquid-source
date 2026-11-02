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
EXPECTED_LOCATIONS = (('0x5697298', 45, 80, ('0x203510b', '0x2035118', '0x204878a', '0x2048799')),
 ('0x56972b0', 50, 73, ('0x2048770', '0x204877d')),
 ('0x56972c8', 60, 82, ('0x203673e', '0x203674d')),
 ('0x56972e0', 33, 60, ('0x204899f', '0x20489ac')),
 ('0x56a09c8', 45, 80, ('0x2264488', '0x226449a')),
 ('0x56a09e0', 50, 73, ('0x226438c', '0x226439e')),
 ('0x571ec08', 45, 80, ('0x4387edb', '0x4387ee8', '0x439ef7a', '0x439ef89')),
 ('0x571ec20', 50, 73, ('0x439ef60', '0x439ef6d')),
 ('0x571ec38', 60, 82, ('0x4387bee', '0x4387bfd')),
 ('0x571ec50', 33, 60, ('0x439f1a7', '0x439f1b4')),
 ('0x572fbf0', 45, 80, ('0x4744c69', '0x4744c9f')),
 ('0x572fc08', 50, 73, ('0x4744bfd', '0x4744c33')),
 ('0x573e160', 45, 80, ('0x4b7333f', '0x4b73354')),
 ('0x573e178', 50, 73, ('0x4b732c6', '0x4b73301')),
 ('0x573e190', 33, 60, ('0x4b3a1c9', '0x4b3a1db')))
EXPECTED_FDES = (('0x2034eb0', '0x203516e', '5a8c091366785d6685c490705f0cccae5a1fbe7e9c3bb8ef5d03b6a92bc0a05a'),
 ('0x2036460', '0x20367c3', '8903a9e37b85d3c2acd05f9d0798614b39a259d212a497a125bdbbeacd762356'),
 ('0x20485e0', '0x20487e7', 'c7f18d8204491b50a37fa3b6a163a7d1aa01a477d5fd4050aa1ce661afd4df4f'),
 ('0x20487f0', '0x2048f05', 'dea84c0bf363471adb4cc01e740f1c9b1bf904781d52ea1261298792e61925b0'),
 ('0x22615b0', '0x22689f0', '541304bb4269d1d3698734b27a4ca082b129ae3c108be4e504b7643221940249'),
 ('0x4387910', '0x4387c73', 'f638065aa6efae4b5eda2308de12268ed506890f633019fd2d55f34d725bb6c0'),
 ('0x4387c80', '0x4387f3e', 'ceceb6a54c8e9cc81bc9ba09ee9cb0c19c51a93b1e76ab4350b452af943c8723'),
 ('0x439edd0', '0x439efd7', '55115bb83c39b672d5e4fad6d8504a01d15875e8cc50433d5ef04f1248e0544e'),
 ('0x439efe0', '0x439f7cb', '7ba76fa8f7fc52256507dece5a0e18d83777caf88e5e674c5dd514f2db6e89db'),
 ('0x4744160', '0x474822f', '1e122bfde4ad0d8a63b9583226572274d37221ce55ee155344b7326fa5fcb338'),
 ('0x4b399a0', '0x4b3b924', '740c8ce1a7c3607aeb3f674a2c6ffd21f3e032e8630927c0a4fd4244ada42812'),
 ('0x4b72900', '0x4b73d7c', 'ad16790699eef6ea29628214c88ebfb760a38a33a99faa5a4d737c3bb85d043f'))
EXPECTED_METRICS = {'adjacent_location_calls': 34,
 'byte_proven_but_unattributed_setups': 12,
 'call_edges': 3,
 'constants_bound': 0,
 'constants_unresolved': 10,
 'counted_fragment_anchors': 0,
 'decoded_instructions': 12213,
 'diagnostics_absent': 12,
 'diagnostics_bound': 3,
 'diagnostics_probed': 18,
 'diagnostics_unresolved': 3,
 'location_leas': 34,
 'locations': 15,
 'only_exact_file_first_party_fdes': 6,
 'pointer_length_anchors': 8,
 'scoped_fde_bytes': 67679,
 'scoped_fdes': 12,
 'shared_first_party_fdes': 6,
 'tail_edges': 0,
 'unique_line_column': 4}
EXPECTED_EDGES = (('0x2264b21', '0x22615b0', '0x2034eb0', 'e88a03ddff'),
 ('0x47450d2', '0x4744160', '0x4387c80', 'e8a92bc4ff'),
 ('0x4b737f4', '0x4b72900', '0x4387c80', 'e8874481ff'))
EXPECTED_DIAGNOSTICS = (('reference-line-136', 'absent', ()),
 ('reference-line-137', 'absent', ()),
 ('reference-line-139', 'absent', ()),
 ('reference-line-141', 'absent', ()),
 ('reference-line-142', 'absent', ()),
 ('reference-line-143', 'absent', ()),
 ('reference-line-144', 'absent', ()),
 ('reference-line-145', 'absent', ()),
 ('reference-line-146', 'absent', ()),
 ('reference-line-147', 'absent', ()),
 ('reference-line-148', 'absent', ()),
 ('reference-line-203', 'present-but-unbound', ()),
 ('reference-line-286', 'present-but-unbound', ()),
 ('reference-line-507', 'absent', ()),
 ('binary-1', 'bound', ('0x2034fc8', '0x20486cf', '0x4387d98', '0x439eebf')),
 ('binary-2', 'bound', ('0x204892e', '0x439f111')),
 ('binary-3', 'bound', ('0x2048c6c', '0x439f586')),
 ('binary-4', 'present-but-unbound', ()))


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
    spec = importlib.util.spec_from_file_location('tcp_stream_inventory', ROOT/'tools/tcp_stream_inventory.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def verify_facts(e):
    check(e['target']['sha256'] == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f', 'target mismatch')
    check(e['scope_rule'] == 'net_utils/src/tcp/tcp_stream.rs', 'scope mismatch')
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

#!/usr/bin/env python3
"""Strict packet manifest, tool identity and deterministic regeneration verification."""
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MANIFEST = frozenset({'README.md', 'RESULT.md', 'oracle-inventory.json',
                      'byte-excerpts.txt', 'objdump-excerpts.txt', 'location-objdump.txt',
                      'check_objdump.py', 'verify.py'})
BIN_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TOOL_SHA = '80860e9e0f52d780cc13339e68de9d94a3f1b3d1210dc42e02f5774437117513'
PARSER_SHA = 'ffe4f98ba84648f6ffa1fdaca288799cc62d51fa7d089c82fb28cba77c1d88d1'
OUTPUT_SHA = '529c9cfdb7c938cd0535711db79ee4d782d06d7c8ac428fe3e8028bc70f77fea'
EXCERPT_SHA = '9ee667179632032d5bcc15d79313dcfce88df45fe5efbbbefcb96b3d799bb3f8'


def require(condition, msg):
    if not condition:
        raise ValueError(msg)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_manifest(here):
    lines = (here / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines()
    records = {}
    for line in lines:
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        require(match is not None, 'invalid manifest line')
        digest, name = match.groups()
        require(name not in records, 'duplicate manifest entry')
        records[name] = digest
    require(set(records) == MANIFEST, 'manifest whitelist mismatch')
    for name, digest in records.items():
        require(sha((here / name).read_bytes()) == digest, f'manifest mismatch: {name}')


def main():
    try:
        verify_manifest(HERE)
        require(sha((ROOT / 'tools/clearinghouse_oracle_inventory.py').read_bytes()) == TOOL_SHA,
                'generator hash mismatch')
        require(sha((ROOT / 'tools/info_request_path.py').read_bytes()) == PARSER_SHA,
                'shared parser hash mismatch')
        binary = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        require(sha(binary) == BIN_SHA, 'binary hash mismatch')
        sys.path.insert(0, str(ROOT / 'tools'))
        import clearinghouse_oracle_inventory as inventory
        result = inventory.build(binary)
        output = inventory.render(result)
        excerpts = inventory.excerpts(binary, result)
        require(sha(output) == OUTPUT_SHA and output == (HERE / 'oracle-inventory.json').read_bytes(),
                'JSON regeneration mismatch')
        require(sha(excerpts) == EXCERPT_SHA and excerpts == (HERE / 'byte-excerpts.txt').read_bytes(),
                'byte excerpts regeneration mismatch')
        require(result['location_counts_by_basename'] == {'oracle.rs': 21} and
                result['lea_count'] == 72 and result['owning_fde_count'] == 67,
                'census mismatch')
        require(sum(x['status'] == 'bound' for x in result['diagnostics']) == 2 and
                sum(x['status'] == 'unresolved' for x in result['diagnostics']) == 7 and
                len(result['constants']) == 8 and
                all(x['status'] == 'unresolved' for x in result['constants']), 'claims mismatch')
        require(result['call_edge']['site'] == '0x26f7929' and
                result['call_edge']['destination_fde'] == '0x26ebdc0', 'edge mismatch')
    except (OSError, ValueError, KeyError, ImportError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1
    print('PASS: pinned packet, manifest and regenerated evidence')
    return 0


if __name__ == '__main__':
    sys.exit(main())

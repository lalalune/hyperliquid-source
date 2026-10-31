#!/usr/bin/env python3
"""Verify retained packet/source bindings, without claiming a fresh Rust build."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKET = HERE.parent
ROOT = HERE.parents[3]
SOURCE_FILES = {
    '.gitattributes',
    'src/node94-u128-division/Cargo.toml',
    'src/node94-u128-division/Cargo.lock',
    'src/node94-u128-division/README.md',
    'src/node94-u128-division/src/lib.rs',
    'src/node94-u128-division/src/tests.rs',
    'tools/u128_division.py',
    'tools/u128_division_rust.py',
    'tools/spot_wei_scale.py',
    'research/work-items/RE-004-u128-division-94/rust/verify.py',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    manifest = {}
    for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
        digest, name = line.split('  ', 1)
        require(name not in manifest, 'duplicate packet member')
        path = PACKET / name
        require(path.is_relative_to(PACKET) and '..' not in path.parts,
                'packet member escapes its root')
        require(path.is_file() and not path.is_symlink() and sha(path) == digest,
                'packet member differs: ' + name)
        manifest[name] = digest
    actual = {p.relative_to(PACKET).as_posix() for p in PACKET.rglob('*') if p.is_file()}
    require(actual == set(manifest) | {'MANIFEST.sha256'}, 'packet member set differs')
    sources = json.loads((HERE / 'source-sha256.json').read_text())
    require(set(sources) == SOURCE_FILES, 'compared source set differs')
    for name, digest in sources.items():
        path = ROOT / name
        require('..' not in path.parts and path.is_file() and not path.is_symlink()
                and sha(path) == digest, 'compared source differs: ' + name)
    static = json.loads((PACKET / 'evidence.json').read_text())
    require(json.loads((HERE / 'static-evidence.json').read_text()) == static,
            'fresh static evidence binding differs')
    result = json.loads((HERE / 'comparison.json').read_text())
    require(result['target_sha256'] == static['target_sha256']
            and result['fixture_count'] == static['vectors'] == 159431
            and result['fixture_sha256'] == static['vector_result_sha256'],
            'Rust corpus binding differs')
    for build in result['clean_release_builds']:
        require(sha(HERE / build['retained_ir']) == build['llvm_ir_sha256'], 'retained IR differs')
    print(json.dumps({'packet_members': len(manifest), 'source_bindings': 'verified',
                      'static_fixture_binding': 159431, 'fresh_build_run': False}))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Losslessly retain public own-run streams and audit records.

Each original content is retained once, with exact byte length and SHA256.
Compression is an observation transport only; it changes no comparison input.
Exclude runnable own executables/libraries and full captured ELFs. Retain only
the explicit small native body byte exports as static evidence.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import zlib

PUBLIC_FILES = {'independent-pre-source/expected.jsonl', 'independent-pre-source/inputs.tsv'}
NATIVE_FILES = {'REPORT.json', 'CONTROLS.json', 'main.objdump.txt', 'captured-main.bin', 'ASCII-zero64.bin'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def verify(record_path, public_root):
    record = json.loads(record_path.read_text())
    contents = {}
    for digest, item in record['contents'].items():
        if 'public_file' in item:
            need(item['public_file'] in PUBLIC_FILES, 'Unadmitted public content path')
            raw = (public_root / item['public_file']).read_bytes()
        else:
            raw = zlib.decompress(base64.b64decode(item['zlib_base64'], validate=True))
        need(len(raw) == item['bytes'] and sha(raw) == digest, 'Changed original content')
        contents[digest] = raw
    for name, item in record['files'].items():
        need(len(contents[item['sha256']]) == item['bytes'], 'Changed file byte extent: ' + name)
    return {'files': len(record['files']), 'unique_contents': len(contents),
            'total_original_bytes': sum(item['bytes'] for item in record['files'].values()),
            'round_trip_exact': True}


def create(run_dir, record_path, public_root):
    need(not record_path.exists(), 'Preserve earlier evidence')
    result = json.loads((run_dir / 'RESULT.json').read_text())
    calls = json.loads((run_dir / 'CALLS.json').read_text())
    need(result['status'] == 'PASS' and result['same_inputs'] and result['calls'] == len(calls), 'Unsuccessful original run')
    paths = {'CALLS.json', 'RESULT.json', 'BEFORE.json', 'AFTER.json', 'inputs.tsv'}
    for call in calls:
        for item in call['streams'].values():
            name = item['file']
            need(Path(name).name == name, 'Unadmitted stream path')
            raw = (run_dir / name).read_bytes()
            need(len(raw) == item['bytes'] and sha(raw) == item['sha256'], 'Changed observed command stream')
            paths.add(name)
    need({p.name for p in (run_dir / 'native').iterdir()} == NATIVE_FILES, 'Changed bounded native file domain')
    paths.update('native/' + name for name in NATIVE_FILES)
    paths.update(str(p.relative_to(run_dir)) for p in run_dir.glob('control-*.rs'))
    public = {}
    for relative in sorted(PUBLIC_FILES):
        public[sha((public_root / relative).read_bytes())] = relative
    files, contents = {}, {}
    for name in sorted(paths):
        raw = (run_dir / name).read_bytes()
        digest = sha(raw)
        files[name] = {'bytes': len(raw), 'sha256': digest}
        if digest not in contents:
            contents[digest] = {'bytes': len(raw), 'public_file': public[digest]} if digest in public else {
                'bytes': len(raw), 'zlib_base64': base64.b64encode(zlib.compress(raw, 9)).decode('ascii')}
    record = {'schema': 'lossless-public-writer649-run/1', 'normalization': 'none',
              'commands': len(calls), 'stdout_stderr_streams': len(calls) * 2,
              'files': files, 'contents': contents}
    record_path.write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    return verify(record_path, public_root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-directory', type=Path)
    parser.add_argument('--public-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.output, args.public_root) if args.verify else
                     create(args.run_directory, args.output, args.public_root), sort_keys=True))

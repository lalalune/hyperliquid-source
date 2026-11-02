#!/usr/bin/env python3
"""Stage original frozen writer649 inputs for independent script reproduction.

Only writes a new scratch directory and the historical script's absent native
staging directory. Does not execute any script, compiler or captured bytes.
"""
import argparse, base64, hashlib, json, shutil, zlib
from pathlib import Path

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def checked(path, record):
    raw = path.read_bytes()
    assert len(raw) == record['bytes'] and sha(raw) == record['sha256']
    return raw

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--packet', type=Path, required=True)
    p.add_argument('--scratch', type=Path, required=True)
    a = p.parse_args()
    packet, out = a.packet.resolve(), a.scratch.resolve()
    historical = Path('/tmp/hl-resume-20261101/root-parts-next')
    assert not out.exists() and not historical.exists(), 'Preserve existing original/replayed evidence; use a fresh scratch host'
    source = packet / 'independent-pre-source'
    freeze = json.loads((source / 'FREEZE.json').read_bytes())
    previous_raw = (source / 'freeze-v1/FREEZE.json').read_bytes()
    assert sha(previous_raw) == freeze['supersedes_v1_sha256']
    previous = json.loads(previous_raw)
    out.mkdir(parents=True)
    (out / 'freeze-v1').mkdir()
    (out / 'freeze-v1/FREEZE.json').write_bytes(previous_raw)
    for name in ['FREEZE.json', 'PROOF.md', 'freeze.py', 'audit_protocol.py', 'challenge_native.py']:
        shutil.copyfile(source / name, out / name)
    for name, record in freeze['files'].items():
        if name == 'authority.jsonl':
            raw = zlib.decompress((source / 'authority.jsonl.zlib').read_bytes())
            assert len(raw) == record['bytes'] and sha(raw) == record['sha256']
        else:
            raw = checked(source / name, record)
        (out / name).write_bytes(raw)
        old = previous['files'][name]
        prefix = raw[:old['bytes']]
        assert sha(prefix) == old['sha256']
        (out / 'freeze-v1' / name).write_bytes(prefix)
    record = json.loads((packet / 'actual/ACTUAL-RAW-TRANSPORT.json').read_bytes())
    body_entry = record['files']['native/captured-main.bin']
    item = record['contents'][body_entry['sha256']]
    body = zlib.decompress(base64.b64decode(item['zlib_base64'], validate=True))
    assert len(body) == body_entry['bytes'] == 649 and sha(body) == body_entry['sha256']
    historical.mkdir(parents=True)
    (historical / '1572b20.raw').write_bytes(body)
    prep = packet / 'preparation'
    for src, dest in [('JOINT-ROOT-ADMISSION.json', 'ADMISSION.json'),
                      ('1572b20.objdump', '1572b20.objdump'),
                      ('WRITER-649-PROOF.md', 'WRITER-649-PROOF.md'),
                      ('DECIMAL-PROOF.json', 'DECIMAL-PROOF.json')]:
        shutil.copyfile(prep / src, historical / dest)
    math = json.loads((prep / 'DECIMAL-COMPRESSION.json').read_bytes())
    raw = zlib.decompress((prep / 'u16-decimal-output.tsv.zlib').read_bytes())
    assert len(raw) == math['original_bytes'] and sha(raw) == math['original_sha256']
    (historical / 'u16-decimal-output.tsv').write_bytes(raw)
    print(json.dumps({'scratch': str(out), 'historical_native': str(historical),
                      'scripts_executed': False, 'fresh_pre_source_claim': False}, sort_keys=True))

if __name__ == '__main__':
    main()

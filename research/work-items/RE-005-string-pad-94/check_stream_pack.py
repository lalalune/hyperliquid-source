#!/usr/bin/env python3
"""Replay the six pure-data stream-pack controls; never reads a target ELF."""
from pathlib import Path
import base64
import copy
import hashlib
import importlib.util
import json
import tempfile
import zlib

root = Path(__file__).resolve().parent
script = root / 'retain_string_pad_streams.py'
spec = importlib.util.spec_from_file_location('retainer', script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
positive = module.verify(root / 'build/RAW-STREAMS.json', root)
raw = b'x'
digest = hashlib.sha256(raw).hexdigest()
base = {'contents': {digest: {'bytes': 1, 'zlib_base64': base64.b64encode(zlib.compress(raw)).decode()}},
        'files': {'stream': {'bytes': 1, 'sha256': digest}}}
controls = {}
for name, path in [('absolute-path', '/tmp/unadmitted-public-placeholder'),
                   ('parent-traversal', '../unadmitted-public-placeholder'),
                   ('nested-traversal', 'independent-pre-source/../../unadmitted-public-placeholder')]:
    controls[name] = {'contents': {digest: {'bytes': 1, 'public_file': path}}, 'files': base['files']}
changed = copy.deepcopy(base)
changed['contents'][digest]['bytes'] = 2
controls['changed-content-extent'] = changed
changed = copy.deepcopy(base)
changed['files']['stream']['bytes'] = 2
controls['changed-file-extent'] = changed
changed = copy.deepcopy(base)
changed['contents'][digest]['zlib_base64'] = '!'
controls['invalid-base64'] = changed
with tempfile.TemporaryDirectory(prefix='padding-pack-controls-') as directory:
    for name, record in controls.items():
        path = Path(directory) / (name + '.json')
        path.write_text(json.dumps(record))
        try:
            module.verify(path, root)
        except ValueError:
            pass
        else:
            raise ValueError('Surviving pack control ' + name)
print(json.dumps({'status': 'PASS', 'packer_sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
                  'positive_roundtrip': positive, 'rejected_controls': list(controls),
                  'no_target_or_instruction_evaluator': True}, sort_keys=True))

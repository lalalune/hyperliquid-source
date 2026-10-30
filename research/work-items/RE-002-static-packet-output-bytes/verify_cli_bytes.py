"""Exercise six actual static analyzer CLIs against unchanged node94 fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser()
p.add_argument('--root', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
root, out = a.root.resolve(), a.out.resolve()
out.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, PYTHONUTF8='0', PYTHONIOENCODING='cp949', PYTHONHASHSEED='0')
cases = [
    ('bincode_varint', 'RE-005-bincode-varint', ['varint-sites.json']),
    ('bincode_varint_decode', 'RE-005-bincode-varint', ['decode-sites.json']),
    ('evm_extra_wei_decimals', 'RE-004-evm-extra-wei-decimals-94', ['evidence.json','guards.tsv','guard-bytes.txt']),
    ('qty_newtype_sign_guards', 'RE-004-qty-newtype-sign-guards-94', ['evidence.json','call-sites.tsv','guard-bytes.txt']),
    ('spot_token_decimals', 'RE-004-spot-token-decimals-94', ['evidence.json','admission.tsv','guard-bytes.txt']),
    ('weipriv_sign_guard', 'RE-004-weipriv-sign-guard-94', ['evidence.json','call-sites.tsv','caller-bytes.txt']),
]
rows = []

def compare(name, actual, expected, channel):
    rows.append({'tool': name, 'channel': channel,
                 'actual_sha256': hashlib.sha256(actual).hexdigest(),
                 'expected_sha256': hashlib.sha256(expected).hexdigest(),
                 'actual_crlf_count': actual.count(b'\r\n'),
                 'byte_equal': actual == expected,
                 'lf_normalized_equal_for_diagnosis_only': actual.replace(b'\r\n',b'\n') == expected})

for module, packet, names in cases:
    tool = root / 'tools' / (module + '.py')
    fixture = root / 'research/work-items' / packet
    dest = out / module
    dest.mkdir()
    if module.startswith('bincode_'):
        command = [sys.executable, str(tool), '--output', str(dest / names[0])]
    else:
        command = [sys.executable, str(tool), '--out', str(dest)]
    result = subprocess.run(command, env=env, capture_output=True, check=True)
    for name in names:
        compare(module, (dest / name).read_bytes(), (fixture / name).read_bytes(), name)
    if module.startswith('bincode_'):
        result = subprocess.run([sys.executable, str(tool)], env=env, capture_output=True, check=True)
        (dest / 'stdout.bin').write_bytes(result.stdout)
        compare(module, result.stdout, (fixture / names[0]).read_bytes(), 'stdout')
report = {'platform': sys.platform, 'python': sys.version.split()[0],
          'target_sha256': hashlib.sha256((root/'artifacts/node/94/hl-node').read_bytes()).hexdigest(),
          'encoding_environment': {'PYTHONUTF8':'0','PYTHONIOENCODING':'cp949'},
          'tool_sha256': {m:hashlib.sha256((root/'tools'/(m+'.py')).read_bytes()).hexdigest() for m,_,_ in cases},
          'checks': len(rows), 'byte_equal':sum(r['byte_equal'] for r in rows),
          'lf_normalized_equal_for_diagnosis_only':sum(r['lf_normalized_equal_for_diagnosis_only'] for r in rows),
          'rows':rows, 'captured_binaries_executed':False}
(out/'comparison.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('rows','tool_sha256')},indent=2))

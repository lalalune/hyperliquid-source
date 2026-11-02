"""Replay the original pre-checker source and exact original expectation hash."""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args()
if a.output.exists():raise ValueError('Preserve earlier output')
a.output.mkdir(parents=True)
raw=(HERE/'FROZEN-ORACLE-SOURCE.py').read_bytes();meta=json.loads((HERE/'FROZEN.json').read_bytes())
if hashlib.sha256(raw).hexdigest()!=meta['sourceSha256']:raise ValueError('Frozen source differs')
proof=(HERE/'PROOF.md').read_bytes()
if hashlib.sha256(proof).hexdigest()!=meta['manualProofSha256']:raise ValueError('Manual freeze changed')
(a.output/'node94-first-connect-proof-draft.md').write_bytes(proof)
script=a.output/'oracle.py';script.write_bytes(raw)
r=subprocess.run([sys.executable]+(['-O'] if not __debug__ else [])+['-B',str(script),'replay'],capture_output=True,timeout=120)
(a.output/'stdout.txt').write_bytes(r.stdout);(a.output/'stderr.txt').write_bytes(r.stderr)
if r.returncode:raise ValueError('Expectation replay failed')
if json.loads((a.output/'replay.json').read_bytes())!=meta or (a.output/'replay.jsonl.gz').read_bytes()!=(HERE/'expectations.jsonl.gz').read_bytes():raise ValueError('Frozen expectation replay differs')
print(json.dumps({'cases':meta['cases'],'sha256':meta['compressedSha256'],'identicalReplay':True}))

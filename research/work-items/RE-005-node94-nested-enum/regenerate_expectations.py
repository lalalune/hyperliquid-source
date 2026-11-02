"""Replay original sealed supplied-field sources without any checker present."""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args()
if a.output.exists():raise ValueError('Preserve earlier output')
a.output.mkdir(parents=True)
meta=json.loads((HERE/'FROZEN.json').read_bytes())
for name,digest in meta['sourceSha256'].items():
    raw=(HERE/name).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('Sealed source changed '+name)
    (a.output/name).write_bytes(raw)
proof=(HERE/'PROOF.md').read_bytes()
if hashlib.sha256(proof).hexdigest()!=meta['manualProofSha256']:raise ValueError('Manual proof changed')
(a.output/'node94-nested-enum-proof-draft.md').write_bytes(proof)
r=subprocess.run([sys.executable]+(['-O'] if not __debug__ else [])+['-B',str(a.output/'freeze_node94_nested_enum_expectations_v2.py'),'replay'],capture_output=True,timeout=120)
(a.output/'stdout.txt').write_bytes(r.stdout);(a.output/'stderr.txt').write_bytes(r.stderr)
if r.returncode:raise ValueError('Original supplied-field replay failed '+r.stderr.decode()[-1000:])
observed=json.loads((a.output/'replay.json').read_bytes())
# Only the newly recorded wall-clock freeze timestamp differs on replay.
# Source/proof identities, all mathematical metadata and compressed bytes must match.
for document in (observed,meta):document.pop('frozenAt')
if observed!=meta or (a.output/'replay.jsonl.gz').read_bytes()!=(HERE/'expectations.jsonl.gz').read_bytes():raise ValueError('Sealed replay differs')
receipt={'cases':meta['cases'],'sha256':meta['compressedSha256'],'identicalDataReplay':True,
 'metadataEqualExceptNewFreezeTimestamp':True,'sourceSha256':meta['sourceSha256'],'checkerImported':False,
 'capturedExecution':False,'instructionEvaluation':False}
(a.output/'receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
print(json.dumps(receipt,sort_keys=True))

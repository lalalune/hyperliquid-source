"""Check a transparent post-checker boundary extension against the unchanged relation."""
from pathlib import Path
import gzip,hashlib,json,sys
import check_relation as model
B=Path(__file__).resolve().parent
META=B/'ADDITION-FROZEN.json'
SOURCE=B/'addition-expectations.jsonl.gz'
meta=json.loads(META.read_bytes());compressed=SOURCE.read_bytes()
if hashlib.sha256(compressed).hexdigest()!=meta['compressedSha256']:raise ValueError('Supplement compressed identity')
raw=gzip.decompress(compressed)
if hashlib.sha256(raw).hexdigest()!=meta['uncompressedSha256']:raise ValueError('Supplement plain identity')
if meta['checkerCreated'] is not True or meta['initialAuthorityCases']!=25905:raise ValueError('Preserve post-checker history')
rows=[json.loads(line) for line in raw.splitlines()]
if len(rows)!=42 or len({(r['input']['dataHex'],r['input']['charge']) for r in rows})!=42:raise ValueError('Supplement denominator')
wrong=0;addition_only=0
for row in rows:
    inp=row['input'];expected=row['expected']
    if model.relation(inp)!=expected:raise ValueError('Supplement differs '+row['id'])
    bad=model.relation(inp,'store-reservation-overflow')
    wrong+=bad!=expected
    data=bytes.fromhex(inp['dataHex']);second=data[32]==0
    start=34 if second else 33
    count=int.from_bytes(data[start:start+8],'little')
    counter=inp['charge']+(48 if second else 40)
    if count*96<=model.U and counter<=1000 and counter+count*96>model.U:
        if bad==expected:raise ValueError('Wrong addition-overflow store accepted')
        if expected['charge']!=counter:raise ValueError('Addition overflow must retain pre-reservation counter')
        addition_only+=1
if addition_only!=12 or not wrong:raise ValueError('Addition-only boundary controls ineffective')
out={'state':'post-checker-boundary-supplement-checked','cases':42,'additionOnlyOverflowWitnesses':addition_only,
     'wrongOverflowStoreMismatches':wrong,'frozenSha256':meta['compressedSha256'],
     'initialAuthorityCases':25905,'initialAuthorityUnchanged':True,'checkerRelationUnchanged':True,
     'capturedExecution':False,'instructionEvaluation':False,'nativeEquivalence':False,
     'history':'These42expectations were constructed after the main checker; never relabel them as initial pre-checker cases.'}
p=Path(sys.argv[1])
if p.exists():raise ValueError('Preserve receipt')
p.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(out,sort_keys=True))

"""Freeze provisional pure byte-predicate expectations before any Rust implementation.

This evaluates independently authored byte equality predicates from frozen
literal annotations. It does not decode or evaluate captured instructions.
The manual CFG/read-set proof is still required before publication.
"""
from pathlib import Path
from itertools import product
import gzip,hashlib,io,json,sys

b=Path(__file__).resolve().parent
def require(ok,message):
    if not ok:raise ValueError(message)

map_file=b/'visor-config-name-map-intake.json';audit_file=b/'literal-audit.json'
mapping=json.loads(map_file.read_bytes());audit=json.loads(audit_file.read_bytes())
require(hashlib.sha256(map_file.read_bytes()).hexdigest()==audit['frozenMapSha256'],'Frozen map changed')
lookup={bytes.fromhex(r['bytesHex']):r['code'] for r in mapping['map']}
buckets={n:[] for n in range(2,14)}
for row in audit['entries']:buckets[row['length']].append(row)

def byte_predicates(raw):
    matches=[]
    for row in buckets.get(len(raw),()):
        if all(raw[f['inputOffset']:f['inputOffset']+f['width']]==bytes.fromhex(f['bytesHex']) for f in row['fragments']):
            matches.append(row['code'])
    require(len(matches)<=1,'Pure predicates are not disjoint')
    return matches[0] if matches else 79

cases={}
families={}
def add(raw,family):
    require(isinstance(raw,bytes),'Input type differs')
    expected=lookup.get(raw,79)
    actual=byte_predicates(raw)
    require(actual==expected,'Independent pure predicate disagreement')
    if raw not in cases:cases[raw]=expected
    families[family]=families.get(family,0)+1

for value in lookup:
    add(value,'positive')
    for i in range(len(value)):
        for byte in range(256):
            if byte==value[i]:continue
            add(value[:i]+bytes([byte])+value[i+1:],'single-byte-substitution')
        add(value[:i]+value[i+1:],'deletion')
    for i in range(len(value)+1):add(value[:i],'prefix')
    for byte in range(256):
        add(bytes([byte])+value,'prefix-one-byte')
        add(value+bytes([byte]),'suffix-one-byte')
    add(value.lower(),'ascii-lowercase')
    add(value.upper(),'ascii-uppercase')
    for padding in [b' ',b'\t',b'\0',b'\xc2\xa0',b'\xe3\x80\x80']:
        add(padding+value+padding,'padding')
for length in range(3):
    for letters in product(range(256),repeat=length):add(bytes(letters),'all-zero-one-two-byte-inputs')
for length in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,255,4096]:
    for byte in [0,32,65,127,128,255]:add(bytes([byte])*length,'length-boundary')

ordered=sorted(cases.items(),key=lambda item:(len(item[0]),item[0]))
raw=b''.join(value.hex().encode()+b'\t'+str(code).encode()+b'\n' for value,code in ordered)
require(len(sys.argv)==2,'Give one fresh output directory');output=Path(sys.argv[1]);require(not output.exists(),'Preserve output');output.mkdir(parents=True);target=output/'visor-config-name-frozen-corpus.tsv.gz';require(not target.exists(),'Preserve existing corpus')
buffer=io.BytesIO()
with gzip.GzipFile(filename='',mode='wb',fileobj=buffer,mtime=0,compresslevel=9) as stream:stream.write(raw)
target.write_bytes(buffer.getvalue())
controls={
    'wrong-reject-byte-0x21':lambda v:lookup.get(v,0x21),
    'accept-prefix':lambda v:next((code for key,code in lookup.items() if v.startswith(key)),79),
    'trim-before-recognition':lambda v:lookup.get(v.strip(b' \t\r\n'),79),
    'ascii-case-insensitive':lambda v:next((code for key,code in lookup.items() if key.lower()==v.lower()),79),
    'drop-nul-bytes':lambda v:lookup.get(v.replace(b'\0',b''),79),
    'collapse-NvTestnet-to-reject':lambda v:79 if v==b'NvTestnet' else lookup.get(v,79),
}
witnesses={}
for name,mutant in controls.items():
    witness=next(((value,expected) for value,expected in ordered if mutant(value)!=expected),None)
    require(witness is not None,'No abstract mutation witness: '+name)
    witnesses[name]={'inputHex':witness[0].hex(),'expected':witness[1],'mutant':mutant(witness[0])}
receipt={'state':'provisional-pure-byte-corpus-frozen-before-implementation','targetSha256':mapping['targetSha256'],
    'mapSha256':hashlib.sha256(map_file.read_bytes()).hexdigest(),'literalAuditSha256':hashlib.sha256(audit_file.read_bytes()).hexdigest(),
    'file':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'compressedBytes':target.stat().st_size,
    'uncompressedSha256':hashlib.sha256(raw).hexdigest(),'uncompressedBytes':len(raw),'uniqueCases':len(cases),
    'familiesGenerated':families,'observedCodes':sorted(set(cases.values())),'abstractMutationWitnesses':witnesses,
    'scope':'Dictionary expectations and annotated byte-fragment equality predicates agree on this finite corpus. Both are new high-level source models supporting a still-pending manual native proof; neither is a target behavior comparator.',
    'implementationExists':False,'semanticQualification':False,'capturedExecution':False,'instructionEvaluation':False,
    'remaining':['Complete addressed native CFG/liveness/read-set proof and independent artifact/binding controls.','Do not treat a frozen corpus as permission to claim reconstruction without a real documented component, actual compiler runs and meaningful comparator controls.']}
out=output/'receipt.json';require(not out.exists(),'Preserve existing receipt')
out.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:receipt[k] for k in ['state','uniqueCases','compressedBytes','uncompressedBytes','observedCodes','semanticQualification']}))

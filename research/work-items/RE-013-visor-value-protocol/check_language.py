"""Independent JSON value model versus a previously frozen manual corpus.

This uses Python's JSON grammar. It is neither a proposed native/Rust port nor
an instruction/register evaluator, and never executes the captured binary.
"""
from pathlib import Path
import json,gzip,hashlib,datetime
b=Path(__file__).resolve().parent
meta=json.loads((b/'FROZEN-CORPUS.json').read_text())
corpus=Path(__import__('sys').argv[1])
compressed=corpus.read_bytes();raw=gzip.decompress(compressed)
if hashlib.sha256(compressed).hexdigest()!=meta['compressedSha256'] or hashlib.sha256(raw).hexdigest()!=meta['uncompressedSha256']:
    raise ValueError('Previously frozen corpus changed')
names=json.loads((b/'frozen-names.json').read_text(encoding='utf-8-sig'))['map']
codes={r['literal']:r['code'] for r in names}
class Pairs(list):pass
def reject_constant(value):raise ValueError('Non-JSON constant')
decoder=json.JSONDecoder(object_pairs_hook=Pairs,parse_constant=reject_constant)
def parse(data):
    text=data.decode('utf-8').lstrip(' \t\r\n')
    value,end=decoder.raw_decode(text)
    return value
def model(data,mutant=None):
    try:value=parse(data)
    except (ValueError,UnicodeError):return (0,0) if mutant=='bare-null' and data==b'null' else (1,None)
    if mutant=='bare-null' and value is None:return (0,0)
    if isinstance(value,Pairs):
        if mutant=='omit-unit-object':return (1,None)
        if mutant=='collapse-duplicate-members':
            value=Pairs(dict(value).items())
        if len(value)!=1:return (1,None)
        name,unit=value[0]
        if unit is not None and mutant!='accept-nonunit-object-value':return (1,None)
    elif isinstance(value,str):name=value
    else:return (1,None)
    if mutant=='trim-name':name=name.strip()
    if mutant=='casefold-name':
        lower={k.lower():v for k,v in codes.items()}
        return (0,lower[name.lower()]) if name.lower() in lower else (1,None)
    if mutant=='accept-name-prefix':
        candidate=next((c for n,c in codes.items() if name.startswith(n)),None)
        if candidate is not None:return (0,candidate)
    if name in codes:return (0,codes[name])
    if mutant=='unknown-name-fallback':return (0,33)
    return (1,None)
cases=[]
for line in raw.decode().splitlines():
    data,tag,code=line.split('\t');cases.append((bytes.fromhex(data),(int(tag),None if code=='-' else int(code))))
if len(cases)!=meta['cases'] or len({r[0] for r in cases})!=len(cases):raise ValueError('Frozen count/uniqueness differs')
for data,want in cases:
    if model(data)!=want:raise ValueError('Independent model disagrees with manual expected value: '+data.hex())
witnesses=[]
for mutant in ['bare-null','omit-unit-object','accept-nonunit-object-value','collapse-duplicate-members',
               'trim-name','casefold-name','accept-name-prefix','unknown-name-fallback']:
    witness=next(((data,want,model(data,mutant)) for data,want in cases if model(data,mutant)!=want),None)
    if witness is None:raise ValueError('Wrong abstract rule survived: '+mutant)
    data,want,observed=witness
    witnesses.append({'mutant':mutant,'inputHex':data.hex(),'expected':want,'mutantResult':observed})
result={
 'state':'independent-abstract-value-model-agrees-with-frozen-expectations-unqualified',

 'targetSha256':meta['targetSha256'],'corpusSha256':meta['compressedSha256'],'cases':len(cases),
 'abstractMutationWitnesses':witnesses,
 'scope':'Python JSON grammar and independently frozen tag/code cases support the manual normal-return value proof. No cursor/error-payload/depth acceptance claim, implementation, target comparator or captured instruction execution/evaluation.',
 'limits':meta['limits'],'capturedExecution':False,'instructionEvaluation':False,'semanticQualification':False,
}
dest=Path(__import__('sys').argv[2])
if dest.exists():raise ValueError('Preserve existing model receipt')
dest.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps({'cases':len(cases),'abstractMutationWitnesses':len(witnesses),'qualified':False}))

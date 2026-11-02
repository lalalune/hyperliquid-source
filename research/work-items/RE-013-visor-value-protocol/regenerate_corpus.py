"""Freeze synthetic value-visitor expectations before any implementation exists."""
from pathlib import Path
import json,hashlib,gzip,io,datetime,collections
b=Path(__file__).resolve().parent
frozen=b/'frozen-names.json'
mapping=json.loads(frozen.read_text(encoding='utf-8-sig'))
expectations={};categories=collections.Counter()
def add(raw,code,category):
    expected=(0,code) if code is not None else (1,None)
    if raw in expectations:
        if expectations[raw]!=expected:raise ValueError('Contradictory manual expectation')
    else:expectations[raw]=expected;categories[category]+=1
def encoded_variants(name):
    return sorted(set([
        json.dumps(name),
        '"'+''.join('\\u%04x'%ord(c) for c in name)+'"',
        '"'+''.join('\\u%04X'%ord(c) for c in name)+'"',
        '"'+''.join(('\\u%04x'%ord(c)) if i%2==0 else c for i,c in enumerate(name))+'"',
        '"'+('\\u%04x'%ord(name[0]))+name[1:]+'"',
    ]))
whitespace=['',' ','\t','\r\n',' \t\r\n']
for item in mapping['map']:
    name=item['literal'];code=item['code']
    for encoded in encoded_variants(name):
        for before in whitespace:
            for after in whitespace:
                add((before+encoded+after).encode(),code,'quoted-known-name')
                for middle in ['', ' ', '\t\r\n']:
                    add((before+'{'+middle+encoded+middle+':'+middle+'null'+middle+'}'+after).encode(),code,'unit-object-known-name')
    for badname in ['',name+' ', ' '+name,name+'\0',name+'x',name.lower() if name.lower()!=name else name+'X']:
        if badname in {v['literal'] for v in mapping['map']}:continue
        value=json.dumps(badname)
        add(value.encode(),None,'quoted-unknown-name')
        add(('{'+value+':null}').encode(),None,'unit-object-unknown-name')
    key=json.dumps(name)
    for value in ['true','false','0','1','-1','""','[]','{}']:
        add(('{'+key+':'+value+'}').encode(),None,'nonunit-object-value')
    for suffix in [',}',',"Ec":null}',',"unknown":null}',']']:
        add(('{'+key+':null'+suffix).encode(),None,'bad-object-close-or-extra-member')
for token in ['', ' ', '\t\r\n', '{}','[]','null','true','false','0','-1','""','{"Ec"}',
              '{"Ec"null}','{"Ec":}','{"Ec":nul}','{"Ec":NULL}',
              '"\\q"','"\\u"','"\\u0"','"\\u00"','"\\u000"','"\\u00g0"',
              '"\\uD800"','"\\uDC00"','"\\uD800\\u0041"','"\\uD800x"',
              '"\\u0000Ec"','"Ec\\u0000"','"é"','"😀"','"Ec\n"']:
    add(token.encode(),None,'synthetic-negative-boundary')
for esc in ['\\"','\\/','\\\\','\\b','\\f','\\n','\\r','\\t']:
    add(('"'+esc+'"').encode(),None,'valid-simple-escape-unknown-name')
lines=[]
for raw,(tag,code) in sorted(expectations.items()):
    lines.append(raw.hex()+'\t'+str(tag)+'\t'+('-' if code is None else str(code))+'\n')
payload=''.join(lines).encode();out=Path(__import__('sys').argv[1]);out.mkdir(exist_ok=False);dest=out/'expectations.tsv.gz'
if dest.exists():raise ValueError('Do not overwrite frozen corpus')
buf=io.BytesIO()
with gzip.GzipFile(fileobj=buf,mode='wb',mtime=0,filename='') as f:f.write(payload)
compressed=buf.getvalue();dest.write_bytes(compressed)
meta=json.loads((b/'FROZEN-CORPUS.json').read_bytes())
require_values={'cases':len(expectations),'categoryUniqueCases':dict(categories),
 'compressedBytes':len(compressed),'uncompressedBytes':len(payload),
 'compressedSha256':hashlib.sha256(compressed).hexdigest(),
 'uncompressedSha256':hashlib.sha256(payload).hexdigest()}
for key,value in require_values.items():
    if value!=meta[key]:raise ValueError('Original frozen expectation identity changed: '+key)
(out/'receipt.json').write_text(json.dumps(require_values,indent=2,sort_keys=True)+'\n')
print(json.dumps(require_values))

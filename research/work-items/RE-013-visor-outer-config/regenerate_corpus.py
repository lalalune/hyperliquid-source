"""Freeze structured grammar expectations before a proposed relation model exists."""
from pathlib import Path
import collections, datetime, gzip, hashlib, io, json

B = Path(__file__).resolve().parent
source = B/'frozen-names.json'
names = json.loads(source.read_text(encoding='utf-8-sig'))['map']
expectations = {}
categories = collections.Counter()
def add(text, default, code, calls, category):
    raw = text.encode('utf-8')
    value = (default, 0 if code is not None else 1, code, calls)
    key = (raw, default)
    if key in expectations:
        if expectations[key] != value:
            raise ValueError('Contradictory independent expectation')
    else:
        expectations[key] = value
        categories[category] += 1
def quoted(s):
    return json.dumps(s, ensure_ascii=True, separators=(',', ':'))
W = ['', ' ', '\t', '\r\n', ' \t\r\n']
valid_ignored = [
    'null','true','false','0','-0','1','-123456789012345678901234567890',
    '0.0','-1.25','1e0','1E+0009','-0.25e-17','1e1000000000000000000000',
    quoted(''),quoted('ordinary é 😀'), '"\\uD800"','"\\uDC00"','"\\uD800x"',
    '"\\uD800\\u0041"', '[]','{}','[0,true,null,{}]',
    '{"same":0,"same":1}', '{"aws_name":0}',
    '{"\\uD800":["\\uDC00",-1e999999]}',
]
for item in names:
    name, code = item['literal'], item['code']
    value_forms = [quoted(name), '{'+quoted(name)+':null}']
    key_forms = ['"aws_name"', '"\\u0061ws_name"', '"aws\\u005fname"']
    for value in value_forms:
        for key in key_forms:
            for w in W:
                add(w+'{'+w+key+w+':'+w+value+w+'}'+w, 21, code, 0, 'known-field-forms')
                add(w+'['+w+value+w+']'+w, 21, code, 0, 'sequence-known-value')
        for ignored in valid_ignored:
            for obj in ['{"u":'+ignored+',"aws_name":'+value+'}',
                        '{"aws_name":'+value+',"u":'+ignored+'}',
                        '{"u":'+ignored+',"aws_name":'+value+',"u":'+ignored+'}']:
                add(obj, 21, code, 0, 'ignored-values-around-known')
        for bad in ['['+value+',]', '['+value+','+value+']',
                    '{"aws_name":'+value+',}',
                    '{"aws_name":'+value+',"aws_name":'+value+'}',
                    '{"aws_name":'+value+'}x', '{"aws_name":'+value+'}\u00a0']:
            add(bad, 21, None, 0, 'known-malformed-separator-or-suffix')
        # A valid name scalar or enum-shaped object is not an outer value.
        add(quoted(name), 21, None, 0, 'scalar-not-outer')
        add('{'+quoted(name)+':null}', 21, 21, 1, 'ordinary-unknown-outer-key')

for default in [0,21,78]:
    for w in W:
        for obj in ['{}','[]']:
            add(w+obj+w, default, default, 1, 'default-producer-code')
        for ignored in valid_ignored:
            add(w+'{"unknown":'+ignored+'}'+w, default, default, 1, 'default-after-ignored')
    for obj in ['{}x','[]x','{}\u00a0','[]\u00a0']:
        add(obj, default, None, 1, 'default-before-suffix-rejection')
for unit in range(65536):
    escape = '\\u%04x' % unit
    add('{"u":"'+escape+'","aws_name":"NvTestnet"}',21,next(x['code'] for x in names if x['literal']=='NvTestnet'),0,'all-u16-ignored-strings')
    add('{"u":{"'+escape+'":0},"aws_name":"NvTestnet"}',21,next(x['code'] for x in names if x['literal']=='NvTestnet'),0,'all-u16-ignored-object-keys')
    is_surrogate = 0xd800 <= unit <= 0xdfff
    add('{"'+escape+'":0}',21,None if is_surrogate else 21,0 if is_surrogate else 1,'all-u16-strict-outer-keys')

bad_ignored = [
    '', '+1','01','-01','-','00','1.','1e','1e+','1e-','1.e1','NaN','Infinity',
    'tru','fals','nul','True','False','Null','truex','0x1','1_0',
    '"\\q"','"\\u"','"\\u0"','"\\u00"','"\\u000"','"\\u00g0"','"a\n"',
    '[,]','[0,]','[0 1]','[0}','{]','{"x"0}','{"x":}','{"x":0,}',
    '{"x":0 "y":1}', '{x:0}', '[truefalse]',
]
for bad in bad_ignored:
    add('{"unknown":'+bad+',"aws_name":"Ec"}',21,None,0,'malformed-ignored-grammar')
    add('{"unknown":'+bad+'}',21,None,0,'malformed-ignored-no-default')
for depth in [1,2,7,127,128,129,256,1024]:
    value = '['*depth+'0'+']'*depth
    add('{"u":'+value+',"aws_name":"Ec"}',21,0,0,'ignored-depth-not-recursion-budget')
    add('{"u":'+value[:-1]+',"aws_name":"Ec"}',21,None,0,'unclosed-deep-ignored')
for bad in ['', ' ', '\t\r\n', 'null','true','false','0','""',
            '{','[','{,}','[,]','{"aws_name":}', '{"aws_name":null}',
            '{"aws_name":[]}', '{"aws_name":{}}', '{"aws_name":"unknown"}',
            '{"\\uD800":0}', '{"unknown":0,}', '["unknown"]', '[null]']:
    add(bad,21,None,0,'outer-negative-boundaries')

lines = []
for (raw,default), (_,tag,code,calls) in sorted(expectations.items()):
    lines.append(raw.hex()+'\t'+str(default)+'\t'+str(tag)+'\t'+('-' if code is None else str(code))+'\t'+str(calls)+'\n')
payload = ''.join(lines).encode('ascii')
import sys
directory=Path(sys.argv[1]);directory.mkdir(exist_ok=False)
out=directory/'expectations.tsv.gz'
buf = io.BytesIO()
with gzip.GzipFile(fileobj=buf, mode='wb', filename='', mtime=0) as f:
    f.write(payload)
compressed = buf.getvalue()
out.write_bytes(compressed)
meta=json.loads((B/'FROZEN-CORPUS.json').read_bytes())
fields={'cases':len(expectations),'categoryUniqueCases':dict(categories),
 'uncompressedBytes':len(payload),'compressedBytes':len(compressed),
 'uncompressedSha256':hashlib.sha256(payload).hexdigest(),
 'compressedSha256':hashlib.sha256(compressed).hexdigest()}
for key,value in fields.items():
    if meta[key]!=value:raise ValueError('Corrected frozen construction changed: '+key)
(directory/'receipt.json').write_text(json.dumps(fields,sort_keys=True,indent=2)+'\n')
print(json.dumps(fields,sort_keys=True))

"""Static seed projection/current Rust evidence; never evaluate captured code."""
import argparse
import ast
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import unwind_index
from fde_extents import eh_frame_records
DIGEST='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FREEZE='2201df213104ca7b79a63049512a90692b22915c9c829e0db04c1419f56b2de0'
PLAN='d46958f9e908781cf15175a6d5abc9ed783c7ad74f6f1d60dd8be9e5d6133465'
MASK=(1<<64)-1
SITES=(0x1452083,0x145209a,0x145209c,0x145209e)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def js(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def require(test,message):
    if not test:raise ValueError(message)
def span(data,secs,address,size):
    require(type(address) is int and type(size) is int and address>=0 and size>0,'bad virtual span')
    choices=[s for s in secs if s['type']!=8 and s['address']<=address and address+size<=s['address']+s['size']]
    require(len(choices)==1,'span must be uniquely file-backed');s=choices[0];at=s['offset']+address-s['address']
    require(0<=at and at+size<=len(data),'span outside file');return data[at:at+size]


def authenticate(data):
    require(len(data)==91774280 and sha(data)==DIGEST,'node94 identity')
    native=json.loads((HERE/'native.json').read_text());frozen=json.loads((HERE/'native-freeze.json').read_text())
    require(sha((HERE/'native-freeze.json').read_bytes())==FREEZE,'pre-Rust native freeze')
    require(sha((HERE/'native.json').read_bytes())==frozen['authenticated_sha256'],'native metadata binding')
    secs,index=unwind_index(data);cies,fdes=eh_frame_records(data,secs)
    for r in native['functions']:
        a,z=int(r['start'],16),int(r['end'],16);matches=[f for f in fdes if (f['start'],f['end'])==(a,z)]
        require(len(matches)==1,'exact FDE extent');f=matches[0]
        require(f['fde']==int(r['fde'],16) and f['cie']==int(r['cie'],16) and f['lsda']==(None if r['lsda'] is None else int(r['lsda'],16)),'unwind metadata')
        require(sum(x['start']==a and x['fde']==f['fde'] for x in index)==1,'unwind index')
        require(sha(span(data,secs,a,z-a))==r['sha256'],'whole native body')
        for key in ('fde','cie'):
            va=f[key];n=int.from_bytes(span(data,secs,va,4),'little')+4
            require(span(data,secs,va,n).hex()==r[key+'_raw'],'raw unwind record')
        if r['role']=='credited generic Once':continue
        exports=[]
        for tool in ('gnu','llvm'):
            rows=[]
            for line in (HERE/(hex(a)[2:]+'-'+tool+'.txt')).read_text().splitlines():
                m=re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S',line)
                if m:rows.append((int(m[1],16),bytes.fromhex(m[2])))
            require(len(rows)==r['rows_each'] and rows[0][0]==a,'export row count/start')
            require(b''.join(v for _,v in rows)==span(data,secs,a,z-a),'whole export bytes')
            require(all(x+len(v)==y for (x,v),(y,_) in zip(rows,rows[1:])),'contiguous export')
            exports.append(rows)
        require(exports[0]==exports[1],'independent instruction starts/bytes')
    relocations={}
    for s in secs:
        if s['type']==4:
            for at in range(s['offset'],s['offset']+s['size'],24):
                where,info,addend=struct.unpack_from('<QQq',data,at)
                if where in (0x576e8b8,0x566a7d8,0x577ae30,0x566a9d8):relocations[where]=data[at:at+24].hex()
    require(relocations=={int(r['slot'],16):r['raw'] for r in native['relocations']},'exact callback/initializer/constant relocations')
    for r in native['source_sites']:
        require(span(data,secs,int(r['site'],16),r['bytes']).hex()==r['raw'],'caller/source site')
    for r in native['constants']:
        raw=bytes.fromhex(r['raw']);require(span(data,secs,int(r['va'],16),len(raw))==raw,'native constant/file image')
    return secs,frozen


def fields(raw,original):
    require(len(raw)==len(original)==101,'complete initializer bytes')
    changed=bytearray(raw);base=bytearray(original)
    for va in SITES:changed[va-0x1452070]=base[va-0x1452070]=0
    require(changed==base,'undeclared native change')
    values=tuple(raw[va-0x1452070] for va in SITES)
    require(values[0] in (0x74,0x75) and values[1] in (3,11) and values[2] in (0x48,0x40) and values[3] in (3,11),'unsupported scalar operand')
    return values


def relation(frame,values):
    """Fixed field-qualified word equations, no instruction/register evaluator."""
    branch,destination,width,direction=values;tls=bytearray.fromhex(frame['tls_before_hex']);flag=tls[16]
    if (flag!=0)!=(branch==0x74):return {'route':'opaque0x13c8970'}
    low,high=struct.unpack('<QQ',tls[:16]);delta=1 if direction==3 else -1
    next_low=(low+delta)&MASK if width==0x48 else (low&0xffffffff00000000)|((low+delta)&0xffffffff)
    tls[:8]=struct.pack('<Q',next_low)
    old=(low,high) if destination==3 else (0x202e90,0)
    return {'route':'admitted','returned_pair':[f'{v:016x}' for v in old],
            'next_pair':[f'{next_low:016x}',f'{high:016x}'],'tls_after_hex':tls.hex(),
            'output56_hex':struct.pack('<QQQQQQQ',0,0x202e90,0,0,0,*old).hex()}


def controls(data,secs,frozen):
    original=span(data,secs,0x1452070,101);normal=fields(original,original)
    for frame in frozen['frames']:
        result=relation(frame,normal)
        require(result['output56_hex']==frame['initializer_output56_hex']==frame['installed_global_object56_hex'],'whole frozen output')
        require(result['tls_after_hex']==frame['tls_after_hex'],'whole frozen TLS envelope')
    results=[]
    for c in frozen['controls']:
        raw=bytearray(original);at=int(c['site'],16)-0x1452070
        require(raw[at]==int(c['original_byte'],16),'control original');raw[at]=int(c['changed_byte'],16)
        frame=next(f for f in frozen['frames'] if f['id']==c.get('witness','zero'))
        before=relation(frame,normal);after=relation(frame,fields(raw,original));require(before!=after,'inoperative native control')
        if c['site']=='0x1452083':require(after['route']=='opaque0x13c8970','excluded route classification')
        elif c['site']=='0x145209a':require(after['returned_pair']==c['changed_returned_pair'] and after['next_pair']==before['next_pair'],'SIMD-source witness')
        else:require(after['next_pair'][0]==c['changed_next_low'] and after['returned_pair']==before['returned_pair'],'increment witness')
        results.append({'site':c['site'],'original_byte':c['original_byte'],'changed_byte':c['changed_byte'],'classification':c['classification'],'frame':frame['id'],'original':before,'changed':after})
    return results


def streams():
    plan=json.loads((HERE/'PLAN.json').read_text());require(sha((HERE/'PLAN.json').read_bytes())==PLAN,'pre-source projection plan')
    vector=(ROOT/'src/node94-alias/evidence/seed-pair-vectors.tsv').read_bytes();require(sha(vector)==plan['files']['seed-pair-vectors.tsv']['sha256'],'projection fixture')
    rows=[]
    for line in vector.decode().splitlines():
        if line.startswith('#'):continue
        name,*words=line.split('\t');require(len(words)==7,'projection fields');rows.append((name,[int(w,16) for w in words]))
    require(len(rows)==7,'seven frames');native=json.loads((HERE/'native-freeze.json').read_text())
    inputs=b'NS94\x01'+struct.pack('<H',7);expected=inputs
    for i,((name,w),frame,composition) in enumerate(zip(rows,native['frames'],plan['cases'])):
        key=bytes.fromhex(composition['composed_key_hex']);require(name==frame['id']==composition['id'],'frame identity')
        require(struct.pack('<QQ',*w[2:4])==bytes.fromhex(frame['initializer_output56_hex'])[40:56],'native old pair projection')
        require(struct.pack('<QQ',*w[4:6])==bytes.fromhex(frame['tls_after_hex'])[:16],'native next pair projection')
        require(f'{w[6]:016x}'==composition['composed_H'],'pre-source composed hash')
        inputs+=struct.pack('<HQQI',i,*w[:2],len(key))+key;expected+=struct.pack('<HQQQQQQ',i,*w[2:6],w[6],w[6])
    for name,raw in [('inputs.bin',inputs),('expected.bin',expected)]:
        require((len(raw),sha(raw))==(plan['files'][name]['bytes'],plan['files'][name]['sha256']),'pre-source exact stream')
    return inputs,expected


def compare(actual,expected):
    require(len(actual)==len(expected) and actual[:7]==expected[:7] and (len(actual)-7)%50==0,'output framing')
    different=[]
    for i in range((len(actual)-7)//50):
        a,b=actual[7+i*50:57+i*50],expected[7+i*50:57+i*50];require(a[:2]==b[:2],'case ID framing')
        if a!=b:different.append({'id':i,'actual_hex':a.hex(),'expected_hex':b.hex()})
    return different


def bundle(name):
    doc=json.loads((HERE/name).read_text());encoded=base64.b64decode(doc['payload_base64'],validate=True)
    require((len(encoded),sha(encoded))==(doc['payload_bytes'],doc['payload_sha256']),'bundle payload')
    with tarfile.open(fileobj=io.BytesIO(encoded),mode='r:gz') as tar:
        members=tar.getmembers();require(all(m.isfile() and not m.name.startswith('/') and '..' not in Path(m.name).parts for m in members),'inert bundle members')
        require(len(members)==len({m.name for m in members}),'duplicate member');raw={m.name:tar.extractfile(m).read() for m in members}
    require(set(raw)==set(doc['files']),'bundle allowlist')
    for n,pin in doc['files'].items():require((len(raw[n]),sha(raw[n]))==(pin['bytes'],pin['sha256']),'bundle member hash')
    return doc,raw


def current_source_pins(receipt):
    # Preserve actual qualified paths. Only the unchanged owned DRIVER artifact
    # moved from ignored work into this packet; production paths are never remapped.
    driver='work/alias-seed-rust-prep/input-only.rs'
    expected={'src/node94-alias/'+n for n in ('Cargo.toml','Cargo.lock','src/lib.rs','src/tests.rs','evidence/contract-vectors.txt','evidence/inline-carrier-vectors.tsv','evidence/key-hash-vectors.tsv','evidence/seed-pair-vectors.tsv')}|{driver}
    require(set(receipt['source_input_pins'])==expected,'exact project source/input set')
    for n,pin in receipt['source_input_pins'].items():
        p=HERE/'input-only.rs' if n==driver else ROOT/n;raw=p.read_bytes()
        require((len(raw),sha(raw))==(pin['bytes'],pin['sha256']),'current production/fixture or identical qualified driver bytes')


def retained():
    receipt=json.loads((HERE/'comparison.json').read_text());current_source_pins(receipt)
    require(sha((HERE/'qualified-runner.py').read_bytes())==receipt['runner_sha256'],'exact qualified runner source')
    tree=ast.parse((HERE/'qualified-runner.py').read_text());recipes=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='RECIPES' for t in n.targets)))
    recipe={n:(a,b) for n,a,b in recipes};doc,raw=bundle('raw-streams.json');require(doc['comparison_json_sha256']==sha((HERE/'comparison.json').read_bytes()),'receipt/text bundle')
    allowed={'snapshot/SNAPSHOT.json','snapshot/recipes.json','snapshot/inputs.bin','snapshot/expected.bin'}
    require(len(raw)==132 and all(n in allowed or not n.startswith('snapshot/') and n.endswith(('.stdout','.stderr','.d','/actual.bin')) for n in raw),'small stream/log-only bundle')
    inputs,expected=streams();require(raw['snapshot/inputs.bin']==inputs and raw['snapshot/expected.bin']==expected,'frozen exact input/expected bytes')
    manifest=json.loads(raw['snapshot/SNAPSHOT.json']);require(sha(raw['snapshot/SNAPSHOT.json'])==receipt['snapshot_sha256'] and manifest==receipt['snapshot_files'],'source/input snapshot')
    omitted={'lib.rs':ROOT/'src/node94-alias/src/lib.rs','input-only.rs':HERE/'input-only.rs','PLAN.json':HERE/'PLAN.json','seed-pair-vectors.tsv':ROOT/'src/node94-alias/evidence/seed-pair-vectors.tsv'}
    for n,pin in manifest.items():
        content=omitted[n].read_bytes() if n in omitted else raw['snapshot/'+n]
        require((len(content),sha(content))==(pin['bytes'],pin['sha256']),'snapshot bytes')
    source=(ROOT/'src/node94-alias/src/lib.rs').read_text();require(len(receipt['builds'])==16 and len(receipt['providers'])==68,'finite build/provider scope')
    for build in receipt['builds']:
        name,opt=build['variant'],build['opt'];derived=source
        if name!='baseline':
            old,new=recipe[name];require(source.count(old)==1,'unique source mutation');derived=source.replace(old,new)
        require(sha(derived.encode())==build['source_sha256'],'actual compiled source variant')
        directory=f'{name}-opt{opt}';actual=raw[directory+'/actual.bin'];different=compare(actual,expected)
        require(len(different)==build['different_cases'] and bool(different)==(name!='baseline'),'actual baseline/mutant result')
        require((different[0] if different else None)==build['first_witness'] and sha(actual)==build['stdout_sha256'],'raw witness')
        require(raw[directory+'/run.stderr']==b'' and build['exit']==0,'driver exit/diagnostics')
        for i,cmd in enumerate(build['commands']):
            require(cmd['exit']==0 and cmd['diagnostic_bytes']==0,'actual compiler result')
            require(cmd['free_before_bytes']>=316*1024*1024 and cmd['free_after_bytes']>=300*1024*1024,'seed compiler disk floor')
            for suffix in ('stdout','stderr'):require(raw[directory+f'/compile-{i}.{suffix}']==b'' and cmd[suffix+'_sha256']==sha(b''),'actual compiler log')
        for dep,text in build['depinfo'].items():
            require(raw[directory+'/'+dep]==text.encode(),'actual dependency log')
            observed={t.rstrip(':') for t in text.replace('\\\n',' ').split() if t.rstrip(':').endswith('.rs')}
            command=build['commands'][0 if dep=='library.d' else 1]['argv']
            require(observed=={command[-3]},'exact compiler-read project source')
        if name=='baseline':require(len(build['framing_controls'])==4,'actual framing controls')
    return receipt


def checkpoint_evidence():
    _,raw=bundle('checkpoints.json');require(len(raw)==8 and all(n.endswith(('.json','.log')) for n in raw),'checkpoint/log-only bundle')
    for name,packet,count in [('inline-carrier-seed-factory-fresh','RE-001-inline-carrier-rust-94',15),('key-hash-seed-factory-fresh','RE-001-key-hash-rust-94',16)]:
        final=json.loads((ROOT/'research/work-items'/packet/'comparison.json').read_text());point=json.loads(raw[name+'-checkpoint.json']);audit=json.loads(raw[name+'-orchestration.json'])
        require(point['status']=='PARTIAL: not final qualifier success' and point['completed_builds']==count,'actual partial checkpoint label')
        require(point['actual_receipt_so_far']['builds']==final['builds'],'actual completed build records match final')
        require(audit['status']=='completed' and audit['receipt_sha256']==sha(js(final)),'final qualification status')
        require(audit['wrapper_sha256']==sha((HERE/'orchestration-wrapper.py').read_bytes()),'actual orchestration source')
        for c in audit['guarded_compiler_calls']:require(c['exit']==0 and c['free_before_bytes']>=316*1024*1024 and c['free_after_bytes']>=300*1024*1024,'current corpus disk guard')
        require(all('/baseline-' not in c['path'] for c in audit['completed_product_cleanup']),'baseline products preserved')
    stopped=json.loads(raw['inline-carrier-seed-factory-current-orchestration.json'])
    require('status' not in stopped and len(stopped['guarded_compiler_calls'])==3 and not stopped['completed_product_cleanup'],'stopped attempt not relabeled')
    require(stopped['wrapper_sha256']==sha((HERE/'stopped-wrapper.py').read_bytes()),'literal stopped wrapper')
    require(b'compiler reservation pending' in raw['stopped-inline.log'],'literal guard stop log')


def manifest_check():
    seen=set()
    for line in (HERE/'MANIFEST.sha256').read_text().splitlines():
        digest,name=line.split('  ');require('/' not in name and name not in seen and name!='MANIFEST.sha256','scoped manifest name')
        require(sha((HERE/name).read_bytes())==digest,'packet manifest');seen.add(name)
    require(seen=={p.name for p in HERE.iterdir() if p.is_file() and p.name!='MANIFEST.sha256'},'complete scoped manifest')


def reproduce(output):
    # Materialize only authored verification text/streams under ignored work.
    require(output.parent==ROOT/'work' and not output.exists(),'fresh direct work/ output required')
    prep=output.with_name(output.name+'-prep');require(not prep.exists(),'fresh preparation required');prep.mkdir()
    inputs,expected=streams()
    for source,name in [('qualified-runner.py','qualify.py'),('input-only.rs','input-only.rs'),('PLAN.json','PLAN.json')]:shutil.copyfile(HERE/source,prep/name)
    shutil.copyfile(ROOT/'src/node94-alias/evidence/seed-pair-vectors.tsv',prep/'seed-pair-vectors.tsv')
    (prep/'inputs.bin').write_bytes(inputs);(prep/'expected.bin').write_bytes(expected)
    native=ROOT/'work/alias-seed-callsite-intake/FROZEN.json'
    if native.exists():require(sha(native.read_bytes())==FREEZE,'existing native freeze differs')
    else:native.parent.mkdir(parents=True,exist_ok=True);native.write_bytes((HERE/'native-freeze.json').read_bytes())
    subprocess.run([sys.executable,'-I','-B',str(prep/'qualify.py'),str(output)],check=True,cwd=ROOT)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--write-controls',action='store_true');parser.add_argument('--qualify',type=Path);args=parser.parse_args()
    secs,frozen=authenticate((ROOT/'artifacts/node/94/hl-node').read_bytes());observed=controls((ROOT/'artifacts/node/94/hl-node').read_bytes(),secs,frozen)
    if args.write_controls:(HERE/'native-controls.json').write_bytes(js(observed));return
    require((HERE/'native-controls.json').read_bytes()==js(observed),'frozen control results');streams();retained();checkpoint_evidence();manifest_check()
    if args.qualify:reproduce(args.qualify.resolve())
    print('seed factory:197 new native bytes/51 rows;7 pair projections;4 operative static controls;16 actual authored builds;no target execution')

if __name__=='__main__':main()

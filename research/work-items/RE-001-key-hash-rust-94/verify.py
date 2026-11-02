"""Private, static data authentication and independent word-equation checks."""
import argparse
import base64
import gzip
import hashlib
import io
import os
import shutil
import struct
import subprocess
import tarfile
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records
spec = importlib.util.spec_from_file_location('private_equations', HERE/'equations.py')
eq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eq)

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(b): return hashlib.sha256(b).hexdigest()
def span(data, secs, va, n):
    s, = [s for s in secs if s['type'] != 8 and s['address'] <= va and va+n <= s['address']+s['size']]
    at=s['offset']+va-s['address']
    return data[at:at+n]

def authenticate(data):
    a=json.loads((HERE/'native.json').read_text())
    f=json.loads((HERE/'frozen.json').read_text())
    require(len(data)==a['target_bytes'] and sha(data)==a['target_sha256']==f['target_sha256'], 'static/source evidence check failed')
    require(sha((HERE/'frozen.json').read_bytes())==a['frozen_sha256'], 'static/source evidence check failed')
    require(sha((HERE/'equations.py').read_bytes())==f['equations_sha256'], 'static/source evidence check failed')
    secs,index=unwind_index(data)
    cies,fdes=eh_frame_records(data,secs)
    by_range={(r['start'],r['end']):r for r in fdes}
    for r in a['functions']:
        start,end=int(r['start'],16),int(r['end'],16)
        require(sum(f['start']==start and f['end']==end for f in fdes)==1, 'duplicate native extent')
        body=span(data,secs,start,end-start)
        require(len(body)==r['bytes'] and sha(body)==r['sha256'], 'static/source evidence check failed')
        native=by_range[start,end]
        require(native['fde']==int(r['fde'],16) and native['cie']==int(r['cie'],16) and native['lsda'] is None, 'static/source evidence check failed')
        require(sum(x['start']==start and x['fde']==native['fde'] for x in index)==1, 'static/source evidence check failed')
        for key in ('cie','fde'):
            va=int(r[key],16);n=int.from_bytes(span(data,secs,va,4),'little')+4
            require(span(data,secs,va,n).hex()==r[key+'_raw'], 'static/source evidence check failed')
    for name in ('native-gnu.txt','native-llvm.txt'):
        rows=[]
        for line in (HERE/name).read_text().splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S',line)
            if m:
                va=int(m[1],16)
                b=bytes.fromhex(m[2])
                require(b==span(data,secs,va,len(b)), 'native listing byte mismatch')
                rows.append((va,b))
        require(len(rows)==a['rows_each'], 'static/source evidence check failed')
        coverage={va+i:byte for va,b in rows for i,byte in enumerate(b)}
        expected={int(r['start'],16)+i:byte for r in a['functions'] for i,byte in enumerate(span(data,secs,int(r['start'],16),r['bytes']))}
        require(coverage==expected and sum(len(b) for _,b in rows)==a['bytes'], 'static/source evidence check failed')
    for e in a['call_edges']:
        va=int(e['site'],16)
        raw=bytes.fromhex(e['raw'])
        require(span(data,secs,va,5)==raw and raw[0]==0xe8, 'native call bytes changed')
        require(va+5+int.from_bytes(raw[1:],'little',signed=True)==int(e['target'],16), 'static/source evidence check failed')
    for e in a['source_forms']+a['constants']:
        va=int(e.get('site',e.get('va')),16)
        raw=bytes.fromhex(e['raw'])
        require(span(data,secs,va,len(raw))==raw, 'native operand bytes changed')
    suffix1=span(data,secs,0x13d392c,244);suffix2=span(data,secs,0x13d3cf7,244)
    require(suffix1==suffix2 and sha(suffix1)==a['identical_finalizer']['sha256'], 'static/source evidence check failed')
    slot=next(s for s in secs if s['address']<=0x577ae58 and 0x577ae68<=s['address']+s['size'])
    require(all(slot[k]==a['seed_slot_section'][k] for k in ('name','type','address','size','offset')), 'static/source evidence check failed')
    require(span(data,secs,0x577ae58,16).hex()==a['seed_slot_section']['raw_16'], 'static/source evidence check failed')
    seed_relocations=[]
    for section in secs:
        if section['type']==4:
            for offset in range(section['offset'],section['offset']+section['size'],24):
                where,info,addend=struct.unpack_from('<QQq',data,offset)
                if 0x577ae58<=where<0x577ae68:
                    seed_relocations.append((where,info,addend))
    require(seed_relocations==a['seed_slot_section']['relocations_targeting_seed_slot']==[], 'seed relocation changed')
    for caller in a['full_caller_contexts']:
        start,end=int(caller['start'],16),int(caller['end'],16)
        require((start,end) in by_range and sha(span(data,secs,start,end-start))==caller['sha256'], 'credited caller changed')
    for r in f['cases']:
        keys=[int(x,16) for x in r['keys_u64']];key=bytes.fromhex(r['input_hex']);h,states,final=eq.stream_key(keys,key)
        require(len(key)==r['length'] and h==eq.bulk_payload(keys,key+b'\xff'), 'static/source evidence check failed')
        require(f'{h:016x}'==r['borrowed_expected_H']==r['owned_expected_H'], 'static/source evidence check failed')
        require(states==[r['after_original_key_feed'],r['after_ff_feed']] and f'{final:016x}'==r['final_word_u64'], 'static/source evidence check failed')
        require(h&31==r['synthetic_mask31_slot'] and h>>57==r['synthetic_fingerprint7'], 'static/source evidence check failed')
    for r,c in zip(f['cases'],f['capacity_ignored_controls']):
        require(c['id']==r['id'] and c['capacity_u64_variants']==[r['length'],r['length']+1,r['length']+16], 'static/source evidence check failed')
        require(c['borrowed_and_owned_expected_H_each_capacity']==r['owned_expected_H'], 'static/source evidence check failed')
    for r in f['substitution_controls']:
        keys=[int(x,16) for x in r['keys_u64']];key=bytes.fromhex(r['original_input_hex']);h,_,_=eq.stream_key(keys,key)
        require(f'{h:016x}'==r['correct_hash_original_key'], 'static/source evidence check failed')
        alias=bytes.fromhex(r['associated_values_can_change_without_hash_change'][0])
        variants={'wrong_key_alias_letters_hash':alias[:10], 'wrong_key_packed_carrier_hash':alias, 'wrong_copied_key_first_byte_hash':b'B'+key[1:]}
        for field,value in variants.items():
            require(f'{eq.stream_key(keys,value)[0]:016x}'==r[field] and r[field]!=f'{h:016x}', 'substitution control changed')
        require(f'{eq.stream_key(keys,key,delimiter=254)[0]:016x}'==r['wrong_delimiter_fe_hash']!=f'{h:016x}', 'static/source evidence check failed')
        require(f'{eq.stream_key([keys[0]^1,keys[1]],key)[0]:016x}'==r['unstable_seed_flip_k0_hash']!=f'{h:016x}', 'static/source evidence check failed')
        for v in r['associated_value_invariance_rows']:
            require(len(bytes.fromhex(v['value_u128_le']))==16 and v['expected_H']==f'{h:016x}' and v['expected_slot31']==h&31 and v['expected_fingerprint7']==h>>57, 'static/source evidence check failed')
    for r in f['prior_fixed20_domain_controls']:
        keys=[int(x,16) for x in r['keys_u64']];key=bytes.fromhex(r['input_hex'])
        require(f'{eq.bulk_payload(keys,key):016x}'==r['prior_plain20_math_H'], 'static/source evidence check failed')
        require(f'{eq.stream_key(keys,key)[0]:016x}'==r['variable_key20_plus_ff_H']!=r['prior_plain20_math_H'], 'static/source evidence check failed')
    legacy=(ROOT/f['legacy_value_check']['source_file']).read_bytes()
    require(sha(legacy)==f['legacy_value_check']['source_sha256'], 'static/source evidence check failed')
    line,=[line for line in legacy.decode().splitlines() if line.startswith('a|'+f['legacy_value_check']['input_hex']+'|')]
    _,keyhex,aliashex,hashes=line.split('|');key=bytes.fromhex(keyhex)
    require([f'{eq.bulk_payload([0,0],key+b"\xff"+i.to_bytes(4,"little")):016x}' for i in range(10)]==hashes.split(','), 'static/source evidence check failed')
    require(bytes(65+int(x,16)%26 for x in hashes.split(',')).decode()==f['legacy_value_check']['alias_ascii'], 'static/source evidence check failed')
    return a, f


def fixtures():
    plan=json.loads((HERE/'PLAN.json').read_text())
    fixture=ROOT/'src/node94-alias/evidence/key-hash-vectors.tsv'
    raw=fixture.read_bytes()
    require(sha(raw)==plan['files']['key-hash-vectors.tsv']['sha256'], 'static/source evidence check failed')
    rows=[]
    for line in raw.decode().splitlines():
        if line.startswith('#'):continue
        name,k0,k1,encoded,h=line.split('\t')
        key=b'' if encoded=='-' else bytes.fromhex(encoded)
        keys=[int(k0,16),int(k1,16)]
        require(int(h,16)==eq.bulk_payload(keys,key+b'\xff')==eq.stream_key(keys,key)[0], 'static/source evidence check failed')
        rows.append((name,keys,key,int(h,16)))
    require(len(rows)==48, 'static/source evidence check failed')
    inputs=b'KH94\x01'+struct.pack('<H',len(rows));expected=inputs
    for i,(_,keys,key,h) in enumerate(rows):
        inputs+=struct.pack('<HQQI',i,*keys,len(key))+key
        expected+=struct.pack('<HQQQQ',i,h,h,h,h)
    for name,stream in [('inputs.bin',inputs),('expected.bin',expected)]:
        require(len(stream)==plan['files'][name]['bytes'] and sha(stream)==plan['files'][name]['sha256'], 'static/source evidence check failed')
    return rows,inputs,expected


def compare(actual,expected):
    if len(actual)!=len(expected) or actual[:7]!=expected[:7] or (len(actual)-7)%34:
        raise ValueError('Rust output framing')
    differences=[]
    for i in range((len(expected)-7)//34):
        a,b=actual[7+34*i:41+34*i],expected[7+34*i:41+34*i]
        if a[:2]!=b[:2]:raise ValueError('Rust case ID framing')
        if a!=b:differences.append({'id':i,'actual_hex':a.hex(),'expected_hex':b.hex()})
    return differences


RUSTC=Path('/workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin/rustc')
PREFIX=RUSTC.parent.parent
ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC'}
# These mutate only the independently authored key_hash composition.
RECIPES=(
 ('seed-lane','state.words[2] ^= seed[0];','state.words[2] ^= seed[1];'),
 ('omit-seed','    state.words[0] ^= seed[0];\n    state.words[2] ^= seed[0];\n    state.words[1] ^= seed[1];\n    state.words[3] ^= seed[1];','    let _ = seed;'),
 ('omit-delimiter','    state.write(key);\n    state.write(&[0xff]);','    state.write(key);'),
 ('delimiter-fe','    state.write(key);\n    state.write(&[0xff]);','    state.write(key);\n    state.write(&[0xfe]);'),
 ('alias-as-key','    state.write(key);','    state.write(&alias10(key));'),
 ('append-counter','    state.write(key);\n    state.write(&[0xff]);','    state.write(key);\n    state.write(&[0xff]);\n    state.write(&0u32.to_le_bytes());'),
 ('truncate16','    state.write(key);','    state.write(&key[..key.len().min(16)]);'),
)


def json_bytes(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()


def source_pins():
    names=['Cargo.toml','Cargo.lock','src/lib.rs','src/tests.rs','evidence/contract-vectors.txt',
           'evidence/inline-carrier-vectors.tsv','evidence/key-hash-vectors.tsv']
    paths=[ROOT/'src/node94-alias'/n for n in names]+[HERE/'input-only.rs']
    return {str(p.relative_to(ROOT)):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in paths}


def provider_pins():
    paths={RUSTC.resolve()}
    paths.update(p.resolve() for p in (PREFIX/'lib').glob('*.so*') if p.is_file())
    paths.update(p.resolve() for p in (PREFIX/'lib/rustlib/x86_64-unknown-linux-gnu/lib').iterdir() if p.is_file())
    paths.update(Path(shutil.which(c,path=ENV['PATH'])).resolve() for c in ('cc','ld'))
    return {str(p):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in sorted(paths)}


def qualify(output,inputs,expected):
    if output.exists():raise ValueError('refuse existing output')
    output.mkdir(parents=True);snapshot=output/'snapshot';snapshot.mkdir()
    payload={'lib.rs':(ROOT/'src/node94-alias/src/lib.rs').read_bytes(),'input-only.rs':(HERE/'input-only.rs').read_bytes(),
             'vectors.tsv':(ROOT/'src/node94-alias/evidence/key-hash-vectors.tsv').read_bytes(),
             'PLAN.json':(HERE/'PLAN.json').read_bytes(),'native.json':(HERE/'native.json').read_bytes(),
             'frozen.json':(HERE/'frozen.json').read_bytes(),'equations.py':(HERE/'equations.py').read_bytes(),
             'inputs.bin':inputs,'expected.bin':expected,'recipes.json':json_bytes(RECIPES)}
    for name,raw in payload.items():(snapshot/name).write_bytes(raw);(snapshot/name).chmod(0o444)
    manifest={n:{'bytes':len(b),'sha256':sha(b)} for n,b in payload.items()}
    manifest_raw=json_bytes(manifest);(snapshot/'SNAPSHOT.json').write_bytes(manifest_raw);(snapshot/'SNAPSHOT.json').chmod(0o444)
    pins,providers=source_pins(),provider_pins()
    version=subprocess.run([str(RUSTC),'-vV'],capture_output=True,env=ENV,check=True)
    require(b'release: 1.94.1\n' in version.stdout and b'host: x86_64-unknown-linux-gnu\n' in version.stdout, 'static/source evidence check failed')
    receipt={'schema':'re001-key-hash-compiled/1','snapshot_sha256':sha(manifest_raw),'snapshot_files':manifest,
             'source_input_pins':pins,'providers':providers,'runner_sha256':sha(Path(__file__).read_bytes()),
             'compiler_version':version.stdout.decode(),'builds':[],'captured_execution':False}
    variants=[('baseline',payload['lib.rs'])]
    for name,old,new in RECIPES:
        original=payload['lib.rs'].decode()
        require(original.count(old)==1, name)
        variants.append((name,original.replace(old,new).encode()))
    for name,source in variants:
        for opt in (0,3):
            require(all((snapshot/n).read_bytes()==b for n,b in payload.items()), 'static/source evidence check failed')
            build=output/f'{name}-opt{opt}';build.mkdir();src=build/'lib.rs';src.write_bytes(source);src.chmod(0o444)
            library,binary=build/'libnode94_alias.rlib',build/'input-only'
            common=[str(RUSTC),'--edition=2021','--target=x86_64-unknown-linux-gnu','--sysroot',str(PREFIX),
                    '-D','warnings','-C','overflow-checks=on','-C',f'opt-level={opt}','-C','debuginfo=0',
                    '--remap-path-prefix',f'{build}=/key-hash-build']
            commands=[common+['--crate-name','node94_alias','--crate-type=rlib',f'--emit=dep-info={build/"library.d"},link',str(src),'-o',str(library)],
                      common+['--crate-name','key_hash_input_only',f'--emit=dep-info={build/"driver.d"},link','--extern',f'node94_alias={library}',str(snapshot/'input-only.rs'),'-o',str(binary)]]
            logs=[]
            for i,command in enumerate(commands):
                require(src.read_bytes()==source and all((snapshot/n).read_bytes()==b for n,b in payload.items()), 'static/source evidence check failed')
                cp=subprocess.run(command,capture_output=True,cwd=build,env=ENV)
                for suffix,b in [('stdout',cp.stdout),('stderr',cp.stderr)]:(build/f'compile-{i}.{suffix}').write_bytes(b)
                logs.append({'argv':command,'exit':cp.returncode,'stdout_sha256':sha(cp.stdout),'stderr_sha256':sha(cp.stderr),'diagnostic_bytes':len(cp.stderr)})
                if cp.returncode or cp.stderr:raise ValueError(cp.stderr.decode())
            for dep,wanted in [('library.d',str(src)),('driver.d',str(snapshot/'input-only.rs'))]:
                seen={t.rstrip(':') for t in (build/dep).read_text().replace('\\\n',' ').split() if t.rstrip(':').endswith('.rs')}
                if seen!={wanted}:raise ValueError('unexpected compiler-read source')
            run=build/'run';run.mkdir();cp=subprocess.run([str(binary)],input=inputs,capture_output=True,cwd=run,env=ENV)
            (build/'actual.bin').write_bytes(cp.stdout);(build/'run.stderr').write_bytes(cp.stderr)
            if cp.returncode or cp.stderr:raise ValueError('Rust driver failure')
            differences=compare(cp.stdout,expected)
            if bool(differences)!=(name!='baseline'):raise ValueError(f'inoperative or wrong source control: {name}')
            framing=[]
            if name=='baseline':
                for label,raw,reason in [('empty',b'','header'),('record',b'KH94\x01\x01\x00','record'),
                                         ('payload',b'KH94\x01\x01\x00'+struct.pack('<HQQI',0,0,0,1),'payload'),
                                         ('trailing',b'KH94\x01\x00\x00x','trailing')]:
                    bad=subprocess.run([str(binary)],input=raw,capture_output=True,cwd=run,env=ENV)
                    if (bad.returncode,bad.stdout,bad.stderr)!=(1,b'',f'key-hash driver: {reason}\n'.encode()):raise ValueError('framing control')
                    framing.append({'id':label,'input_hex':raw.hex(),'exit':bad.returncode,'stderr':bad.stderr.decode()})
            receipt['builds'].append({'variant':name,'opt':opt,'source_sha256':sha(source),'commands':logs,'exit':cp.returncode,
                'stdout_sha256':sha(cp.stdout),'stdout_bytes':len(cp.stdout),'different_cases':len(differences),
                'first_witness':differences[0] if differences else None,'framing_controls':framing,
                'library_sha256':sha(library.read_bytes()),'executable_sha256':sha(binary.read_bytes()),
                'depinfo':{n:(build/n).read_text() for n in ('library.d','driver.d')}})
            require(src.read_bytes()==source and all((snapshot/n).read_bytes()==b for n,b in payload.items()), 'static/source evidence check failed')
            print(f'{name} opt{opt}: compiler0; differing paired cases {len(differences)}/48',flush=True)
    require(source_pins()==pins and provider_pins()==providers, 'static/source evidence check failed')
    receipt['status']='all compiled comparisons and seven operative source controls passed'
    (output/'receipt.json').write_bytes(json_bytes(receipt))
    # Only these small input/output/log streams are encoded, never compiled products.
    allowed={snapshot/'SNAPSHOT.json',snapshot/'recipes.json',snapshot/'inputs.bin',snapshot/'expected.bin'}
    allowed.update(p for p in output.rglob('*') if p.is_file() and p.suffix in ('.stdout','.stderr','.d'))
    allowed.update(output/f'{name}-opt{opt}'/'actual.bin' for name,_ in variants for opt in (0,3))
    archive=io.BytesIO()
    with tarfile.open(fileobj=archive,mode='w') as tar:
        for p in sorted(allowed):
            raw=p.read_bytes();info=tarfile.TarInfo(str(p.relative_to(output)));info.size=len(raw);info.mode=0o444;info.mtime=0;tar.addfile(info,io.BytesIO(raw))
    compressed=gzip.compress(archive.getvalue(),mtime=0)
    bound={'lib.rs':'src/node94-alias/src/lib.rs','input-only.rs':str((HERE/'input-only.rs').relative_to(ROOT)),
           'vectors.tsv':'src/node94-alias/evidence/key-hash-vectors.tsv',**{n:str((HERE/n).relative_to(ROOT)) for n in ('PLAN.json','native.json','frozen.json','equations.py')}}
    bundle={'schema':'re001-key-hash-raw-text/1','description':'Only authored inputs/expected/observed output and compiler stdout/stderr, dep-info, recipes, source-hash manifest. No captured or compiled executable/object/rlib bytes.',
            'encoding':'base64 deterministic gzip/tar; inert data only','payload_base64':base64.b64encode(compressed).decode(),
            'payload_bytes':len(compressed),'payload_sha256':sha(compressed),'comparison_json_sha256':sha(json_bytes(receipt)),
            'files':{str(p.relative_to(output)):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in sorted(allowed)},
            'omitted_snapshot_files_bound_to_current_text':bound}
    (output/'raw-streams.json').write_bytes(json_bytes(bundle))
    print(f'snapshot {receipt["snapshot_sha256"]}; receipt {sha(json_bytes(receipt))}',flush=True)
    return receipt


def manifest_check():
    seen=set()
    for line in (HERE/'MANIFEST.sha256').read_text().splitlines():
        digest,name=line.split('  ')
        require(name not in seen and '/' not in name and name!='MANIFEST.sha256', 'manifest name')
        require(sha((HERE/name).read_bytes())==digest, 'static/source evidence check failed')
        seen.add(name)
    require(seen=={p.name for p in HERE.iterdir() if p.is_file() and p.name!='MANIFEST.sha256'}, 'static/source evidence check failed')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--qualify',type=Path);args=parser.parse_args()
    a,f=authenticate((ROOT/'artifacts/node/94/hl-node').read_bytes());rows,inputs,expected=fixtures()
    if args.qualify:qualify(args.qualify.resolve(),inputs,expected)
    else:manifest_check()
    print('key hash: 3 whole native FDEs;48 paired cases;144 capacity/9 value/15 negative controls;no captured execution')

if __name__=='__main__':
    main()

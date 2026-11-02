"""Private input-only authored Rust qualifier; never execute captured code."""
import argparse
import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
RUSTC = Path('/workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin/rustc')
PREFIX = RUSTC.parent.parent
ENV = {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC'}
MIB = 1024*1024
FLOOR = 300*MIB
PLAN_SHA = 'd46958f9e908781cf15175a6d5abc9ed783c7ad74f6f1d60dd8be9e5d6133465'
NATIVE_FREEZE_SHA = '2201df213104ca7b79a63049512a90692b22915c9c829e0db04c1419f56b2de0'
RECIPES = (
 ('return-new','    old\n}', '    let _ = old;\n    *source\n}'),
 ('omit-increment','    source[0] = source[0].wrapping_add(1);','    let _ = source;'),
 ('increment-high','    source[0] = source[0].wrapping_add(1);','    source[1] = source[1].wrapping_add(1);'),
 ('memory32','    source[0] = source[0].wrapping_add(1);','    source[0] = (source[0] & 0xffffffff00000000) | u64::from((source[0] as u32).wrapping_add(1));'),
 ('decrement','    source[0] = source[0].wrapping_add(1);','    source[0] = source[0].wrapping_sub(1);'),
 ('swap-return','    old\n}', '    [old[1], old[0]]\n}'),
 ('wrong-native-source','    old\n}', '    let _ = old;\n    [0x202e90, 0]\n}'),
)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def js(value): return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def require(condition,message):
    if not condition: raise ValueError(message)


def check_free(reserve=16*MIB):
    free=shutil.disk_usage(ROOT).free
    require(free>=FLOOR+reserve,f'disk reservation pending: {free} bytes free, need {FLOOR+reserve}')
    return free


def source_pins():
    component=ROOT/'src/node94-alias'
    paths=[component/n for n in ('Cargo.toml','Cargo.lock','src/lib.rs','src/tests.rs','evidence/contract-vectors.txt',
           'evidence/inline-carrier-vectors.tsv','evidence/key-hash-vectors.tsv','evidence/seed-pair-vectors.tsv')]
    paths += [HERE/'input-only.rs']
    return {str(p.relative_to(ROOT)):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in paths}


def provider_pins():
    paths={RUSTC.resolve()}
    paths.update(p.resolve() for p in (PREFIX/'lib').glob('*.so*') if p.is_file())
    paths.update(p.resolve() for p in (PREFIX/'lib/rustlib/x86_64-unknown-linux-gnu/lib').iterdir() if p.is_file())
    paths.update(Path(shutil.which(c,path=ENV['PATH'])).resolve() for c in ('cc','ld'))
    return {str(p):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in sorted(paths)}


def freeze():
    require(sha((HERE/'PLAN.json').read_bytes())==PLAN_SHA,'pre-source plan changed')
    plan=json.loads((HERE/'PLAN.json').read_text())
    native=ROOT/'work/alias-seed-callsite-intake/FROZEN.json'
    require(sha(native.read_bytes())==NATIVE_FREEZE_SHA,'accepted native freeze changed')
    frozen=json.loads(native.read_text())
    for n,pin in plan['files'].items():
        raw=(HERE/n).read_bytes();require(len(raw)==pin['bytes'] and sha(raw)==pin['sha256'],'frozen input/expected changed')
    require((ROOT/'src/node94-alias/evidence/seed-pair-vectors.tsv').read_bytes()==(HERE/'seed-pair-vectors.tsv').read_bytes(),'current fixture changed')
    expected=(HERE/'expected.bin').read_bytes()
    require(len(expected)==357 and expected[:7]==b'NS94\x01\x07\x00','expected framing')
    for i,row in enumerate(frozen['frames']):
        record=expected[7+i*50:57+i*50]
        require(record[:2]==struct.pack('<H',i),'case ID')
        require(record[2:18]==bytes.fromhex(row['initializer_output56_hex'])[40:56],'old installed native pair')
        require(record[18:34]==bytes.fromhex(row['tls_after_hex'])[:16],'new native TLS pair')
    return plan


def compare(actual,expected):
    if len(actual)!=len(expected) or actual[:7]!=expected[:7] or (len(actual)-7)%50:
        raise ValueError('output framing')
    differences=[]
    for i in range((len(actual)-7)//50):
        a,b=actual[7+i*50:57+i*50],expected[7+i*50:57+i*50]
        require(a[:2]==b[:2],'case ID framing')
        if a!=b:differences.append({'id':i,'actual_hex':a.hex(),'expected_hex':b.hex()})
    return differences


def qualify(output):
    check_free();freeze();require(not output.exists(),'fresh output required')
    output.mkdir();snapshot=output/'snapshot';snapshot.mkdir()
    payload={'lib.rs':(ROOT/'src/node94-alias/src/lib.rs').read_bytes(),'input-only.rs':(HERE/'input-only.rs').read_bytes(),
             **{n:(HERE/n).read_bytes() for n in ('PLAN.json','seed-pair-vectors.tsv','inputs.bin','expected.bin')},'recipes.json':js(RECIPES)}
    for n,raw in payload.items():(snapshot/n).write_bytes(raw);(snapshot/n).chmod(0o444)
    manifest={n:{'bytes':len(raw),'sha256':sha(raw)} for n,raw in payload.items()};(snapshot/'SNAPSHOT.json').write_bytes(js(manifest));(snapshot/'SNAPSHOT.json').chmod(0o444)
    pins,providers=source_pins(),provider_pins();check_free()
    version=subprocess.run([str(RUSTC),'-vV'],capture_output=True,check=True,env=ENV)
    require(b'release: 1.94.1\n' in version.stdout,'compiler version')
    receipt={'schema':'alias-seed-pair-compiled/1','snapshot_sha256':sha(js(manifest)),'snapshot_files':manifest,
             'source_input_pins':pins,'providers':providers,'runner_sha256':sha(Path(__file__).read_bytes()),
             'compiler_version':version.stdout.decode(),'builds':[],'captured_execution':False,
             'scope':'logical initialized-pair operation once per cache; old pair stable for subsequent key_hash calls',
             'disk_floor_bytes':FLOOR,'native_freeze_sha256':NATIVE_FREEZE_SHA}
    variants=[('baseline',payload['lib.rs'])]
    for name,old,new in RECIPES:
        original=payload['lib.rs'].decode();require(original.count(old)==1,name)
        variants.append((name,original.replace(old,new).encode()))
    for name,source in variants:
        for opt in (0,3):
            require(all((snapshot/n).read_bytes()==raw for n,raw in payload.items()),'immutable snapshot changed')
            build=output/f'{name}-opt{opt}';build.mkdir();src=build/'lib.rs';src.write_bytes(source);src.chmod(0o444)
            library,binary=build/'libnode94_alias.rlib',build/'input-only'
            common=[str(RUSTC),'--edition=2021','--target=x86_64-unknown-linux-gnu','--sysroot',str(PREFIX),'-D','warnings',
                    '-C','overflow-checks=on','-C',f'opt-level={opt}','-C','debuginfo=0','--remap-path-prefix',f'{build}=/seed-pair-build']
            commands=[common+['--crate-name','node94_alias','--crate-type=rlib',f'--emit=dep-info={build/"library.d"},link',str(src),'-o',str(library)],
                      common+['--crate-name','seed_pair_input_only',f'--emit=dep-info={build/"driver.d"},link','--extern',f'node94_alias={library}',str(snapshot/'input-only.rs'),'-o',str(binary)]]
            logs=[]
            for ordinal,command in enumerate(commands):
                available=check_free();require(src.read_bytes()==source,'source changed')
                cp=subprocess.run(command,capture_output=True,cwd=build,env=ENV)
                for suffix,raw in [('stdout',cp.stdout),('stderr',cp.stderr)]:(build/f'compile-{ordinal}.{suffix}').write_bytes(raw)
                logs.append({'argv':command,'exit':cp.returncode,'stdout_sha256':sha(cp.stdout),'stderr_sha256':sha(cp.stderr),'diagnostic_bytes':len(cp.stderr),'free_before_bytes':available,'free_after_bytes':check_free(0)})
                require(cp.returncode==0 and not cp.stderr,'compiler failure or diagnostic')
            for dep,wanted in [('library.d',str(src)),('driver.d',str(snapshot/'input-only.rs'))]:
                seen={t.rstrip(':') for t in (build/dep).read_text().replace('\\\n',' ').split() if t.rstrip(':').endswith('.rs')}
                require(seen=={wanted},'compiler read unexpected source')
            run=build/'run';run.mkdir();cp=subprocess.run([str(binary)],input=payload['inputs.bin'],capture_output=True,cwd=run,env=ENV)
            (build/'actual.bin').write_bytes(cp.stdout);(build/'run.stderr').write_bytes(cp.stderr)
            require(cp.returncode==0 and not cp.stderr,'authored driver failed')
            differences=compare(cp.stdout,payload['expected.bin']);require(bool(differences)==(name!='baseline'),'inoperative mutant or incorrect baseline')
            framing=[]
            if name=='baseline':
                for label,raw,why in [('empty',b'','header'),('truncated',b'NS94\x01\x01\x00','record'),('payload',b'NS94\x01\x01\x00'+struct.pack('<HQQI',0,0,0,1),'payload'),('trailing',b'NS94\x01\x00\x00x','trailing')]:
                    bad=subprocess.run([str(binary)],input=raw,capture_output=True,cwd=run,env=ENV)
                    require((bad.returncode,bad.stdout,bad.stderr)==(1,b'',f'seed-pair driver: {why}\n'.encode()),'framing control')
                    framing.append({'id':label,'input_hex':raw.hex(),'exit':bad.returncode,'stderr':bad.stderr.decode()})
            products={str(x.relative_to(output)):{'bytes':x.stat().st_size,'sha256':sha(x.read_bytes())} for x in (library,binary)}
            receipt['builds'].append({'variant':name,'opt':opt,'source_sha256':sha(source),'commands':logs,'exit':cp.returncode,
                'stdout_sha256':sha(cp.stdout),'stdout_bytes':len(cp.stdout),'different_cases':len(differences),
                'first_witness':differences[0] if differences else None,'framing_controls':framing,'products':products,
                'depinfo':{n:(build/n).read_text() for n in ('library.d','driver.d')},'products_retained':name=='baseline' and opt==3})
            # Newly authored transient products are removed only after their run/hash;
            # all source/input/outputs/logs/receipts and baseline-opt3 products remain.
            if name!='baseline' or opt!=3:
                library.unlink();binary.unlink()
            require(src.read_bytes()==source and all((snapshot/n).read_bytes()==raw for n,raw in payload.items()),'snapshot/source changed')
            print(f'{name} opt{opt}: compiler0; different {len(differences)}/7; free {check_free(0)//MIB} MiB',flush=True)
    require(source_pins()==pins and provider_pins()==providers,'project/provider changed')
    receipt['status']='seven pair projections and hash compositions pass; seven mutants operative at opt0/3'
    (output/'receipt.json').write_bytes(js(receipt))
    allowed={snapshot/'SNAPSHOT.json',snapshot/'recipes.json',snapshot/'inputs.bin',snapshot/'expected.bin'}
    allowed.update(p for p in output.rglob('*') if p.is_file() and p.suffix in ('.stdout','.stderr','.d'))
    allowed.update(output/f'{name}-opt{opt}'/'actual.bin' for name,_ in variants for opt in (0,3))
    archive=io.BytesIO()
    with tarfile.open(fileobj=archive,mode='w') as tar:
        for p in sorted(allowed):
            raw=p.read_bytes();info=tarfile.TarInfo(str(p.relative_to(output)));info.size=len(raw);info.mode=0o444;info.mtime=0;tar.addfile(info,io.BytesIO(raw))
    compressed=gzip.compress(archive.getvalue(),mtime=0)
    bundle={'schema':'alias-seed-raw-text/1','encoding':'base64 deterministic gzip/tar; inert data only','payload_base64':base64.b64encode(compressed).decode(),
        'payload_bytes':len(compressed),'payload_sha256':sha(compressed),'comparison_json_sha256':sha(js(receipt)),
        'description':'Only authored input/expected/observed streams, compiler stdout/stderr, dep-info, recipes and snapshot hashes; no executable/object/rlib/captured artifact bytes.',
        'files':{str(p.relative_to(output)):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in sorted(allowed)}}
    (output/'raw-streams.json').write_bytes(js(bundle));print('snapshot',receipt['snapshot_sha256'],'receipt',sha(js(receipt)),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);args=parser.parse_args();qualify(args.output.resolve())

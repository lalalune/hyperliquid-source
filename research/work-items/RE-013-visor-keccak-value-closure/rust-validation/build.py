#!/usr/bin/env python3
"""Qualify the unchanged merged Keccak provider; no target execution.

MIT orchestration mechanics adapted from independently authored
RE-007-impact-notional-walk-94/source-validation/build.py, SHA256
cdd4aecec53c710bbe2419a8e577d72426dbda9d3dc4f9524eccce88b754541f.
No arithmetic/source/oracle from that component is imported.
Compilation requires a separate gate naming this phase source freeze.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib

HERE=Path(__file__).resolve().parent
PACKET=HERE.parent
ROOT=PACKET.parents[2]
SOURCE=ROOT/'src/node94-action-signable'
FIXTURE='research/work-items/RE-005-action-signable-94/vectors.tsv'
PRE_FREEZE='12263950e60ce1b78ec3bb6d44c619ada9baad1b4f742b396e2fd1cdb2fea26c'
PRE_MANIFEST='51d1b37e9cac893525d416bcfbc59bbabe2788f9ad3b4dbe0e56f999969bbf60'


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def identity(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=sha(raw))


def inventory(path):
    return {str(q.relative_to(path)):identity(q) for q in sorted(path.rglob('*')) if q.is_file()}


def write_json(path,value):
    path.write_text(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')


def precode_files():
    require(identity(PACKET/'PRE-RUST-FREEZE.json')['sha256']==PRE_FREEZE,'pre-code freeze identity')
    require(identity(PACKET/'MANIFEST.sha256')['sha256']==PRE_MANIFEST,'pre-code manifest identity')
    frozen=json.loads((PACKET/'PRE-RUST-FREEZE.json').read_text())
    require(len(frozen['files'])==29,'pre-code file count')
    names=[]
    for name,expected in frozen['files'].items():
        relative=Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts,'pre-code path')
        require(not(PACKET/name).is_symlink() and identity(PACKET/name)==expected,'pre-code changed: '+name)
        names.append(name)
    return sorted(names+['PRE-RUST-FREEZE.json','MANIFEST.sha256'])


def admit_sources(expected):
    names=precode_files()
    require(identity(HERE/'SOURCE-FREEZE.json')['sha256']==expected,'source freeze identity')
    f=json.loads((HERE/'SOURCE-FREEZE.json').read_text())
    require(not any(q.is_symlink() for q in [SOURCE,*SOURCE.parents]),'source ancestor symlink')
    require(not any(q.is_symlink() for q in SOURCE.rglob('*')),'source symlink')
    require(inventory(SOURCE)==f['source'] and len(f['source'])==11,'exact existing provider graph')
    require(identity(ROOT/FIXTURE)==f['external_fixture'] and not(ROOT/FIXTURE).is_symlink(),'existing test fixture')
    for name,expected_file in f['harness'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,'harness path')
        require(not(HERE/name).is_symlink() and identity(HERE/name)==expected_file,'harness changed: '+name)
    manifest=tomllib.loads((SOURCE/'Cargo.toml').read_text());lock=tomllib.loads((SOURCE/'Cargo.lock').read_text())
    require(set(manifest)=={'package','lib','dependencies'} and manifest['dependencies']=={} and
            manifest['lib']=={'path':'src/lib.rs'} and 'build' not in manifest['package'],'actual package hooks')
    require(lock['package']==[{'name':'node94-action-signable','version':'0.1.0'}],'actual lock graph')
    baseline=json.loads((PACKET/'BASIS-PINS.json').read_text())
    for item in baseline['prior_files']:
        require(identity(ROOT/item['path'])=={k:item[k] for k in ('bytes','sha256')},'pre-existing baseline changed')
    return f,names,manifest,lock


def mutants(original):
    final='    absorb(&mut state, &final_block);\n    keccak_f1600(&mut state);'
    edits=[
        ('sha3-delimiter', 'KECCAK_DELIMITER: u8 = 0x01;', 'KECCAK_DELIMITER: u8 = 0x06;'),
        ('rate-128', 'KECCAK_RATE: usize = 136;', 'KECCAK_RATE: usize = 128;'),
        ('missing-first-pad', 'final_block[remainder.len()] = KECCAK_DELIMITER;', 'final_block[remainder.len()] = KECCAK_DELIMITER & 0;'),
        ('missing-final-pad', 'final_block[KECCAK_RATE - 1] |= 0x80;', 'final_block[KECCAK_RATE - 1] |= 0;'),
        ('omit-exact-rate-final-block',final,'    if !remainder.is_empty() {\n'+final+'\n    }'),
        ('skip-complete-blocks','for block in &mut chunks {','for block in (&mut chunks).take(0) {'),
        ('absorb-replaces-state','*lane ^= u64::from_le_bytes(word);','*lane = u64::from_le_bytes(word);'),
        ('input-big-endian','u64::from_le_bytes(word)','u64::from_be_bytes(word)'),
        ('output-big-endian','bytes.copy_from_slice(&lane.to_le_bytes());','bytes.copy_from_slice(&lane.to_be_bytes());'),
        ('shift-output-lanes','state[..KECCAK_OUTPUT_LENGTH / 8]','state[1..1 + KECCAK_OUTPUT_LENGTH / 8]'),
        ('rounds-23','for round_constant in ROUND_CONSTANTS {','for round_constant in ROUND_CONSTANTS.into_iter().take(23) {'),
        ('first-round-constant','    0x0000_0000_0000_0001,','    0x0000_0000_0000_0003,'),
        ('theta-neighbor','column[(x + 4) % 5]','column[(x + 3) % 5]'),
        ('theta-rotation','column[(x + 1) % 5].rotate_left(1)','column[(x + 1) % 5].rotate_left(2)'),
        ('rho-offset','    1, 3, 6, 10, 15, 21,','    2, 3, 6, 10, 15, 21,'),
        ('pi-destination','    10, 7, 11, 17, 18, 3,','    11, 7, 11, 17, 18, 3,'),
        ('chi-no-negation','(!row[(x + 1) % 5])','row[(x + 1) % 5]'),
        ('chi-second-neighbor','row[(x + 2) % 5]','row[(x + 3) % 5]'),
        ('iota-wrong-lane','state[0] ^= round_constant;','state[1] ^= round_constant;'),
        ('rho-wrong-carried','let mut carried = state[1];','let mut carried = state[2];'),
        ('absorb-missing-rate-lane','.take(KECCAK_RATE / 8)','.take(KECCAK_RATE / 8 - 1)'),
        ('drop-last-remainder-byte','    final_block[..remainder.len()].copy_from_slice(remainder);',
         '    if !remainder.is_empty() {\n        final_block[..remainder.len()-1].copy_from_slice(&remainder[..remainder.len()-1]);\n    }'),
    ]
    result=[]
    for name,before,after in edits:
        require(original.count(before)==1,'unique mutation coordinate: '+name)
        changed=original.replace(before,after,1);require(changed!=original,'neutral mutant')
        result.append((name,changed,dict(name=name,before=before,after=after,source_sha256=sha(changed.encode()))))
    return result


def compare(actual,expected,ids):
    lines=actual.splitlines(keepends=True)
    require(len(lines)==len(ids),'incomplete value stream')
    for line,i in zip(lines,ids,strict=True):
        require(line.endswith(b'\n') and len(line)==90 and line[:25]==i+b'\t' and
                all(b in b'0123456789abcdef' for b in line[25:-1]),'output protocol/ID/order')
    e=expected.splitlines(keepends=True);differences=[i for i,(x,y) in enumerate(zip(lines,e,strict=True)) if x!=y]
    return dict(equal=actual==expected,rows=len(lines),different_rows=len(differences),first_different_rows=differences[:12],
                actual_sha256=sha(actual),expected_sha256=sha(expected))


def comparator_controls(expected,ids):
    lines=expected.splitlines(keepends=True)
    changed=bytearray(expected);changed[25]=ord('0') if changed[25]!=ord('0') else ord('1')
    values={'missing':b''.join(lines[:-1]),'extra':expected+lines[0],'reorder':b''.join([lines[1],lines[0],*lines[2:]]),
            'duplicate':b''.join([lines[0],lines[0],*lines[2:]]),'changed-ID':b'f'*24+expected[24:],
            'changed-value':bytes(changed),'short-digest':expected[:25]+expected[26:],
            'missing-LF':expected[:-1],'CRLF':expected.replace(b'\n',b'\r\n'),'empty':b''}
    require(compare(expected,expected,ids)['equal'],'positive comparator')
    result={}
    for name,actual in values.items():
        try:
            r=compare(actual,expected,ids)
        except ValueError as e:result[name]=dict(rejected=True,kind='protocol rejection',message=str(e))
        else:
            require(not r['equal'],'neutral comparator control')
            result[name]=dict(rejected=True,kind='value difference',different_rows=r['different_rows'])
    return result


def malformed_inputs(inputs):
    first=inputs.splitlines(keepends=True)[0];i=first[:24]
    return {'missing-LF':first[:-1],'empty-line':b'\n','short-ID':first[1:],
            'long-ID':b'0'+first,'uppercase-ID':b'A'*24+first[24:],
            'bad-ID':b'g'+first[1:],'missing-tab':first.replace(b'\t',b' ',1),
            'extra-tab':i+b'\t\t-\n','duplicate-ID':first+first,'empty-hex':i+b'\t\n',
            'odd-hex':i+b'\t0\n','uppercase-hex':i+b'\tAF\n','nonhex':i+b'\tgg\n',
            'bad-marker':i+b'\t--\n','space-suffix':i+b'\t00 \n','CRLF':first[:-1]+b'\r\n',
            'invalid-UTF8':first+b'\xff\n','malformed-after-valid':first+b'bad\n'}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--toolchain',type=Path,required=True);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--private-map',type=Path,required=True);ap.add_argument('--source-freeze-sha',required=True);args=ap.parse_args()
    require(Path(__file__).absolute()==Path(__file__).resolve(),'canonical nonsymlink harness invocation')
    f,pre_names,manifest,lock=admit_sources(args.source_freeze_sha)
    lexical=args.out.absolute();require(not lexical.is_symlink(),'output symlink');out=lexical.resolve()
    private=args.private_map.resolve();toolchain=args.toolchain.resolve()
    require(out.parent==Path('/tmp').resolve() and not out.exists(),'fresh direct /tmp output')
    require(not private.exists() and not private.is_relative_to(PACKET),'fresh private map outside packet')
    pins=json.loads((HERE/'TOOLCHAIN-PINS.json').read_text())
    def tools_inventory():return {d+'/'+n:e for d in ['bin','lib'] for n,e in inventory(toolchain/d).items()}
    def tool_links():return {str(q.relative_to(toolchain)):os.readlink(q) for d in ['bin','lib'] for q in (toolchain/d).rglob('*') if q.is_symlink()}
    require(tools_inventory()==pins['payload_files'] and tool_links()==pins['symlinks'],'actual toolchain payload/symlinks')
    variations=mutants((SOURCE/'src/keccak.rs').read_text())
    out.mkdir(mode=0o700);receipts=out/'receipts';(receipts/'raw').mkdir(parents=True);(out/'compiled-private').mkdir()
    cargo_home=out/'cargo-home';cargo_home.mkdir()
    mapping={'<BUILD>':str(out),'<TOOLCHAIN>':str(toolchain),'<SOURCE>':str(SOURCE),'<PACKET>':str(PACKET),'<REPO>':str(ROOT)}
    for i,parent in enumerate(ROOT.parents):
        if str(parent) not in ('/','/Users','/home'):mapping[f'<REPO_PARENT_{i}>']=str(parent)
    write_json(private,dict(logical_to_private=mapping))
    def logical(x):
        s=str(x)
        for key,value in sorted(mapping.items(),key=lambda x:-len(x[1])):s=s.replace(value,key)
        return s
    env0={'PATH':str(toolchain/'bin')+':/usr/bin:/bin:/usr/sbin:/sbin','CARGO_HOME':str(cargo_home),'RUSTC':str(toolchain/'bin/rustc'),
          'RUSTDOC':str(toolchain/'bin/rustdoc'),'CARGO_NET_OFFLINE':'true','CARGO_INCREMENTAL':'0','CARGO_TERM_COLOR':'never',
          'CARGO_BUILD_JOBS':'2','RUST_TEST_THREADS':'2','LANG':'C','LC_ALL':'C','TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1',
          'DEVELOPER_DIR':'/Library/Developer/CommandLineTools'}
    if 'HOME' in os.environ:env0['HOME']=os.environ['HOME']
    configs=set();workspaces={}
    def ancestors(start):
        for s in {start.absolute(),start.resolve()}:
            for q in [s,*s.parents]:
                for name in ['config','config.toml']:
                    x=q/'.cargo'/name;require(not x.exists() and not x.is_symlink(),'ancestor Cargo config');configs.add(logical(x))
                x=q/'Cargo.toml';require(not x.is_symlink(),'ancestor Cargo manifest symlink')
                if x.exists():
                    require('workspace' not in tomllib.loads(x.read_text()),'ancestor Cargo workspace');workspaces[logical(x)]=identity(x)
                else:workspaces[logical(x)]=dict(state='absent')
    ancestors(lexical);ancestors(out);ancestors(SOURCE)
    commands=[]
    def retain(raw):
        h=sha(raw);q=receipts/'raw'/(h+'.gz')
        if not q.exists():q.write_bytes(gzip.compress(raw,mtime=0))
        return dict(bytes=len(raw),sha256=h,gzip_ref='raw/'+h+'.gz')
    def run(label,argv,cwd=None,env=None,stdin=None,allowed=(0,)):
        used=env or env0;started=time.monotonic();completion='completed';diagnostic=None
        try:
            r=subprocess.run([str(x) for x in argv],cwd=cwd or out,env=used,input=stdin,capture_output=True,timeout=300)
            stdout,stderr,code=r.stdout,r.stderr,r.returncode
        except subprocess.TimeoutExpired as e:
            stdout,stderr,code=e.stdout or b'',e.stderr or b'',None;completion='timeout'
        except OSError as e:
            stdout,stderr,code=b'',b'',None;completion='launch-error';diagnostic=retain(str(e).encode())
        commands.append(dict(label=label,argv=[logical(x) for x in argv],cwd=logical(cwd or out),completion=completion,exit_code=code,
            elapsed_seconds=round(time.monotonic()-started,3),stdin=None if stdin is None else dict(bytes=len(stdin),sha256=sha(stdin)),
            stdout=retain(stdout),stderr=retain(stderr),launch_error_diagnostic=diagnostic))
        write_json(receipts/'commands.json',commands)
        for raw in [stdout,stderr]:
            if 'HOME' in used:require(used['HOME'].encode() not in raw,'private home path in retained stream: '+label)
        require(completion=='completed' and code in allowed,'command failed: '+label)
        return stdout
    for name,flag in [('cargo','--version'),('rustc','-vV'),('rustdoc','--version'),('rustfmt','--version'),('clippy-driver','--version')]:
        run(name+'-version',[toolchain/'bin'/name,flag])
    run('clang-version',['/usr/bin/clang','--version'])
    sdk=run('sdk-path',['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path']).decode().strip();env0['SDKROOT']=sdk
    run('sdk-version',['/usr/bin/xcrun','--sdk','macosx','--show-sdk-version'])
    external={}
    for name in ['clang','ld']:
        q=Path(run('resolved-'+name,['/usr/bin/xcrun','--find',name]).decode().strip());external[str(q)]=identity(q)
    for name in ['/usr/bin/clang','/usr/bin/xcrun','/usr/bin/ld','/usr/bin/ar',sys.executable]:external[logical(name)]=identity(Path(name))
    sdk_inputs={n:identity(Path(sdk)/n) for n in ['SDKSettings.json','usr/lib/libSystem.tbd']}
    static=out/'precode-copy';static.mkdir()
    for name in pre_names:
        q=static/name;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(PACKET/name,q)
        require(identity(q)==identity(PACKET/name),'exact static copy')
    require(len(inventory(static))==31,'exact pre-code copied graph')
    run('post-source-static-replay',[sys.executable,'-B',static/'verify.py','--repo',ROOT,'--out',receipts/'static-replay.json'])
    expected_static=gzip.decompress((PACKET/'validation/final-normal.json.gz').read_bytes())
    require((receipts/'static-replay.json').read_bytes()==expected_static,'immutable pre-code replay differs')
    inputs=gzip.decompress((PACKET/'corpus/inputs.tsv.gz').read_bytes());expected=gzip.decompress((PACKET/'corpus/expected.tsv.gz').read_bytes())
    provenance=json.loads((PACKET/'corpus/provenance.json').read_text())
    require(sha(inputs)==provenance['inputs_sha256'] and sha(expected)==provenance['expected_sha256'],'frozen streams')
    ids=[line.split(b'\t')[0] for line in inputs.splitlines()];require(len(ids)==len(set(ids))==2000,'frozen input IDs')
    controls=comparator_controls(expected,ids);source_copies={};driver_copies={};observations={};environments={};driver_controls=[];artifacts=[]
    def archive(path,label):
        raw=path.read_bytes();h=sha(raw);q=out/'compiled-private'/(h+'.gz')
        if not q.exists():q.write_bytes(gzip.compress(raw,mtime=0))
        require(gzip.decompress(q.read_bytes())==raw,'compiled private retention')
        item=dict(label=label,bytes=len(raw),sha256=h,private_gzip=logical(q),stored_sha256=sha(q.read_bytes()),public_bytes_distributed=False,
                  private_home_prefix_present='HOME' in env0 and env0['HOME'].encode() in raw,
                  canonical_build_prefix_present=str(out).encode() in raw)
        artifacts.append(item);write_json(receipts/'compiled-artifact-identities.json',artifacts);return item
    def build(label,altered=None,test=False,repeat=False):
        phase=(out/label).resolve();record=label+('-same-path-repeat' if repeat else '')
        component=phase/'src/node94-action-signable';fixture=phase/FIXTURE;client_source=phase/'input_client.rs'
        if repeat:
            require(phase.exists() and altered is None,'same-path repeat admission')
            # First-pass bytes already reside in content-addressed private archives.
            for profile in ['debug','release']:
                for suffix,path in [('rlib',phase/'target'/profile/'libnode94_action_signable.rlib'),('client',phase/('client-'+profile))]:
                    matches=[x for x in artifacts if x['label']==label+'/'+profile+'/'+suffix]
                    require(len(matches)==1,'unique before-repeat artifact')
                    x=matches[0];saved=out/'compiled-private'/(x['sha256']+'.gz')
                    require(identity(path)=={k:x[k] for k in ['bytes','sha256']} and sha(saved.read_bytes())==x['stored_sha256'] and
                            gzip.decompress(saved.read_bytes())==path.read_bytes(),'before-repeat artifact retention')
            shutil.rmtree(phase/'target')
            for profile in ['debug','release']:(phase/('client-'+profile)).unlink()
        else:
            phase.mkdir();component.parent.mkdir();shutil.copytree(SOURCE,component)
            fixture.parent.mkdir(parents=True);shutil.copyfile(ROOT/FIXTURE,fixture)
            shutil.copyfile(HERE/'input_client.rs',client_source)
            if altered is not None:(component/'src/keccak.rs').write_text(altered)
        require(not any(q.is_symlink() for q in phase.rglob('*')),'build copy symlink')
        before=inventory(component);wanted=dict(f['source'])
        if altered is not None:wanted['src/keccak.rs']=dict(bytes=len(altered.encode()),sha256=sha(altered.encode()))
        require(before==wanted and identity(fixture)==f['external_fixture'],'actual copied source/fixture')
        require(identity(client_source)==f['harness']['input_client.rs'],'actual copied input-only client')
        source_copies[record]=dict(source=before,external_fixture=identity(fixture));driver_copies[record]=identity(client_source)
        write_json(receipts/'source-copies.json',source_copies);write_json(receipts/'driver-copies.json',driver_copies)
        ancestors(component)
        flags=['-Dwarnings','-C','overflow-checks=on','-C','linker=/usr/bin/clang',
               '--remap-path-prefix='+str(phase)+'=/visor-keccak-build','--remap-path-prefix='+str(toolchain)+'=/visor-keccak-toolchain']
        env=dict(env0,CARGO_TARGET_DIR=str(phase/'target'),CARGO_ENCODED_RUSTFLAGS='\x1f'.join(flags))
        environments[record]={k:('<ORIGINAL_HOME_UNCHANGED_NOT_RECORDED>' if k=='HOME' else logical(v)) for k,v in env.items()}
        write_json(receipts/'compile-environments.json',environments)
        if altered is None:
            md=json.loads(run(record+'-metadata',[toolchain/'bin/cargo','metadata','--offline','--locked','--format-version','1'],component,env))
            require(len(md['packages'])==len(md['workspace_members'])==1 and Path(md['workspace_root']).resolve()==component,'actual one-package workspace')
            pkg=md['packages'][0]
            require(pkg['source'] is None and pkg['dependencies']==[] and [(t['name'],t['kind']) for t in pkg['targets']]==[('node94_action_signable',['lib'])],'actual lib/test graph')
            run(record+'-format-check',[toolchain/'bin/rustfmt','--edition','2024','--check',*sorted((component/'src').glob('*.rs')),client_source],component,env)
        result={}
        for profile in ['debug','release']:
            release=['--release'] if profile=='release' else []
            run(record+'-'+profile+'-cargo-build',[toolchain/'bin/cargo','build','--offline','--locked','--lib',*release],component,env)
            if test:run(record+'-'+profile+'-cargo-test',[toolchain/'bin/cargo','test','--offline','--locked','--lib',*release],component,env)
            rlib=phase/'target'/profile/'libnode94_action_signable.rlib';client=phase/('client-'+profile)
            run(record+'-'+profile+'-link-client',[toolchain/'bin/rustc','--edition=2024','--crate-name','visor_keccak_input_client',client_source,
                '--extern','node94_action_signable='+str(rlib),'-L','dependency='+str(phase/'target'/profile/'deps'),'-C','opt-level='+('3' if profile=='release' else '0'),
                '-C','debuginfo='+('0' if profile=='release' else '2'),*flags,'-o',client],component,env)
            rlib_info=archive(rlib,record+'/'+profile+'/rlib')
            client_info=archive(client,record+'/'+profile+'/client')
            output=run(record+'-'+profile+'-values',[client],component,env,inputs)
            observation=compare(output,expected,ids)
            result[profile]=dict(comparison=observation,rlib=rlib_info,client=client_info)
            observations[record]=result;write_json(receipts/'build-results.json',observations)
            require(observation['equal'] if altered is None else not observation['equal'],'value qualification failed: '+record+'/'+profile)
            if label=='clean-one' and not repeat and profile=='debug':
                for name,bad in malformed_inputs(inputs).items():
                    raw=run('malformed-'+name,[client],component,env,bad,allowed=(2,));require(not raw,'malformed partial output')
                    driver_controls.append(dict(name=name,exit_code=2,input_sha256=sha(bad),output_bytes=0))
                raw=run('extra-argument',[client,'unexpected'],component,env,inputs[:inputs.index(b'\n')+1],allowed=(2,));require(not raw,'argument value output')
                driver_controls.append(dict(name='extra-argument',exit_code=2,output_bytes=0))
                raw=run('valid-empty',[client],component,env,b'');require(not raw,'empty value output')
                driver_controls.append(dict(name='valid-empty',exit_code=0,output_bytes=0))
        if test:run(record+'-clippy',[toolchain/'bin/cargo','clippy','--offline','--locked','--all-targets','--','-D','warnings'],component,env)
        require(inventory(component)==before and identity(fixture)==f['external_fixture'],'copy changed during build')
        return result
    baseline=build('clean-one',test=True)
    repeat=build('clean-one',repeat=True)
    second=build('clean-two')
    def equal_artifacts(a,b):return {profile:{kind:a[profile][kind]['sha256']==b[profile][kind]['sha256'] for kind in ['rlib','client']} for profile in ['debug','release']}
    mutation_results=[]
    for name,changed,definition in variations:
        observation=build('mutant-'+name,altered=changed);mutation_results.append(dict(definition=definition,profiles=observation))
        print('compiled complete-stream mutant detected: '+name,flush=True)
    require(tools_inventory()==pins['payload_files'] and tool_links()==pins['symlinks'],'toolchain changed')
    for path,expected_file in external.items():
        for key,value in mapping.items():path=path.replace(key,value)
        require(identity(Path(path))==expected_file,'external tool changed')
    require({n:identity(Path(sdk)/n) for n in sdk_inputs}==sdk_inputs,'selected SDK changed')
    admit_sources(args.source_freeze_sha)
    write_json(receipts/'build-audit.json',dict(source_freeze_sha256=args.source_freeze_sha,manifest=manifest,lock=lock,
        original_provider_unchanged=True,external_fixture=f['external_fixture'],toolchain_payloads_unchanged=True,
        configs_absent=sorted(configs),ancestor_manifests=workspaces,external_tools=external,SDKROOT=sdk,sdk_inputs=sdk_inputs,
        limit='Exact bin/lib and selected linker/SDK inputs; OS/dyld/full SDK not hermetic or captured-target compiler evidence.'))
    result=dict(source_freeze_sha256=args.source_freeze_sha,cases=2000,baseline=baseline,same_path_clean_repeat=repeat,separate_directory_rebuild=second,
        exact_raw_comparisons=dict(same_path=equal_artifacts(baseline,repeat),separate_directory=equal_artifacts(baseline,second),masks=[],normalization=None),
        mutants=mutation_results,comparator_controls=controls,input_controls=driver_controls,commands=len(commands),value_streams=6+2*len(variations),
        source_unchanged=True,precode_unchanged=True,scope='Actual existing MIT provider and input-only client only; no target execution or ABI/compiler/security equivalence.')
    write_json(receipts/'results.json',result)
    print(json.dumps(dict(status='PASS actual host qualification',commands=len(commands),cases=2000,mutants=len(variations),value_streams=result['value_streams'],receipts=logical(receipts))))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError) as e:
        print(str(e),file=sys.stderr);raise SystemExit(1) from e

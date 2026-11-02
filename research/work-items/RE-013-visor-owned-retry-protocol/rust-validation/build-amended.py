#!/usr/bin/env python3
"""Qualify supplied retry/ownership values; no target execution.

MIT orchestration mechanics adapted from independently authored
RE-013-visor-keccak-value-closure/rust-validation/build.py, SHA256
3f2d9755c41a55e688893ab36264ee21af4ef3b62ab7d9d430d1a569f9e5d065.
No provider/oracle implementation is imported. The only production dependency
is the real unchanged sibling visor-duration-value Cargo package.
Compilation requires a separate gate naming this exact source freeze.
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
import struct
import time
import tomllib

HERE=Path(__file__).resolve().parent
PACKET=HERE.parent
ROOT=PACKET.parents[2]
SOURCE=ROOT/'src/visor-retry-protocol'
DEPENDENCY=ROOT/'src/visor-duration-value'
PRE_FREEZE='4a77497d5fdc8c701cf4f44216c1e3af18cb885655c26d399c68260fc248303e'
PRE_MANIFEST='32851b28e3dd622036f3dbf9f23555e092614143994b85e044c9986e22c45fbf'


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
    require(identity(PACKET/'MANIFEST.json')['sha256']==PRE_MANIFEST,'pre-code manifest identity')
    frozen=json.loads((PACKET/'PRE-RUST-FREEZE.json').read_text())
    require(len(frozen['files'])==53,'pre-code file count')
    names=[]
    for name,expected in frozen['files'].items():
        relative=Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts,'pre-code path')
        require(not(PACKET/name).is_symlink() and identity(PACKET/name)==expected,'pre-code changed: '+name)
        names.append(name)
    return sorted(names+['PRE-RUST-FREEZE.json'])


def admit_sources(expected):
    names=precode_files()
    require(identity(HERE/'SOURCE-FREEZE-2.json')['sha256']==expected,'source freeze identity')
    f=json.loads((HERE/'SOURCE-FREEZE-2.json').read_text())
    for source,key in [(SOURCE,'source'),(DEPENDENCY,'dependency')]:
        require(not any(q.is_symlink() for q in [source,*source.parents,*source.rglob('*')]),'source symlink')
        require(inventory(source)==f[key] and len(f[key])==5,'exact actual source graph: '+key)
    for name,expected_file in f['harness'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,'harness path')
        require(not(HERE/name).is_symlink() and identity(HERE/name)==expected_file,'harness changed: '+name)
    manifest=tomllib.loads((SOURCE/'Cargo.toml').read_text());lock=tomllib.loads((SOURCE/'Cargo.lock').read_text())
    require(set(manifest)=={'package','lib','dependencies','profile'} and
            manifest['dependencies']=={'visor-duration-value':{'path':'../visor-duration-value'}} and
            manifest['lib']=={'path':'src/lib.rs'} and 'build' not in manifest['package'],'actual package hooks')
    require(lock['package']==[{'name':'visor-duration-value','version':'0.1.0'},
        {'name':'visor-retry-protocol','version':'0.1.0','dependencies':['visor-duration-value']}],'actual two-package lock')
    dependency=tomllib.loads((DEPENDENCY/'Cargo.toml').read_text())
    require(dependency['dependencies']=={} and 'workspace' not in dependency and 'build' not in dependency['package'],'dependency graph')
    baseline=json.loads((PACKET/'DEPENDENCY-PINS.json').read_text())
    for name,pin in {**baseline['source'],**baseline['credited_evidence']}.items():
        require(identity(ROOT/name)==pin,'prior duration changed: '+name)
    old=json.loads((ROOT/'research/work-items/RE-013-visor-duration-value-rust/PUBLIC-MANIFEST.json').read_text())
    require(len(old['files'])==336,'prior public set')
    for name,pin in old['files'].items():require(identity(ROOT/name)==pin,'prior public bytes changed')
    return f,names,manifest,lock


def mutants(original):
    edits=[
        ('default-empty','delays.unwrap_or(&DEFAULT_DELAYS)','delays.unwrap_or(&DEFAULT_DELAYS[..0])','native'),
        ('default-first-word','0x3f50_624d_d2f1_a9fc,','0x3f60_624d_d2f1_a9fc,','native'),
        ('owned-last-delay','0x4024_0000_0000_0000,','0x4022_0000_0000_0000,','native'),
        ('skip-first-delay','for &bits in selected {','for &bits in selected.iter().skip(1) {','native'),
        ('skip-last-delay','for &bits in selected {','for &bits in selected.iter().take(selected.len().saturating_sub(1)) {','native'),
        ('reverse-delay-order','for &bits in selected {','for &bits in selected.iter().rev() {','native'),
        ('clock-selector','pub const fn clock(self) -> i32 {\n        1','pub const fn clock(self) -> i32 {\n        2','native'),
        ('flags-selector','pub const fn flags(self) -> i32 {\n        0','pub const fn flags(self) -> i32 {\n        1','native'),
        ('chunk-limit','const CHUNK_LIMIT: u64 = i64::MAX as u64;','const CHUNK_LIMIT: u64 = i64::MAX as u64 - 1;','native'),
        ('drop-initial-nanos','let mut nanoseconds = duration.nanoseconds();','let mut nanoseconds = duration.nanoseconds() * 0;','native'),
        ('completion-drops-unrequested','seconds = unrequested_seconds;','seconds = unrequested_seconds * 0;','native'),
        ('interruption-drops-unrequested','seconds = unrequested_seconds + reply.remaining_seconds as u64;','seconds = unrequested_seconds * 0 + reply.remaining_seconds as u64;','native'),
        ('interruption-consumes-remainder','seconds = unrequested_seconds + reply.remaining_seconds as u64;\n                nanoseconds = reply.remaining_nanoseconds as u32;',
         'seconds = unrequested_seconds;\n                nanoseconds = 0;','native'),
        ('equal-remainder-refused','reply.remaining_seconds as u64 > requested_seconds','reply.remaining_seconds as u64 >= requested_seconds','native'),
        ('builder-forgets-full-schedule','terminal(description, selected, &current)','terminal(description, &selected[..0], &current)','native'),
        ('replacement-error-leak','drop(current);\n                current = next;','std::mem::forget(current);\n                current = next;','native'),
        ('success-error-leak','drop(current);\n                return RetryOutcome::Succeeded;','std::mem::forget(current);\n                return RetryOutcome::Succeeded;','native'),
        ('terminal-error-leak','drop(current);\n    RetryOutcome::Exhausted(result)','std::mem::forget(current);\n    RetryOutcome::Exhausted(result)','native'),
        ('late-command-drop','    drop(command);','    let _command = command;','native'),
        ('skip-cleanup-callback','        drop(cleanup(&value));','        let _unused_callback = cleanup;','native'),
        ('cleanup-error-leak','        drop(cleanup(&value));','        std::mem::forget(cleanup(&value));','native'),
        ('invalid-remainder-policy','return Err(SleepRefusal::InvalidRemainder);','return Err(SleepRefusal::UnexpectedSleepCode(4));','new_policy'),
        ('unexpected-code-policy','code => return Err(SleepRefusal::UnexpectedSleepCode(code)),','_code => return Err(SleepRefusal::InvalidRemainder),','new_policy'),
        ('refusal-runs-cleanup','    if matches!(&result, RetryOutcome::Refused(_)) {\n        drop(cleanup_value);\n        return result;\n    }',
         '    if matches!(&result, RetryOutcome::Refused(_)) {\n        let _policy = 0;\n    }','new_policy'),
    ]
    result=[]
    for name,before,after,domain in edits:
        require(original.count(before)==1,'unique mutation coordinate: '+name)
        changed=original.replace(before,after,1);require(changed!=original,'neutral mutant')
        result.append((name,changed,dict(name=name,before=before,after=after,domain=domain,source_sha256=sha(changed.encode()))))
    return result


def strict_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def parse_values(raw,ids):
    lines=raw.splitlines(keepends=True);require(len(lines)==len(ids),'incomplete value stream')
    result=[]
    for line,key in zip(lines,ids,strict=True):
        require(line.endswith(b'\n') and b'\r' not in line,'canonical output LF')
        fields=line[:-1].split(b'\t');require(len(fields)==2 and fields[0]==key,'output ID/order/fields')
        value=strict_json(fields[1]);require(isinstance(value,dict) and set(value)=={'code','outcome','terminal','terminal_identity','trace'},'output keys')
        require(value['outcome'] in ['succeeded','exhausted','invalid_remainder','unexpected_sleep_code'],'outcome domain')
        require(value['code'] is None or type(value['code']) is int and -(1<<31)<=value['code']<(1<<31),'code domain')
        require(value['terminal'] is None or type(value['terminal']) is int and 0<=value['terminal']<1<<64,'terminal domain')
        require(value['terminal_identity'] is None or type(value['terminal_identity']) is bool,'terminal identity type')
        require(isinstance(value['trace'],list),'trace list')
        for event in value['trace']:
            require(isinstance(event,list) and event and isinstance(event[0],str),'trace event shape')
        canonical=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
        require(fields[1]==canonical,'canonical JSON output')
        result.append(value)
    return result


def compare(actual,expected,ids,domains):
    values=parse_values(actual,ids);wanted=parse_values(expected,ids)
    changed=[i for i,(a,b) in enumerate(zip(values,wanted,strict=True)) if a!=b]
    return dict(equal=actual==expected,rows=len(values),different_rows=len(changed),first_different_rows=changed[:12],
        differences_by_domain={d:sum(domains[i]==d for i in changed) for d in sorted(set(domains))},
        actual_sha256=sha(actual),expected_sha256=sha(expected))


def comparator_controls(expected,ids,domains):
    lines=expected.splitlines(keepends=True);value=strict_json(lines[0].split(b'\t')[1]);value['terminal_identity']=False
    altered=ids[0]+b'\t'+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'+b''.join(lines[1:])
    bad={'missing':b''.join(lines[:-1]),'extra':expected+lines[0],'reorder':b''.join([lines[1],lines[0],*lines[2:]]),
        'duplicate':b''.join([lines[0],lines[0],*lines[2:]]),'changed-ID':b'X'+expected[1:],'changed-value':altered,
        'missing-LF':expected[:-1],'CRLF':expected.replace(b'\n',b'\r\n'),'empty':b'',
        'duplicate-key':expected.replace(b'{"code":',b'{"code":null,"code":',1),
        'truncated-json':lines[0][:-2]+b'\n'+b''.join(lines[1:])}
    require(compare(expected,expected,ids,domains)['equal'],'positive comparator')
    results={}
    for name,raw in bad.items():
        try:r=compare(raw,expected,ids,domains)
        except (ValueError,TypeError) as e:results[name]=dict(rejected=True,kind='protocol rejection',message=str(e))
        else:
            require(not r['equal'],'neutral comparator control');results[name]=dict(rejected=True,kind='value difference',different_rows=r['different_rows'])
    return results


def malformed_inputs(inputs):
    first=inputs.splitlines(keepends=True)[0]
    base=b'VR01'+b'\0'+struct.pack('<QIQI',1,0,2,0)+b'\1'+struct.pack('<III',0,0,0)
    require(len(base)==42,'independent minimal frame length')
    def line(frame):return b'C999999\t'+frame.hex().encode()+b'\n'
    def field(at,value):return line(base[:at]+value+base[at+len(value):])
    return {'empty-batch':b'','missing-LF':first[:-1],'empty-line':b'\n','short-ID':first[1:],
        'bad-ID':b'X'+first[1:],'missing-tab':first.replace(b'\t',b' ',1),'extra-tab':first.replace(b'\t',b'\t\t',1),
        'duplicate-ID':first+first,'empty-hex':b'C999999\t\n','odd-hex':b'C999999\t0\n',
        'uppercase-hex':b'C999999\tAF\n','nonhex':b'C999999\tgg\n','CRLF':first[:-1]+b'\r\n',
        'invalid-UTF8-transport':first+b'\xff\n','malformed-after-valid':first+b'bad\n',
        'bad-magic':field(0,b'WR01'),'bad-mode':field(4,b'\2'),'request-byte-cap':field(13,struct.pack('<I',65537)),
        'description-UTF8':line(base[:25]+struct.pack('<I',1)+b'\xff'+base[29:]),
        'bad-delay-option':field(29,b'\2'),'delay-count-cap':field(30,struct.pack('<I',257)),
        'attempt-count-cap':field(34,struct.pack('<I',257)),'sleep-count-cap':field(38,struct.pack('<I',1025)),
        'bad-attempt-option':line(base[:34]+struct.pack('<I',1)+b'\2'+struct.pack('<I',0)),
        'truncated-frame':line(base[:-1]),'trailing-frame':line(base+b'\0'),
        'frame-cap':line(bytes((1<<20)+1))}


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
    variations=mutants((SOURCE/'src/lib.rs').read_text())
    out.mkdir(mode=0o700);receipts=out/'receipts';(receipts/'raw').mkdir(parents=True);(out/'compiled-private').mkdir()
    cargo_home=out/'cargo-home';cargo_home.mkdir()
    mapping={'<BUILD>':str(out),'<TOOLCHAIN>':str(toolchain),'<SOURCE>':str(SOURCE),'<DEPENDENCY>':str(DEPENDENCY),'<PACKET>':str(PACKET),'<REPO>':str(ROOT)}
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
    ancestors(lexical);ancestors(out);ancestors(SOURCE);ancestors(DEPENDENCY)
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
    static=out/'isolated-precode/research/work-items/RE-013-visor-owned-retry-protocol';static.mkdir(parents=True)
    for name in pre_names:
        q=static/name;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(PACKET/name,q)
        require(identity(q)==identity(PACKET/name),'exact static copy')
    require(len(inventory(static))==54,'exact pre-code copied graph')
    run('post-source-static-replay',[sys.executable,'-B',static/'verify.py','--binary',ROOT/'artifacts/visor/captured/hl-visor',
        '--dependency-root',ROOT,'--freeze-sha',PRE_FREEZE,'--out',receipts/'static-replay.json'])
    expected_static=gzip.decompress((HERE/'precode-frozen-replay.json.gz').read_bytes())
    require((receipts/'static-replay.json').read_bytes()==expected_static,'immutable frozen-admission replay differs')
    summary=json.loads((PACKET/'corpus/summary.json').read_text())
    inputs=gzip.decompress((PACKET/'corpus/inputs.tsv.gz').read_bytes());expected=gzip.decompress((PACKET/'corpus/expected.tsv.gz').read_bytes())
    provenance=gzip.decompress((PACKET/'corpus/cases.jsonl.gz').read_bytes())
    for name,raw in [('inputs.tsv',inputs),('expected.tsv',expected),('cases.jsonl',provenance)]:
        require(sha(raw)==summary['files'][name]['sha256'],'frozen stream '+name)
    cases=[json.loads(line) for line in provenance.splitlines()];domains=[c['domain'] for c in cases]
    ids=[line.split(b'\t')[0] for line in inputs.splitlines()];require(len(ids)==len(set(ids))==775,'frozen input IDs')
    require([c['id'].encode() for c in cases]==ids and domains.count('new_safe_refusal')==48,'frozen domains/IDs')
    controls=comparator_controls(expected,ids,domains);source_copies={};driver_copies={};observations={};environments={};driver_controls=[];artifacts=[]
    def archive(path,label):
        raw=path.read_bytes();h=sha(raw);q=out/'compiled-private'/(h+'.gz')
        if not q.exists():q.write_bytes(gzip.compress(raw,mtime=0))
        require(gzip.decompress(q.read_bytes())==raw,'compiled private retention')
        item=dict(label=label,bytes=len(raw),sha256=h,private_gzip=logical(q),stored_sha256=sha(q.read_bytes()),public_bytes_distributed=False,
                  private_home_prefix_present='HOME' in env0 and env0['HOME'].encode() in raw,
                  canonical_build_prefix_present=str(out).encode() in raw)
        artifacts.append(item);write_json(receipts/'compiled-artifact-identities.json',artifacts);return item
    def build(label,altered=None,test=False,repeat=False,mutation_domain=None,focused_option=False):
        phase=(out/label).resolve();record=label+('-same-path-repeat' if repeat else '')
        component=phase/'src/visor-retry-protocol';dependency=phase/'src/visor-duration-value';client_source=phase/'input_client.rs'
        if repeat:
            require(phase.exists() and altered is None,'same-path repeat admission')
            # First-pass bytes already reside in content-addressed private archives.
            for profile in ['debug','release']:
                for suffix,path in [('rlib',phase/'target'/profile/'libvisor_retry_protocol.rlib'),('dependency_rlib',next((phase/'target'/profile/'deps').glob('libvisor_duration_value-*.rlib'))),('client',phase/('client-'+profile))]:
                    matches=[x for x in artifacts if x['label']==label+'/'+profile+'/'+suffix]
                    require(len(matches)==1,'unique before-repeat artifact')
                    x=matches[0];saved=out/'compiled-private'/(x['sha256']+'.gz')
                    require(identity(path)=={k:x[k] for k in ['bytes','sha256']} and sha(saved.read_bytes())==x['stored_sha256'] and
                            gzip.decompress(saved.read_bytes())==path.read_bytes(),'before-repeat artifact retention')
            shutil.rmtree(phase/'target')
            for profile in ['debug','release']:(phase/('client-'+profile)).unlink()
        else:
            phase.mkdir();component.parent.mkdir();shutil.copytree(SOURCE,component)
            shutil.copytree(DEPENDENCY,dependency)
            shutil.copyfile(HERE/'input_client.rs',client_source)
            if altered is not None:(component/'src/lib.rs').write_text(altered)
        require(not any(q.is_symlink() for q in phase.rglob('*')),'build copy symlink')
        before=inventory(component);wanted=dict(f['source'])
        if altered is not None:wanted['src/lib.rs']=dict(bytes=len(altered.encode()),sha256=sha(altered.encode()))
        require(before==wanted and inventory(dependency)==f['dependency'],'actual copied two-package source')
        require(identity(client_source)==f['harness']['input_client.rs'],'actual copied input-only client')
        source_copies[record]=dict(source=before,dependency=inventory(dependency));driver_copies[record]=identity(client_source)
        write_json(receipts/'source-copies.json',source_copies);write_json(receipts/'driver-copies.json',driver_copies)
        ancestors(component);ancestors(dependency)
        flags=['-Dwarnings','-C','overflow-checks=on','-C','linker=/usr/bin/clang',
               '--remap-path-prefix='+str(phase)+'=/visor-retry-build','--remap-path-prefix='+str(toolchain)+'=/visor-retry-toolchain']
        env=dict(env0,CARGO_TARGET_DIR=str(phase/'target'),CARGO_ENCODED_RUSTFLAGS='\x1f'.join(flags))
        environments[record]={k:('<ORIGINAL_HOME_UNCHANGED_NOT_RECORDED>' if k=='HOME' else logical(v)) for k,v in env.items()}
        write_json(receipts/'compile-environments.json',environments)
        if altered is None:
            md=json.loads(run(record+'-metadata',[toolchain/'bin/cargo','metadata','--offline','--locked','--format-version','1'],component,env))
            require(len(md['packages'])==len(md['resolve']['nodes'])==2 and len(md['workspace_members'])==1 and
                    Path(md['workspace_root']).resolve()==component,'actual two-package workspace')
            packages={p['name']:p for p in md['packages']};require(set(packages)=={'visor-retry-protocol','visor-duration-value'},'actual packages')
            for name,pkg in packages.items():
                expected_path=component if name=='visor-retry-protocol' else dependency
                require(pkg['source'] is None and Path(pkg['manifest_path']).resolve()==expected_path/'Cargo.toml','actual local package')
                target_name=name.replace('-','_')
                require([(t['name'],t['kind']) for t in pkg['targets']]==[(target_name,['lib']),('value_contract',['test'])],'actual lib/test targets')
                require(pkg['license']=='MIT' and pkg['features']=={},'license/features')
                if name=='visor-retry-protocol':
                    require(len(pkg['dependencies'])==1 and pkg['dependencies'][0]['name']=='visor-duration-value' and
                            Path(pkg['dependencies'][0]['path']).resolve()==dependency and pkg['dependencies'][0]['kind'] is None and
                            not pkg['dependencies'][0]['optional'],'actual sole path dependency')
                else:require(pkg['dependencies']==[],'dependency closure')
            run(record+'-format-check',[toolchain/'bin/rustfmt','--edition','2024','--check',component/'src/lib.rs',component/'tests/value_contract.rs',client_source],component,env)
        result={}
        for profile in ['debug','release']:
            release=['--release'] if profile=='release' else []
            run(record+'-'+profile+'-cargo-build',[toolchain/'bin/cargo','build','--offline','--locked','--lib',*release],component,env)
            if test:
                run(record+'-'+profile+'-cargo-test',[toolchain/'bin/cargo','test','--offline','--locked','--lib','--test','value_contract',*release],component,env)
                run(record+'-'+profile+'-dependency-test',[toolchain/'bin/cargo','test','--offline','--locked','--manifest-path',dependency/'Cargo.toml','--target-dir',phase/'dependency-test-target','--lib','--test','value_contract',*release],component,env)
            rlib=phase/'target'/profile/'libvisor_retry_protocol.rlib';client=phase/('client-'+profile)
            run(record+'-'+profile+'-link-client',[toolchain/'bin/rustc','--edition=2024','--crate-name','visor_retry_input_client',client_source,
                '--extern','visor_retry_protocol='+str(rlib),'-L','dependency='+str(phase/'target'/profile/'deps'),'-C','opt-level='+('3' if profile=='release' else '0'),
                '-C','debuginfo='+('0' if profile=='release' else '2'),*flags,'-o',client],component,env)
            rlib_info=archive(rlib,record+'/'+profile+'/rlib')
            client_info=archive(client,record+'/'+profile+'/client')
            dependency_candidates=list((phase/'target'/profile/'deps').glob('libvisor_duration_value-*.rlib'))
            require(len(dependency_candidates)==1,'one linked dependency rlib')
            dependency_info=archive(dependency_candidates[0],record+'/'+profile+'/dependency_rlib')
            output=run(record+'-'+profile+'-values',[client],component,env,inputs)
            observation=compare(output,expected,ids,domains)
            result[profile]=dict(comparison=observation,rlib=rlib_info,client=client_info,dependency_rlib=dependency_info)
            observations[record]=result;write_json(receipts/'build-results.json',observations)
            require(observation['equal'] if altered is None or focused_option else not observation['equal'],'value qualification failed: '+record+'/'+profile)
            if mutation_domain=='native':require(observation['differences_by_domain']['native_conditional_protocol']>0,'native mutant must differ in native domain')
            if mutation_domain=='new_policy':
                require(observation['differences_by_domain']['native_conditional_protocol']==0 and observation['differences_by_domain']['new_safe_refusal']>0,'policy-only mutant domain')
            if focused_option:
                raw=run(record+'-'+profile+'-focused-option-test',[toolchain/'bin/cargo','test','--offline','--locked','--test','value_contract',*release,
                    'owned_option_zero_is_passed_on_every_reached_attempt','--','--exact'],component,env,allowed=(101,))
                require(b'test owned_option_zero_is_passed_on_every_reached_attempt ... FAILED' in raw and
                        b'0 passed; 1 failed;' in raw and b'test result: FAILED.' in raw,'focused runtime assertion failure, not compiler failure')
                result[profile]['focused_option_test']=dict(exit_code=101,kind='compiled focused-test rejection; full corpus intentionally equal')
            if label=='clean-one' and not repeat and profile=='debug':
                for name,bad in malformed_inputs(inputs).items():
                    raw=run('malformed-'+name,[client],component,env,bad,allowed=(2,));require(not raw,'malformed partial output')
                    driver_controls.append(dict(name=name,exit_code=2,input_sha256=sha(bad),output_bytes=0))
                raw=run('extra-argument',[client,'unexpected'],component,env,inputs[:inputs.index(b'\n')+1],allowed=(2,));require(not raw,'argument value output')
                driver_controls.append(dict(name='extra-argument',exit_code=2,output_bytes=0))
        if test:run(record+'-clippy',[toolchain/'bin/cargo','clippy','--offline','--locked','--lib','--test','value_contract','--','-D','warnings'],component,env)
        require(inventory(component)==before and inventory(dependency)==f['dependency'],'source/dependency changed during build')
        return result
    baseline=build('clean-one',test=True)
    repeat=build('clean-one',repeat=True)
    second=build('clean-two')
    def equal_artifacts(a,b):return {profile:{kind:a[profile][kind]['sha256']==b[profile][kind]['sha256'] for kind in ['rlib','dependency_rlib','client']} for profile in ['debug','release']}
    mutation_results=[]
    for name,changed,definition in variations:
        observation=build('mutant-'+name,altered=changed,mutation_domain=definition['domain']);mutation_results.append(dict(definition=definition,profiles=observation))
        print('compiled complete-stream mutant detected: '+name,flush=True)
    option_original=(SOURCE/'src/lib.rs').read_text()
    option_before='|value| attempt(value, 0),';option_after='|value| attempt(value, 1),'
    require(option_original.count(option_before)==1,'unique option control')
    option_changed=option_original.replace(option_before,option_after,1)
    option_result=build('focused-option-one',altered=option_changed,focused_option=True)
    option_control=dict(before=option_before,after=option_after,source_sha256=sha(option_changed.encode()),profiles=option_result,
        scope='The frozen trace does not observe option. Equal775-row streams are required; dedicated compiled assertion must fail in both profiles.')
    require(tools_inventory()==pins['payload_files'] and tool_links()==pins['symlinks'],'toolchain changed')
    for path,expected_file in external.items():
        for key,value in mapping.items():path=path.replace(key,value)
        require(identity(Path(path))==expected_file,'external tool changed')
    require({n:identity(Path(sdk)/n) for n in sdk_inputs}==sdk_inputs,'selected SDK changed')
    admit_sources(args.source_freeze_sha)
    write_json(receipts/'build-audit.json',dict(source_freeze_sha256=args.source_freeze_sha,manifest=manifest,lock=lock,
        original_duration_unchanged=True,dependency=f['dependency'],toolchain_payloads_unchanged=True,
        configs_absent=sorted(configs),ancestor_manifests=workspaces,external_tools=external,SDKROOT=sdk,sdk_inputs=sdk_inputs,
        limit='Exact bin/lib and selected linker/SDK inputs; OS/dyld/full SDK not hermetic or captured-target compiler evidence.'))
    result=dict(source_freeze_sha256=args.source_freeze_sha,cases=775,domains=summary['domains'],baseline=baseline,same_path_clean_repeat=repeat,separate_directory_rebuild=second,
        exact_raw_comparisons=dict(same_path=equal_artifacts(baseline,repeat),separate_directory=equal_artifacts(baseline,second),masks=[],normalization=None),
        mutants=mutation_results,focused_option_control=option_control,comparator_controls=controls,input_controls=driver_controls,commands=len(commands),value_streams=8+2*len(variations),
        source_unchanged=True,precode_unchanged=True,scope='Actual two-package MIT source and input-only client; 775-case partition comprises727native conditional cases and48new safe refusals; no captured execution, external effects or whole-Visor equivalence.')
    write_json(receipts/'results.json',result)
    print(json.dumps(dict(status='PASS actual host qualification',commands=len(commands),cases=775,domains=summary['domains'],mutants=len(variations),value_streams=result['value_streams'],receipts=logical(receipts))))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError) as e:
        print(str(e),file=sys.stderr);raise SystemExit(1) from e

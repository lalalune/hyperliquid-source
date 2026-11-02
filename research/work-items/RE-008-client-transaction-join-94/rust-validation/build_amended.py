#!/usr/bin/env python3
"""Qualify only the real authored dependency-free Rust package after a source gate.

Additive amendment1 preserves the original frozen driver/harness and source graph.
No captured execution, emulator, fake workspace, expected-file client input or
unmerged runtime dependency. Every compiled command stream is retained exactly.
"""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,re,shutil,subprocess,sys,time,tomllib
from pathlib import Path
HERE=Path(__file__).resolve().parent.parent
ROOT=HERE.parents[2]
PRE_FREEZE='dc729f9dd4d9a794daad2dd5f7d538080c3c0266fc37be512d90ec46a71a3f5c'
CRATES=['node94-consensus-admission']
MODULE='src/node94-consensus-admission/src/client_transaction_join.rs'
EXTRA=['LICENSE']
EDITABLE={'src/node94-consensus-admission/'+n for n in ['README.md','src/lib.rs']}
NEW={MODULE,'src/node94-consensus-admission/tests/client_transaction_join.rs'}

def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def identity(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=sha(raw))
def write_json(path,value):path.write_text(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
def no_symlinks(path,base):
    need(path.is_relative_to(base),'admitted path outside base')
    for f in [path,*path.parents]:
        need(not f.is_symlink(),'symlink in admitted path')
        if f==base:break

def source_inventory(root):
    result={}
    for name in CRATES:
        directory=root/'src'/name;no_symlinks(directory,root)
        for f in sorted(directory.rglob('*')):
            need(not f.is_symlink() and (f.is_file() or f.is_dir()),'source nonregular entry')
            if f.is_file():result[f.relative_to(root).as_posix()]=identity(f)
    for name in EXTRA:
        no_symlinks(root/name,root);result[name]=identity(root/name)
    return dict(sorted(result.items()))

def admit(source_freeze_sha):
    need(identity(HERE/'PRE-RUST-FREEZE.json')['sha256']==PRE_FREEZE,'pre-Rust freeze')
    need(identity(HERE/'MANIFEST.sha256')['sha256']=='ad456b0066ae54cdb0978314dffe4f7d0607eb6b4b2160687b740c051c3a03f3','original precode manifest')
    pre=json.loads((HERE/'PRE-RUST-FREEZE.json').read_text());need(len(pre['files'])==49,'pre-Rust file census')
    for name,digest in pre['files'].items():
        relative=Path(name);need(not relative.is_absolute() and '..' not in relative.parts,'pre-Rust path')
        no_symlinks(HERE/name,HERE);need(identity(HERE/name)['sha256']==digest,'frozen pre-Rust file '+name)
    need(identity(HERE/'SOURCE-FREEZE-2.json')['sha256']==source_freeze_sha,'source freeze identity')
    freeze=json.loads((HERE/'SOURCE-FREEZE-2.json').read_text())
    source=source_inventory(ROOT);need(source==freeze['source'],'actual source graph changed')
    need(identity(HERE/'SOURCE-FREEZE.json')['sha256']=='07930faa65af0a5d8b59fddca522cc711656e9e2bd9c3279b6e12dbe3b5f48b6','original source freeze preserved')
    prior=json.loads((HERE/'SOURCE-FREEZE.json').read_text())
    for name,expected in prior['source'].items():
        path=HERE/'rust-validation/amendment-1/original-test.rs' if name=='src/node94-consensus-admission/tests/client_transaction_join.rs' else ROOT/name
        need(identity(path)==expected,'original source graph reconstructs exactly '+name)
    for name,expected in prior['harness'].items():
        need(identity(HERE/name)==expected,'original harness preserved '+name)

    base=json.loads((HERE/'BASELINE-SOURCE-PLAN.json').read_text())
    need(set(source)==set(base['files'])|NEW,'exact actual graph files')
    for name,digest in base['files'].items():
        if name not in EDITABLE:need(source[name]['sha256']==digest,'unmodified baseline prerequisite '+name)
    for name,expected in freeze['harness'].items():
        relative=Path(name);need(not relative.is_absolute() and '..' not in relative.parts,'harness path')
        no_symlinks(HERE/name,HERE);need(identity(HERE/name)==expected,'harness changed '+name)
    for name in CRATES:
        m=tomllib.loads((ROOT/'src'/name/'Cargo.toml').read_text())
        need('workspace' not in m and 'build' not in m['package'] and not (ROOT/'src'/name/'build.rs').exists(),'no invented workspace/build script')
        need(not m.get('build-dependencies') and not m.get('dev-dependencies'),'no auxiliary dependencies')
        need(not m.get('dependencies'),'dependency-free real package')
    lock=tomllib.loads((ROOT/'src'/CRATES[0]/'Cargo.lock').read_text())
    need(lock['package']==[{'name':'node94-consensus-admission','version':'0.1.0'}], 'actual unchanged one-package lock')
    return freeze

def rows(raw):
    need(raw==b'' or raw.endswith(b'\n'),'missing final line ending')
    out=[];seen=set()
    for line in raw.splitlines():
        fields=line.split(b'\t');need(len(fields)==2,'output line shape')
        identifier,payload=fields;need(re.fullmatch(rb'C[0-9]{6}',identifier) is not None,'opaque ID shape')
        need(identifier not in seen,'duplicate ID');seen.add(identifier)
        need(len(payload)%2==0 and re.fullmatch(rb'[0-9a-f]*',payload) is not None,'payload hex')
        out.append((identifier,bytes.fromhex(payload.decode())))
    return out

def pack(values):return b''.join(identifier+b'\t'+data.hex().encode()+b'\n' for identifier,data in values)
def compare(actual,expected):
    right=rows(expected)
    try:left=rows(actual);error=None
    except ValueError as exc:left=[];error=str(exc)
    differences=[i for i in range(max(len(left),len(right))) if (left[i] if i<len(left) else None)!=(right[i] if i<len(right) else None)]
    return dict(equal=actual==expected and error is None,actual_rows=len(left),expected_rows=len(right),parse_error=error,different_rows=len(differences),first_different_rows=differences[:12],actual_sha256=sha(actual),expected_sha256=sha(expected))

def comparator_controls(expected):
    values=rows(expected);changed=bytearray(values[0][1]);changed[0]^=1
    variants={'missing-final':pack(values[:-1]),'extra':expected+pack([(b'C999999',b'\0')]),
              'reordered':pack([values[1],values[0],*values[2:]]),'duplicate-ID':pack([values[0],values[0],*values[2:]]),
              'changed-active-byte':pack([(values[0][0],bytes(changed)),*values[1:]]),'truncated-final':expected[:-1],
              'nonhex':expected.replace(b'\t',b'\tg',1),'empty':b''}
    need(compare(expected,expected)['equal'],'positive comparison')
    result={name:compare(raw,expected) for name,raw in variants.items()};need(all(not x['equal'] for x in result.values()),'comparator corruption survived');return result

def malformed_inputs(inputs):
    first=inputs.splitlines(keepends=True)[0];identifier,payload=rows(first)[0]
    return {'odd-hex':identifier+b'\t0\n','invalid-hex':identifier+b'\tgg\n',
            'short-frame':pack([(identifier,payload[:10])]),'wrong-kind':pack([(identifier,b'\xff'+payload[1:])]),
            'trailing-byte':pack([(identifier,payload+b'\0')]),'duplicate-ID':first+first,
            'missing-LF':first[:-1],'extra-field':first[:-1]+b'\textra\n'}

def mutants(original):
    definitions=[
        ('eager-hash-view',[
            ('    let ClientJoinInput { block, rows, time } = input;', '    let ClientJoinInput { block, rows, time } = input;\n    let early_hashes = hash_view().map_err(JoinError::HashView)?;'),
            ('    let hashes = hash_view().map_err(JoinError::HashView)?;', '    let hashes = early_hashes;')]),
        ('eager-map-view',[
            ('    let ClientJoinInput { block, rows, time } = input;', '    let ClientJoinInput { block, rows, time } = input;\n    let early_map = map_view().map_err(JoinError::MapView)?;'),
            ('        let map = map_view().map_err(JoinError::MapView)?;', '        let map = early_map;')]),
        ('empty-invokes-map', [('    if !hashes.is_empty() {', '    if true {')]),
        ('sort-request-order', [('    let hashes = hash_view().map_err(JoinError::HashView)?;', '    let hashes = hash_view().map_err(JoinError::HashView)?;\n    let mut reordered = hashes.to_vec();\n    reordered.sort();\n    let hashes = reordered.as_slice();')]),
        ('deduplicate-request-runs', [('    let hashes = hash_view().map_err(JoinError::HashView)?;', '    let hashes = hash_view().map_err(JoinError::HashView)?;\n    let mut deduplicated = hashes.to_vec();\n    deduplicated.dedup();\n    let hashes = deduplicated.as_slice();')]),
        ('reverse-request-order', [('        for hash in hashes {', '        for hash in hashes.iter().rev() {')]),
        ('last-missing-first', [('        for hash in hashes {', '        if let Some(hash) = hashes.iter().rev().find(|hash| !map.contains_key(*hash)) {\n            drop(rows);\n            drop(block);\n            return Err(JoinError::MissingTransaction(*hash));\n        }\n        for hash in hashes {')]),
        ('copy-value-object', [('                bytes: Arc::clone(bytes),', '                bytes: Arc::new((**bytes).clone()),')]),
        ('copy-provided-rows', [('    if let Some(rows) = rows {', '    if let Some(rows) = rows {\n        let rows = Arc::new((*rows).clone());')]),
        ('retain-failed-block', [('                drop(block);', '                std::mem::forget(block);')]),
        ('retain-failed-prefix', [('                drop(rows);', '                std::mem::forget(rows);')]),
        ('alter-missing-hash', [('                return Err(JoinError::MissingTransaction(*hash));', '                let mut changed = *hash;\n                changed.0[0] ^= 1;\n                return Err(JoinError::MissingTransaction(changed));')]),
        ('alter-raw-time', [('    let ClientJoinInput { block, rows, time } = input;', '    let ClientJoinInput { block, rows, time } = input;\n    let mut time = time;\n    time[11] ^= 1;')]),
        ('row-width-39', [('    let bytes = count.checked_mul(40)?;', '    let bytes = count.checked_mul(39)?;')]),
        ('reject-last-valid-count', [('    if bytes > i64::MAX as u64 {', '    if bytes >= (i64::MAX as u64) - 7 {')]),
        ('wrapping-row-size', [('    let bytes = count.checked_mul(40)?;', '    let bytes = count.wrapping_mul(40);')]),
        ('provided-empty-is-absent', [('    if let Some(rows) = rows {\n        return Ok(JoinedClientBlock { block, rows, time });\n    }', '    if let Some(rows) = rows {\n        if !rows.is_empty() {\n            return Ok(JoinedClientBlock { block, rows, time });\n        }\n    }')]),
    ]
    result=[]
    for name,edits in definitions:
        altered=original;coordinates=[]
        for before,after in edits:
            need(original.count(before)==1 and altered.count(before)==1,'unique original and current mutant coordinate '+name)
            coordinates.append(dict(original_line=original[:original.index(before)].count('\n')+1,before=before,after=after))
            altered=altered.replace(before,after,1)
        need(altered!=original,'unchanged mutant '+name)
        result.append((name,altered,dict(name=name,source_sha256=sha(altered.encode()),edits=coordinates)))
    need(len(result)==17 and len({name for name,_,_ in result})==17,'mutant census')
    return result


def payload_inventory(toolchain):
    result={}
    for directory in ['bin','lib']:
        no_symlinks(toolchain/directory,toolchain)
        for f in sorted((toolchain/directory).rglob('*')):
            need(not f.is_symlink() and (f.is_file() or f.is_dir()),'toolchain nonregular entry')
            if f.is_file():result[directory+'/'+f.relative_to(toolchain/directory).as_posix()]=identity(f)
    need(len(result)==97,'toolchain payload census')
    return result

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--toolchain',type=Path,required=True);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--source-freeze-sha',required=True);ap.add_argument('--private-map',type=Path,required=True);a=ap.parse_args()
    requested_out=Path(os.path.abspath(a.out));out=a.out.resolve();toolchain=a.toolchain.resolve();private=a.private_map.resolve()
    need(out.parent==Path('/tmp').resolve() and not out.exists(),'fresh direct canonical /tmp child')
    need(not private.exists() and not private.is_relative_to(HERE),'fresh private map outside packet')
    freeze=admit(a.source_freeze_sha);original=(ROOT/MODULE).read_text();variants=mutants(original)
    need([definition for _,_,definition in variants]==json.loads((HERE/'rust-validation/MUTANTS.json').read_text()),'frozen mutant definitions')
    pins=json.loads((HERE/'rust-validation/TOOLCHAIN-PINS.json').read_text());before_tools=payload_inventory(toolchain);need(before_tools==pins['payload_files'],'97-file toolchain admission')
    out.mkdir(mode=0o700);receipts=out/'receipts';(receipts/'raw').mkdir(parents=True);cargo_home=out/'cargo-home';cargo_home.mkdir()
    mapping={'<BUILD>':str(out),'<TOOLCHAIN>':str(toolchain),'<SOURCE_ROOT>':str(ROOT),'<PACKET>':str(HERE)}
    write_json(private,dict(logical_to_private=mapping,lexical_build=str(requested_out),canonical_build=str(out)))
    def logical(value):
        text=str(value)
        for name,path in sorted(mapping.items(),key=lambda pair:-len(pair[1])):text=text.replace(path,name)
        return text
    env_base={'PATH':str(toolchain/'bin')+':/usr/bin:/bin:/usr/sbin:/sbin','CARGO_HOME':str(cargo_home),
              'RUSTC':str(toolchain/'bin/rustc'),'RUSTDOC':str(toolchain/'bin/rustdoc'),'CARGO_NET_OFFLINE':'true',
              'CARGO_INCREMENTAL':'0','CARGO_TERM_COLOR':'never','LC_ALL':'C','LANG':'C','TZ':'UTC','DEVELOPER_DIR':'/Library/Developer/CommandLineTools'}
    if 'HOME' in os.environ:env_base['HOME']=os.environ['HOME']
    configs=set();workspace_ancestors=set()
    def audit(directory,form):
        for parent in directory.parents:
            manifest=parent/'Cargo.toml';need(not manifest.exists() and not manifest.is_symlink(),'unexpected ancestor workspace '+form);workspace_ancestors.add((form,logical(manifest)))
        for parent in [directory,*directory.parents]:
            for name in ['.cargo/config','.cargo/config.toml','rustfmt.toml','.rustfmt.toml']:
                path=parent/name;need(not path.exists() and not path.is_symlink(),'unexpected '+form+' build config');configs.add((form,logical(path)))
    audit(requested_out,'lexical');audit(out,'canonical')
    source_ancestors=[]
    for distance,parent in enumerate([ROOT,*ROOT.parents]):
        path=parent/'Cargo.toml';source_ancestors.append(dict(distance=distance,Cargo_toml_present=path.exists(),cargo_config_present=any((parent/'.cargo'/name).exists() or (parent/'.cargo'/name).is_symlink() for name in ['config','config.toml'])))
    commands=[]
    def retain(raw):
        digest=sha(raw);name='raw/'+digest+'.gz';path=receipts/name
        if not path.exists():path.write_bytes(gzip.compress(raw,mtime=0))
        return dict(bytes=len(raw),sha256=digest,gzip_ref=name)
    def run(label,argv,cwd=None,env=None,stdin=None,allowed=(0,)):
        used=env or env_base;started=time.monotonic();timeout=False;launch_error=None
        try:
            r=subprocess.run([str(x) for x in argv],cwd=cwd or out,env=used,input=stdin,capture_output=True,timeout=300)
            stdout,stderr,exit_code=r.stdout,r.stderr,r.returncode
        except subprocess.TimeoutExpired as exc:
            stdout,stderr,exit_code=exc.stdout or b'',exc.stderr or b'',None;timeout=True
        except OSError as exc:
            stdout,stderr,exit_code=b'',b'',None;launch_error=logical(str(exc))
        commands.append(dict(label=label,argv=[logical(x) for x in argv],cwd=logical(cwd or out),exit_code=exit_code,timed_out=timeout,launch_error=launch_error,elapsed_seconds=round(time.monotonic()-started,3),stdin=None if stdin is None else dict(bytes=len(stdin),sha256=sha(stdin)),stdout=retain(stdout),stderr=retain(stderr)))
        write_json(receipts/'commands.json',commands)
        if 'HOME' in used:need(used['HOME'].encode() not in stdout+stderr,'private home path in raw stream '+label)
        need(not timeout and launch_error is None and exit_code in allowed,'command failed '+label);return stdout
    for name,flag in [('cargo','--version'),('rustc','-vV'),('rustdoc','--version'),('rustfmt','--version'),('clippy-driver','--version')]:run(name+'-version',[toolchain/'bin'/name,flag])
    run('clang-version',['/usr/bin/clang','--version']);sdk=run('SDK-path',['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path']).decode().strip();env_base['SDKROOT']=sdk
    run('SDK-version',['/usr/bin/xcrun','--sdk','macosx','--show-sdk-version']);external={}
    for name in ['clang','ld']:
        path=Path(run('resolve-'+name,['/usr/bin/xcrun','--find',name]).decode().strip());external[str(path)]=identity(path)
    for name in ['/usr/bin/clang','/usr/bin/ld','/usr/bin/ar','/usr/bin/xcrun',sys.executable]:external[logical(name)]=identity(Path(name))
    sdk_pins={name:identity(Path(sdk)/name) for name in ['SDKSettings.json','usr/lib/libSystem.tbd']}
    inputs=gzip.decompress((HERE/'fixtures/vectors.tsv.gz').read_bytes());expected=gzip.decompress((HERE/'fixtures/expected.tsv.gz').read_bytes());need(len(rows(inputs))==len(rows(expected))==361,'frozen corpus count')
    controls=comparator_controls(expected);environments={};copies={};compiled_archives=[]
    def archive_compiled(path,label,profile,kind):
        raw=path.read_bytes();digest=sha(raw);name='compiled-artifacts/'+digest+'.gz';destination=receipts/name
        destination.parent.mkdir(exist_ok=True)
        if not destination.exists():destination.write_bytes(gzip.compress(raw,mtime=0))
        reference=dict(bytes=len(raw),sha256=digest,gzip_ref=name)
        compiled_archives.append(dict(sequence=len(compiled_archives),label=label,profile=profile,kind=kind,artifact=reference))
        write_json(receipts/'compiled-artifacts.json',compiled_archives)
        return reference
    def build(label,profiles,test=False,altered=None):
        phase=(out/label).resolve();phase.mkdir();tree=phase/'repo';tree.mkdir()
        for name in freeze['source']:
            dest=tree/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest)
        if altered is not None:(tree/MODULE).write_text(altered)
        expected_copy=dict(freeze['source'])
        if altered is not None:expected_copy[MODULE]=dict(bytes=len(altered.encode()),sha256=sha(altered.encode()))
        need(source_inventory(tree)==expected_copy,'copied real source graph');driver=phase/'driver.rs';shutil.copyfile(HERE/'rust-validation/driver_amended.rs',driver)
        need(identity(driver)==freeze['harness']['rust-validation/driver_amended.rs'],'copied driver identity');no_symlinks(driver,phase)
        component=tree/'src'/CRATES[0];audit(requested_out/label/'repo/src'/CRATES[0],'lexical');audit(component,'canonical')
        flags=['-Dwarnings','-C','overflow-checks=on','-C','linker=/usr/bin/clang',
               '--remap-path-prefix='+str(phase)+'=/transaction-join-build',
               '--remap-path-prefix='+str(requested_out/label)+'=/transaction-join-build',
               '--remap-path-prefix='+str(toolchain)+'=/transaction-join-toolchain']
        env=dict(env_base,CARGO_TARGET_DIR=str(phase/'target'),CARGO_ENCODED_RUSTFLAGS='\x1f'.join(flags));environments[label]={k:'<HOME_PRESERVED_NOT_RECORDED>' if k=='HOME' else logical(v) for k,v in env.items()};write_json(receipts/'compile-environments.json',environments)
        if altered is None:
            metadata=json.loads(run(label+'-metadata',[toolchain/'bin/cargo','metadata','--offline','--locked','--format-version','1'],component,env))
            need([p['name'] for p in metadata['packages']]==CRATES and len(metadata['workspace_members'])==1,'exact actual one-package graph')
            package=metadata['packages'][0]
            need(package['source'] is None and package['dependencies']==[],'no registry/path/build/dev dependencies')
            need(sorted((t['name'],t['kind']) for t in package['targets'])==[('client_transaction_join',['test']),('evidence_contract',['test']),('node94_consensus_admission',['lib'])],'actual package targets')
            run(label+'-rustfmt-check',[toolchain/'bin/rustfmt','--edition','2021','--check',tree/MODULE,component/'tests/client_transaction_join.rs',driver],component,env)
        observations={}
        for profile in profiles:
            release=['--release'] if profile=='release' else []
            run(label+'-'+profile+'-cargo-build',[toolchain/'bin/cargo','build','--offline','--locked','--lib',*release],component,env)
            if test:run(label+'-'+profile+'-cargo-test',[toolchain/'bin/cargo','test','--offline','--locked','--lib','--test','client_transaction_join',*release],component,env)
            rlib=phase/'target'/profile/'libnode94_consensus_admission.rlib';client=phase/('client-'+profile)
            run(label+'-'+profile+'-link-driver',[toolchain/'bin/rustc','--edition=2021','--crate-name','client_transaction_join_input_client',driver,'--extern','node94_consensus_admission='+str(rlib),'-L','dependency='+str(phase/'target'/profile/'deps'),'-C','opt-level='+('3' if profile=='release' else '0'),'-C','debuginfo='+('0' if profile=='release' else '2'),*flags,'-o',client],component,env)
            archived=None
            if altered is None:
                archived={kind:archive_compiled(path,label,profile,kind) for kind,path in [('rlib',rlib),('client',client)]}
            actual=run(label+'-'+profile+'-values',[client],component,env,inputs);comparison=compare(actual,expected);need(comparison['actual_rows']==361,'all actual case outputs')
            observations[profile]=dict(comparison=comparison,rlib=identity(rlib),client=identity(client),archived_compiled_bytes=archived,canonical_build_prefix_absent_in_rlib=str(phase).encode() not in rlib.read_bytes(),canonical_build_prefix_absent_in_client=str(phase).encode() not in client.read_bytes())
        if test:run(label+'-clippy',[toolchain/'bin/cargo','clippy','--offline','--locked','--all-targets','--','-D','warnings'],component,env)
        need(source_inventory(tree)==expected_copy,'copied source changed');need(identity(driver)==freeze['harness']['rust-validation/driver_amended.rs'],'copied driver changed');copies[label]=expected_copy;return observations
    baseline=build('clean-one',('debug','release'),test=True);need(all(x['comparison']['equal'] for x in baseline.values()),'production mismatch')
    parser={};client=out/'clean-one/client-release'
    for name,raw in malformed_inputs(inputs).items():
        need(run('malformed-'+name,[client],stdin=raw,allowed=(2,))==b'','no partial output for rejected input '+name)
        parser[name]=dict(exit_code=commands[-1]['exit_code'],command_index=len(commands)-1)
    need(run('extra-argument',[client,'unexpected'],stdin=b'',allowed=(2,))==b'','no output for extra argument');parser['extra-argument']=dict(exit_code=2,command_index=len(commands)-1)
    need(run('empty-input',[client],stdin=b'')==b'','empty input output');parser['empty-valid']=dict(exit_code=0,command_index=len(commands)-1)
    # Repeat from a clean directory at the identical physical path, recording raw
    # artifact identity separately from a coordinator's different-root replay.
    shutil.rmtree(out/'clean-one');repeat=build('clean-one',('debug','release'));need(all(x['comparison']['equal'] for x in repeat.values()),'clean same-path mismatch')
    own_bytes={p:{key:baseline[p][key]==repeat[p][key] for key in ['rlib','client']} for p in ['debug','release']}
    need(all(all(values.values()) for values in own_bytes.values()),'same-path raw artifact inequality')
    mutation_results=[]
    for name,altered,definition in variants:
        observation=build('mutant-'+name,('debug','release'),altered=altered)
        need(all(not x['comparison']['equal'] and x['comparison']['different_rows']>0 for x in observation.values()),'compiled mutant survived '+name)
        mutation_results.append(dict(definition=definition,observations=observation))
    need(payload_inventory(toolchain)==before_tools,'toolchain payload changed')
    for name,expected_identity in external.items():
        actual=name.replace('<TOOLCHAIN>',str(toolchain)).replace('<BUILD>',str(out));need(identity(Path(actual))==expected_identity,'external tool changed')
    for name,expected_identity in sdk_pins.items():need(identity(Path(sdk)/name)==expected_identity,'selected SDK input changed')
    admit(a.source_freeze_sha)
    write_json(receipts/'source-copies.json',copies)
    write_json(receipts/'build-audit.json',dict(source_freeze_sha256=a.source_freeze_sha,actual_source=freeze['source'],ancestor_config_checks=sorted(configs),ancestor_workspace_checks=sorted(workspace_ancestors),source_ancestor_context_excluded=source_ancestors,fresh_CARGO_HOME=True,toolchain_payload_sha256=identity(HERE/'rust-validation/TOOLCHAIN-PINS.json')['sha256'],toolchain_payload_unchanged=True,external_tools=external,SDKROOT=sdk,sdk_inputs=sdk_pins,limit='Actual graph and97 toolchain files plus selected linker/SDK bytes pinned; host OS/dyld and entire SDK are not hermetic.'))
    result=dict(source_freeze_sha256=a.source_freeze_sha,corpus_cases=361,baseline=baseline,same_path_clean_repeat=repeat,raw_same_path_artifact_equality=own_bytes,compiled_artifact_archives=compiled_archives,compiled_mutants=mutation_results,comparator_controls=controls,parser_controls=parser,commands=len(commands),actual_and_copied_source_unchanged=True,precode_unchanged=True,scope='Authored Rust value/state execution only; conditional native memory/map/ownership and helper-frame limits preserved; no captured execution, emulator, full suite or cross-directory byte identity claim.')
    write_json(receipts/'results.json',result);print(json.dumps(dict(cases=361,mutants=len(mutation_results),profiles=2,commands=len(commands),raw_same_path_artifact_equality=own_bytes)))

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);raise SystemExit(1) from exc

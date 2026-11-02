#!/usr/bin/env python3
"""Qualify only the real authored two-package Rust graph after a source gate.

No captured execution, emulator, fake workspace, expected-file client input or
unmerged runtime dependency. Every compiled command stream is retained exactly.
"""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,re,shutil,subprocess,sys,time,tomllib
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
PRE_FREEZE='9d3cab41d443e9425919aa0d3f0a13f88bfd840e3c8a0812a15e7ec702200041'
CRATES=['node94-consensus-admission','node94-action-signable']
MODULE='src/node94-consensus-admission/src/client_batch.rs'
EXTRA=['LICENSE','research/work-items/RE-005-action-signable-94/vectors.tsv']
EDITABLE={'src/node94-consensus-admission/'+n for n in ['Cargo.toml','Cargo.lock','README.md','src/lib.rs']}
NEW={MODULE,'src/node94-consensus-admission/tests/client_batch.rs'}

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

def admit_original(source_freeze_sha):
    need(identity(HERE/'PRE-RUST-FREEZE.json')['sha256']==PRE_FREEZE,'pre-Rust freeze')
    pre=json.loads((HERE/'PRE-RUST-FREEZE.json').read_text());need(len(pre['files'])==53,'pre-Rust file census')
    for name,digest in pre['files'].items():
        relative=Path(name);need(not relative.is_absolute() and '..' not in relative.parts,'pre-Rust path')
        no_symlinks(HERE/name,HERE);need(identity(HERE/name)['sha256']==digest,'frozen pre-Rust file '+name)
    need(identity(HERE/'SOURCE-FREEZE.json')['sha256']==source_freeze_sha,'source freeze identity')
    freeze=json.loads((HERE/'SOURCE-FREEZE.json').read_text())
    source=source_inventory(ROOT)
    need(source[MODULE] in [identity(HERE/'amendment-1/original/client_batch.rs'),identity(HERE/'amendment-1/corrected/client_batch.rs')],'only exact original or declared public source patch')
    source[MODULE]=identity(HERE/'amendment-1/original/client_batch.rs')
    need(source==freeze['source'],'reconstructed original source graph changed')
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
        expected={'node94-action-signable':{'path':'../node94-action-signable'}} if name==CRATES[0] else {}
        need(m['dependencies']==expected,'exact MIT baseline dependency')
    lock=tomllib.loads((ROOT/'src'/CRATES[0]/'Cargo.lock').read_text())
    need(lock['package']==[{'name':'node94-action-signable','version':'0.1.0'},
                          {'name':'node94-consensus-admission','version':'0.1.0','dependencies':['node94-action-signable']}], 'real Cargo-generated two-package lock')
    return freeze

def corrected(name):
    edits=json.loads((HERE/'amendment-1/type-edits.json').read_text())[name]
    result=(HERE/'amendment-1/original'/name).read_text()
    for before,after in edits:
        need(result.count(before)==1,'exact type-adapter coordinate '+name)
        result=result.replace(before,after,1)
    need(result==(HERE/'amendment-1/corrected'/name).read_text(),'declared type projection '+name)
    return result

def admit(source_freeze_sha):
    path=HERE/'SOURCE-FREEZE-2.json'
    need(identity(path)['sha256']==source_freeze_sha,'amended source freeze identity')
    amendment=json.loads(path.read_text())
    for name,expected in amendment['files'].items():
        relative=Path(name);need(not relative.is_absolute() and '..' not in relative.parts,'amendment path')
        no_symlinks(HERE/name,HERE);need(identity(HERE/name)==expected,'amendment changed '+name)
    original=admit_original('fd33cfb20eadc9b643266dce91496196354b352b8127b4fd19cae309c2b0b4c4')
    for name in ['client_batch.rs','driver.rs']:corrected(name)
    source=dict(original['source']);source[MODULE]=identity(HERE/'amendment-1/corrected/client_batch.rs')
    effective={'source':source,'harness':{'driver.rs':identity(HERE/'amendment-1/corrected/driver.rs')}}
    need(effective==amendment['effective'],'effective corrected source graph')
    return effective

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
            'short-frame':pack([(identifier,payload[:10])]),'wrong-version':pack([(identifier,b'XX1'+payload[3:])]),
            'unknown-mode':pack([(identifier,payload[:3]+b'\xff'+payload[4:])]),
            'trailing-byte':pack([(identifier,payload+b'\0')]),'duplicate-ID':first+first}

def mutants(original):
    definitions=[
        ('untimed-signer',[('self.authenticator\n            .recover_timed_block_signer(block, self.time)','{ let _ = self.time; self.authenticator.recover_block_signer(block) }')]),
        ('allow-earlier-proof',[('if item.proof.is_some() && index + 1 != items.len() {','if false && item.proof.is_some() && index + 1 != items.len() {')]),
        ('one-sided-qc-round',[('if block.qc.round != expected_round {','if block.qc.round < expected_round {')]),
        ('invent-first-parent-anchor',[('        if let Some(expected) = previous_hash {','        if index == 0 && block.qc.block_hash != BlockHash([0; 32]) {\n            return Err(ClientBatchError::QcHash { hash: block.qc.block_hash, expected: BlockHash([0; 32]) });\n        }\n        if let Some(expected) = previous_hash {')]),
        ('invent-consecutive-batch-rounds',[('        verify_timed(history, authenticator, &item.signed)?;','        if block.round.0 != expected_round.0.saturating_add(1) { return Err(ClientBatchError::NonconsecutiveChild); }\n        verify_timed(history, authenticator, &item.signed)?;')]),
        ('tx-hash-only31',[('*keccak256(&transaction.bytes).as_bytes() != transaction.hash.0','keccak256(&transaction.bytes).as_bytes()[..31] != transaction.hash.0[..31]')]),
        ('count-before-tx-hash',[('        // Hash every tx before comparing the count or block hash vector.','        if item.transactions.len() != block.transaction_hashes.len() { return Err(ClientBatchError::TransactionHashes); }\n        // Hash every tx before comparing the count or block hash vector.')]),
        ('ignore-tx-order',[('transaction.hash != *hash','!block.transaction_hashes.contains(&transaction.hash) && transaction.hash != *hash')]),
        ('time-only-first-word',[('if item.copied_time != item.signed.time {','if item.copied_time.0[0] != item.signed.time.0[0] {')]),
        ('omit-last-digest-repeat',[('let last_hash = authenticator.client_block_digest(&last.signed);','let last_hash = previous_hash.expect("nonempty batch");')]),
        ('omit-child-digest-repeat',[('        let _ = authenticator.client_block_digest(&proof.child);','        // Mutant omits the observable duplicate digest.')]),
        ('wrapping-child-successor',[('last.signed.block.round.0.saturating_add(1)','last.signed.block.round.0.wrapping_add(1)')]),
        ('rollback-received-on-error',[('        verify_admitted_batch(history, authenticator, &self.pending, self.confirmed)\n            .map_err(ClientBufferError::Verification)?;','        if let Err(error) = verify_admitted_batch(history, authenticator, &self.pending, self.confirmed) {\n            self.last_received = self.confirmed;\n            return Err(ClientBufferError::Verification(error));\n        }')]),
        ('clear-pending-on-error',[('        verify_admitted_batch(history, authenticator, &self.pending, self.confirmed)\n            .map_err(ClientBufferError::Verification)?;','        if let Err(error) = verify_admitted_batch(history, authenticator, &self.pending, self.confirmed) {\n            self.pending.clear();\n            return Err(ClientBufferError::Verification(error));\n        }')]),
        ('unconfirmed-limit101',[('self.pending.len() <= 100','self.pending.len() <= 101')]),
        ('limit-proof-flush',[('if !has_proof {','if !has_proof || self.pending.len() > 100 {')]),
        ('confirm-after-send',[('        self.confirmed = self.last_received;\n        let drained','        let drained'),('        }\n        Ok(())\n    }\n}\n\n#[cfg(test)]','        }\n        self.confirmed = self.last_received;\n        Ok(())\n    }\n}\n\n#[cfg(test)]')]),
        ('retain-pending-on-flush',[('let drained = std::mem::take(&mut self.pending);','let drained = self.pending.clone();')]),
        ('ignore-closed-sink',[('                return Err(ClientBufferError::ClosedChannel);','                continue;')]),
        ('proof-qc-before-child',[('    verify_timed(history, authenticator, &proof.child)?;\n    verify_qc(history, authenticator, &proof.qc).map_err(ClientBatchError::Verification)?;','    verify_qc(history, authenticator, &proof.qc).map_err(ClientBatchError::Verification)?;\n    verify_timed(history, authenticator, &proof.child)?;')]),
    ]
    result=[]
    for name,edits in definitions:
        altered=original
        for before,after in edits:
            need(altered.count(before)==1,'mutation coordinate '+name);altered=altered.replace(before,after,1)
        need(altered!=original,'unchanged mutation');result.append((name,altered,dict(name=name,edits=edits,source_sha256=sha(altered.encode()))))
    return result

def payload_inventory(toolchain):
    return {directory+'/'+f.relative_to(toolchain/directory).as_posix():identity(f)
            for directory in ['bin','lib'] for f in sorted((toolchain/directory).rglob('*')) if f.is_file()}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--toolchain',type=Path,required=True);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--source-freeze-sha',required=True);ap.add_argument('--private-map',type=Path,required=True);a=ap.parse_args()
    requested_out=Path(os.path.abspath(a.out));out=a.out.resolve();toolchain=a.toolchain.resolve();private=a.private_map.resolve()
    need(out.parent==Path('/tmp').resolve() and not out.exists(),'fresh direct canonical /tmp child')
    need(not private.exists() and not private.is_relative_to(HERE),'fresh private map outside packet')
    freeze=admit(a.source_freeze_sha);original=corrected('client_batch.rs');variants=mutants(original)
    pins=json.loads((HERE/'TOOLCHAIN-PINS.json').read_text());before_tools=payload_inventory(toolchain);need(before_tools==pins['payload_files'],'97-file toolchain admission')
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
            for name in ['config','config.toml']:
                path=parent/'.cargo'/name;need(not path.exists() and not path.is_symlink(),'unexpected '+form+' Cargo config');configs.add((form,logical(path)))
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
        used=env or env_base;started=time.monotonic();r=subprocess.run([str(x) for x in argv],cwd=cwd or out,env=used,input=stdin,capture_output=True,timeout=300)
        commands.append(dict(label=label,argv=[logical(x) for x in argv],cwd=logical(cwd or out),exit_code=r.returncode,elapsed_seconds=round(time.monotonic()-started,3),stdin=None if stdin is None else dict(bytes=len(stdin),sha256=sha(stdin)),stdout=retain(r.stdout),stderr=retain(r.stderr)))
        write_json(receipts/'commands.json',commands)
        if 'HOME' in used:need(used['HOME'].encode() not in r.stdout+r.stderr,'private home path in raw stream '+label)
        need(r.returncode in allowed,'command failed '+label);return r.stdout
    for name,flag in [('cargo','--version'),('rustc','-vV'),('rustdoc','--version'),('rustfmt','--version'),('clippy-driver','--version')]:run(name+'-version',[toolchain/'bin'/name,flag])
    run('clang-version',['/usr/bin/clang','--version']);sdk=run('SDK-path',['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path']).decode().strip();env_base['SDKROOT']=sdk
    run('SDK-version',['/usr/bin/xcrun','--sdk','macosx','--show-sdk-version']);external={}
    for name in ['clang','ld']:
        path=Path(run('resolve-'+name,['/usr/bin/xcrun','--find',name]).decode().strip());external[str(path)]=identity(path)
    for name in ['/usr/bin/clang','/usr/bin/ld','/usr/bin/ar','/usr/bin/xcrun',sys.executable]:external[logical(name)]=identity(Path(name))
    sdk_pins={name:identity(Path(sdk)/name) for name in ['SDKSettings.json','usr/lib/libSystem.tbd']}
    inputs=gzip.decompress((HERE/'fixtures/inputs.tsv.gz').read_bytes());expected=gzip.decompress((HERE/'fixtures/expected.tsv.gz').read_bytes());need(len(rows(inputs))==len(rows(expected))==221,'frozen corpus count')
    controls=comparator_controls(expected);environments={};copies={}
    def build(label,profiles,test=False,altered=None):
        phase=(out/label).resolve();phase.mkdir();tree=phase/'repo';tree.mkdir()
        for name in freeze['source']:
            dest=tree/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest)
        # Admit the real graph, then reconstruct the exact original module even
        # when a public checkout already contains the declared corrected source.
        (tree/MODULE).write_bytes((HERE/'amendment-1/original/client_batch.rs').read_bytes())
        original_graph=json.loads((HERE/'SOURCE-FREEZE.json').read_text())['source']
        need(source_inventory(tree)==original_graph,'copied original actual graph')
        (tree/MODULE).write_text(corrected('client_batch.rs') if altered is None else altered)
        expected_copy=dict(freeze['source'])
        if altered is not None:expected_copy[MODULE]=dict(bytes=len(altered.encode()),sha256=sha(altered.encode()))
        need(source_inventory(tree)==expected_copy,'copied real source graph');driver=phase/'driver.rs';driver.write_text(corrected('driver.rs'))
        need(identity(driver)==freeze['harness']['driver.rs'],'copied driver identity');no_symlinks(driver,phase)
        component=tree/'src'/CRATES[0];audit(requested_out/label/'repo/src'/CRATES[0],'lexical');audit(component,'canonical')
        flags=['-Dwarnings','-C','overflow-checks=on','-C','linker=/usr/bin/clang',
               '--remap-path-prefix='+str(phase)+'=/client-batch-build',
               '--remap-path-prefix='+str(requested_out/label)+'=/client-batch-build',
               '--remap-path-prefix='+str(toolchain)+'=/client-batch-toolchain']
        env=dict(env_base,CARGO_TARGET_DIR=str(phase/'target'),CARGO_ENCODED_RUSTFLAGS='\x1f'.join(flags));environments[label]={k:'<HOME_PRESERVED_NOT_RECORDED>' if k=='HOME' else logical(v) for k,v in env.items()};write_json(receipts/'compile-environments.json',environments)
        if altered is None:
            metadata=json.loads(run(label+'-metadata',[toolchain/'bin/cargo','metadata','--offline','--locked','--format-version','1'],component,env))
            need(sorted(p['name'] for p in metadata['packages'])==sorted(CRATES) and len(metadata['workspace_members'])==1,'exact real two-package graph')
            for package in metadata['packages']:
                need(package['source'] is None,'registry dependency forbidden')
                if package['name']==CRATES[0]:
                    need([(x['name'],x['source']) for x in package['dependencies']]==[('node94-action-signable',None)],'only baseline Keccak dependency')
                    need(sorted((t['name'],t['kind']) for t in package['targets'])==[('client_batch',['test']),('evidence_contract',['test']),('node94_consensus_admission',['lib'])],'actual main package targets')
                else:need(package['dependencies']==[] and [(t['name'],t['kind']) for t in package['targets']]==[('node94_action_signable',['lib'])],'actual leaf package')
            run(label+'-rustfmt-check',[toolchain/'bin/rustfmt','--edition','2021','--check',tree/MODULE,component/'tests/client_batch.rs',driver],component,env)
        observations={}
        for profile in profiles:
            release=['--release'] if profile=='release' else []
            run(label+'-'+profile+'-cargo-build',[toolchain/'bin/cargo','build','--offline','--locked','--lib',*release],component,env)
            if test:run(label+'-'+profile+'-cargo-test',[toolchain/'bin/cargo','test','--offline','--locked','--lib','--test','client_batch',*release],component,env)
            rlib=phase/'target'/profile/'libnode94_consensus_admission.rlib';leaf=list((phase/'target'/profile/'deps').glob('libnode94_action_signable-*.rlib'));need(len(leaf)==1,'one compiled leaf rlib');client=phase/('client-'+profile)
            run(label+'-'+profile+'-link-driver',[toolchain/'bin/rustc','--edition=2021','--crate-name','client_batch_input_client',driver,'--extern','node94_consensus_admission='+str(rlib),'--extern','node94_action_signable='+str(leaf[0]),'-L','dependency='+str(phase/'target'/profile/'deps'),'-C','opt-level='+('3' if profile=='release' else '0'),'-C','debuginfo='+('0' if profile=='release' else '2'),*flags,'-o',client],component,env)
            actual=run(label+'-'+profile+'-values',[client],component,env,inputs);comparison=compare(actual,expected);need(comparison['actual_rows']==221,'all actual case outputs')
            observations[profile]=dict(comparison=comparison,rlib=identity(rlib),leaf_rlib=identity(leaf[0]),client=identity(client),canonical_build_prefix_absent_in_rlib=str(phase).encode() not in rlib.read_bytes(),canonical_build_prefix_absent_in_client=str(phase).encode() not in client.read_bytes())
        if test:run(label+'-clippy',[toolchain/'bin/cargo','clippy','--offline','--locked','--all-targets','--','-D','warnings'],component,env)
        need(source_inventory(tree)==expected_copy,'copied source changed');need(identity(driver)==freeze['harness']['driver.rs'],'copied driver changed');copies[label]=expected_copy;return observations
    baseline=build('clean-one',('debug','release'),test=True);need(all(x['comparison']['equal'] for x in baseline.values()),'production mismatch')
    parser={};client=out/'clean-one/client-release'
    for name,raw in malformed_inputs(inputs).items():run('malformed-'+name,[client],stdin=raw,allowed=(2,));parser[name]=dict(exit_code=commands[-1]['exit_code'],command_index=len(commands)-1)
    run('extra-argument',[client,'unexpected'],stdin=b'',allowed=(2,));parser['extra-argument']=dict(exit_code=2,command_index=len(commands)-1)
    need(run('empty-input',[client],stdin=b'')==b'','empty input output');parser['empty-valid']=dict(exit_code=0,command_index=len(commands)-1)
    # Repeat from a clean directory at the identical physical path, recording raw
    # artifact identity separately from a coordinator's different-root replay.
    shutil.rmtree(out/'clean-one');repeat=build('clean-one',('debug','release'));need(all(x['comparison']['equal'] for x in repeat.values()),'clean same-path mismatch')
    own_bytes={p:{key:baseline[p][key]==repeat[p][key] for key in ['rlib','leaf_rlib','client']} for p in ['debug','release']}
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
    write_json(receipts/'build-audit.json',dict(source_freeze_sha256=a.source_freeze_sha,original_source_freeze_sha256='fd33cfb20eadc9b643266dce91496196354b352b8127b4fd19cae309c2b0b4c4',production_route='exact original-or-declared public patch admitted; copy original graph then apply pinned projection',actual_source=freeze['source'],ancestor_config_checks=sorted(configs),ancestor_workspace_checks=sorted(workspace_ancestors),source_ancestor_context_excluded=source_ancestors,fresh_CARGO_HOME=True,toolchain_payload_sha256=identity(HERE/'TOOLCHAIN-PINS.json')['sha256'],toolchain_payload_unchanged=True,external_tools=external,SDKROOT=sdk,sdk_inputs=sdk_pins,limit='Actual graph and97 toolchain files plus selected linker/SDK bytes pinned; host OS/dyld and entire SDK are not hermetic.'))
    result=dict(source_freeze_sha256=a.source_freeze_sha,corpus_cases=221,baseline=baseline,same_path_clean_repeat=repeat,raw_same_path_artifact_equality=own_bytes,compiled_mutants=mutation_results,comparator_controls=controls,parser_controls=parser,commands=len(commands),actual_and_copied_source_unchanged=True,precode_unchanged=True,scope='Authored Rust value/state execution only; conditional native/authenticator and TC limits preserved; no captured execution, emulator, full suite or cross-directory byte identity claim.')
    write_json(receipts/'results.json',result);print(json.dumps(dict(cases=221,mutants=len(mutation_results),profiles=2,commands=len(commands),raw_same_path_artifact_equality=own_bytes)))

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);raise SystemExit(1) from exc

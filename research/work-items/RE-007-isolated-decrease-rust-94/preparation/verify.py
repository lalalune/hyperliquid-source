"""Guarded scalar reconstruction comparison; default replays actual receipts.

No captured node code executes. Semantic expectations precede Rust; subsequent
wire packaging is explicitly separate. EnterCommit is not action success.
"""
from pathlib import Path
import argparse,base64,gzip,hashlib,importlib.util,json,os,re,shutil,struct,subprocess,time,zlib
HERE=Path(__file__).resolve().parent;PRE=HERE.parent;ROOT=HERE.parents[2]
COMPONENT=Path('src/node94-margin-risk')
RUST_DEFAULT=Path('/workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin')
FLOOR=300*1024**2;TRANSIENT=16*1024**2;PROJECTED=64*1024**2
def sha(b):return hashlib.sha256(b).hexdigest()
def need(ok,msg):
    if not ok:raise ValueError(msg)
def module(path):
    spec=importlib.util.spec_from_file_location('reviewed_decrease_oracle',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def decision(ident,value):
    kind,tag,cap=value
    return struct.pack('<IBHBI',ident,0 if kind=='EnterCommit' else 1,tag or 0,int(cap is not None),cap or 0)
def corpus(folder,wire):
    pre=json.loads((folder/'PRE-RUST-FREEZE.json').read_text())
    for name,digest in pre['files'].items():need(sha((folder/name).read_bytes())==digest,'semantic pre-source '+name)
    rows=json.loads((folder/'inputs.json').read_text());answers=json.loads((folder/'expected.json').read_text());controls=json.loads((folder/'controls.json').read_text());policies=json.loads((folder/'excluded-domain.json').read_text());oracle=module(folder/'freeze_expectations.py');codec=module(wire/'freeze_wire.py')
    need(len(rows)==341 and len(policies)==9 and len(controls)==8,'denominators')
    need(all(oracle.normal(r) for r in rows),'qualified normal inputs')
    need(len({json.dumps({k:v for k,v in r.items() if k!='id'},sort_keys=True) for r in rows})==341,'unique qualified inputs')
    need(answers==[{'id':r['id'],'value':oracle.value(r)} for r in rows],'pre-source values')
    policy_rows=[dict(x['input'],id=341+i) for i,x in enumerate(policies)]
    need(not any(oracle.normal(r) for r in policy_rows),'policy cases are outside native domain')
    expected=b''.join(decision(x['id'],x['value']) for x in answers)
    policy_expected=b''.join(struct.pack('<IBHBI',r['id'],2,0,0,0) for r in policy_rows)
    streams={'qualified-input.bin.b64':codec.inputs(rows),'qualified-expected.bin.b64':expected,'policy-input.bin.b64':codec.inputs(policy_rows),'policy-expected.bin.b64':policy_expected}
    freeze=json.loads((wire/'WIRE-FREEZE.json').read_text());need(freeze['semantic_freeze_sha256']==sha((folder/'PRE-RUST-FREEZE.json').read_bytes()),'wire semantic provenance')
    for name,raw in streams.items():
        encoded=(wire/name).read_bytes();need(base64.b64decode(encoded.rstrip(b'\n'),validate=True)==raw,'wire bytes '+name);need(freeze['files'][name]=={'decoded_bytes':len(raw),'decoded_sha256':sha(raw),'text_sha256':sha(encoded)},'wire pin '+name)
    for c in controls:
        changed=[r for r in rows if oracle.value(r,c['name'])!=oracle.value(r)]
        branches=[r for r in changed if (oracle.value(r,c['name'])[0]=='EnterCommit')!=(oracle.value(r)[0]=='EnterCommit')]
        need(len(changed)==c['changed_values'] and len(branches)==c['changed_commit_vs_refusal'],'planned counts')
        w=next(r for r in rows if r['id']==c['witness_id']);need(oracle.value(w)==c['expected'] and oracle.value(w,c['name'])==c['wrong'],'planned witness')
    return rows,controls,oracle,streams
def variants(source):
    rules={
      'old-divisor-in-shadow':('leverage_divisor: input.requested_leverage,','leverage_divisor: input.old_leverage,'),
      'tiered-initial-instead-mode1':('MarginMode::PositionDivisor as u8','MarginMode::TieredInitial as u8'),
      'absolute-size-in-shadow':('size: input.position_size,','size: input.position_size.saturating_abs(),'),
      'reject-zero-surplus':('if assessment.eligible {','if assessment.surplus <= 0 {'),
      'zero-margin-in-shadow':('margin: input.isolated_margin,','margin: 0,'),
      'price-zero-in-shadow':('shadow, price, MarginMode::PositionDivisor','shadow, 0, MarginMode::PositionDivisor'),
      'skip-cap':('if input.requested_leverage > cap {','if false && input.requested_leverage > cap {'),
      'wrong-cross-refusal-tag':('Some((0x47, None))','Some((0x46, None))'),
    }
    result={}
    for name,(old,new) in rules.items():need(source.count(old)==1,'unique mutant anchor '+name);result[name]=source.replace(old,new)
    return result
def component_files(comp):
    return {str(p.relative_to(comp)):p.read_bytes() for p in sorted(comp.rglob('*')) if p.is_file() and 'target' not in p.parts and '__pycache__' not in p.parts}
def payloads():
    files={str(COMPONENT/n):b for n,b in component_files(ROOT/COMPONENT).items()}
    need(not any(n.endswith('/build.rs') or '/.cargo/' in n for n in files),'unexpected compiler hooks')
    paths=[ROOT/'research/work-items/RE-007-margin-path-94/boundaries.tsv',HERE/'driver.rs',HERE/'verify.py',HERE/'freeze_wire.py',HERE/'WIRE-FREEZE.json']
    paths+=list(HERE.glob('*.bin.b64'))
    pre=json.loads((PRE/'PRE-RUST-FREEZE.json').read_text())
    paths += [PRE/'PRE-RUST-FREEZE.json']+[PRE/n for n in pre['files']]
    for p in paths:files[str(p.relative_to(ROOT))]=p.read_bytes()
    return files
def build(out,rust_bin):
    start=time.time();need(not out.exists(),'existing output tree');free=shutil.disk_usage(ROOT).free;need(free-PROJECTED>=FLOOR,'projected64MiB reserve below300MiB')
    corpus(PRE,HERE);files=payloads();snap=out/'snapshot';snap.mkdir(parents=True)
    for n,b in files.items():p=snap/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
    frozen={'files':{n:sha(b) for n,b in sorted(files.items())},'qualified_cases':341,'policy_cases':9,'semantic_freeze_sha256':sha((PRE/'PRE-RUST-FREEZE.json').read_bytes()),'disk_reserve_floor_bytes':FLOOR,'per_command_transient_bytes':TRANSIENT,'projected_build_bytes':PROJECTED,'free_before_bytes':free,'captured_execution':False,'EnterCommit_is_not_success':True}
    (out/'SOURCE-FREEZE.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n');packet=snap/HERE.relative_to(ROOT);presource=snap/PRE.relative_to(ROOT);rows,controls,oracle,streams=corpus(presource,packet);source=(snap/COMPONENT/'src/isolated_decrease.rs').read_text();mutated=variants(source);active=None
    env=os.environ.copy()
    for key in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTDOCFLAGS','RUSTUP_TOOLCHAIN']:env.pop(key,None)
    # Invocation-local resource controls; no manifest or global setting changes.
    settings={'RUSTC':str(rust_bin/'rustc'),'RUSTDOC':str(rust_bin/'rustdoc'),'CARGO_HOME':str(out/'cargo-home'),'CARGO_NET_OFFLINE':'true','CARGO_INCREMENTAL':'0','CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0','CARGO_PROFILE_RELEASE_DEBUG':'0','CARGO_PROFILE_DEV_STRIP':'symbols','CARGO_PROFILE_TEST_STRIP':'symbols','CARGO_PROFILE_RELEASE_STRIP':'symbols'}
    env.update(settings);records=[];products=[];dep_info=[]
    def guard(before=False):
        need(shutil.disk_usage(ROOT).free>=FLOOR+(TRANSIENT if before else 0),'disk reserve below300MiB plus pre-command16MiB')
        for n,h in frozen['files'].items():need(sha((snap/n).read_bytes())==h and sha((ROOT/n).read_bytes())==h,'source/input changed '+n)
        if active:
            comp,want=active;need({n:sha(b) for n,b in component_files(comp).items()}==want,'mutant compiler tree changed')
    def run(argv,stdin=b'',want=None,exit=0,cwd=None):
        guard(True);t=time.time();r=subprocess.run([str(x) for x in argv],input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=cwd,env=env)
        rec={'argv':[str(x) for x in argv],'cwd':str(cwd) if cwd else None,'exit':r.returncode,'stdin_sha256':sha(stdin),'stdout_b64':base64.b64encode(r.stdout).decode(),'stderr_b64':base64.b64encode(r.stderr).decode(),'seconds':round(time.time()-t,6),'free_after_bytes':shutil.disk_usage(ROOT).free};records.append(rec)
        with (out/'records.jsonl').open('a') as f:f.write(json.dumps(rec,sort_keys=True)+'\n')
        guard();need(r.returncode==exit,'command exit '+str(argv));need(want is None or r.stdout==want,'external complete output '+str(argv));return len(records)-1
    tools={}
    for name in ['rustc','cargo','rustdoc']:
        exe=rust_bin/name;i=run([exe,'--version','--verbose'] if name=='rustc' else [exe,'--version']);tools[name]={'path':str(exe),'sha256':sha(exe.read_bytes()),'record':i}
    need(b'rustc 1.94.1' in base64.b64decode(records[tools['rustc']['record']]['stdout_b64']),'pinned rustc')
    def compile_client(comp,dest,opt):
        dest.mkdir(parents=True,exist_ok=True);rlib=dest/'libnode94_margin_risk.rlib';client=dest/'client'
        run([rust_bin/'rustc','--edition=2024','--crate-name','node94_margin_risk','--crate-type','rlib','-C',f'opt-level={opt}',comp/'src/lib.rs','-o',rlib],cwd=comp)
        run([rust_bin/'rustc','--edition=2024','-C',f'opt-level={opt}','-C','strip=symbols',packet/'driver.rs','--extern',f'node94_margin_risk={rlib}','-o',client],cwd=comp)
        return client,{'rlib_sha256':sha(rlib.read_bytes()),'client_sha256':sha(client.read_bytes())}
    baseline=[]
    for opt in [0,3]:
        for repeat in [1,2]:
            dest=out/f'base-{opt}-{repeat}';client,pins=compile_client(snap/COMPONENT,dest,opt);q=run([client],streams['qualified-input.bin.b64'],streams['qualified-expected.bin.b64']);p=run([client],streams['policy-input.bin.b64'],streams['policy-expected.bin.b64']);baseline.append({'opt':opt,'repeat':repeat,'qualified_record':q,'policy_record':p,**pins})
    cargo=[]
    for release in [False,True]:
        target=out/'cargo-target';argv=[rust_bin/'cargo','test','--frozen','--offline','--manifest-path',snap/COMPONENT/'Cargo.toml','--target-dir',target]+(['--release'] if release else []);index=run(argv,cwd=snap/COMPONENT);cargo.append({'profile':'release' if release else 'debug','record':index})
        # Retain actual dep-info and hashes before removing only this new target.
        for p in sorted(target.rglob('*.d')):
            raw=p.read_bytes();dep_info.append({'profile':'release' if release else 'debug','path':str(p.relative_to(target)),'sha256':sha(raw),'raw_base64':base64.b64encode(raw).decode()})
        product={str(p.relative_to(target)):sha(p.read_bytes()) for p in sorted(target.rglob('*')) if p.is_file()};products.append({'new_tree':str(target),'files':product,'removed_after_completion':True});shutil.rmtree(target)
    mutants=[]
    for control in controls:
        name=control['name'];comp=out/'mutant-component';shutil.copytree(snap/COMPONENT,comp);(comp/'src/isolated_decrease.rs').write_text(mutated[name]);manifest={n:sha(b) for n,b in component_files(comp).items()};active=(comp,manifest)
        dest=out/'mutant-build';client,pins=compile_client(comp,dest,3);wrong=b''.join(decision(r['id'],oracle.value(r,name)) for r in rows);need(wrong!=streams['qualified-expected.bin.b64'],'operative mutant');index=run([client],streams['qualified-input.bin.b64'],wrong);mutants.append({'name':name,'output_record':index,'component_manifest':manifest,'control':control,**pins});active=None;products.append({'new_tree':str(dest),'files':{str(p.relative_to(dest)):sha(p.read_bytes()) for p in dest.iterdir() if p.is_file()},'removed_after_completion':True});shutil.rmtree(comp);shutil.rmtree(dest)
    framing=[];client=out/'base-3-2/client';inp=streams['qualified-input.bin.b64']
    for name,data in [('bad-magic',b'BAD!'+inp[4:]),('truncated',inp[:-1]),('trailing',inp+b'x')]:framing.append({'name':name,'record':run([client],data,b'',exit=2)})
    guard();report={'source_freeze_sha256':sha((out/'SOURCE-FREEZE.json').read_bytes()),'tools':tools,'baseline':baseline,'cargo':cargo,'mutants':mutants,'framing':framing,'records':records,'invocation_environment':settings,'removed_new_products':products,'cargo_dep_info':dep_info,'qualified_cases':341,'policy_cases':9,'captured_execution':False,'EnterCommit_is_not_success':True,'seconds':round(time.time()-start,6)}
    (out/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    archive={'SOURCE-FREEZE.json':base64.b64encode((out/'SOURCE-FREEZE.json').read_bytes()).decode(),'REPORT.json':base64.b64encode((out/'REPORT.json').read_bytes()).decode(),'snapshot':{n:base64.b64encode(b).decode() for n,b in files.items()}};raw=(json.dumps(archive,sort_keys=True,separators=(',',':'))+'\n').encode();encoded=base64.b64encode(gzip.compress(raw,mtime=0))+b'\n';(out/'compiled.json.gz.b64').write_bytes(encoded)
    print(json.dumps({'source_freeze_sha256':report['source_freeze_sha256'],'report_sha256':sha((out/'REPORT.json').read_bytes()),'archive_payload_sha256':sha(raw),'archive_text_sha256':sha(encoded),'commands':len(records),'qualified':341,'policy':9,'mutants':8,'framing':3,'snapshot_files':len(files),'seconds':report['seconds'],'free_after_bytes':shutil.disk_usage(ROOT).free},sort_keys=True));return report
def audit(path,current=True):
    b=base64.b64decode(path.read_bytes().rstrip(b'\n'),validate=True);z=zlib.decompressobj(16+zlib.MAX_WBITS);raw=z.decompress(b)+z.flush();need(z.eof and not z.unused_data and not z.unconsumed_tail,'strict gzip');a=json.loads(raw);fr=base64.b64decode(a['SOURCE-FREEZE.json'],validate=True);rr=base64.b64decode(a['REPORT.json'],validate=True);f=json.loads(fr);r=json.loads(rr);need(sha(fr)==r['source_freeze_sha256'],'report freeze pin');files={n:base64.b64decode(v,validate=True) for n,v in a['snapshot'].items()};need({n:sha(b) for n,b in files.items()}==f['files'],'full snapshot pins')
    if current:
        for n,b in files.items():need((ROOT/n).read_bytes()==b,'exact current source/input '+n)
        want={n[len(str(COMPONENT))+1:]:b for n,b in files.items() if n.startswith(str(COMPONENT)+'/')};need(component_files(ROOT/COMPONENT)==want,'exact current component membership')
    rows,controls,oracle,streams=corpus(PRE,HERE)
    def channel(i,k):return base64.b64decode(r['records'][i][k+'_b64'],validate=True)
    def check(i,stdin,stdout,exit=0):
        rec=r['records'][i];need(rec['exit']==exit and rec['stdin_sha256']==sha(stdin) and channel(i,'stdout')==stdout,'actual complete output')
    need([(b['opt'],b['repeat']) for b in r['baseline']]==[(0,1),(0,2),(3,1),(3,2)],'four baselines')
    for b in r['baseline']:check(b['qualified_record'],streams['qualified-input.bin.b64'],streams['qualified-expected.bin.b64']);check(b['policy_record'],streams['policy-input.bin.b64'],streams['policy-expected.bin.b64'])
    variants_=variants(files[str(COMPONENT/'src/isolated_decrease.rs')].decode());base={n[len(str(COMPONENT))+1:]:sha(b) for n,b in files.items() if n.startswith(str(COMPONENT)+'/')};need({m['name'] for m in r['mutants']}==set(variants_),'mutant membership');byname={c['name']:c for c in controls}
    for m in r['mutants']:
        name=m['name'];manifest=dict(base);manifest['src/isolated_decrease.rs']=sha(variants_[name].encode());need(m['component_manifest']==manifest and m['control']==byname[name],'full mutant tree/witness');wrong=b''.join(decision(x['id'],oracle.value(x,name)) for x in rows);check(m['output_record'],streams['qualified-input.bin.b64'],wrong)
    need([c['profile'] for c in r['cargo']]==['debug','release'],'Cargo profiles')
    counts=[]
    for c in r['cargo']:
        need(r['records'][c['record']]['exit']==0,'Cargo exit');counts.append(sum(int(v) for v in re.findall(rb'test result: ok\. (\d+) passed',channel(c['record'],'stdout'))))
    need(counts==[52,52],'all52 Cargo tests per profile')
    malformed={'bad-magic':b'BAD!'+streams['qualified-input.bin.b64'][4:],'truncated':streams['qualified-input.bin.b64'][:-1],'trailing':streams['qualified-input.bin.b64']+b'x'};need({c['name'] for c in r['framing']}==set(malformed),'framing controls')
    for c in r['framing']:check(c['record'],malformed[c['name']],b'',2)
    for d in r['cargo_dep_info']:need(sha(base64.b64decode(d['raw_base64'],validate=True))==d['sha256'],'Cargo dep-info bytes')
    need(b'rustc 1.94.1' in channel(r['tools']['rustc']['record'],'stdout'),'compiler version')
    for rec in r['records']:need(rec['exit'] in [0,2] and rec['free_after_bytes']>=FLOOR,'actual exit/resource floor');base64.b64decode(rec['stdout_b64'],validate=True);base64.b64decode(rec['stderr_b64'],validate=True)
    return {'source_freeze_sha256':sha(fr),'report_sha256':sha(rr),'archive_payload_sha256':sha(raw),'snapshot_files':len(files),'qualified_cases':341,'policy_cases':9,'baseline_builds':4,'commit_refusal_controls':7,'refusal_only_controls':1,'framing_controls':3,'cargo_tests_per_profile':counts,'dep_info_records':len(r['cargo_dep_info']),'commands':len(r['records']),'channels':2*len(r['records']),'captured_execution':False,'EnterCommit_is_not_success':True}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path);p.add_argument('--rust-bin',type=Path,default=RUST_DEFAULT);p.add_argument('--archive',type=Path,default=HERE/'compiled.json.gz.b64');args=p.parse_args()
    if args.build:build(args.build.resolve(),args.rust_bin.resolve())
    else:print(json.dumps(audit(args.archive),sort_keys=True))

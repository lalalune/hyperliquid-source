"""Guarded independent Rust decision comparison; default only replays receipts.

Inputs/expected decisions were frozen before Rust. No captured code executes.
EnterCommit is not Success. Domain and framing policies are separate classes.
"""
from pathlib import Path
import argparse,base64,gzip,hashlib,importlib.util,json,os,shutil,struct,subprocess,time,zlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];COMPONENT=Path('src/node94-margin-risk')
RUST_DEFAULT=Path('/workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin')
def sha(b):return hashlib.sha256(b).hexdigest()
def need(ok,msg):
    if not ok:raise ValueError(msg)
def module(path):
    spec=importlib.util.spec_from_file_location('frozen_increase_oracle',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def decision_bytes(ident,value):
    kind,tag,cap=value
    return struct.pack('<IBHBI',ident,0 if kind=='EnterCommit' else 1,tag or 0,int(cap is not None),cap or 0)
def policy_bytes(ident,label):
    code={'OutsideCustomId':1,'OutsideSameTable':2,'OutsideActivePosition':3,'OutsideIncrease':4}[label]
    return struct.pack('<IBHBI',ident,2,code,0,0)
def input_bytes(rows):
    out=bytearray(b'LCG1'+struct.pack('<I',len(rows)))
    for r in rows:
        out+=struct.pack('<IIIBBIIIQqB',r['id'],r['custom_id_u32'],r['position_table_u32'],r['kind_byte'],int(r['cross']),r['mode_word_u32'],r['old_leverage_u32'],r['requested_u32'],r['price_u64'],r['size_i64'],len(r['tiers']))
        for key,cap in r['tiers']:out+=struct.pack('<QB',key,cap)
    return bytes(out)
def corpus(folder):
    frozen=json.loads((folder/'PRE-RUST-FREEZE.json').read_text())
    for name,digest in frozen['files'].items():need(sha((folder/name).read_bytes())==digest,'pre-Rust '+name)
    oracle=module(folder/'freeze_decisions.py');rows=json.loads((folder/'inputs.json').read_text());answers=json.loads((folder/'expected.json').read_text());policies=json.loads((folder/'policy-cases.json').read_text());controls=json.loads((folder/'planned-controls.json').read_text())
    need(len(rows)==487 and len(policies)==4 and len(controls)==9,'semantic denominators')
    need(answers==[{'id':r['id'],'decision':list(oracle.native(r))} for r in rows],'independent native decision values')
    need(len({json.dumps({k:v for k,v in r.items() if k!='id'},sort_keys=True) for r in rows})==487,'unique cases')
    policy_rows=[dict(r,id=487+i) for i,r in enumerate(policies)];allrows=rows+policy_rows
    expected=b''.join(decision_bytes(a['id'],a['decision']) for a in answers)+b''.join(policy_bytes(r['id'],r['chosen_policy']) for r in policy_rows)
    for c in controls:
        changed=[r for r in rows if oracle.native(r,c['name'])!=oracle.native(r)]
        branches=[r for r in changed if (oracle.native(r,c['name'])[0]=='EnterCommit')!=(oracle.native(r)[0]=='EnterCommit')]
        need(len(changed)==c['different_decision_cases'] and len(branches)==c['different_commit_vs_refusal_cases'],'planned wrong count')
        witness=next(r for r in rows if r['id']==c['witness_id']);need(list(oracle.native(witness))==c['expected'] and list(oracle.native(witness,c['name']))==c['wrong'],'planned witness')
    return rows,policy_rows,input_bytes(allrows),expected,controls,oracle

def variants(source):
    rules={
      'reject-max-equality':('if input.requested_leverage > maximum {','if input.requested_leverage >= maximum {'),
      'reject-cap-equality':('if input.requested_leverage > cap {','if input.requested_leverage >= cap {'),
      'read-mode-byte':('(input.position_mode_word == 0)','(input.position_mode_word as u8 == 0)'),
      'overall-max-last-tier':('table.tiers()[0].max_leverage()','table.tiers().last().expect("nonempty").max_leverage()'),
      'zero-price-cap-join':('Some(table), input.price_word, input.position_size,','Some(table), 0, input.position_size,'),
      'ignore-cross-kind':('if input.cross_requested && input.kind_byte != 0 {','if false && input.cross_requested && input.kind_byte != 0 {'),
      'skip-global-maximum':('if input.requested_leverage > maximum {','if false && input.requested_leverage > maximum {'),
    }
    out={}
    for name,(old,new) in rules.items():need(source.count(old)==1,'anchor '+name);out[name]=source.replace(old,new)
    old='    if input.cross_requested && input.kind_byte != 0 {'
    changed=source.replace(old,'    let requested = u32::from(input.requested_leverage as u8);\n'+old)
    for bound in ['maximum','cap']:
        anchor='if input.requested_leverage > '+bound+' {';need(changed.count(anchor)==1,'truncate native gate anchor');changed=changed.replace(anchor,'if requested > '+bound+' {')
    out['truncate-request-u8']=changed
    mode='''    if (input.position_mode_word == 0) != input.cross_requested {
        return Ok(CustomIncreaseDecision::RejectAccountingMode);
    }
'''
    cap='''    let cap = u32::from(position_leverage_cap(
        Some(table), input.price_word, input.position_size,
    ));
    if input.requested_leverage > cap {
        return Ok(CustomIncreaseDecision::RejectPositionCap { cap });
    }
'''
    need(source.count(mode+cap)==1,'ordered mode/cap anchor');out['cap-before-mode']=source.replace(mode+cap,cap+mode)
    need(len(out)==9,'variant set');return out

def compiler_payloads():
    paths=sorted(p for p in (ROOT/COMPONENT).rglob('*') if p.is_file() and 'target' not in p.parts and '__pycache__' not in p.parts)
    need(not any(p.name=='build.rs' or '.cargo' in p.parts for p in paths),'unexpected build hooks')
    paths += [ROOT/'research/work-items/RE-007-margin-path-94/boundaries.tsv',HERE/'driver.rs',HERE/'verify.py']+sorted(p for p in (HERE/'pre-source').iterdir() if p.is_file())
    return {str(p.relative_to(ROOT)):p.read_bytes() for p in paths}
def prepare(out):
    need(shutil.disk_usage(ROOT).free-160_000_000>=300_000_000,'projected disk reserve below300MB')
    need(not out.exists(),'existing output tree');corpus(HERE/'pre-source');files=compiler_payloads();snap=out/'snapshot';snap.mkdir(parents=True)
    for n,b in files.items():p=snap/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
    freeze={'component':str(COMPONENT),'files':{n:sha(b) for n,b in sorted(files.items())},'qualified_cases':487,'policy_cases':4,'semantic_freeze_sha256':sha((HERE/'pre-source/PRE-RUST-FREEZE.json').read_bytes()),'disk_reserve_floor_bytes':300_000_000,'projected_build_bytes':160_000_000,'free_before_bytes':shutil.disk_usage(ROOT).free,'EnterCommit_is_not_success':True,'captured_execution':False}
    (out/'SOURCE-FREEZE.json').write_text(json.dumps(freeze,sort_keys=True,indent=2)+'\n');return freeze

def build(out,rust_bin):
    start=time.time();freeze=prepare(out);snap=out/'snapshot';packet=snap/HERE.relative_to(ROOT);rows,policies,inputs,expected,controls,oracle=corpus(packet/'pre-source');active=None
    source=(snap/COMPONENT/'src/leverage_increase.rs').read_text();changed_sources=variants(source)
    def guard():
        need(shutil.disk_usage(ROOT).free>=300_000_000,'actual disk reserve below300MB')
        for n,h in freeze['files'].items():need(sha((snap/n).read_bytes())==h and sha((ROOT/n).read_bytes())==h,'frozen/current input changed '+n)
        if active:
            comp,want=active;have={str(p.relative_to(comp)):sha(p.read_bytes()) for p in sorted(comp.rglob('*')) if p.is_file()};need(have==want,'active mutant tree changed')
    env=os.environ.copy()
    for key in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTDOCFLAGS','RUSTUP_TOOLCHAIN']:env.pop(key,None)
    env.update(RUSTC=str(rust_bin/'rustc'),RUSTDOC=str(rust_bin/'rustdoc'),CARGO_HOME=str(out/'cargo-home'),CARGO_NET_OFFLINE='true')
    records=[]
    def run(argv,stdin=b'',want=None,exit=0,cwd=None):
        guard();t=time.time();r=subprocess.run([str(a) for a in argv],input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,cwd=cwd)
        rec={'argv':[str(a) for a in argv],'cwd':str(cwd) if cwd else None,'exit':r.returncode,'stdin_sha256':sha(stdin),'stdout_b64':base64.b64encode(r.stdout).decode(),'stderr_b64':base64.b64encode(r.stderr).decode(),'seconds':round(time.time()-t,6),'free_after_bytes':shutil.disk_usage(ROOT).free};records.append(rec)
        with (out/'records.jsonl').open('a') as f:f.write(json.dumps(rec,sort_keys=True)+'\n')
        guard();need(r.returncode==exit,'command exit '+str(argv))
        if want is not None:need(r.stdout==want,'external complete output '+str(argv))
        return len(records)-1
    tools={}
    for name in ['rustc','cargo','rustdoc']:
        exe=rust_bin/name;i=run([exe,'--version','--verbose'] if name=='rustc' else [exe,'--version']);tools[name]={'path':str(exe),'sha256':sha(exe.read_bytes()),'record':i}
    need(b'rustc 1.94.1' in base64.b64decode(records[tools['rustc']['record']]['stdout_b64']),'pinned rustc')
    def compile_client(comp,dest,opt):
        dest.mkdir(parents=True,exist_ok=True);rlib=dest/'libnode94_margin_risk.rlib';client=dest/'client'
        run([rust_bin/'rustc','--edition=2024','--crate-name','node94_margin_risk','--crate-type','rlib','-C',f'opt-level={opt}',comp/'src/lib.rs','-o',rlib],cwd=comp)
        run([rust_bin/'rustc','--edition=2024','-C',f'opt-level={opt}',packet/'driver.rs','--extern',f'node94_margin_risk={rlib}','-o',client],cwd=comp)
        return client,{'rlib_sha256':sha(rlib.read_bytes()),'client_sha256':sha(client.read_bytes())}
    baselines=[]
    for opt in [0,3]:
        for repeat in [1,2]:
            client,hashes=compile_client(snap/COMPONENT,out/f'base-{opt}-{repeat}',opt);idx=run([client],inputs,expected);baselines.append({'opt':opt,'repeat':repeat,'output_record':idx,**hashes})
    cargo=[]
    for release in [False,True]:
        cmd=[rust_bin/'cargo','test','--frozen','--offline','--manifest-path',snap/COMPONENT/'Cargo.toml','--target-dir',out/'cargo-target']+(['--release'] if release else [])
        cargo.append({'profile':'release' if release else 'debug','record':run(cmd,cwd=snap/COMPONENT)})
    mutants=[]
    for c in controls:
        name=c['name'];comp=out/'mutant-component';shutil.copytree(snap/COMPONENT,comp);(comp/'src/leverage_increase.rs').write_text(changed_sources[name]);manifest={str(p.relative_to(comp)):sha(p.read_bytes()) for p in sorted(comp.rglob('*')) if p.is_file()};active=(comp,manifest)
        client,hashes=compile_client(comp,out/'mutant-build',3)
        wrong=b''.join(decision_bytes(r['id'],oracle.native(r,name)) for r in rows)+expected[487*12:]
        idx=run([client],inputs,wrong);need(wrong!=expected,'operative mutant');mutants.append({'name':name,'output_record':idx,'component_manifest':manifest,'control':c,**hashes});active=None;shutil.rmtree(comp);shutil.rmtree(out/'mutant-build')
    framing=[];client=out/'base-3-2/client'
    for name,data in [('bad-magic',b'BAD!'+inputs[4:]),('truncated',inputs[:-1]),('trailing',inputs+b'x')]:framing.append({'name':name,'record':run([client],data,b'',exit=2)})
    guard();report={'source_freeze_sha256':sha((out/'SOURCE-FREEZE.json').read_bytes()),'qualified_cases':487,'policy_cases':4,'tools':tools,'baseline':baselines,'cargo':cargo,'mutants':mutants,'framing':framing,'records':records,'EnterCommit_is_not_success':True,'captured_execution':False,'seconds':round(time.time()-start,6)}
    (out/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    archive={'SOURCE-FREEZE.json':base64.b64encode((out/'SOURCE-FREEZE.json').read_bytes()).decode(),'REPORT.json':base64.b64encode((out/'REPORT.json').read_bytes()).decode(),'snapshot':{n:base64.b64encode((snap/n).read_bytes()).decode() for n in freeze['files']}}
    raw=(json.dumps(archive,sort_keys=True,separators=(',',':'))+'\n').encode();encoded=base64.b64encode(gzip.compress(raw,mtime=0))+b'\n';(out/'compiled.json.gz.b64').write_bytes(encoded)
    print(json.dumps({'source_freeze_sha256':report['source_freeze_sha256'],'report_sha256':sha((out/'REPORT.json').read_bytes()),'archive_payload_sha256':sha(raw),'archive_text_sha256':sha(encoded),'commands':len(records),'qualified':487,'policy':4,'mutants':9,'framing':3,'seconds':report['seconds'],'free_after_bytes':shutil.disk_usage(ROOT).free},sort_keys=True));return report

def audit(path,current_component=False):
    raw=base64.b64decode(path.read_bytes().rstrip(b'\n'),validate=True);d=zlib.decompressobj(16+zlib.MAX_WBITS);raw=d.decompress(raw)+d.flush();need(d.eof and not d.unused_data and not d.unconsumed_tail,'gzip framing');a=json.loads(raw)
    fr=base64.b64decode(a['SOURCE-FREEZE.json'],validate=True);rr=base64.b64decode(a['REPORT.json'],validate=True);f=json.loads(fr);r=json.loads(rr);need(sha(fr)==r['source_freeze_sha256'],'report/freeze binding')
    files={n:base64.b64decode(b,validate=True) for n,b in a['snapshot'].items()};need(set(files)==set(f['files']),'frozen file membership')
    skip={str(COMPONENT/'src/lib.rs'),str(HERE.relative_to(ROOT)/'verify.py')}
    for n,b in files.items():
        need(sha(b)==f['files'][n],'snapshot payload '+n)
        if n not in skip:need((ROOT/n).read_bytes()==b,'current bound source/input '+n)
    need('check_custom_leverage_increase,' in (ROOT/COMPONENT/'src/lib.rs').read_text(),'public caller export')
    if current_component:
        have={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted((ROOT/COMPONENT).rglob('*')) if p.is_file() and 'target' not in p.parts and '__pycache__' not in p.parts};want={n:h for n,h in f['files'].items() if n.startswith(str(COMPONENT)+'/')};need(have==want,'current component differs from frozen build')
    rows,policies,inputs,expected,controls,oracle=corpus(HERE/'pre-source')
    def channel(i,kind):return base64.b64decode(r['records'][i][kind+'_b64'],validate=True)
    def check(i,want,stdin=inputs,exit=0):
        rec=r['records'][i];need(rec['exit']==exit and rec['stdin_sha256']==sha(stdin) and channel(i,'stdout')==want,'actual complete output')
    need(len(r['baseline'])==4 and [(x['opt'],x['repeat']) for x in r['baseline']]==[(0,1),(0,2),(3,1),(3,2)],'baseline builds')
    for b in r['baseline']:check(b['output_record'],expected)
    variant=variants(files[str(COMPONENT/'src/leverage_increase.rs')].decode());base={n[len(str(COMPONENT))+1:]:h for n,h in f['files'].items() if n.startswith(str(COMPONENT)+'/')};byname={c['name']:c for c in controls};need({m['name'] for m in r['mutants']}==set(variant),'mutant set')
    for m in r['mutants']:
        name=m['name'];manifest=dict(base);manifest['src/leverage_increase.rs']=sha(variant[name].encode());need(m['component_manifest']==manifest and m['control']==byname[name],'full operative mutant tree/witness')
        wrong=b''.join(decision_bytes(x['id'],oracle.native(x,name)) for x in rows)+expected[487*12:];need(wrong!=expected,'changed native decision');check(m['output_record'],wrong)
    for c in r['cargo']:need(r['records'][c['record']]['exit']==0 and b'test result: ok.' in channel(c['record'],'stdout'),'Cargo actual tests')
    malformed={'bad-magic':b'BAD!'+inputs[4:],'truncated':inputs[:-1],'trailing':inputs+b'x'};need(len(r['framing'])==3,'framing count')
    for p in r['framing']:check(p['record'],b'',malformed[p['name']],2)
    need(b'rustc 1.94.1' in channel(r['tools']['rustc']['record'],'stdout'),'compiler version')
    for rec in r['records']:
        need(rec['exit'] in [0,2],'failed recorded command');base64.b64decode(rec['stdout_b64'],validate=True);base64.b64decode(rec['stderr_b64'],validate=True)
    return {'source_freeze_sha256':sha(fr),'report_sha256':sha(rr),'archive_payload_sha256':sha(raw),'snapshot_files':len(files),'qualified_cases':487,'policy_cases':4,'baseline_builds':4,'commit_refusal_controls':7,'refusal_only_controls':2,'framing_controls':3,'commands':len(r['records']),'channels':2*len(r['records']),'captured_execution':False,'EnterCommit_is_not_success':True}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path);p.add_argument('--rust-bin',type=Path,default=RUST_DEFAULT);p.add_argument('--current-component',action='store_true');p.add_argument('--archive',type=Path,default=HERE/'compiled.json.gz.b64');args=p.parse_args()
    if args.build:build(args.build.resolve(),args.rust_bin.resolve())
    else:print(json.dumps(audit(args.archive,args.current_component),sort_keys=True))

"""Freeze/build the independent Rust cap, or replay retained synthetic receipts.

Default execution authenticates/replays archive only. --build compiles only new
Rust component/client copies, never captured target code. Expected answers are
external to the input-only client. CLI framing failures are client policy.
"""
from pathlib import Path
import argparse,base64,gzip,hashlib,importlib.util,json,os,shutil,struct,subprocess,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
COMPONENT=Path('src/node94-margin-risk')
RUST_DEFAULT=Path('/workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin')

def sha(b):return hashlib.sha256(b).hexdigest()
def need(ok,msg):
    if not ok:raise ValueError(msg)
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def variants(source):
    rules={
      'ignore-wide-overflow':('if wide_overflow || low > SIGNED_RANGE_MAX {','if low > SIGNED_RANGE_MAX {'),
      'positive-size-only':('signed_size.unsigned_abs()','if signed_size < 0 { 0 } else { signed_size as u64 }'),
      'min-magnitude-zero':('signed_size.unsigned_abs()','if signed_size == i64::MIN { 0 } else { signed_size.unsigned_abs() }'),
      'truncate-price32':('price_word.overflowing_mul(magnitude)','(price_word as u32 as u64).overflowing_mul(magnitude)'),
      'reject-high-unsigned-price':('let magnitude = signed_size.unsigned_abs();','if price_word > i64::MAX as u64 { return MAX_LEVERAGE; }\n    let magnitude = signed_size.unsigned_abs();'),
      'negative-cast-u64':('signed_size.unsigned_abs()','signed_size as u64'),
      'unbounded-first':('table.tiers().last()','table.tiers().first()'),
      'exclusive-upper':('select_tier(table, low).max_leverage()','table.tiers().iter().rev().find(|tier| tier.lower_bound() < low).map_or(MAX_LEVERAGE, |tier| tier.max_leverage())'),
      'first-eligible':('select_tier(table, low).max_leverage()','table.tiers().iter().find(|tier| tier.lower_bound() <= low).expect("zero lower").max_leverage()'),
      'default49':('return MAX_LEVERAGE;','return MAX_LEVERAGE - 1;'),
    }
    out={}
    for name,(old,new) in rules.items():
        need(source.count(old)==1,'mutation anchor '+name);out[name]=source.replace(old,new)
        if name=='first-eligible':
            # The pre-source wrong relation chooses the first member for both
            # finite and unbounded queries, so mutate both extraction sites.
            need(out[name].count('table.tiers().last()')==1,'first-member unbounded anchor')
            out[name]=out[name].replace('table.tiers().last()','table.tiers().first()')
    return out

def payload(folder,name):
    p=folder/name
    if p.is_file():return p.read_bytes()
    # Text packaging preserves the pre-Rust canonical raw payload digest.
    return base64.b64decode((folder/(name+'.b64')).read_bytes().rstrip(b'\n'),validate=True)

def corpus(folder):
    frozen=json.loads((folder/'PRE-RUST-FREEZE.json').read_text())
    for name,digest in frozen['payload_sha256'].items():need(sha(payload(folder,name))==digest,'pre-Rust '+name)
    oracle=load_module('tier_cap_frozen_oracle',folder/'oracle.py');rows=oracle.cases()
    need(len(rows)==frozen['case_count']==925,'case count')
    raw=payload(folder,'input.bin');need(raw[:4]==b'TCP1' and struct.unpack_from('<I',raw,4)[0]==len(rows),'input header')
    at=8;expected=bytearray()
    for r in rows:
        ident,n,p,s=struct.unpack_from('<IBQq',raw,at);at+=21
        entries=[]
        for _ in range(n):entries.append(struct.unpack_from('<QB',raw,at));at+=9
        need((ident,p,s,entries)==(r['id'],r['price_u64'],r['size_i64'],[tuple(t) for t in r['entries']]),'input recipe')
        # A second independent comparison expression using the full integer
        # product and sorted key rank, separate from the source's flags.
        if not entries:cap=50
        else:
            product=p*abs(s);eligible=[v for k,v in entries if product>((1<<63)-2) or k<=product];cap=eligible[-1] if eligible else 50
        need(cap==r['cap'],'external answer');expected+=struct.pack('<IB',ident,cap)
    need(at==len(raw) and bytes(expected)==payload(folder,'expected.bin'),'complete external streams')
    controls=json.loads((folder/'wrong-cap-controls.json').read_text())
    need(len(controls)==10,'control count')
    for c in controls:
        wrong=[oracle.wrong(r['entries'],r['price_u64'],r['size_i64'],c['name']) for r in rows]
        changed=[i for i,(r,w) in enumerate(zip(rows,wrong)) if r['cap']!=w]
        need(len(changed)==c['changed_cap_cases'] and changed[0]==c['witness']['id'],'wrong-cap witnesses')
    return rows,raw,bytes(expected),controls,oracle

def snapshot_payloads():
    paths=sorted(p for p in (ROOT/COMPONENT).rglob('*') if p.is_file() and 'target' not in p.parts and '__pycache__' not in p.parts)
    need(not any(p.name=='build.rs' or '.cargo' in p.parts for p in paths),'unexpected build hooks')
    paths += [ROOT/'research/work-items/RE-007-margin-path-94/boundaries.tsv',HERE/'driver.rs',HERE/'verify.py',HERE/'native.py']+sorted(p for p in (HERE/'pre-source').iterdir() if p.is_file())
    return {str(p.relative_to(ROOT)):p.read_bytes() for p in paths}

def prepare(out):
    need(not out.exists(),'refuse existing output tree')
    rows,_,_,_,_=corpus(HERE/'pre-source');payloads=snapshot_payloads()
    snap=out/'snapshot';snap.mkdir(parents=True)
    for name,b in payloads.items():p=snap/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
    freeze={'component':str(COMPONENT),'target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','pre_rust_freeze_sha256':sha((HERE/'pre-source/PRE-RUST-FREEZE.json').read_bytes()),'files':{n:sha(b) for n,b in sorted(payloads.items())},'cases':len(rows),'source_written_after_pre_rust_freeze':True}
    (out/'SOURCE-FREEZE.json').write_text(json.dumps(freeze,sort_keys=True,indent=2)+'\n')
    return freeze

def run_build(out,rust_bin):
    started=time.time();freeze=prepare(out);snap=out/'snapshot';frozen_here=snap/HERE.relative_to(ROOT)
    active_component=None
    rows,inputs,expected,controls,oracle=corpus(frozen_here/'pre-source');source=(snap/COMPONENT/'src/tier_cap.rs').read_text();mutants=variants(source)
    def guard():
        for name,digest in freeze['files'].items():
            need(sha((snap/name).read_bytes())==digest,'snapshot changed '+name)
            need(sha((ROOT/name).read_bytes())==digest,'live source changed '+name)
        if active_component is not None:
            comp,manifest=active_component
            actual={str(p.relative_to(comp)):sha(p.read_bytes()) for p in sorted(comp.rglob('*')) if p.is_file()}
            need(actual==manifest,'active mutant compiler inputs changed')
        need(payload(frozen_here/'pre-source','input.bin')==inputs and payload(frozen_here/'pre-source','expected.bin')==expected,'guarded comparison streams')
    env=os.environ.copy()
    for key in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTDOCFLAGS','RUSTUP_TOOLCHAIN']:
        env.pop(key,None)
    env.update(RUSTC=str(rust_bin/'rustc'),RUSTDOC=str(rust_bin/'rustdoc'),CARGO_HOME=str(out/'cargo-home'),CARGO_NET_OFFLINE='true')
    records=[]
    def command(argv,*,stdin=b'',cwd=None,code=0,check=None):
        guard();t=time.time();p=subprocess.run([str(a) for a in argv],input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=cwd,env=env)
        rec={'argv':[str(a) for a in argv],'cwd':str(cwd) if cwd else None,'exit':p.returncode,'stdin_sha256':sha(stdin),'stdout_b64':base64.b64encode(p.stdout).decode(),'stderr_b64':base64.b64encode(p.stderr).decode(),'elapsed_seconds':round(time.time()-t,6)};records.append(rec)
        with (out/'records.jsonl').open('a') as journal:journal.write(json.dumps(rec,sort_keys=True)+'\n')
        guard();need(p.returncode==code,'command exit '+str(argv))
        if check is not None:need(p.stdout==check,'external complete output '+str(argv))
        return len(records)-1
    tools={}
    for name in ['rustc','cargo','rustdoc']:
        exe=rust_bin/name;idx=command([exe,'--version','--verbose'] if name=='rustc' else [exe,'--version']);tools[name]={'path':str(exe),'sha256':sha(exe.read_bytes()),'command':idx}
    need(b'rustc 1.94.1' in base64.b64decode(records[tools['rustc']['command']]['stdout_b64']),'pinned compiler')
    baseline=[]
    def compile_client(comp,dest,opt):
        dest.mkdir(parents=True,exist_ok=True);rlib=dest/'libnode94_margin_risk.rlib';client=dest/'client'
        command([rust_bin/'rustc','--edition=2024','--crate-name','node94_margin_risk','--crate-type','rlib','-C',f'opt-level={opt}',comp/'src/lib.rs','-o',rlib],cwd=comp)
        command([rust_bin/'rustc','--edition=2024','-C',f'opt-level={opt}',frozen_here/'driver.rs','--extern',f'node94_margin_risk={rlib}','-o',client],cwd=comp)
        return client,{'rlib_sha256':sha(rlib.read_bytes()),'client_sha256':sha(client.read_bytes())}
    for opt in [0,3]:
        for repeat in [1,2]:
            client,binaries=compile_client(snap/COMPONENT,out/f'baseline-o{opt}-{repeat}',opt);idx=command([client],stdin=inputs,check=expected)
            baseline.append({'opt_level':opt,'repeat':repeat,'output_record':idx,**binaries})
    cargo=[]
    for release in [False,True]:
        argv=[rust_bin/'cargo','test','--frozen','--offline','--manifest-path',snap/COMPONENT/'Cargo.toml','--target-dir',out/'cargo-target']+(['--release'] if release else [])
        cargo.append({'profile':'release' if release else 'debug','record':command(argv,cwd=snap/COMPONENT)})
    mutations=[]
    for c in controls:
        name=c['name'];comp=out/'mutant-component';shutil.copytree(snap/COMPONENT,comp)
        (comp/'src/tier_cap.rs').write_text(mutants[name]);manifest={str(p.relative_to(comp)):sha(p.read_bytes()) for p in sorted(comp.rglob('*')) if p.is_file()}
        active_component=(comp,manifest)
        client,binaries=compile_client(comp,out/'mutant-build',3)
        wrong=b''.join(struct.pack('<IB',r['id'],oracle.wrong(r['entries'],r['price_u64'],r['size_i64'],name)) for r in rows)
        idx=command([client],stdin=inputs,check=wrong);need(wrong!=expected,'operative mutant')
        mutations.append({'name':name,'output_record':idx,'changed_cap_cases':c['changed_cap_cases'],'witness':c['witness'],'component_manifest':manifest,**binaries})
        active_component=None
        shutil.rmtree(comp);shutil.rmtree(out/'mutant-build')
    policy=[];client=out/'baseline-o3-2/client'
    for name,data in [('bad-magic',b'BAD!'+inputs[4:]),('truncated',inputs[:-1]),('trailing',inputs+b'x')]:
        idx=command([client],stdin=data,code=2,check=b'');policy.append({'name':name,'record':idx,'class':'client framing policy, excluded from native cap denominator'})
    guard();report={'source_freeze_sha256':sha((out/'SOURCE-FREEZE.json').read_bytes()),'case_count':len(rows),'tools':tools,'baseline':baseline,'cargo':cargo,'mutants':mutations,'framing_policy':policy,'records':records,'environment':{'RUSTC':env['RUSTC'],'RUSTDOC':env['RUSTDOC'],'CARGO_HOME':env['CARGO_HOME'],'CARGO_NET_OFFLINE':'true','removed_flags':['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTDOCFLAGS','RUSTUP_TOOLCHAIN']},'elapsed_seconds':round(time.time()-started,6),'captured_execution':False}
    (out/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    # Preserve compiler inputs and every actual stdout/stderr stream. Executable
    # hashes are receipts only; original binaries are never used as reconstruction.
    archive={'SOURCE-FREEZE.json':base64.b64encode((out/'SOURCE-FREEZE.json').read_bytes()).decode(),'REPORT.json':base64.b64encode((out/'REPORT.json').read_bytes()).decode(),'snapshot':{n:base64.b64encode((snap/n).read_bytes()).decode() for n in freeze['files']}}
    raw=(json.dumps(archive,sort_keys=True,separators=(',',':'))+'\n').encode();encoded=base64.b64encode(gzip.compress(raw,mtime=0))
    (out/'compiled.json.gz.b64').write_bytes(encoded+b'\n')
    print(json.dumps({'output':str(out),'source_freeze_sha256':report['source_freeze_sha256'],'report_sha256':sha((out/'REPORT.json').read_bytes()),'archive_payload_sha256':sha(raw),'archive_text_sha256':sha(encoded+b'\n'),'commands':len(records),'cases_per_baseline':len(rows),'native_normal_result_mutants':len(mutations),'framing_policy':len(policy),'seconds':report['elapsed_seconds']},sort_keys=True))
    return report

def audit(archive_path,current=True,current_component=False):
    # Strict base64 and compressed trailing-data rejection.
    import zlib
    encoded=archive_path.read_bytes();compressed=base64.b64decode(encoded.rstrip(b'\n'),validate=True);d=zlib.decompressobj(16+zlib.MAX_WBITS);payload=d.decompress(compressed)+d.flush();need(d.eof and not d.unused_data and not d.unconsumed_tail,'gzip framing')
    archive=json.loads(payload);freeze_raw=base64.b64decode(archive['SOURCE-FREEZE.json'],validate=True);report_raw=base64.b64decode(archive['REPORT.json'],validate=True);freeze=json.loads(freeze_raw);report=json.loads(report_raw)
    need(sha(freeze_raw)==report['source_freeze_sha256'],'report/freeze binding')
    files={n:base64.b64decode(b,validate=True) for n,b in archive['snapshot'].items()};need(set(files)==set(freeze['files']),'snapshot file set')
    for n,b in files.items():
        need(sha(b)==freeze['files'][n],'snapshot '+n)
        # The historical lib export surface and this evolving replay auditor
        # are current support files, not refreshed original compiler inputs.
        if current and n not in {str(COMPONENT/'src/lib.rs'),str(HERE.relative_to(ROOT)/'verify.py')}:
            need((ROOT/n).read_bytes()==b,'current source/input '+n)
    if current:
        need('pub use tier_cap::position_leverage_cap;' in (ROOT/COMPONENT/'src/lib.rs').read_text(),'public tier-cap export missing')
    if current_component:
        actual={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted((ROOT/COMPONENT).rglob('*')) if p.is_file() and 'target' not in p.parts and '__pycache__' not in p.parts}
        wanted={n:d for n,d in freeze['files'].items() if n.startswith(str(COMPONENT)+'/')}
        need(actual==wanted,'current component differs from historical compiler tree')
    pre=HERE/'pre-source';rows,inputs,expected,controls,oracle=corpus(pre)
    def channel(idx,kind):return base64.b64decode(report['records'][idx][kind+'_b64'],validate=True)
    def output(idx,want,code=0,stdin=inputs):
        r=report['records'][idx];need(r['exit']==code and r['stdin_sha256']==sha(stdin) and channel(idx,'stdout')==want,'actual output record')
    need(report['case_count']==len(rows) and len(report['baseline'])==4 and len(report['mutants'])==10,'compiled denominators')
    for b in report['baseline']:output(b['output_record'],expected)
    need([(b['opt_level'],b['repeat']) for b in report['baseline']]==[(0,1),(0,2),(3,1),(3,2)],'build variants')
    source=files[str(COMPONENT/'src/tier_cap.rs')].decode();mutants=variants(source)
    base={n[len(str(COMPONENT))+1:]:digest for n,digest in freeze['files'].items() if n.startswith(str(COMPONENT)+'/')}
    need({m['name'] for m in report['mutants']}==set(mutants),'mutant set')
    byname={c['name']:c for c in controls}
    for m in report['mutants']:
        name=m['name'];manifest=dict(base);manifest['src/tier_cap.rs']=sha(mutants[name].encode());need(m['component_manifest']==manifest,'full derived mutant compiler-input tree')
        wrong=b''.join(struct.pack('<IB',r['id'],oracle.wrong(r['entries'],r['price_u64'],r['size_i64'],name)) for r in rows)
        output(m['output_record'],wrong);need(wrong!=expected and m['changed_cap_cases']==byname[name]['changed_cap_cases'] and m['witness']==byname[name]['witness'],'normal mutant witness')
    for entry in report['cargo']:
        need(report['records'][entry['record']]['exit']==0,'Cargo exit');need(b'test result: ok.' in channel(entry['record'],'stdout'),'actual Cargo test result')
    policy_inputs={'bad-magic':b'BAD!'+inputs[4:],'truncated':inputs[:-1],'trailing':inputs+b'x'}
    need(len(report['framing_policy'])==3,'framing count')
    for p in report['framing_policy']:output(p['record'],b'',2,policy_inputs[p['name']])
    need(b'rustc 1.94.1' in channel(report['tools']['rustc']['command'],'stdout'),'compiler version receipt')
    for r in report['records']:
        need(r['exit'] in [0,2],'recorded command failure')
        base64.b64decode(r['stdout_b64'],validate=True);base64.b64decode(r['stderr_b64'],validate=True)
    return {'source_freeze_sha256':sha(freeze_raw),'report_sha256':sha(report_raw),'archive_payload_sha256':sha(payload),'snapshot_files':len(files),'cases_per_baseline':len(rows),'baseline_builds':4,'normal_cap_mutants':10,'framing_policy_controls':3,'commands':len(report['records']),'raw_channels':2*len(report['records']),'captured_execution':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--current-component',action='store_true');parser.add_argument('--build',type=Path);parser.add_argument('--rust-bin',type=Path,default=RUST_DEFAULT);parser.add_argument('--archive',type=Path,default=HERE/'compiled.json.gz.b64');args=parser.parse_args()
    if args.build:run_build(args.build.resolve(),args.rust_bin.resolve())
    else:print(json.dumps(audit(args.archive,current_component=args.current_component),sort_keys=True))

"""Replay immutable compiler evidence with explicit durable source relocation.
No compilation or captured node execution occurs here.
"""
from pathlib import Path
import base64,hashlib,importlib.util,json,posixpath,re,zlib
from pathlib import PurePosixPath
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];PRE=HERE/'pre-source'
COMPONENT=Path('src/node94-margin-risk');FLOOR=300*1024**2
spec=importlib.util.spec_from_file_location('frozen_decrease_builder',HERE/'preparation/verify.py')
frozen=importlib.util.module_from_spec(spec);spec.loader.exec_module(frozen)
need=frozen.need;sha=frozen.sha;decision=frozen.decision;variants=frozen.variants;component_files=frozen.component_files

def source_path(name):
    if name.startswith('work/isolated-decrease/rust/'):
        return HERE/'preparation'/name.removeprefix('work/isolated-decrease/rust/')
    if name.startswith('work/isolated-decrease/'):
        return PRE/name.removeprefix('work/isolated-decrease/')
    return ROOT/name

def corpus(folder,wire):return frozen.corpus(folder,HERE/'preparation')
def compiler_reads(report,freeze,report_raw):
    receipt=json.loads((HERE/'COMPILER-READS.json').read_text())
    need(receipt['source_freeze_sha256']==report['source_freeze_sha256'] and receipt['report_sha256']==sha(report_raw),'dep-info receipt binding')
    need(receipt['dep_info_records']==report['cargo_dep_info'] and len(report['cargo_dep_info'])==20,'actual20 dependency records')
    cwd=PurePosixPath(next(r for r in report['records'] if '--crate-type' in r['argv'])['cwd']);snapshot=cwd.parents[1];found={};byprofile={'debug':{},'release':{}};counts={'debug':0,'release':0}
    for record in report['cargo_dep_info']:
        raw=base64.b64decode(record['raw_base64'],validate=True);need(sha(raw)==record['sha256'] and raw,'nonempty dependency bytes');profile=record['profile'];need(profile in byprofile and record['path'].startswith(profile+'/'),'dependency profile');counts[profile]+=1
        for line in raw.decode().splitlines():
            if ': ' not in line:continue
            for token in line.split(': ',1)[1].split():
                p=PurePosixPath(token);name=str(p.relative_to(snapshot)) if p.is_absolute() else posixpath.normpath(str(COMPONENT)+'/'+token)
                need(name in freeze['files'],'unfrozen actual compiler input '+name);found[name]=freeze['files'][name];byprofile[profile][name]=freeze['files'][name]
    need(found==receipt['project_compiler_inputs'] and len(found)==23,'exact23 project compiler inputs')
    need(counts=={'debug':10,'release':10} and all(v==found for v in byprofile.values()),'per-profile exact project read closure')
    return len(found)
def roles(report):
    records=report['records'];need(len(records)==48,'actual48 command positions')
    need(set(report['tools'])=={'rustc','cargo','rustdoc'},'three compiler tools')
    for i,name in enumerate(['rustc','cargo','rustdoc']):
        tool=report['tools'][name];need(tool['record']==i and records[i]['argv']==[tool['path'],'--version']+(['--verbose'] if name=='rustc' else []),'tool command position')
    compiler=report['tools']['rustc']['path']
    def builds(lib,client,opt):
        a=records[lib]['argv'];b=records[client]['argv'];need(a[0]==compiler and b[0]==compiler and '--crate-type' in a and a[a.index('--crate-type')+1]=='rlib' and f'opt-level={opt}' in a and f'opt-level={opt}' in b and '--extern' in b,'library/client compiler roles')
        need(a[-3].endswith('/src/node94-margin-risk/src/lib.rs') or a[-3].endswith('/mutant-component/src/lib.rs'),'library input position');need(b[b.index('--extern')-1].endswith('/work/isolated-decrease/rust/driver.rs'),'input-only driver compiler role')
    for i,b in enumerate(report['baseline']):
        q=5+4*i;p=q+1;need(b['qualified_record']==q and b['policy_record']==p,'baseline command positions');builds(q-2,q-1,b['opt']);need(records[q]['argv']==records[p]['argv']==[records[q-1]['argv'][-1]],'baseline client run positions')
    for i,c in enumerate(report['cargo']):
        at=19+i;need(c['record']==at and records[at]['argv'][0]==report['tools']['cargo']['path'] and records[at]['argv'][1:4]==['test','--frozen','--offline'],'Cargo command positions')
    for i,m in enumerate(report['mutants']):
        at=23+3*i;need(m['output_record']==at,'mutant command position');builds(at-2,at-1,3);need(records[at]['argv']==[records[at-1]['argv'][-1]],'mutant client run position')
    for i,c in enumerate(report['framing']):need(c['record']==45+i and records[45+i]['argv']==records[18]['argv'],'framing client positions')
    for i,record in enumerate(records):need(record['exit']==(2 if i>=45 else 0),'exit belongs to exact compiler/run/framing role')
def audit(path,current=True):
    b=base64.b64decode(path.read_bytes().rstrip(b'\n'),validate=True);z=zlib.decompressobj(16+zlib.MAX_WBITS);raw=z.decompress(b)+z.flush();need(z.eof and not z.unused_data and not z.unconsumed_tail,'strict gzip');a=json.loads(raw);fr=base64.b64decode(a['SOURCE-FREEZE.json'],validate=True);rr=base64.b64decode(a['REPORT.json'],validate=True);f=json.loads(fr);r=json.loads(rr);need(sha(fr)==r['source_freeze_sha256'],'report freeze pin');files={n:base64.b64decode(v,validate=True) for n,v in a['snapshot'].items()};need({n:sha(b) for n,b in files.items()}==f['files'],'full snapshot pins')
    if current:
        for n,b in files.items():need(source_path(n).read_bytes()==b,'exact current source/input '+n)
        want={n[len(str(COMPONENT))+1:]:b for n,b in files.items() if n.startswith(str(COMPONENT)+'/')};need(component_files(ROOT/COMPONENT)==want,'exact current component membership')
    need(json.loads((HERE/'SOURCE-PATHS.json').read_text())=={n:str(source_path(n).relative_to(ROOT)) for n in f['files']},'explicit receipt source relocation');roles(r);rows,controls,oracle,streams=corpus(PRE,HERE)
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
    project_inputs=compiler_reads(r,f,rr)
    need(b'rustc 1.94.1' in channel(r['tools']['rustc']['record'],'stdout'),'compiler version')
    for rec in r['records']:need(rec['exit'] in [0,2] and rec['free_after_bytes']>=FLOOR,'actual exit/resource floor');base64.b64decode(rec['stdout_b64'],validate=True);base64.b64decode(rec['stderr_b64'],validate=True)
    need(len(r['records'])==48,'actual command denominator')
    return {'source_freeze_sha256':sha(fr),'report_sha256':sha(rr),'archive_payload_sha256':sha(raw),'snapshot_files':len(files),'qualified_cases':341,'policy_cases':9,'baseline_builds':4,'commit_refusal_controls':7,'refusal_only_controls':1,'framing_controls':3,'cargo_tests_per_profile':counts,'dep_info_records':len(r['cargo_dep_info']),'project_compiler_inputs':project_inputs,'commands':len(r['records']),'channels':2*len(r['records']),'captured_execution':False,'EnterCommit_is_not_success':True}
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,default=HERE/'compiled.json.gz.b64');a=p.parse_args();print(json.dumps(audit(a.archive),sort_keys=True))

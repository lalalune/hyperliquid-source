#!/usr/bin/env python3
"""Compile only independently authored Rust; compare to pre-Rust frozen math."""
from pathlib import Path
import gzip,hashlib,importlib.util,json,shutil,subprocess,sys
P=Path(__file__).resolve().parent; R=P.parents[2]; C=R/'src/node115-bulk-record-decoder'; W=R/'work/environment/next-ten/bulk-record/qualification'
def sha(b):return hashlib.sha256(b).hexdigest()
def need(x,m):
 if not x:raise ValueError(m)
def run(name,args,**kwargs):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs)
 (W/(name+'.stdout')).write_bytes(p.stdout);(W/(name+'.stderr')).write_bytes(p.stderr)
 need(p.returncode==0,name+' failed');return p.stdout
if __name__=='__main__':
 W.mkdir(parents=True,exist_ok=True)
 freeze=json.loads((P/'freeze.json').read_text());fixture=gzip.decompress(bytes.fromhex((P/'cases.tsv.gz.hex').read_text()))
 need(freeze['new_rust_exists_at_freeze'] is False,'missing historical pre-Rust freeze')
 need(sha(fixture)==freeze['sha256'],'fixture drift')
 need(sha((P/'oracle.py').read_bytes())==freeze['oracle_sha256'],'oracle drift')
 spec=importlib.util.spec_from_file_location('oracle',P/'oracle.py');oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
 need(oracle.render()==fixture,'independent relation drift')
 rows=fixture.splitlines();inputs=b'\n'.join(b'\t'.join(x.split(b'\t')[:6]) for x in rows)+b'\n';expected=b'\n'.join(x.split(b'\t')[6] for x in rows)+b'\n'
 results=[]
 for profile in ['debug','release']:
  args=['cargo','+1.95.0','build','--offline','--locked','--manifest-path',str(C/'Cargo.toml')]
  if profile=='release':args+=['--release']
  run('build-'+profile,args,cwd=R)
  actual=run('production-'+profile,[str(C/'target'/profile/'bulk-record-probe')],input=inputs)
  need(actual==expected,'production '+profile+' mismatch')
  results.append({'profile':profile,'matched':len(rows),'stdout_sha256':sha(actual)})
 source=(C/'src/lib.rs').read_text()
 mutants=[
 ('wrong-field1','expected_raw: 5','expected_raw: 2'),
 ('charge-2047','charged.checked_add(2048)','charged.checked_add(2047)'),
 ('rollback-refused-charge','charged = next;','if next <= limit { charged = next; }'),
 ('reject-equal-limit','if next > limit {','if next >= limit {'),
 ('consume-short-payload','additional: (2048 - remaining.len()) as u64,\n            }),\n            remaining,','additional: (2048 - remaining.len()) as u64,\n            }),\n            remaining: &remaining[remaining.len()..],'),
 ('reverse-payload','bytes.copy_from_slice(&remaining[..2048]);','bytes.copy_from_slice(&remaining[..2048]); bytes.reverse();'),
 ('swap-scalars','Record { bytes, fields }','Record { bytes, fields: [fields[1], fields[0]] }'),
 ('consume-2047-on-success','remaining: &remaining[2048..]','remaining: &remaining[2047..]'),
 ]
 controls=[]
 for name,old,new in mutants:
  need(old in source,'mutant selector '+name)
  dest=W/name
  if dest.exists():shutil.rmtree(dest)
  (dest/'src').mkdir(parents=True)
  for f in ['Cargo.toml','Cargo.lock','src/probe.rs']:shutil.copyfile(C/f,dest/f)
  (dest/'src/lib.rs').write_text(source.replace(old,new))
  manifest=(dest/'Cargo.toml').read_text().replace('../node115-u64-reader-state',str(R/'src/node115-u64-reader-state'))
  (dest/'Cargo.toml').write_text(manifest)
  run(name+'-build',['cargo','+1.95.0','build','--release','--offline','--locked','--manifest-path',str(dest/'Cargo.toml')],cwd=R)
  p=subprocess.run([str(dest/'target/release/bulk-record-probe')],input=inputs,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  (W/(name+'.stdout')).write_bytes(p.stdout);(W/(name+'.stderr')).write_bytes(p.stderr)
  need(p.returncode!=0 or p.stdout!=expected,'compiled mutant survived '+name)
  mismatch=next((i for i,(a,b) in enumerate(zip(p.stdout.splitlines(),expected.splitlines())) if a!=b),None)
  controls.append({'name':name,'compiled':True,'exit':p.returncode,'first_mismatch_0based':mismatch,'mutant_source_sha256':sha((dest/'src/lib.rs').read_bytes()),'rejected':True})
 result={'target_sha256':freeze['target_sha256'],'fixture_sha256':sha(fixture),'case_count':len(rows),'profiles':results,'compiled_mutants':controls,'source_sha256':{str(f.relative_to(R)):sha(f.read_bytes()) for f in [C/'Cargo.toml',C/'Cargo.lock',C/'src/lib.rs',C/'src/probe.rs',R/'src/node115-u64-reader-state/Cargo.toml',R/'src/node115-u64-reader-state/lib.rs']},'capture_execution_or_emulation':False,'limits':'Complete safe logical bulk record only; exact native output/error ABI and field units remain unclosed. Genuine base Reader reused with explicitly proven field1 metadata projection.'}
 (P/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

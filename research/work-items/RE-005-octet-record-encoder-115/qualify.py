#!/usr/bin/env python3
"""Compile only independently authored Rust; compare to pre-Rust frozen math."""
from pathlib import Path
import gzip,hashlib,importlib.util,json,shutil,subprocess,sys
P=Path(__file__).resolve().parent; R=P.parents[2]; C=R/'src/node115-octet-record-encoder'; W=R/'work/environment/eight-batch/octet-record/qualification'
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
 rows=fixture.splitlines();inputs=b'\n'.join(b'\t'.join(x.split(b'\t')[:7]) for x in rows)+b'\n';expected=b'\n'.join(x.split(b'\t')[7] for x in rows)+b'\n'
 results=[]
 for profile in ['debug','release']:
  args=['cargo','+1.95.0','build','--offline','--locked','--manifest-path',str(C/'Cargo.toml')]
  if profile=='release':args+=['--release']
  run('build-'+profile,args,cwd=R)
  actual=run('production-'+profile,[str(C/'target'/profile/'octet-record-probe')],input=inputs)
  need(actual==expected,'production '+profile+' mismatch')
  results.append({'profile':profile,'matched':len(rows),'stdout_sha256':sha(actual)})
 source=(C/'src/lib.rs').read_text()
 mutants=[
 ('reverse-size-field-order','record.words.iter().enumerate()','record.words.iter().rev().enumerate()'),
 ('skip-eighth-field-size','record.words.iter().enumerate()','record.words[..7].iter().enumerate()'),
 ('reverse-wire-field-order','scalar::write_u64(vector, *value)','scalar::write_u64(vector, record.words[7-index])'),
 ('normalize-trailer-as-bool','vector.push(record.trailer);','vector.push(u8::from(record.trailer != 0));'),
 ('put-trailer-before-record','vector.push(record.trailer);','vector.insert(0, record.trailer);'),
 ('omit-trailer-count','counter.checked_add(1)','counter.checked_add(0)'),
 ('rollback-byte-on-field-error','.map_err(|stage| WriteBoundary::Field { index, stage })?;','.map_err(|stage| {vector.pop(); WriteBoundary::Field { index, stage }})?;'),
 ('preflight-size-all-at-once','for (index, value) in record.words.iter().enumerate() {','let need=1_u64+record.words.iter().map(|v|if *v<251 {1} else if *v<65536 {3} else if *v<(1_u64<<32) {5} else {9}).sum::<u64>(); if let Some(next)=counter.checked_add(need){*counter=next;return Ok(());}else{return Err(SizeBoundary::Field(0));}\n    for (index, value) in record.words.iter().enumerate() {'),
 ]
 controls=[]
 for name,old,new in mutants:
  need(old in source,'mutant selector '+name)
  dest=W/name
  if dest.exists():shutil.rmtree(dest)
  (dest/'src').mkdir(parents=True)
  for f in ['Cargo.toml','Cargo.lock','src/probe.rs']:shutil.copyfile(C/f,dest/f)
  (dest/'src/lib.rs').write_text(source.replace(old,new,1))
  shutil.copytree(C/'scalar',dest/'scalar')
  (dest/'counter').mkdir()
  (dest/'counter/Cargo.toml').write_text((C/'counter/Cargo.toml').read_text().replace('../../node115-varint-size-state/lib.rs',str(R/'src/node115-varint-size-state/lib.rs')))
  run(name+'-build',['cargo','+1.95.0','build','--release','--offline','--locked','--manifest-path',str(dest/'Cargo.toml')],cwd=R)
  p=subprocess.run([str(dest/'target/release/octet-record-probe')],input=inputs,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  (W/(name+'.stdout')).write_bytes(p.stdout);(W/(name+'.stderr')).write_bytes(p.stderr)
  need(p.returncode!=0 or p.stdout!=expected,'compiled mutant survived '+name)
  mismatch=next((i for i,(a,b) in enumerate(zip(p.stdout.splitlines(),expected.splitlines())) if a!=b),None)
  controls.append({'name':name,'compiled':True,'exit':p.returncode,'first_mismatch_0based':mismatch,'mutant_source_sha256':sha((dest/'src/lib.rs').read_bytes()),'rejected':True})
 result={'target_sha256':freeze['target_sha256'],'fixture_sha256':sha(fixture),'case_count':len(rows),'profiles':results,'compiled_mutants':controls,'source_sha256':{str(f.relative_to(R)):sha(f.read_bytes()) for f in [C/'Cargo.toml',C/'Cargo.lock',C/'src/lib.rs',C/'src/probe.rs',C/'scalar/lib.rs',C/'scalar/Cargo.toml',C/'scalar/PROVENANCE.json',C/'scalar/LICENSE',C/'counter/Cargo.toml',R/'src/node115-varint-size-state/lib.rs']},'capture_execution_or_emulation':False,'limits':'Complete logical eight-word/raw-byte type size/wire relation. Existing scalar/counter primitives reused without new credit; native output/panic ABI, source pointer ownership and application field meaning remain open.'}
 (P/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

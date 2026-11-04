#!/usr/bin/env python3
"""Compile only independently authored Rust; compare to pre-Rust frozen math."""
from pathlib import Path
import gzip,hashlib,importlib.util,json,shutil,subprocess,sys
P=Path(__file__).resolve().parent; R=P.parents[2]; C=R/'src/node115-varint-buffer-writer'; W=R/'work/environment/next-ten/varint-buffer-writer/qualification'
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
 rows=fixture.splitlines();inputs=b'\n'.join(b'\t'.join(x.split(b'\t')[:5]) for x in rows)+b'\n';expected=b'\n'.join(x.split(b'\t')[5] for x in rows)+b'\n'
 results=[]
 for profile in ['debug','release']:
  args=['cargo','+1.95.0','build','--offline','--locked','--manifest-path',str(C/'Cargo.toml')]
  if profile=='release':args+=['--release']
  run('build-'+profile,args,cwd=R)
  actual=run('production-'+profile,[str(C/'target'/profile/'varint-buffer-probe')],input=inputs)
  need(actual==expected,'production '+profile+' mismatch')
  results.append({'profile':profile,'matched':len(rows),'stdout_sha256':sha(actual)})
 source=(C/'src/lib.rs').read_text()
 mutants=[
 ('inline-threshold250','value < 251','value < 250'),
 ('u16-threshold65535','value < 65_536','value < 65_535'),
 ('u32-threshold-max-not-next','value < (1_u64 << 32)','value < ((1_u64 << 32) - 1)'),
 ('payload-big-endian','value.to_le_bytes()','value.to_be_bytes()'),
 ('wrong-u16-marker','(251, 2)','(252, 2)'),
 ('exact-not-amortized-growth','vector.try_reserve(additional)','vector.try_reserve_exact(additional)'),
 ('preflight-entire-encoding','reserve(vector, 1, Error::PrefixGrowth)?;\n    vector.push(marker);','reserve(vector, width + 1, Error::PrefixGrowth)?;\n    vector.push(marker);'),
 ('rollback-marker-on-payload-growth-error','reserve(vector, width, Error::PayloadGrowth)?;','if let Err(error)=reserve(vector, width, Error::PayloadGrowth) { vector.pop(); return Err(error); }'),
 ('piecemeal-payload','reserve(vector, width, Error::PayloadGrowth)?;\n    vector.extend_from_slice(&value.to_le_bytes()[..width]);','for byte in &value.to_le_bytes()[..width] { reserve(vector, 1, Error::PayloadGrowth)?; vector.push(*byte); }'),
 ]
 controls=[]
 for name,old,new in mutants:
  need(old in source,'mutant selector '+name)
  dest=W/name
  if dest.exists():shutil.rmtree(dest)
  (dest/'src').mkdir(parents=True)
  for f in ['Cargo.toml','Cargo.lock','src/probe.rs']:shutil.copyfile(C/f,dest/f)
  (dest/'src/lib.rs').write_text(source.replace(old,new))
  run(name+'-build',['cargo','+1.95.0','build','--release','--offline','--locked','--manifest-path',str(dest/'Cargo.toml')],cwd=R)
  p=subprocess.run([str(dest/'target/release/varint-buffer-probe')],input=inputs,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  (W/(name+'.stdout')).write_bytes(p.stdout);(W/(name+'.stderr')).write_bytes(p.stderr)
  need(p.returncode!=0 or p.stdout!=expected,'compiled mutant survived '+name)
  mismatch=next((i for i,(a,b) in enumerate(zip(p.stdout.splitlines(),expected.splitlines())) if a!=b),None)
  controls.append({'name':name,'compiled':True,'exit':p.returncode,'first_mismatch_0based':mismatch,'mutant_source_sha256':sha((dest/'src/lib.rs').read_bytes()),'rejected':True})
 result={'target_sha256':freeze['target_sha256'],'fixture_sha256':sha(fixture),'case_count':len(rows),'profiles':results,'compiled_mutants':controls,'source_sha256':{str(f.relative_to(R)):sha(f.read_bytes()) for f in [C/'Cargo.toml',C/'Cargo.lock',C/'src/lib.rs',C/'src/probe.rs']},'capture_execution_or_emulation':False,'limits':'Complete unsigned64 varint writer logical bytes/capacity/growth boundaries using actual alloc::Vec. Allocation-failure controls execute only independently authored Rust via real System-backed GlobalAlloc. Original allocator ABI, native fatal/panic continuation and application schema remain unclosed.'}
 (P/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

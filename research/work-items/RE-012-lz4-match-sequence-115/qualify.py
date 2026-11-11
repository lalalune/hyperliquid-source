#!/usr/bin/env python3
"""Compile only independently authored Rust; compare to pre-Rust frozen math."""
from pathlib import Path
import hashlib,importlib.util,json,shutil,subprocess,sys
P=Path(__file__).resolve().parent; R=P.parents[2]; C=R/'src/node115-lz4-match-sequence'; W=R/'work/environment/next-ten/match-sequence/qualification'
def sha(b):return hashlib.sha256(b).hexdigest()
def need(x,m):
 if not x:raise ValueError(m)
def run(name,args,**kwargs):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs)
 (W/(name+'.stdout')).write_bytes(p.stdout);(W/(name+'.stderr')).write_bytes(p.stderr)
 need(p.returncode==0,name+' failed');return p.stdout
if __name__=='__main__':
 W.mkdir(parents=True,exist_ok=True)
 freeze=json.loads((P/'freeze.json').read_text());fixture=(P/'cases.tsv').read_bytes()
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
  actual=run('production-'+profile,[str(C/'target'/profile/'match-sequence-probe')],input=inputs)
  need(actual==expected,'production '+profile+' mismatch')
  results.append({'profile':profile,'matched':len(rows),'stdout_sha256':sha(actual)})
 # Arithmetic proof obligations for scalar reduction of native grouped FF stores.
 reciprocal=0x8080808080808081
 need(reciprocal*255==(1<<71)+127,'reciprocal identity')
 need(((1<<64)-1)*127 < (1<<71),'reciprocal strict error bound')
 for quotient in range(514):
  for free in range(514):
   grouped=4*(min(quotient-1,free)//4) if quotient else 0
   need(0<=grouped<=min(quotient,free),'grouped store bounds')
   need(grouped+min(quotient-grouped,free-grouped)==min(quotient,free),'partial prefix equality')
 source=(C/'src/lib.rs').read_text()
 mutants=[
 ('literal-nibble-low','(literals.len().min(15) as u8) << 4','(literals.len().min(15) as u8) << 0'),
 ('match-count-includes-initial-four','additional_match.min(15)','additional_match.saturating_add(4).min(15)'),
 ('offset-big-endian','distance.to_le_bytes()','distance.to_be_bytes()'),
 ('omit-required-zero','// Including zero when the amount is an exact multiple of 255.','if remaining == 0 { return Ok(()); }'),
 ('skip-match-fifteen','if additional_match >= 15 {','if additional_match > 15 {'),
 ('partial-offset-before-refusal','if after_offset > sink.len() {\n        return Err(Error::Offset);\n    }','if after_offset > sink.len() {\n        if *used < sink.len() { sink[*used] = distance as u8; *used += 1; }\n        return Err(Error::Offset);\n    }'),
 ('partial-literals-before-refusal','if next > sink.len() {\n        return Err(Error::Literals);\n    }','if next > sink.len() {\n        let free=sink.len()-*used; sink[*used..].copy_from_slice(&literals[..free]); *used += free;\n        return Err(Error::Literals);\n    }'),
 ('preflight-whole-operation','let token =','let need = 1_u128 + literals.len() as u128 + 2 + if literals.len()>=15 {((literals.len()-15)/255+1) as u128} else {0} + if additional_match>=15 {(additional_match as u128-15)/255+1} else {0}; if need > (sink.len()-*used) as u128 {return Err(Error::Token);}\n    let token ='),
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
  p=subprocess.run([str(dest/'target/release/match-sequence-probe')],input=inputs,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  (W/(name+'.stdout')).write_bytes(p.stdout);(W/(name+'.stderr')).write_bytes(p.stderr)
  need(p.returncode!=0 or p.stdout!=expected,'compiled mutant survived '+name)
  mismatch=next((i for i,(a,b) in enumerate(zip(p.stdout.splitlines(),expected.splitlines())) if a!=b),None)
  controls.append({'name':name,'compiled':True,'exit':p.returncode,'first_mismatch_0based':mismatch,'mutant_source_sha256':sha((dest/'src/lib.rs').read_bytes()),'rejected':True})
 result={'target_sha256':freeze['target_sha256'],'fixture_sha256':sha(fixture),'case_count':len(rows),'profiles':results,'compiled_mutants':controls,'grouped_extension_proof':{'reciprocal_identity':True,'strict_error_bound':True,'prefix_cases':514*514},'source_sha256':{str(f.relative_to(R)):sha(f.read_bytes()) for f in [C/'Cargo.toml',C/'Cargo.lock',C/'src/lib.rs',C/'src/probe.rs']},'capture_execution_or_emulation':False,'limits':'Conditional complete match-sequence stage only; native ABI/panic payloads, match selection, table mutations and full compressor remain unclosed. Extreme additional-count cases test conditional integer emission, not reachability in an allocated capture input.'}
 (P/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

#!/usr/bin/env python3
"""Build real Rust composition and compare frozen Node115 prefix-state cases."""
import argparse, hashlib, importlib.util, json, os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
C=ROOT/'src/node115-gossip-rpc-request'
D=ROOT/'research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a'
import gossip_rpc_request as oracle

def digest(raw): return hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--rustc',required=True,type=Path);p.add_argument('--linker',type=Path)
 p.add_argument('--output',required=True,type=Path);p.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/115/hl-node')
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 calls=[]
 def run(args,name,input=None,ok=True):
  print('$ '+name,flush=True)
  q=subprocess.run(list(map(str,args)),input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=ROOT,timeout=120)
  (a.output/(name+'.stdout')).write_bytes(q.stdout);(a.output/(name+'.stderr')).write_bytes(q.stderr)
  calls.append({'command':list(map(str,args)),'label':name,'exitCode':q.returncode,'stdoutSHA256':digest(q.stdout),'stderrSHA256':digest(q.stderr)})
  if ok and q.returncode: raise RuntimeError(name+': '+q.stderr.decode(errors='replace'))
  return q
 target=a.binary.read_bytes();frozen=oracle.validate(a.binary)
 rows=[line.split('\t') for line in (C/'cases.tsv').read_text().splitlines()]
 inputs=(''.join('\t'.join(r[:4])+'\n' for r in rows)).encode()
 expected=(''.join(r[4]+'\n' for r in rows)).encode()
 version=run([a.rustc,'--version','--verbose'],'rustc-version').stdout.decode()
 common=['--edition=2024','-Dwarnings']
 link=[] if a.linker is None else ['-Clinker='+str(a.linker),'-Clinker-flavor=ld.lld','-Clink-self-contained=yes']
 results=[]
 for opt in (0,3):
  folder=a.output/('opt'+str(opt));folder.mkdir()
  dep=folder/'libnode115_u64_reader_state.rlib';lib=folder/'libnode115_gossip_rpc_request.rlib'
  flags=common+['-Copt-level='+str(opt)]
  run([a.rustc,D/'lib.rs','--crate-name','node115_u64_reader_state','--crate-type=rlib',*flags,'-o',dep],f'dep-opt{opt}')
  ext=['--extern','node115_u64_reader_state='+str(dep),'-L','dependency='+str(folder)]
  run([a.rustc,C/'lib.rs','--crate-name','node115_gossip_rpc_request','--crate-type=rlib',*flags,*ext,'-o',lib],f'lib-opt{opt}')
  exe=folder/('probe.exe' if os.name=='nt' else 'probe')
  run([a.rustc,C/'probe.rs',*flags,*link,*ext,'--extern','node115_gossip_rpc_request='+str(lib),'-o',exe],f'probe-build-opt{opt}')
  output=run([exe],f'probe-opt{opt}',inputs).stdout
  if output!=expected:
   actual=output.decode().splitlines();wanted=expected.decode().splitlines()
   mismatch=[{'row':i,'input':rows[i][:4],'expected':e,'actual':v} for i,(e,v) in enumerate(zip(wanted,actual)) if e!=v]
   (a.output/'mismatches.json').write_bytes((json.dumps(mismatch[:20],indent=2)+'\n').encode())
   raise AssertionError('frozen corpus mismatch')
  assert run([exe],f'probe-repeat-opt{opt}',inputs).stdout==output
  test=folder/'tests.exe'
  run([a.rustc,C/'lib.rs','--test',*flags,*link,*ext,'-o',test],f'test-build-opt{opt}')
  run([test,'--test-threads=1'],f'unit-tests-opt{opt}')
  repeatdir=folder/'repeat';repeatdir.mkdir();repeat=repeatdir/'libnode115_gossip_rpc_request.rlib'
  run([a.rustc,C/'lib.rs','--crate-name','node115_gossip_rpc_request','--crate-type=rlib',*flags,*ext,'-o',repeat],f'lib-repeat-opt{opt}')
  assert lib.read_bytes()==repeat.read_bytes(),'nonreproducible library'
  results.append({'optLevel':opt,'caseCount':len(rows),'matching':True,'repeatEqual':True,'libraryRepeatBytesEqual':True,'unitTests':4,'outputSHA256':digest(output),'librarySHA256':digest(lib.read_bytes())})
 # Compile mutations only in ignored output storage. Never alter licensed input.
 raw=(C/'lib.rs').read_text()
 mutations={
  'swap-fields':('Ok(Request::Variant0 { first, second })','Ok(Request::Variant0 { first: second, second: first })'),
  'swap-unit':('1 => Ok(Request::Variant1)','1 => Ok(Request::Variant2)'),
  'charge-five':('charged.checked_add(4)','charged.checked_add(5)'),
  'fast-invalid-consumes':('if slow { *input = &source[1..]; }','if slow || marker >= 253 { *input = &source[1..]; }'),
 }
 mutants=[];folder=a.output/'opt0'
 dep=folder/'libnode115_u64_reader_state.rlib'
 ext=['--extern','node115_u64_reader_state='+str(dep),'-L','dependency='+str(folder)]
 for label,(old,new) in mutations.items():
  assert raw.count(old)==1
  f=a.output/(label+'.rs');f.write_bytes(raw.replace(old,new).encode());lib=a.output/('lib'+label.replace('-','_')+'.rlib')
  run([a.rustc,f,'--crate-name','node115_gossip_rpc_request','--crate-type=rlib',*common,*ext,'-o',lib],'mutant-lib-'+label)
  exe=a.output/(label+'.exe')
  run([a.rustc,C/'probe.rs',*common,*link,*ext,'--extern','node115_gossip_rpc_request='+str(lib),'-o',exe],'mutant-probe-'+label)
  actual=run([exe],'mutant-run-'+label,inputs).stdout.decode().splitlines();wanted=expected.decode().splitlines()
  differences=[i for i,(x,y) in enumerate(zip(actual,wanted)) if x!=y]
  assert differences,label+' not killed'
  i=differences[0];mutants.append({'mutation':label,'differingRows':len(differences),'firstInput':rows[i][:4],'expected':wanted[i],'mutated':actual[i]})
 # Native-byte controls are below authentication only for corruption testing.
 # No modified image is executed, emulated, or admitted by production validation.
 controls=[];secs=oracle.sections(target)
 for label,va,value in [('tag-charge',0x5821167,5),('tag-fast-threshold',0x5821180,3)]:
  offset=oracle.read(target,secs,va,1)[0];changed=bytearray(target);changed[offset]=value
  try: oracle.analyze(changed)
  except ValueError: rejected=True
  else: rejected=False
  assert rejected
  params=oracle.parameters(changed);baseparams=oracle.parameters(target)
  witnesses=[]
  for mode,count,limit,source in oracle.cases():
   x=oracle.relation(source,mode==1,count,limit,baseparams);y=oracle.relation(source,mode==1,count,limit,params)
   if x!=y:
    witnesses.append({'mode':mode,'charged':count,'limit':limit,'inputHex':source.hex(),'original':x,'corrupted':y});break
  assert witnesses
  controls.append({'label':label,'imageVA':hex(va),'productionAuthenticationRejected':rejected,'witness':witnesses[0]})
 linux=[]
 if 'x86_64-unknown-linux-gnu' in run([a.rustc,'--print','target-list'],'target-list').stdout.decode():
  for opt in (0,3):
   folder=a.output/('linux-opt'+str(opt));folder.mkdir();dep=folder/'libnode115_u64_reader_state.rlib';lib=folder/'libnode115_gossip_rpc_request.rlib'
   flags=common+['--target','x86_64-unknown-linux-gnu','-Copt-level='+str(opt)]
   run([a.rustc,D/'lib.rs','--crate-name','node115_u64_reader_state','--crate-type=rlib',*flags,'-o',dep],f'linux-dep-opt{opt}')
   run([a.rustc,C/'lib.rs','--crate-name','node115_gossip_rpc_request','--crate-type=rlib',*flags,'--extern','node115_u64_reader_state='+str(dep),'-o',lib],f'linux-lib-opt{opt}')
   linux.append({'target':'x86_64-unknown-linux-gnu','optLevel':opt,'rlibSHA256':digest(lib.read_bytes()),'executed':False})
 result={'status':'PASS','target':oracle.SHA,'rustc':version,'compilerSHA256':digest(a.rustc.read_bytes()),'linkerSHA256':digest(a.linker.read_bytes()) if a.linker else None,'frozen':frozen,'sourceSHA256':digest((C/'lib.rs').read_bytes()),'dependencySHA256':digest((D/'lib.rs').read_bytes()),'dependencyCommit':'45e91f8499f1a78460407d235f580c1625f44d1a','dependencyNewReconstructionCredit':False,'profiles':results,'compiledMutants':mutants,'nativeCorruptionControls':controls,'linuxLibraryBuilds':linux,'commands':calls,'captureExecution':False,'targetMachineCodeEquivalence':'unmeasured; logical relation only, no registered byte credit'}
 (a.output/'RESULT.json').write_bytes((json.dumps(result,indent=2)+'\n').encode());print(json.dumps({'status':'PASS','cases':len(rows),'profiles':2,'compiledMutants':len(mutants),'nativeControls':len(controls)}),flush=True)
if __name__=='__main__': main()

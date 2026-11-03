"""Compile owned route/state projection and compare input-only clients."""
import argparse,hashlib,json,subprocess
from pathlib import Path
import native

def run(command,log,**kwargs):
 result=subprocess.run([str(x) for x in command],capture_output=True,**kwargs);log.write_bytes(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError(f'command exited {result.returncode}: {log.name}')
 return result.stdout

def build(rustc,out):
 source=native.ROOT/'src/node115-liquidity-bucket';original=(source/'lib.rs').read_text()
 variants=[('original',original),('bypass-low-bit',original.replace('if bypass != 0','if bypass & 1 != 0')),('zero-or-one',original.replace('if divisor == 0','if divisor <= 1')),('no-signed-clamp',original.replace('(raw_word as i64).max(0) as u64','raw_word')),('equal-active',original.replace('bucket > *previous','bucket >= *previous')),('wrong-state-store',original.replace('*previous = bucket;','*previous = 0;'))]
 if any(text==original for name,text in variants if name!='original'):raise ValueError('compiled mutation anchor changed')
 inputs,expected=native.verify();record=json.loads((native.PACKET/'FREEZE.json').read_text())
 out.mkdir(parents=True,exist_ok=False);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
 compiler=run([rustc,'-vV'],out/'compiler.txt').decode()
 if not compiler.startswith('rustc 1.94.1 '):raise ValueError('research compiler must be1.94.1')
 results=[]
 for name,text in variants:
  text=text.replace('../../research/work-items/RE-014-liquidity-bucket-115/target-smoke.tsv',str(native.PACKET/'target-smoke.tsv'));candidate=out/(name+'.rs');candidate.write_text(text)
  for opt in (['0','3'] if name=='original' else ['3']):
   stem=name+'-o'+opt;flags=['--edition=2021','-D','warnings','-C','opt-level='+opt];rlib=out/('lib'+stem+'.rlib')
   run([rustc,*flags,'--crate-name','node115_liquidity_bucket','--crate-type','rlib',candidate,'-o',rlib],out/(stem+'-library.log'))
   exe=out/(stem+'-client');run([rustc,*flags,source/'input_only_driver.rs','--extern','node115_liquidity_bucket='+str(rlib),'-o',exe],out/(stem+'-client-build.log'))
   actual=run([exe],out/(stem+'-actual.tsv'),input=inputs)
   if len(actual.splitlines())!=record['rows']:raise ValueError('row denominator changed')
   mismatches=sum(a!=b for a,b in zip(actual.splitlines(),expected.splitlines()))
   if (name=='original')!=(mismatches==0):raise ValueError('compiled comparison/control failed')
   test=out/(stem+'-test');run([rustc,*flags,'--test',candidate,'-o',test],out/(stem+'-test-build.log'))
   smoke=subprocess.run([str(test)],capture_output=True);(out/(stem+'-test.log')).write_bytes(smoke.stdout+smoke.stderr)
   if name=='original' and smoke.returncode or name!='original' and (smoke.returncode!=101 or b'assertion `left == right` failed' not in smoke.stdout):raise ValueError('unexpected smoke result')
   if name=='original' and opt=='3':
    if run([exe],out/'own-rlib-repeat.tsv',input=inputs)!=actual:raise ValueError('own rlib repeat differs')
   results.append({'variant':name,'opt':opt,'rows':record['rows'],'mismatches':mismatches,'smoke_exit':smoke.returncode,'actual_sha256':hashlib.sha256(actual).hexdigest()})
 report={'target_sha256':native.SHA,'pre_rust_freeze_commit':'4897719e','source_sha256':hashlib.sha256((source/'lib.rs').read_bytes()).hexdigest(),'driver_sha256':hashlib.sha256((source/'input_only_driver.rs').read_bytes()).hexdigest(),'native_full_expected_sha256':record['expected_sha256'],'semantic_projection_sha256':record['semantic_projection_sha256'],'excluded_native_field':'division-width metadata; Z/D are boundary tags','compiler':compiler,'runs':results,'captured_process_executed':False,'whole_function_or_abi_equivalence':False}
 (out/'results.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.rustc.resolve(),a.output.resolve())

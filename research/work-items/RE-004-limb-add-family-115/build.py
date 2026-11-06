"""Build owned Rust, compare input-only outputs to pre-Rust target streams."""
import argparse,hashlib,json,subprocess
from pathlib import Path
import native

def run(cmd,log,**kwargs):
 result=subprocess.run([str(x) for x in cmd],capture_output=True,**kwargs);log.write_bytes(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError(f'command exit {result.returncode}: {log.name}')
 return result.stdout

def build(rustc,out):
 source=native.ROOT/'src/node115-limb-add-family';original=(source/'lib.rs').read_text()
 changes=[('carry-limb1','+ carry;','+ if i == 1 { 0 } else { carry };'),
 ('carry-limb2','+ carry;','+ if i == 2 { 0 } else { carry };'),
 ('carry-limb3','+ carry;','+ if i == 3 { 0 } else { carry };'),
 ('right-order','u128::from(right[i])','u128::from(right[3-i])'),
 ('carry-output','carry: carry as u8','carry: (carry as u8) ^ 1'),
 ('count-guard','count < 2','count < 3'),
 ('count-decrement','count: count - 1','count: count'),
 ('stack-operand','let right = entries[count - 1];','let right = entries[count - 2];'),
 ('short-status','status: 44','status: 45')]

 variants=[('original',original)]
 for name,anchor,replacement in changes:
  if original.count(anchor)!=1:raise ValueError('missing/ambiguous mutation anchor '+name)
  variants.append((name,original.replace(anchor,replacement)))
 inputs,expected=native.verify();record=json.loads((native.PACKET/'FREEZE.json').read_text())
 out.mkdir(parents=True,exist_ok=False);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
 compiler=run([rustc,'-vV'],out/'compiler.txt').decode()
 if not compiler.startswith('rustc 1.94.1 '):raise ValueError('research compiler must be1.94.1')
 results=[]
 for name,text in variants:
  text=text.replace('../../research/work-items/RE-004-limb-add-family-115/target-smoke.tsv',str(native.PACKET/'target-smoke.tsv'));text=text.replace('../../research/work-items/RE-004-limb-add-family-115/client_fixture.rs',str(native.PACKET/'client_fixture.rs'));candidate=out/(name+'.rs');candidate.write_text(text)
  for opt in (['0','3'] if name=='original' else ['3']):
   stem=name+'-o'+opt;flags=['--edition=2021','-D','warnings','-C','opt-level='+opt];rlib=out/('lib'+stem+'.rlib')
   run([rustc,*flags,'--crate-name','node115_limb_add_family','--crate-type','rlib',candidate,'-o',rlib],out/(stem+'-library.log'))
   exe=out/(stem+'-client');run([rustc,*flags,source/'input_only_driver.rs','--extern','node115_limb_add_family='+str(rlib),'-o',exe],out/(stem+'-client-build.log'))
   actual=run([exe],out/(stem+'-actual.tsv'),input=inputs)
   if len(actual.splitlines())!=record['rows']:raise ValueError('row denominator changed')
   mismatches=sum(a!=b for a,b in zip(actual.splitlines(),expected.splitlines()))
   if (name=='original')!=(mismatches==0):raise ValueError(f'comparison/control failed {stem}: {mismatches}')
   test=out/(stem+'-test');run([rustc,*flags,'--test',candidate,'-o',test],out/(stem+'-test-build.log'))
   smoke=subprocess.run([str(test)],capture_output=True);(out/(stem+'-test.log')).write_bytes(smoke.stdout+smoke.stderr)
   if name=='original' and smoke.returncode or name!='original' and (smoke.returncode!=101 or b'assertion `left == right` failed' not in smoke.stdout):raise ValueError('unexpected smoke result')
   if name=='original' and opt=='3':
    if run([exe],out/'own-rlib-repeat.tsv',input=inputs)!=actual:raise ValueError('own rlib repeat differs')
   results.append(dict(variant=name,opt=opt,rows=record['rows'],mismatches=mismatches,smoke_exit=smoke.returncode,actual_sha256=hashlib.sha256(actual).hexdigest()))
 report=dict(client_fixture_sha256=hashlib.sha256((native.PACKET/'client_fixture.rs').read_bytes()).hexdigest(),target_sha256=native.SHA,pre_rust_output_freeze_commit='2311463613149d7f590895dacd6de1087e863ee8',source_sha256=hashlib.sha256((source/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((source/'input_only_driver.rs').read_bytes()).hexdigest(),input_sha256=record['input_sha256'],expected_sha256=record['expected_sha256'],compiler=compiler,runs=results,captured_process_executed=False,ABI_or_whole_caller_equivalence=False)
 (out/'results.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.rustc.resolve(),a.output.resolve())

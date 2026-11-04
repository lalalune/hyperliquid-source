"""Build owned Rust, compare input-only outputs to pre-Rust target streams."""
import argparse,hashlib,json,subprocess
from pathlib import Path
import native

def run(cmd,log,**kwargs):
 result=subprocess.run([str(x) for x in cmd],capture_output=True,**kwargs);log.write_bytes(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError(f'command exit {result.returncode}: {log.name}')
 return result.stdout

def build(rustc,out):
 source=native.ROOT/'src/node115-ipv6-groups';original=(source/'lib.rs').read_text()
 changes=[('colon',"Some(&b':')","Some(&b';')"),('ipv4-room','capacity - count >= 2','capacity - count >= 3'),('hex-limit','if n == 4','if n == 3'),('hex-letter',"b'a'..=b'f'","b'g'..=b'l'"),('separator-rollback','*cursor = checkpoint;','let _ = checkpoint;'),('unused-output','let mut count = 0;','out.fill(0); let mut count = 0;')]
 variants=[('original',original)]
 for name,anchor,replacement in changes:
  if original.count(anchor)!=1:raise ValueError('missing/ambiguous mutation anchor '+name)
  variants.append((name,original.replace(anchor,replacement)))
 if original.count('u16::from_be_bytes')!=2:raise ValueError('IPv4 pair anchors changed')
 variants.append(('ipv4-byte-order',original.replace('u16::from_be_bytes','u16::from_le_bytes')))
 inputs,expected=native.verify();record=json.loads((native.PACKET/'FREEZE.json').read_text())
 out.mkdir(parents=True,exist_ok=False);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
 compiler=run([rustc,'-vV'],out/'compiler.txt').decode()
 if not compiler.startswith('rustc 1.94.1 '):raise ValueError('research compiler must be1.94.1')
 results=[]
 for name,text in variants:
  text=text.replace('../../research/work-items/RE-012-ipv6-groups-115/target-smoke.tsv',str(native.PACKET/'target-smoke.tsv'));candidate=out/(name+'.rs');candidate.write_text(text)
  for opt in (['0','3'] if name=='original' else ['3']):
   stem=name+'-o'+opt;flags=['--edition=2021','-D','warnings','-C','opt-level='+opt];rlib=out/('lib'+stem+'.rlib')
   run([rustc,*flags,'--crate-name','node115_ipv6_groups','--crate-type','rlib',candidate,'-o',rlib],out/(stem+'-library.log'))
   exe=out/(stem+'-client');run([rustc,*flags,source/'input_only_driver.rs','--extern','node115_ipv6_groups='+str(rlib),'-o',exe],out/(stem+'-client-build.log'))
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
 report=dict(target_sha256=native.SHA,pre_rust_output_freeze_commit='a19a4825',pre_rust_smoke_commit='af584bd5',source_sha256=hashlib.sha256((source/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((source/'input_only_driver.rs').read_bytes()).hexdigest(),input_sha256=record['input_sha256'],expected_sha256=record['expected_sha256'],compiler=compiler,runs=results,captured_process_executed=False,ABI_or_whole_caller_equivalence=False)
 (out/'results.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.rustc.resolve(),a.output.resolve())

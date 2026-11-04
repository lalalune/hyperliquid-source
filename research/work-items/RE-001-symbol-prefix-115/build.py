"""Build owned Rust, compare input-only outputs to pre-Rust target streams."""
import argparse,hashlib,json,subprocess
from pathlib import Path
import native

def run(cmd,log,**kwargs):
 result=subprocess.run([str(x) for x in cmd],capture_output=True,**kwargs);log.write_bytes(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError(f'command exit {result.returncode}: {log.name}')
 return result.stdout

def build(rustc,out):
 source=native.ROOT/'src/node115-symbol-prefix';original=(source/'lib.rs').read_text()
 changes=[('USDC-id','return PrefixObservation::Direct(0);','return PrefixObservation::Direct(1);'),
 ('PURR-id','return PrefixObservation::Direct(1);','return PrefixObservation::Direct(0);'),
 ('prefix-case','strip_prefix(b"outcomeToken")','strip_prefix(b"OutcomeToken")'),
 ('plus-rule','strip_prefix(b"+")','strip_prefix(b"-")'),
 ('digit-nine','if !byte.is_ascii_digit() {',"if !byte.is_ascii_digit() || byte == b'9' {"),
 ('decimal-scale','.checked_mul(10)','.checked_mul(9)'),
 ('mul-overflow','.checked_mul(10)','.checked_mul(10).or(Some(value.wrapping_mul(10)))'),
 ('add-overflow','.and_then(|scaled| scaled.checked_add(u64::from(byte - b\'0\')))','.map(|scaled| scaled.wrapping_add(u64::from(byte - b\'0\')))'),
 ('premature-canonical','if digits.is_empty() {',"if digits.is_empty() || suffix.len() > 1 && suffix[0] == b'0' {"),
 ('premature-length','if digits.is_empty() {','if digits.is_empty() || digits.len() > 20 {'),
 ('formatter-digit',"decimal[start] = b'0' + (remaining % 10) as u8;","decimal[start] = b'1' + (remaining % 10) as u8;"),
 ('formatter-quotient','remaining /= 10;','remaining /= 11;')]

 variants=[('original',original)]
 for name,anchor,replacement in changes:
  if original.count(anchor)!=1:raise ValueError('missing/ambiguous mutation anchor '+name)
  variants.append((name,original.replace(anchor,replacement)))
 inputs,expected=native.verify();record=json.loads((native.PACKET/'FREEZE.json').read_text())
 out.mkdir(parents=True,exist_ok=False);(out/'inputs.hex').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
 empty=out/'empty-client-cwd';empty.mkdir()
 compiler=run([rustc,'-vV'],out/'compiler.txt').decode()
 if not compiler.startswith('rustc 1.94.1 '):raise ValueError('research compiler must be1.94.1')
 results=[]
 for name,text in variants:
  text=text.replace('../../research/work-items/RE-001-symbol-prefix-115/target-smoke.tsv',str(native.PACKET/'target-smoke.tsv'));text=text.replace('../../research/work-items/RE-001-symbol-prefix-115/client_fixture.rs',str(native.PACKET/'client_fixture.rs'));candidate=out/(name+'.rs');candidate.write_text(text)
  for opt in (['0','3'] if name=='original' else ['3']):
   stem=name+'-o'+opt;flags=['--edition=2021','-D','warnings','-C','opt-level='+opt];rlib=out/('lib'+stem+'.rlib')
   run([rustc,*flags,'--crate-name','node115_symbol_prefix','--crate-type','rlib',candidate,'-o',rlib],out/(stem+'-library.log'))
   exe=out/(stem+'-client');run([rustc,*flags,source/'input_only_driver.rs','--extern','node115_symbol_prefix='+str(rlib),'-o',exe],out/(stem+'-client-build.log'))
   actual=run([exe],out/(stem+'-actual.tsv'),input=inputs,cwd=empty)
   if len(actual.splitlines())!=record['rows']:raise ValueError('row denominator changed')
   mismatches=sum(a!=b for a,b in zip(actual.splitlines(),expected.splitlines()))
   if (name=='original')!=(mismatches==0):raise ValueError(f'comparison/control failed {stem}: {mismatches}')
   test=out/(stem+'-test');run([rustc,*flags,'--test',candidate,'-o',test],out/(stem+'-test-build.log'))
   smoke=subprocess.run([str(test)],capture_output=True);(out/(stem+'-test.log')).write_bytes(smoke.stdout+smoke.stderr)
   if name=='original' and smoke.returncode or name!='original' and (smoke.returncode!=101 or b'assertion `left == right` failed' not in smoke.stdout):raise ValueError('unexpected smoke result')
   if name=='original' and opt=='3':
    if run([exe],out/'own-rlib-repeat.tsv',input=inputs,cwd=empty)!=actual:raise ValueError('own rlib repeat differs')
   results.append(dict(variant=name,opt=opt,rows=record['rows'],mismatches=mismatches,smoke_exit=smoke.returncode,actual_sha256=hashlib.sha256(actual).hexdigest()))
 report=dict(target_sha256=native.SHA,pre_rust_output_freeze_commit='66e9b42c1646be7380bf801f00c7882cb4d47135',source_sha256=hashlib.sha256((source/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((source/'input_only_driver.rs').read_bytes()).hexdigest(),fixture_sha256=hashlib.sha256((native.PACKET/'client_fixture.rs').read_bytes()).hexdigest(),input_sha256=record['input_sha256'],expected_sha256=record['expected_sha256'],compiler=compiler,runs=results,captured_process_executed=False,ABI_or_whole_caller_equivalence=False)
 (out/'results.json').write_text(json.dumps(report,indent=2)+'\n');print('BUILD PASS',[(r['variant'],r['opt'],r['mismatches'],r['smoke_exit']) for r in results])
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.rustc.resolve(),a.output.resolve())

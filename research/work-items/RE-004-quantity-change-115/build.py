"""Build owned Rust, compare input-only outputs to pre-Rust target streams."""
import argparse,hashlib,json,subprocess
from pathlib import Path
import native

def run(cmd,log,**kwargs):
 result=subprocess.run([str(x) for x in cmd],capture_output=True,**kwargs);log.write_bytes(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError(f'command exit {result.returncode}: {log.name}')
 return result.stdout

def build(rustc,out):
 source=native.ROOT/'src/node115-quantity-change';original=(source/'lib.rs').read_text()
 changes=[('counter-insert','if old == 0 && new != 0 {','if old == 0 && new == 0 {'),
 ('counter-saturation','counter.saturating_add(1)','counter.wrapping_add(1)'),
 ('counter-decrement','out.store(counter - 1);','out.store(counter.saturating_add(1));'),
 ('lookup-gate','if has_total {','if !has_total {'),
 ('notify-change','notification.word != 0 && old != new','notification.word != 0 && old == new'),
 ('notify-copy','payload: notification.payload','payload: [0; 20]'),
 ('old-absolute','old.checked_abs()','old.checked_neg()'),
 ('subtraction','total.checked_sub(old_abs)','total.checked_add(old_abs)'),
 ('sub-endpoint','pending: i64::MIN','pending: i64::MAX'),
 ('first-store','out.store(subtracted as u64);','out.value = subtracted as u64;'),
 ('new-absolute','new.checked_abs()','new.checked_neg()'),
 ('addition','subtracted.checked_add(new_abs)','subtracted.checked_sub(new_abs)'),
 ('add-endpoint','pending: i64::MAX','pending: i64::MIN')]

 variants=[('original',original)]
 production,tests=original.split('#[cfg(test)]',1)
 for name,anchor,replacement in changes:
  if production.count(anchor)!=1:raise ValueError('missing/ambiguous mutation anchor '+name)
  variants.append((name,production.replace(anchor,replacement)+'#[cfg(test)]'+tests))
 inputs,expected=native.verify();record=json.loads((native.PACKET/'FREEZE.json').read_text())
 out.mkdir(parents=True,exist_ok=False);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
 empty=out/'empty-client-cwd';empty.mkdir()
 compiler=run([rustc,'-vV'],out/'compiler.txt').decode()
 if not compiler.startswith('rustc 1.94.1 '):raise ValueError('research compiler must be1.94.1')
 results=[]
 for name,text in variants:
  text=text.replace('../../research/work-items/RE-004-quantity-change-115/target-smoke.tsv',str(native.PACKET/'target-smoke.tsv'));text=text.replace('../../research/work-items/RE-004-quantity-change-115/client_fixture.rs',str(native.PACKET/'client_fixture.rs'));candidate=out/(name+'.rs');candidate.write_text(text)
  for opt in (['0','3'] if name=='original' else ['3']):
   stem=name+'-o'+opt;flags=['--edition=2021','-D','warnings','-C','opt-level='+opt];rlib=out/('lib'+stem+'.rlib')
   run([rustc,*flags,'--crate-name','node115_quantity_change','--crate-type','rlib',candidate,'-o',rlib],out/(stem+'-library.log'))
   exe=out/(stem+'-client');run([rustc,*flags,source/'input_only_driver.rs','--extern','node115_quantity_change='+str(rlib),'-o',exe],out/(stem+'-client-build.log'))
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
 report=dict(target_sha256=native.SHA,pre_rust_output_freeze_commit='3649e42abb2e9dec64d280acd9a8d6783f6cf1b0',source_sha256=hashlib.sha256((source/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((source/'input_only_driver.rs').read_bytes()).hexdigest(),fixture_sha256=hashlib.sha256((native.PACKET/'client_fixture.rs').read_bytes()).hexdigest(),input_sha256=record['input_sha256'],expected_sha256=record['expected_sha256'],compiler=compiler,runs=results,captured_process_executed=False,ABI_or_whole_caller_equivalence=False)
 (out/'results.json').write_text(json.dumps(report,indent=2)+'\n');print('BUILD PASS',[(r['variant'],r['opt'],r['mismatches'],r['smoke_exit']) for r in results])
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.rustc.resolve(),a.output.resolve())

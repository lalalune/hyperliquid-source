"""Build owned Rust, compare input-only outputs to pre-Rust target streams."""
import argparse,hashlib,json,subprocess
from pathlib import Path
import native

def run(cmd,log,**kwargs):
 result=subprocess.run([str(x) for x in cmd],capture_output=True,**kwargs);log.write_bytes(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError(f'command exit {result.returncode}: {log.name}')
 return result.stdout

def build(rustc,out):
 source=native.ROOT/'src/node115-stake-cursor';original=(source/'lib.rs').read_text()
 changes=[('cursor-increment','index.checked_add(1)','index.checked_add(2)'),
 ('offset-addition','offset.checked_add(incremented)','offset.checked_sub(incremented)'),
 ('cursor-cap','let cursor = if total >= 5 { 4 } else { incremented };','let cursor = if total >= 5 { 3 } else { incremented };'),
 ('terminal-index','if index >= 4 || total >= 5','if index >= 3 || total >= 5'),
 ('bonus-comparison','identity_byte == index as u8','identity_byte != index as u8'),
 ('base-saturation','helper_value.saturating_add','helper_value.wrapping_add'),
 ('row-alias','[A, B, C, A]','[A, B, C, B]'),
 ('column-order','ROWS[index.0 as usize][column.0 as usize]','ROWS[column.0 as usize][index.0 as usize]'),
 ('product','.checked_mul(multiplier)','.checked_add(multiplier)'),
 ('existing-C5','old_tag == 0x1a2 || old_tag == 0xc5','old_tag == 0x1a2'),
 ('output-tag','output_tag: 0xc5','output_tag: 0xc4'),
 ('output-store','wrote_tag: true','wrote_tag: false'),
 ('unknown-cleanup','next: ItemNext::ExistingCleanupBoundary','next: ItemNext::FailedRawC5')]

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
  text=text.replace('../../research/work-items/RE-001-stake-cursor-115/target-smoke.tsv',str(native.PACKET/'target-smoke.tsv'));text=text.replace('../../research/work-items/RE-001-stake-cursor-115/client_fixture.rs',str(native.PACKET/'client_fixture.rs'));candidate=out/(name+'.rs');candidate.write_text(text)
  for opt in (['0','3'] if name=='original' else ['3']):
   stem=name+'-o'+opt;flags=['--edition=2021','-D','warnings','-C','opt-level='+opt];rlib=out/('lib'+stem+'.rlib')
   run([rustc,*flags,'--crate-name','node115_stake_cursor','--crate-type','rlib',candidate,'-o',rlib],out/(stem+'-library.log'))
   exe=out/(stem+'-client');run([rustc,*flags,source/'input_only_driver.rs','--extern','node115_stake_cursor='+str(rlib),'-o',exe],out/(stem+'-client-build.log'))
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
 report=dict(target_sha256=native.SHA,pre_rust_output_freeze_commit='eef0842675218626e6423dca232d630d4b3eec80',source_sha256=hashlib.sha256((source/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((source/'input_only_driver.rs').read_bytes()).hexdigest(),fixture_sha256=hashlib.sha256((native.PACKET/'client_fixture.rs').read_bytes()).hexdigest(),input_sha256=record['input_sha256'],expected_sha256=record['expected_sha256'],compiler=compiler,runs=results,captured_process_executed=False,ABI_or_whole_caller_equivalence=False)
 (out/'results.json').write_text(json.dumps(report,indent=2)+'\n');print('BUILD PASS',[(r['variant'],r['opt'],r['mismatches'],r['smoke_exit']) for r in results])
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.rustc.resolve(),a.output.resolve())

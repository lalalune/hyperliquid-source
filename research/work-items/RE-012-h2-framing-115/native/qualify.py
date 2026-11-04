#!/usr/bin/env python3
"""Compile only independently authored Rust, using input-only frozen fixtures."""
import argparse,gzip,hashlib,json,pathlib,subprocess,time
P=pathlib.Path(__file__).resolve().parents[1];ROOT=P.parents[2]
def check(c,m):
    if not c:raise RuntimeError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--rustc',action='append',required=True,type=pathlib.Path);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();check(not a.out.exists(),'output exists');a.out.mkdir(parents=True)
 rows=[json.loads(x)for x in gzip.decompress((P/'oracle/cases.jsonl.gz').read_bytes()).splitlines()];inputs=''.join('|'.join(map(str,x['input']))+'\n'for x in rows).encode();want=''.join(x['expected']+'\n'for x in rows).encode();(a.out/'inputs.txt').write_bytes(inputs);(a.out/'expected.txt').write_bytes(want)
 source=ROOT/'src/node115-h2-framing/src/lib.rs';original=source.read_bytes();driver=P/'native/driver.rs';commands=[]
 def run(label,argv,stdin=None):
  start=time.monotonic();r=subprocess.run(list(map(str,argv)),input=stdin,capture_output=True);(a.out/(label+'.stdout')).write_bytes(r.stdout);(a.out/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=list(map(str,argv)),exit_code=r.returncode,seconds=time.monotonic()-start,stdout_sha256=sha(r.stdout),stderr_sha256=sha(r.stderr)));(a.out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');check(r.returncode==0,label+' failed');return r.stdout
 def build(label,rustc,opt,src):
  lib=a.out/('lib'+label+'.rlib');exe=a.out/(label+'.bin');run(label+'-library',[rustc,'--edition=2021','--crate-name','node115_h2_framing','--crate-type','rlib','-C','opt-level='+str(opt),src,'-o',lib]);run(label+'-client',[rustc,'--edition=2021','--extern','node115_h2_framing='+str(lib),'-C','opt-level='+str(opt),driver,'-o',exe]);out=run(label+'-run',[exe],inputs);return out,dict(label=label,library_sha256=sha(lib.read_bytes()),client_sha256=sha(exe.read_bytes()),output_sha256=sha(out))
 correct=[]
 for t,rustc in enumerate(a.rustc):
  version=run('rustc-'+str(t),[rustc,'-Vv']).decode()
  for opt in [0,3]:
   out,row=build(f'correct-{t}-{opt}',rustc,opt,source);check(out==want,'correct output mismatch');row.update(version=version,cases=len(rows),optimization=opt);correct.append(row)
 mutants=[
 ('endian','if config.big_endian {','if !config.big_endian {'),
 ('limit-equality','if value > config.maximum {','if value >= config.maximum {'),
 ('adjust-wrap-add','value.checked_add(config.adjustment as u64)','Some(value.wrapping_add(config.adjustment as u64))'),
 ('adjust-wrap-sub','value.checked_sub((-config.adjustment) as u64)','Some(value.wrapping_sub((-config.adjustment) as u64))'),
 ('min-diagnostic','out.status=Status::AdjustmentNegationBoundary;','out.status=Status::AdjustmentOverflow;'),
 ('field-width','if config.field_bytes > 8 {','if config.field_bytes >= 8 {'),
 ('data-length','State::Data(length) => length,','State::Data(_) => 0,'),
 ('extra-head','let requirement = head.max(skip);','let requirement = head.max(skip).saturating_add(1);'),
 ('split-equality','if remaining < length {','if remaining <= length {'),
 ('builder-cap','Some(maximum.min(adjusted))','Some(maximum.max(adjusted))'),
 ('h2-lower','16_384..=16_777_215','16_385..=16_777_215'),
 ('skip-consumption','out.consumed=skip;','out.consumed=0;')]
 controls=[];text=original.decode()
 for name,before,after in mutants:
  check(text.count(before)==1,'mutation anchor count '+name);src=a.out/('mutant-'+name+'.rs');src.write_text(text.replace(before,after));out,row=build('mutant-'+name,a.rustc[0],3,src);got=out.splitlines();expected=want.splitlines();check(len(got)==len(expected),'mutant truncated '+name);diff=[i for i,(x,y)in enumerate(zip(got,expected))if x!=y];check(diff,'ineffective mutant '+name);row.update(name=name,differences=len(diff),first_difference=diff[0],normal_return=True,source_sha256=sha(src.read_bytes()));controls.append(row)
 result=dict(cases=len(rows),correct=correct,controls=controls,input_sha256=sha(inputs),expected_sha256=sha(want),source_sha256=sha(original),driver_sha256=sha(driver.read_bytes()),captured_execution=False)
 (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(cases=len(rows),builds=len(correct),mutants=len(controls),status='PASS')))
if __name__=='__main__':main()

"""Build independent Rust, feed inputs only, compare fixed pre-Rust outputs."""
import argparse,hashlib,json,subprocess
from pathlib import Path
import native,parser

def run(cmd,log,**kwargs):
 result=subprocess.run([str(x) for x in cmd],capture_output=True,**kwargs);log.write_bytes(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError(f'command exit {result.returncode}: {log.name}')
 return result.stdout

def build(rustc,out):
 source=native.ROOT/'src/node115-host-ip-gates';original=(source/'lib.rs').read_text()
 changes=[('length-limit','if length > 15','if length > 14'),('return-low-bit','parser_al & 1 != 0','parser_al != 0'),('remaining-check','remaining == 0','remaining <= 1'),('override-word','override_word == (1u64 << 63)','override_word & (1u64 << 63) != 0'),('leading-zero',"(at - start > 1 && bytes[start] == b'0')",'false'),('octet-upper-bound','value > 255','value > 256'),('cursor-store','*cursor = &bytes[at..];','*cursor = &bytes[at.saturating_sub(1)..];')]
 variants=[('original',original)]
 for name,anchor,replacement in changes:
  if original.count(anchor)!=1:raise ValueError('mutation anchor missing/ambiguous: '+name)
  variants.append((name,original.replace(anchor,replacement)))
 raw_inputs,raw_expected=native.verify();parser_inputs,parser_expected=parser.verify();inputs=raw_inputs+parser_inputs;expected=raw_expected+parser_expected
 out.mkdir(parents=True,exist_ok=False);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
 compiler=run([rustc,'-vV'],out/'compiler.txt').decode()
 if not compiler.startswith('rustc 1.94.1 '):raise ValueError('research compiler must be1.94.1')
 results=[]
 for name,text in variants:
  for filename in ('target-smoke.tsv','parser-smoke.tsv'):text=text.replace('../../research/work-items/RE-014-host-ip-gates-115/'+filename,str(native.PACKET/filename))
  candidate=out/(name+'.rs');candidate.write_text(text)
  for opt in (['0','3'] if name=='original' else ['3']):
   stem=name+'-o'+opt;flags=['--edition=2021','-D','warnings','-C','opt-level='+opt];rlib=out/('lib'+stem+'.rlib')
   run([rustc,*flags,'--crate-name','node115_host_ip_gates','--crate-type','rlib',candidate,'-o',rlib],out/(stem+'-library.log'))
   exe=out/(stem+'-client');run([rustc,*flags,source/'input_only_driver.rs','--extern','node115_host_ip_gates='+str(rlib),'-o',exe],out/(stem+'-client-build.log'))
   actual=run([exe],out/(stem+'-actual.tsv'),input=inputs)
   if len(actual.splitlines())!=len(expected.splitlines()):raise ValueError('row count changed')
   mismatches=sum(a!=b for a,b in zip(actual.splitlines(),expected.splitlines()))
   if (name=='original')!=(mismatches==0):raise ValueError(f'comparison/control failed: {stem}, mismatches={mismatches}')
   test=out/(stem+'-test');run([rustc,*flags,'--test',candidate,'-o',test],out/(stem+'-test-build.log'))
   smoke=subprocess.run([str(test)],capture_output=True);(out/(stem+'-test.log')).write_bytes(smoke.stdout+smoke.stderr)
   if name=='original' and smoke.returncode or name!='original' and (smoke.returncode!=101 or b'assertion `left == right` failed' not in smoke.stdout):raise ValueError('smoke did not distinguish candidate')
   if name=='original' and opt=='3':
    if run([exe],out/'own-rlib-repeat.tsv',input=inputs)!=actual:raise ValueError('repeat differs')
   results.append(dict(variant=name,opt=opt,rows=len(expected.splitlines()),mismatches=mismatches,smoke_exit=smoke.returncode,actual_sha256=hashlib.sha256(actual).hexdigest()))
 report=dict(target_sha256=native.SHA,pre_rust_raw_freeze_commit='ba1d5653',pre_rust_parser_freeze_commit='4179b8a1',source_sha256=hashlib.sha256((source/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((source/'input_only_driver.rs').read_bytes()).hexdigest(),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),compiler=compiler,runs=results,captured_process_executed=False,whole_caller_or_ABI_equivalence=False)
 (out/'results.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--rustc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.rustc.resolve(),a.output.resolve())

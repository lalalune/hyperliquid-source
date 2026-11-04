#!/usr/bin/env python3
"""Run only newly compiled own Rust against a frozen UTF-8 reference relation."""
from pathlib import Path
import hashlib,itertools,json,random,subprocess,sys
P=Path(__file__).resolve().parent;R=P.parents[2]
sys.path.insert(0,str(P));import verify as evidence

def corpus():
 yield b''
 for n in range(256):yield bytes([n])
 for a in range(256):
  for b in range(256):yield bytes([a,b])
 classes=[0,0x7f,0x80,0x8f,0x90,0x9f,0xa0,0xbf,0xc0,0xff]
 for first in [0xc1,0xc2,0xdf,0xe0,0xe1,0xec,0xed,0xee,0xef,0xf0,0xf1,0xf3,0xf4,0xf5,0xff]:
  for tail in itertools.product(classes,repeat=3):
   for n in [2,3,4]:yield bytes([first,*tail])[:n]
 for prefix in range(40):
  for value in [b'\x80',b'\xc2',b'\xc2\x80',b'\xe0\xa0\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xf0\x90\x80\x80']:
   yield b'A'*prefix+value
 rng=random.Random(115)
 for _ in range(10000):yield rng.randbytes(rng.randrange(1,60))

def reference(value):
 try:value.decode('utf-8');return 'ok'
 except UnicodeDecodeError as e:
  return f"{e.start}:{-1 if e.reason=='unexpected end of data' else e.end-e.start}"

def main():
 out=Path(sys.argv[1]);evidence.need(not out.exists(),'fresh output required');out.mkdir(parents=True)
 evidence.collect(evidence.TARGET.read_bytes(),True)
 d=evidence.TARGET.read_bytes();ss=evidence.sections(d);v=json.loads((P/'scope.json').read_text())['data'][0];width=bytes.fromhex(v['raw'])
 expected=bytes(1 if x<128 else 2 if 0xc2<=x<=0xdf else 3 if 0xe0<=x<=0xef else 4 if 0xf0<=x<=0xf4 else 0 for x in range(256));evidence.need(width==expected,'captured width table classes')
 rows=sorted(set(corpus()));payload=''.join(x.hex()+'\n' for x in rows);want=[reference(x) for x in rows];expect='\n'.join(want)+'\n';(out/'inputs.hex').write_text(payload);(out/'expected.txt').write_text(expect)
 rustc=Path(sys.argv[2]);source=R/'src/node115-utf8-admission/src';version=subprocess.check_output([str(rustc),'-Vv'],text=True)
 freeze={'cases':len(rows),'input_sha256':hashlib.sha256(payload.encode()).hexdigest(),'expected_sha256':hashlib.sha256(expect.encode()).hexdigest(),'oracle':'CPython strict UTF-8 codec error start/length; truncated final sequence maps to absent error_len','ordering':'Corpus frozen after initial independent Rust source was authored; no pre-production oracle claim','target_sha256':evidence.SPEC['target_sha256'],'rustc':version}
 (out/'freeze.json').write_text(evidence.dump(freeze));results=[]
 for opt in ['0','3']:
  executable=out/('probe'+opt);subprocess.run([str(rustc),'--edition=2021','-C','opt-level='+opt,str(source/'probe.rs'),'-o',str(executable)],check=True,capture_output=True)
  run=subprocess.run([str(executable)],input=payload,text=True,capture_output=True,check=True);(out/('actual'+opt+'.txt')).write_text(run.stdout);evidence.need(run.stdout==expect,'production/reference mismatch '+opt);results.append({'opt':opt,'matched_rows':len(rows),'output_sha256':hashlib.sha256(run.stdout.encode()).hexdigest()})
 original=(source/'lib.rs').read_text();controls=[('ascii inclusive','first < 0x80','first <= 0x80'),('overlong two-byte','0xc2..=0xdf','0xc1..=0xdf'),('surrogate upper','0x80..=0x9f','0x80..=0xbf'),('four-byte ceiling','0x80..=0x8f','0x80..=0x9f'),('truncation length','error_len: None','error_len: Some(1)')];mutants=[]
 for n,(name,old,new) in enumerate(controls):
  evidence.need(original.count(old)==1,'unique mutant selector '+name);q=out/('mutant'+str(n));q.mkdir();(q/'lib.rs').write_text(original.replace(old,new));(q/'probe.rs').write_bytes((source/'probe.rs').read_bytes());exe=q/'probe';subprocess.run([str(rustc),'--edition=2021','-O',str(q/'probe.rs'),'-o',str(exe)],check=True,capture_output=True);run=subprocess.run([str(exe)],input=payload,text=True,capture_output=True,check=True);actual=run.stdout.splitlines();evidence.need(len(actual)==len(want),'mutant normal output');diff=[i for i,(a,b) in enumerate(zip(actual,want)) if a!=b];evidence.need(diff,'surviving mutant '+name);i=diff[0];mutants.append({'name':name,'mismatches':len(diff),'witness_hex':rows[i].hex(),'expected':want[i],'actual':actual[i]})
 result={'freeze':freeze,'production':results,'compiled_mutants_detected':mutants,'capture_executed_or_emulated':False,'native_behavior_observed':False,'limits':'Agreement with an independent public UTF-8 reference plus static target obligations, not machine-code or original ABI equivalence.'};(out/'qualification.json').write_text(evidence.dump(result));print(evidence.dump(result))
if __name__=='__main__':main()

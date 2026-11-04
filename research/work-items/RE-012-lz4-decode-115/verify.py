#!/usr/bin/env python3
"""Reproduce static bindings, frozen witnesses and independently compiled Rust."""
import argparse,collections,hashlib,json,re,subprocess,tempfile
from pathlib import Path
import collect,corpus
P=Path(__file__).resolve().parent;ROOT=collect.ROOT;SRC=ROOT/'src/node115-lz4-decode/lib.rs'
def run(cmd,stdin=None,stdout=None):
 r=subprocess.run(cmd,input=stdin,stdout=stdout or subprocess.PIPE,stderr=subprocess.PIPE,cwd=ROOT)
 if r.returncode:raise ValueError(f'process failed {cmd[0]}: '+r.stderr.decode()[-1500:])
 return r.stdout

def main(out,rustc):
 out.mkdir(parents=True,exist_ok=False);data=collect.TARGET.read_bytes()
 record,exports=collect.collect(data,True)
 # Two exact regenerations, including all selected native bytes and partitions.
 other,ex2=collect.collect(data,True);collect.need(record==other and exports==ex2,'static regeneration drift')
 collect.need(record==json.loads((P/'evidence.json').read_text()),'committed evidence drift')
 for n,t in exports.items():collect.need((P/n).read_text()==t,'native export drift '+n)
 controls=[]
 # Individual operative or structural changes are tested below full-artifact hashing.
 for name,(at,h) in collect.PINS.items():
  original=collect.Image(data)
  class Counterfactual:
   def read(self,a,n):
    raw=bytearray(original.read(a,n))
    if a<=at<a+n:raw[at-a]^=1
    return bytes(raw)
  try:collect.obligations(Counterfactual())
  except ValueError:controls.append(name)
  else:raise ValueError('missed native obligation corruption '+name)
 for d in [data[:-1],bytes([data[0]^1])+data[1:]]:
  try:collect.collect(d)
  except ValueError:controls.append('artifact identity')
  else:raise ValueError('missed capture corruption')
 # Cross-check FDE headers with GNU readelf (not the Python FDE parser).
 frames=run(['readelf','--debug-dump=frames',str(collect.TARGET)]).decode();selected=[]
 for owner in record['owners']:
  a,b=int(owner['start'],16),int(owner['end'],16)
  matches=[l for l in frames.splitlines() if re.search(r'pc=0*'+f'{a:x}'+r'\.\.0*'+f'{b:x}'+r'\b',l)]
  collect.need(len(matches)==1,'readelf FDE disagreement');selected+=matches
 (out/'readelf-selected.txt').write_text('\n'.join(selected)+'\n')
 frozen=json.loads((P/'frozen.json').read_text());collect.need(collect.sha((P/'corpus.py').read_bytes())==frozen['corpus_script_sha256'],'frozen generator drift')
 ih=hashlib.sha256();eh=hashlib.sha256();count=0;results=collections.Counter()
 with (out/'input.txt').open('w') as fi,(out/'expected.txt').open('w') as fe:
  for category,b,lim,want in corpus.cases():
   expected=corpus.outcome(b,lim)
   collect.need(want is None or want==expected,'construction witness fails')
   a=f'{lim} {corpus.hx(b)}\n';z=expected+'\n';fi.write(a);fe.write(z);ih.update(a.encode());eh.update(z.encode());count+=1;results[expected.split()[0]+' '+expected.split()[1] if not expected.startswith('O ') else 'success']+=1
 collect.need(count==frozen['cases'] and ih.hexdigest()==frozen['input_sha256'] and eh.hexdigest()==frozen['expected_sha256'],'frozen cases drift')
 expected=(out/'expected.txt').read_bytes();input_bytes=(out/'input.txt').read_bytes()
 builds=[]
 def compile_run(path,label,opt):
  lib=out/(label+'.rlib');exe=out/(label+'.exe')
  # rustc requires a lib-prefixed file for --extern.
  lib=out/'libnode115_lz4_decode.rlib'
  commands=[[rustc,'--edition=2021','--crate-name','node115_lz4_decode','--crate-type','rlib','-C','opt-level='+str(opt),str(path),'-o',str(lib)],
   [rustc,'--edition=2021',str(P/'driver.rs'),'--extern','node115_lz4_decode='+str(lib),'-o',str(exe)]]
  for cmd in commands:run(cmd)
  actual=run([str(exe)],input_bytes);(out/(label+'.actual')).write_bytes(actual)
  library=lib.read_bytes();(out/('lib'+label+'.rlib')).write_bytes(library)
  return actual,collect.sha(library)
 for label,opt in [('debug',0),('optimized',3),('repeat',3)]:
  actual,h=compile_run(SRC,label,opt);collect.need(actual==expected,'Rust mismatch '+label);builds.append({'profile':label,'cases':count,'library_sha256':h,'output_sha256':collect.sha(actual)})
 collect.need(builds[1]['library_sha256']==builds[2]['library_sha256'],'optimized reproducibility drift')
 text=SRC.read_text()
 mutations={
 'prefix-endian':('u32::from_le_bytes(prefix)','u32::from_be_bytes(prefix)'),
 'equal-limit':('capacity as u64 > maximum','capacity as u64 >= maximum'),
 'exact-size':('return Ok(output);','return if output.len()==capacity {Ok(output)} else {Err(DecodeError::Output)};'),
 'literal-nibble':('token >> 4','token >> 3'),
 'match-base':('usize::from(token & 15) + 4','usize::from(token & 15) + 3'),
 'offset-endian':('u16::from_le_bytes([pair[0], pair[1]])','u16::from_be_bytes([pair[0], pair[1]])'),
 'zero-accepted':('return Err(DecodeError::ZeroOffset);','return Ok(output);'),
 'history-bytes':('output[output.len() - distance]','output[0]'),
 'extension-stop':('if byte != 255','if byte != 254'),
 'extension-wrap':('extra\n            .checked_add(u32::from(byte))\n            .ok_or(DecodeError::ExtensionOverflow)?','extra.wrapping_add(u32::from(byte))'),
 }
 mutants=[]
 for label,(old,new) in mutations.items():
  collect.need(text.count(old)==1,'mutation no longer unique '+label);path=out/(label+'.rs');path.write_text(text.replace(old,new));actual,_=compile_run(path,label,3)
  lines=actual.splitlines();want=expected.splitlines();collect.need(len(lines)==count,'mutant terminated abnormally')
  mismatches=sum(x!=y for x,y in zip(lines,want));collect.need(mismatches>0,'undetected compiled mutant '+label);mutants.append({'name':label,'normal_exit':True,'mismatched_cases':mismatches})
 # Explicit checks of error ordering that a mere valid-block decoder misses.
 ordering=[('literal-before-output',bytes.fromhex('000000002041'),'E literal'),('output-before-history',bytes.fromhex('00000000000100'),'E output'),('zero-before-extension',bytes.fromhex('200000000f0000'),'E zero')]
 for name,b,want in ordering:collect.need(corpus.outcome(b,int.from_bytes(b[:4],'little'))==want,name)
 versions={tool:' / '.join(run([tool,'--version']).decode().splitlines()[:3]) for tool in ['objdump','llvm-objdump','readelf',rustc]}
 result={'target':collect.SHA,'static_bytes':sum(o['bytes'] for o in record['owners']),'static_instructions':sum(o['instructions'] for o in record['owners']),'selected_native_obligations':len(collect.PINS),'corruption_rejections':len(controls),'cases_per_build':count,'rust_observations':count*3,'outcomes':dict(results),'builds':builds,'compiled_mutants':mutants,'versions':{Path(k).name:v for k,v in versions.items()},'source_sha256':collect.sha(SRC.read_bytes()),'support_sha256':{n:collect.sha((ROOT/n).read_bytes()) for n in ['tools/elf_index.py','tools/fde_extents.py']},'collector_sha256':collect.sha((P/'collect.py').read_bytes()),'verifier_sha256':collect.sha(Path(__file__).read_bytes()),'driver_sha256':collect.sha((P/'driver.rs').read_bytes()),'captured_execution':False,'proof_limit':'Logical-byte specification checks under documented memory/helper premises; not captured execution, emulator differential, native ABI or code identity.'}
 (out/'results.json').write_text(collect.dump(result));print(collect.dump(result))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);ap.add_argument('--rustc',default='rustc');a=ap.parse_args();main(a.out.resolve(),a.rustc)

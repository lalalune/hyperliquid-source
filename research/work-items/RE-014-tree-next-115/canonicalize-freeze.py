"""Remove recipe aliases only after proving identical original machine frames."""
import hashlib,json
from pathlib import Path
import native
if (native.ROOT/'src/node115-tree-next/lib.rs').exists():raise RuntimeError('canonicalization refuses new Rust source')
old=native.ROOT/'work/tree-next115-frozen-v2';out=native.ROOT/'work/tree-next115-frozen-final'
if out.exists():raise ValueError('refuse existing output')
pairs=list(zip((old/'inputs.tsv').read_text().splitlines(),(old/'expected.tsv').read_text().splitlines()));lookup=dict(pairs);keep=[];proof=[]
for line,expected in pairs:
 r=list(map(int,line.split('\t')));canonical=r.copy()
 if r[0]==0 and r[1]==0:
  canonical[2]=2
  if r[3]==0:canonical[4]=1000
 key='\t'.join(map(str,canonical))
 if key!=line:
  def frame(row):
   shape,h,fan,leaf,seed,tag,ready,index,level,remaining,walk=row
   return native.fixture(None,h,fan,leaf,tag,shape,seed,ready,index,level,remaining)[0]
  a,b=frame(r),frame(canonical)
  if a.mem!=b.mem or a.regs!=b.regs or a.known!=b.known or a.nodes!=b.nodes or lookup[key]!=expected:raise ValueError('non-equivalent recipe cannot be removed')
  proof.append([line,key])
 else:keep.append((line,expected))
inputs=''.join(a+'\n' for a,b in keep).encode();expected=''.join(b+'\n' for a,b in keep).encode();record=json.loads((native.PACKET/'FREEZE.json').read_text());prior_rows=record['rows']
record.update(rows=len(keep),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),canonicalization='Equivalent height0 fanout and empty-root seed recipes removed after exact initial memory/GPR/known-mask/nodecount and expected-transcript equality; every retained machine frame existed in the actual original freeze, coverage unchanged because removed frames have retained identical representatives.')
# Coverage equality follows actual identical machine frames/code, not regenerated high-level answers.
out.mkdir();(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected);(native.PACKET/'FREEZE.json').write_text(json.dumps(record,indent=2)+'\n')
receipt=dict(original_rows=prior_rows,canonical_rows=len(keep),removed_identical_frames=len(proof),pair_proof_sha256=hashlib.sha256(json.dumps(proof,separators=(',',':')).encode()).hexdigest(),raw_original_streams_preserved='work/tree-next115-frozen and frozen-v2',newRustExists=False,expectations_recomputed_from_model=False)
(native.PACKET/'canonicalization.json').write_text(json.dumps(receipt,indent=2)+'\n')
lookup=dict(keep);smoke=[]
for line in (native.PACKET/'target-smoke.tsv').read_text().splitlines():
 f=line.split('\t');r=list(map(int,f[:11]))
 if r[0]==0 and r[1]==0:
  r[2]=2
  if r[3]==0:r[4]=1000
 key='\t'.join(map(str,r));combined=key+'\t'+lookup[key]+'\n'
 if combined not in smoke:smoke.append(combined)
(native.PACKET/'target-smoke.tsv').write_text(''.join(smoke));print(json.dumps(receipt))

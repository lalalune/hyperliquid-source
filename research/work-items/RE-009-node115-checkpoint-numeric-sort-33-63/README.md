# RE-009 · Node #115 checkpoint numeric sort composition for 33–511 entries

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [restore canonical-height packet](../RE-017-node115-restore-canonical-heights/README.md) links the local checkpoint path to a shared numeric sort but does not establish its 33–511-entry mixed-input result. The [prune path packet](../RE-017-abci-prune-path-115/README.md) supplies the conditional max-heap fallback. This packet composes the selected target-bound contracts for the missing range: prefix/small sorting [#5920](https://github.com/lalalune/hyperliquid-source/pull/5920), [#5921](https://github.com/lalalune/hyperliquid-source/pull/5921), [#5922](https://github.com/lalalune/hyperliquid-source/pull/5922), [#5923](https://github.com/lalalune/hyperliquid-source/pull/5923); pivot [#5926](https://github.com/lalalune/hyperliquid-source/pull/5926) and [#5932](https://github.com/lalalune/hyperliquid-source/pull/5932); partitions [#5927](https://github.com/lalalune/hyperliquid-source/pull/5927), [#5928](https://github.com/lalalune/hyperliquid-source/pull/5928); and recursion [#5929](https://github.com/lalalune/hyperliquid-source/pull/5929).

For a selected N=33..511 valid unsigned vector, a nondecreasing scan returns unchanged; a strictly decreasing scan uses the recorded vector-plus-scalar reversal; mixed input enters the partition worker with budget 2*floor(log2(N)). The cited contracts describe a median pivot, strict partition, the equal-prefix shortcut under its propagated lower bound, smaller recursive/tail slices, small-range sorting and zero-budget heap fallback. Assuming each cited contract, valid buffers, normal returns and no interfering mutation, this composition returns the same multiset in ascending unsigned order. Existing restore evidence separately reverses the rendered candidate rows, subject to its own formatting and filesystem assumptions.

This is a dependency-bound static composition, not independent verification of every cited packet, an execution of the target, evidence that a real checkpoint was selected, or a state-root match. These referenced PRs are unmerged and require review. Zero-budget and small-range behavior in the synthetic model are assumptions backed by the cited evidence, not reimplemented target behavior.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 72 selected spans. Python authenticates target identity, FDEs, selected dispatch and recursion edges, then tests a conditional model for ordering, multiset and propagated bounds on 7,185 duplicate-rich 33–511-word inputs and boundary cases. The model uses independent sorted oracles at helper/fallback leaves and does not execute captured target bytes.

```sh
PYTHONPATH=tools python3 -B - <<'PY'
import csv
import hashlib
from pathlib import Path
import struct
from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, header = unwind_index(data)
_, fdes = eh_frame_records(data, sections)
indexed = {(row["start"], row["fde"]) for row in header}
bounds = {(row["start"], row["end"]) for row in fdes if (row["start"], row["fde"]) in indexed}

def elf_bytes(section_name, address, size):
    section = next(row for row in sections if row["name"] == section_name)
    displacement = address - section["address"]
    assert 0 <= displacement <= displacement + size <= section["size"]
    offset = section["offset"] + displacement
    return data[offset:offset + size]

with Path("research/work-items/RE-009-node115-checkpoint-numeric-sort-33-63/instructions.tsv").open() as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))
spans = {}
for row in rows:
    start, end, address = (int(row[key], 16) for key in ("fde_start", "fde_end", "va"))
    raw = bytes.fromhex(row["bytes"])
    assert address not in spans
    assert (start, end) in bounds and start <= address < address + len(raw) <= end
    assert elf_bytes(".text", address, len(raw)) == raw
    spans[address] = raw

def rip_target(address):
    raw = spans[address]
    return address + len(raw) + struct.unpack_from("<i", raw, len(raw) - 4)[0]

section = next(row for row in sections if row["name"] == ".rela.dyn")
relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
    "<QQq", data[section["offset"]:section["offset"] + section["size"]]
)}

import random
from collections import Counter
assert len(spans)==72
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x1550536)==0x15506d0
assert rip_target(0x1550703)==0x14c6420
assert rip_target(0x1550753)==0x15509d0
assert rip_target(0x1550846)==0x1550340
assert rip_target(0x1550853)==0x15507b6
assert rip_target(0x1550965)==0x15506d0
assert rip_target(0x1550974)==0x1550751
assert rip_target(0x15509e4)==0x64e10b8
assert relocations[0x64e10b8][1]==0x1550630
def rotated_partition(v,pidx,equal=False):
 a=v[:];n=len(a);a[0],a[pidx]=a[pidx],a[0]
 pivot=a[0];saved=a[1];k=0
 for i in range(2,n):
  x=a[i];a[i-1]=a[1+k];a[1+k]=x
  if x<=pivot if equal else x<pivot:k+=1
 a[n-1]=a[1+k];a[1+k]=saved
 if saved<=pivot if equal else saved<pivot:k+=1
 assert k<n
 a[0],a[k]=a[k],a[0]
 return a,k,pivot
def walk(v,prior,budget):
 if prior is not None:assert all(x>=prior for x in v)
 if len(v)<33 or budget==0:return sorted(v) # cited small/heap contracts
 n=len(v);q=n//8
 def middle(ids):return sorted(ids,key=lambda i:v[i])[1]
 ids=(0,4*q,7*q)
 if n>=64:
  r=q//8
  ids=tuple(middle((base,base+4*r,base+7*r)) for base in ids)
 pidx=middle(ids);pivot=v[pidx]
 if prior is not None and prior>=pivot:
  a,k,p=rotated_partition(v,pidx,True)
  assert p==prior and all(x==p for x in a[:k+1]) and all(x>p for x in a[k+1:])
  return a[:k+1]+walk(a[k+1:],None,budget-1)
 a,k,p=rotated_partition(v,pidx)
 assert all(x<p for x in a[:k]) and all(x>=p for x in a[k+1:])
 return walk(a[:k],prior,budget-1)+[p]+walk(a[k+1:],p,budget-1)
def entry(v):
 if all(v[i]>=v[i-1] for i in range(1,len(v))):return v[:]
 if all(v[i]<v[i-1] for i in range(1,len(v))):return v[::-1]
 return walk(v,None,2*(len(v).bit_length()-1))
rng=random.Random(115);cases=0
for n in range(33,512):
 for _ in range(15):
  v=[rng.choice((0,1,2,2**63,2**64-1)) for i in range(n)]
  a=entry(v);assert a==sorted(v) and Counter(a)==Counter(v);cases+=1
 asc=list(range(n));desc=asc[::-1]
 assert entry(asc)==asc and entry(desc)==asc and walk(desc,None,0)==asc
v=[1,1,0]+[2]*30
a,k,p=rotated_partition(v,0,True)
assert not all(x<p for x in a[:k]) # wrong comparison violates strict partition
for addr in (0x1550536,0x1550965):
 bad=bytearray(spans[addr]);bad[-1]^=1
 assert bad!=elf_bytes('.text',addr,len(bad))
print(f'{len(spans)} authenticated spans and {cases} conditional sort models pass')
PY
```

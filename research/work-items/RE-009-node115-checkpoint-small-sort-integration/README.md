# RE-009 · Node #115 checkpoint small-sort half integration

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [checkpoint prune small-sort packet](../RE-009-node115-checkpoint-prune-small-sort/README.md) proves the insertion loop for 2–8 words. [#5920](https://github.com/lalalune/hyperliquid-source/pull/5920) and [#5921](https://github.com/lalalune/hyperliquid-source/pull/5921) validate distinct nine- and thirteen-word prefix networks; [#5922](https://github.com/lalalune/hyperliquid-source/pull/5922) models the later merge when both halves are sorted. This packet traces the intervening insertion and repeated-half control flow.

For N=9..17 the selected network sorts a prefix of the entire range; the same insertion loop finishes that range and the N<18 branch returns directly. For selected helper inputs N=18..32, the first half has floor(N/2) words and the second has the remainder, each of length 9..16. A half of length 9..12 selects the nine-word network; a half of length 13..16 selects the thirteen-word network. With the network output sorted and valid non-overlapping storage, the selected loop starts at the first unprocessed word, compares unsigned with its predecessor, shifts strictly greater predecessors right until the beginning or a no-greater word, and inserts the saved word. Equality does not shift. It repeats until the current half ends, switches once to the second half, then transfers to the selected merge at `0x14c6a2d`.

Combining those conditional contracts, the modeled selected helper path produces two sorted halves and supplies them to the previously documented merge. This is a composition of separate unmerged evidence packets and is not an independent full-function execution, a claim of actual checkpoint reachability, or a state-root proof. Normal returns, valid buffers and no interfering mutation are assumed. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 60 selected instruction spans. The script checks target identity, FDEs, selected control transfers, and a synthetic model of sorted-prefix insertion and two-ended merge over binary inputs. The exhaustive domain assumes the prefix networks' outputs are sorted; it does not verify those networks again or execute target bytes.

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

with Path("research/work-items/RE-009-node115-checkpoint-small-sort-integration/instructions.tsv").open() as handle:
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

import itertools
assert len(spans)==60
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x14c6494)==0x14c67d0
assert rip_target(0x14c67d9)==0x14c699c
assert rip_target(0x14c69c5)==0x14c6490
assert short(0x14c69cb)==0x14c6a2d
assert short(0x14c69ac)==0x14c69d0
assert short(0x14c69f1)==0x14c69ae
assert short(0x14c69fd)==0x14c69e6
assert short(0x14c6a18)==0x14c69e0
assert short(0x14c6a26)==0x14c6a10
assert short(0x14c6a2b)==0x14c69e3
def insertion(values,p,mutate=False):
 a=list(values)
 assert a[:p]==sorted(a[:p])
 for i in range(p,len(a)):
  x=a[i];j=i
  while j and ((x<a[j-1]) != mutate):
   a[j]=a[j-1];j-=1
  a[j]=x
 return a
def merge(a,b):
 li,lj,ri,rj=0,len(a)-1,0,len(b)-1
 n=len(a)+len(b);out=[None]*n
 for i in range(n//2):
  if b[ri]<a[li]:out[i]=b[ri];ri+=1
  else:out[i]=a[li];li+=1
  if b[rj]>=a[lj]:out[n-1-i]=b[rj];rj-=1
  else:out[n-1-i]=a[lj];lj-=1
 if n%2:
  if li<=lj:out[n//2]=a[li];li+=1
  else:out[n//2]=b[ri];ri+=1
 assert li==lj+1 and ri==rj+1
 return out
def halves(length):
 p=9 if length<=12 else 13
 for zeros in range(p+1):
  for suffix in itertools.product((0,1),repeat=length-p):
   yield [0]*zeros+[1]*(p-zeros)+list(suffix),p
cases=0
for n in range(9,18):
 for v,p in halves(n):
  assert insertion(v,p)==sorted(v)
  cases+=1
for n in range(18,33):
 h=n//2
 for left,lp in halves(h):
  for right,rp in halves(n-h):
   a=insertion(left,lp);b=insertion(right,rp)
   assert merge(a,b)==sorted(left+right)
   cases+=1
v=[0]*9+[1,0]
assert insertion(v,9)==sorted(v)
assert insertion(v,9,True)!=sorted(v)
for a in (0x14c69c5,0x14c69fd):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans; {cases} selected-half compositions pass')
PY
```

# RE-009 · Node #115 checkpoint equal-pivot partition

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [prune path packet](../RE-017-abci-prune-path-115/README.md) identifies the mixed numeric-sort boundary. [#5926](https://github.com/lalalune/hyperliquid-source/pull/5926) selects a pivot for 33–63 words and [#5932](https://github.com/lalalune/hyperliquid-source/pull/5932) covers 64–511 words; [#5927](https://github.com/lalalune/hyperliquid-source/pull/5927) examines the first partition and leaves the nonzero previous-pivot case open.

On the selected nonzero previous-pivot branch, if the prior pivot word is unsigned-smaller than the new pivot, the code transfers to the ordinary partition. Otherwise it moves the new pivot to the first word, scans the other words through a rotation loop, and advances the prefix count when a word is unsigned-less-than-or-equal to the pivot. After the saved second word is inserted, the pivot is moved to the end of that prefix and the continuation skips the prefix without a left recursive call. If, additionally, every current word is at least the prior pivot, then the new pivot must equal the prior pivot on this branch and the skipped prefix consists only of equal words. Those ordering assumptions are explicit; the packet does not prove them for every recursive call, later recursion, actual checkpoint inputs, full sorting or state-root equality. No captured binary executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 80 selected spans. Python authenticates the target bytes, indexed FDE and branches; a derived rotation model checks equal-prefix partitions across 33–511 words, unsigned edge values and a strict-comparison mutation. The synthetic model is not target execution.

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

with Path("research/work-items/RE-009-node115-checkpoint-equal-pivot-partition/instructions.tsv").open() as handle:
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
assert len(spans)==80
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x15507b0)==0x1550859
assert rip_target(0x1550853)==0x15507b6
assert rip_target(0x15507c1)==0x1550860
assert rip_target(0x15507e8)==0x155097f
assert short(0x1550823)==0x15507f0
assert short(0x15509c2)==0x15509a0
assert rip_target(0x15509cb)==0x1550710
assert rip_target(0x1550725)==0x15509ea
assert short(0x155074f)==0x15506eb
def partition(values,pidx,strict=False):
 a=values[:];n=len(a);a[0],a[pidx]=a[pidx],a[0]
 pivot=a[0];saved=a[1];k=0
 for i in range(2,n):
  x=a[i];a[i-1]=a[1+k];a[1+k]=x
  if x<pivot if strict else x<=pivot:k+=1
 a[n-1]=a[1+k];a[1+k]=saved
 if saved<pivot if strict else saved<=pivot:k+=1
 assert k<n
 a[0],a[k]=a[k],a[0]
 return a,k,pivot
rng=random.Random(115);cases=0
for n in range(33,512):
 for prior in (0,1,2**63,2**64-2,2**64-1):
  for _ in range(2):
   vals=[rng.choice((prior,2**64-1)) for i in range(n)]
   vals[0]=prior
   a,k,pivot=partition(vals,0)
   assert Counter(a)==Counter(vals) and pivot==prior
   assert all(x==prior for x in a[:k+1]) and all(x>prior for x in a[k+1:])
   cases+=1
v=[1]*33
a,k,p=partition(v,0,True)
assert k+1!=len(v)
for a in (0x15507c1,0x15509cb):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and {cases} equal-prefix models pass')
PY
```

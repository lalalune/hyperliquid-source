# RE-009 · Node #115 checkpoint numeric partition recursion contract

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [prune path packet](../RE-017-abci-prune-path-115/README.md) identifies the partition and heap fallback. [#5927](https://github.com/lalalune/hyperliquid-source/pull/5927) models the selected strict partition; [#5928](https://github.com/lalalune/hyperliquid-source/pull/5928) models the separate equal-prefix branch conditional on a previous-pivot lower bound. This packet traces how the selected caller passes lengths, the lower-bound pointer and partition budget between these branches.

For an initial mixed-input N=33..511, the caller's BSR/XOR arithmetic supplies budget 2*floor(log2(N)). A selected normal strict partition puts pivot at index k, calls the left slice with k words and the incoming previous-pivot pointer, then continues with N-k-1 words to the right and points the previous-pivot argument at the placed pivot. If the incoming lower-bound invariant held, it is preserved for the left subset; the strict partition's documented `>= pivot` right side establishes the new bound for the right subset. Both slices are shorter than N. Each selected partition decrements its local budget; zero budget selects relocation-resolved fallback `0x1550630`, and a slice smaller than 33 selects the previously documented small helper. On the equal-prefix route, the code skips k+1 words and clears the previous-pivot pointer before continuing.

This is a conditional composition of the cited unmerged partition findings and their valid-buffer, no-mutation and normal-return assumptions. It does not independently prove pivot choice, partition results, fallback semantics, completion of sorting, runtime checkpoint reachability, or any state root. The initial budget bounds consecutive partition levels on the selected budget path, not total recursive calls. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 61 selected spans. Python verifies the pinned target and indexed FDEs, branch/call/relocation targets, initial budgets for N=33..63, and a synthetic invariant model; the model assumes the cited partition contracts and does not execute target bytes.

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

with Path("research/work-items/RE-009-node115-checkpoint-partition-recursion-contract/instructions.tsv").open() as handle:
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
assert len(spans)==61
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x1550536)==0x15506d0
assert rip_target(0x1550753)==0x15509d0
assert rip_target(0x1550853)==0x15507b6
assert rip_target(0x1550965)==0x15506d0
assert rip_target(0x1550974)==0x1550751
assert short(0x155074f)==0x15506eb
assert rip_target(0x15509e4)==0x64e10b8
assert relocations[0x64e10b8][1]==0x1550630
assert spans[0x15507a8]==bytes.fromhex('ffcd')
assert spans[0x155095c]==bytes.fromhex('4c89e2')
assert spans[0x155096a]==bytes.fromhex('4d89ec')
for n in range(33,512):
 bsr=(n|1).bit_length()-1
 budget=((bsr^63)*2)^126
 assert budget==2*(n.bit_length()-1)
 for k in range(n):
  assert 0<=k<n and 0<=n-k-1<n
# Abstract contract test: strict partition, bound propagation, bounded depth.
def walk(v,prior,budget):
 if prior is not None:assert all(x>=prior for x in v)
 if len(v)<33 or budget==0:return sorted(v) # helper contracts assumed
 pivot=v[len(v)//2]
 if prior is not None and prior>=pivot:
  assert prior==pivot
  equal=[x for x in v if x<=pivot];right=[x for x in v if x>pivot]
  assert all(x==pivot for x in equal) and len(right)<len(v)
  return equal+walk(right,None,budget-1)
 left=[x for x in v if x<pivot];right=[x for x in v if x>=pivot]
 right.remove(pivot)
 assert len(left)<len(v) and len(right)<len(v)
 return walk(left,prior,budget-1)+[pivot]+walk(right,pivot,budget-1)
rng=random.Random(115)
for n in range(33,512):
 for _ in range(5):
  v=[rng.choice((0,1,2,2**63,2**64-1)) for i in range(n)]
  assert walk(v,None,2*(n.bit_length()-1))==sorted(v)
assert not all(x>=2 for x in [1,2,3]) # corrupted prior bound is rejected
for a in (0x1550965,0x1550974):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and conditional recursion models pass')
PY
```

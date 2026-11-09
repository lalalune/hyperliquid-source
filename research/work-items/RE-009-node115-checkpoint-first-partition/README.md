# RE-009 · Node #115 checkpoint numeric first partition

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [prune path packet](../RE-017-abci-prune-path-115/README.md) identifies the mixed-input partition boundary; [#5926](https://github.com/lalalune/hyperliquid-source/pull/5926) maps the selected 33–63-word pivot and [#5932](https://github.com/lalalune/hyperliquid-source/pull/5932) maps the larger pivot. This packet traces the first partition on the branch entered with a zero previous-pivot pointer, as supplied by the selected `0x15504d0` mixed-input entry.

With a valid contiguous range, selected nonzero budget and N=33..511, the code swaps the chosen pivot into element zero, saves element one, and traverses the remaining words using a two-at-a-time loop plus an optional final word. Its unsigned less-than decisions rotate each scanned word into the prefix and advance the prefix count exactly when the word is strictly smaller than the pivot. It reinserts the saved second word and swaps the pivot to index k, where k is the count of strictly smaller words. The selected normal path therefore partitions into words `< pivot`, the pivot, then words `>= pivot`, preserving the multiset. It recursively calls the left slice and continues with the right slice. An out-of-range k reaches `ud2`.

The claim assumes normal memory accesses, no alias mutation and the selected zero-previous-pivot branch. It does not prove recursive completion, the separate nonzero previous-pivot branch, runtime reachability, full checkpoint ordering or state-root equivalence. No captured target code executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 93 selected spans. Python authenticates the pinned bytes, indexed FDEs and selected branch/call edges; a derived rotation model tests duplicates, zero, high-bit and maximum unsigned values across 28,740 synthetic partitions plus a mutated comparison. The model does not execute the target.

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

with Path("research/work-items/RE-009-node115-checkpoint-first-partition/instructions.tsv").open() as handle:
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
assert len(spans)==93
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert spans[0x1550534]==bytes.fromhex('31d2')
assert spans[0x155070a]==bytes.fromhex('4989d4')
assert rip_target(0x1550536)==0x15506d0
assert rip_target(0x15507b0)==0x1550859
assert rip_target(0x1550853)==0x15507b6
assert short(0x1550881)==0x15508e0
assert short(0x15508c9)==0x1550890
assert short(0x1550912)==0x15508f0
assert rip_target(0x1550930)==0x15509ea
assert rip_target(0x1550965)==0x15506d0
def partition(values,pidx,mutate=False):
 a=values[:];n=len(a);a[0],a[pidx]=a[pidx],a[0]
 pivot=a[0];saved=a[1];k=0
 for i in range(2,n):
  x=a[i];a[i-1]=a[1+k];a[1+k]=x
  if (x<pivot)!=mutate:k+=1
 a[n-1]=a[1+k];a[1+k]=saved
 if (saved<pivot)!=mutate:k+=1
 assert k<n
 a[0],a[k]=a[k],a[0]
 return a,k,pivot
rng=random.Random(115)
cases=0
for n in range(33,512):
 for _ in range(20):
  v=[rng.choice((0,1,2,2**63,2**64-1)) for i in range(n)]
  for pidx in (0,n//2,n-1):
   a,k,pivot=partition(v,pidx)
   assert Counter(a)==Counter(v) and all(x<pivot for x in a[:k]) and a[k]==pivot and all(x>=pivot for x in a[k+1:])
   cases+=1
v=[1,0]+[2]*31
a,k,pivot=partition(v,0,True)
assert not (all(x<pivot for x in a[:k]) and all(x>=pivot for x in a[k+1:]))
for a in (0x15507b0,0x1550965):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and {cases} partition models pass')
PY
```

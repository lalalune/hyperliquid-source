# RE-009 · Node #115 checkpoint numeric pivot for 64–511 words

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [prune path packet](../RE-017-abci-prune-path-115/README.md) identifies a mixed numeric-sort partition boundary. [#5926](https://github.com/lalalune/hyperliquid-source/pull/5926) traces the different 33–63-word median selection. This packet resolves the selected larger-range pivot call for N=64..511 and nonzero partition budget.

The caller computes q=floor(N/8) and invokes `0x1550340` with base candidates at word indices 0, 4q and 7q, and step q. Since 8<=q<=63, the helper performs exactly one recursive level: it uses r=floor(q/8), and recursively chooses the median from each base plus offsets 0, 4r and 7r. Each child receives r<8 and therefore takes the leaf comparison. The parent returns the median of those three medians. All nine resulting indices are in the selected range. This median-of-three-medians need not be the median of all nine words. For N>=512 the same helper recurses more than once: writing q0=floor(N/8), q(i+1)=floor(qi/8), it continues while qi>=8 and takes a three-candidate median leaf when qi<8. With a valid nonwrapping input buffer, the maximum candidate index is at most 7 times the sum of these q values, which is strictly less than 8q0<=N; this bounds every selected read. The return is a recursive median tree, not a global median. The equal-candidate pointer choice, later partition, actual checkpoint reachability and complete sort remain outside this packet. No captured target code executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 74 selected spans. Python authenticates target bytes/FDEs and recursive/caller edges, checks all 448 candidate-index bounds, validates the leaf median comparisons on ternary triples and their composition over 19,683 ternary nine-tuples, checks recursive candidate bounds for sampled larger N, and checks a counterexample to the global-median interpretation. The model does not execute target code.

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

with Path("research/work-items/RE-009-node115-checkpoint-large-sort-ninther/instructions.tsv").open() as handle:
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
assert len(spans)==74
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert short(0x1550355)==0x15503ac
assert rip_target(0x1550371)==0x1550340
assert rip_target(0x1550387)==0x1550340
assert rip_target(0x15503a1)==0x1550340
assert rip_target(0x1550775)==0x1550840
assert rip_target(0x1550846)==0x1550340
for n in range(64,512):
 q=n//8;r=q//8
 assert 8<=q<=63 and 1<=r<8
 idx=[base+offset for base in (0,4*q,7*q) for offset in (0,4*r,7*r)]
 assert len(set(idx))==9 and all(0<=x<n for x in idx)
# Recursive levels use q, q//8, ...; the largest candidate offset is
# 7*sum(q_i), bounded by N-1.  Large inputs are checked arithmetically
# instead of materializing a potentially enormous recursion tree.
for n in list(range(512,8193))+[2**30-1,2**40+17,2**60-1]:
 q=n//8;levels=[]
 while True:
  levels.append(q)
  if q<8:break
  q//=8
 assert 7*sum(levels)<n and len(levels)<=20
assert len([8,1])==2 and 7*(8+1)==63 # first recursive boundary
def median(a,b,c):
 p=a<b;q=a<c;r=b<c
 ix=1
 if r!=p:ix=2
 if q!=p:ix=0
 return (a,b,c)[ix]
for t in itertools.product(range(3),repeat=3):
 assert median(*t)==sorted(t)[1]
for v in itertools.product(range(3),repeat=9):
 m=[median(*v[i:i+3]) for i in (0,3,6)]
 assert median(*m)==sorted(m)[1]
v=(0,0,9,0,0,9,9,9,9)
assert median(*(median(*v[i:i+3]) for i in (0,3,6)))!=sorted(v)[4]
for addr in (0x1550371,0x1550846):
 bad=bytearray(spans[addr]);bad[-1]^=1
 assert bad!=elf_bytes('.text',addr,len(bad))
print(f'{len(spans)} authenticated spans; 448 index cases and 19683 pivot models pass')
PY
```

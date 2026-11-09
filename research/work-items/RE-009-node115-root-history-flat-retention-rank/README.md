# RE-009 · Node #115 flat root-history retention rank

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [history retention walk](../RE-009-node115-root-history-retention-walk/README.md) establishes a count threshold and 43 subsequent successful cursor calls but leaves the logical rank open. The [flat cutoff packet](../RE-009-node115-root-history-flat-cutoff/README.md) shows that the selected removal helper counts keys strictly below the supplied cutoff. This packet joins the flat cursor's initial unrolled advances to the 43 calls.

On the selected flat-ring path with valid nonzero backing storage, capacity C<2^63, start S<C and 51<=N<=C, with nonwrapping pointer arithmetic, the cursor constructs up to two 40-byte physical spans and walks them backward in logical order. Seven successful inlined advances precede 43 calls to `0x4e2a530`; each call returns the next earlier row on the selected flat representation. The final key passed to `0x4de5ad0` is therefore the 50th row from the logical end, i.e. zero-based logical index N−50. The 51 threshold and valid ring assumptions guarantee enough rows for this selected traversal. The tree cursor is not covered.

If logical keys are nondecreasing, the previously documented cutoff count leaves at least 50 candidate survivors; with strictly increasing keys it specifies exactly 50, while duplicate cutoff keys can specify more. Publication of those survivors is not established. This conclusion depends on the cited removal packet, valid metadata, no intervening mutation and successful helpers; it is not evidence of a real node's retention count, persistence, or checkpoint root. No captured target code executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 373 selected spans. Python verifies the pinned target, indexed FDEs, seven inline 40-byte advances, all 43 call/test/exit sequences, final projection and removal edge. The synthetic flat-ring model checks wrapped and unwrapped layouts, rank and duplicate cutoffs; it is not execution of target bytes.

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

with Path("research/work-items/RE-009-node115-root-history-flat-retention-rank/instructions.tsv").open() as handle:
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

assert len(spans)==373
assert rip_target(0x5a03fb8)==0x4dd45c0
assert rip_target(0x5a03fc5)==0x5a040aa
assert spans[0x5a03fc1]==bytes.fromhex('4883fa33')
first=0x5a04099
assert spans[first]==bytes.fromhex('4883c0d8')
for addr in (0x5a040f5,0x5a0414b,0x5a041a8,0x5a04205,0x5a0426f,0x5a042c4):
 assert spans[addr]==bytes.fromhex('4883c1d8')
for i in range(43):
 addr=0x5a042ff+i*0x13
 assert rip_target(addr)==0x4e2a530
 assert spans[addr+5]==bytes.fromhex('4885c0')
 assert rip_target(addr+8)==0x5a040aa
assert rip_target(0x4e2a533)==0x514dc20
assert spans[0x4e2a55f]==bytes.fromhex('4883c1d8')
assert rip_target(0x5a0464a)==0x4de5ad0
assert spans[0x5a04635]==bytes.fromhex('488b00')
cases=0
for n in range(51,81):
 keys=[i//3 for i in range(n)]
 for cap in (n,n+1,n+7):
  for start in range(cap):
   physical=[None]*cap
   for i,x in enumerate(keys):physical[(start+i)%cap]=x
   tail=min(n,cap-start);first=physical[start:start+tail];second=physical[:n-tail]
   walked=list(reversed(second))+list(reversed(first))
   assert walked==list(reversed(keys))
   cutoff=walked[49]
   assert cutoff==keys[n-50]
   kept=[x for x in keys if x>=cutoff]
   assert len(kept)>=50
   cases+=1
 keys=list(range(n));assert len([x for x in keys if x>=keys[n-50]])==50
assert len([x for x in range(60) if x//3>=10//3])>50
for addr in (0x5a042ff,0x5a0464a):
 bad=bytearray(spans[addr]);bad[-1]^=1
 assert bad!=elf_bytes('.text',addr,len(bad))
print(f'{len(spans)} authenticated spans and {cases} flat-ring models pass')
PY
```

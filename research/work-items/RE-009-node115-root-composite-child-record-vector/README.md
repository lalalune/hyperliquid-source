# RE-009 · Node #115 composite root child-record vector

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [block-root packet](../RE-017-abci-block-root-115/README.md) identifies reducer `0x141a250`; [#5951](https://github.com/lalalune/hyperliquid-source/pull/5951) traces its first non-skipped composite child record. This packet follows subsequent selected child slots into the record vector.

Assume valid 24-byte child slots, at least one non-skipped child, normal recursive returns, successful allocation/growth and no alias mutation. After the first record, the selected path initializes a vector with capacity four and length one. Each subsequent sentinel `0x8000000000000001` slot or recursive result with tag byte 2 is skipped; for each other result it stages a 48-byte record containing the original zero-based child index followed by the returned tag and copied 39-byte region, then appends it at 48 times the current vector length. If length equals capacity, it calls the growth helper with one additional element, alignment 8 and element size 48 before storing. The length increments only after an append. Relative input order and original indexes are retained across skipped slots.

The first child's 32-byte digest interpretation is conditional on #5951 and the child finalizer; the final seven bytes of the copied region and later vector consumption are not interpreted. The zero-eligible case, helper internals, allocation failure, actual runtime state and complete root remain open. No captured target code executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 124 selected spans. Python authenticates target/FDE, recursive dispatch, skip/growth/store edges and selected vector layout; synthetic child sequences check ordering, indexes and 48-byte boundaries. The model assumes successful growth and is not target execution.

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

with Path("research/work-items/RE-009-node115-root-composite-child-record-vector/instructions.tsv").open() as handle:
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
assert len(spans)==124
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x141a3f1)==0x64df500 and relocations[0x64df500][1]==0x141a250
assert rip_target(0x141a595)==0x64df500
assert short(0x141a566)==0x141a5ad
assert short(0x141a5ab)==0x141a5c0
assert rip_target(0x141a64e)==0x141a550
assert rip_target(0x141a6b3)==0x141b050
assert rip_target(0x141a705)==0x141a543
assert spans[0x141a4ab]==bytes.fromhex('bfc0000000')
assert spans[0x141a6a5]==bytes.fromhex('41b830000000')
assert spans[0x141a6cb]==bytes.fromhex('48c1e104')
assert spans[0x141a6fa]==bytes.fromhex('49ffc6')
def records(kinds):
 out=[]
 for i,k in enumerate(kinds):
  if k in (0,2):continue # sentinel or result tag 2
  result=bytes([0])+bytes([i%256])*39
  out.append(i.to_bytes(8,'little')+result)
 return out
cases=0
for n in range(1,9):
 for kinds in itertools.product((0,1,2),repeat=n):
  rows=records(kinds)
  if not rows:continue
  assert all(len(r)==48 for r in rows)
  assert [int.from_bytes(r[:8],'little') for r in rows]==[i for i,k in enumerate(kinds) if k==1]
  assert b''.join(rows)[::48]==bytes(int.from_bytes(r[:8],'little') for r in rows)
  cases+=1
assert [int.from_bytes(r[:8],'little') for r in records((1,0,2,1,1))]==[0,3,4]
for a in (0x141a595,0x141a6b3):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and {cases} child-vector models pass')
PY
```

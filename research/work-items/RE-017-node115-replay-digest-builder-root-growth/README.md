# RE-017 · Node #115 replay digest builder first root growth

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5903](https://github.com/lalalune/hyperliquid-source/pull/5903) traces insertion while the current digest-builder node has fewer than 11 rows. This packet examines a different selected boundary: a full root node with no parent and recorded depth zero.

When its node count is 11, the builder follows `+0x160` to the null-parent branch. Assuming the original root and zero depth, the first successful allocation requests `0x1d0` bytes, clears the new node's `+0x160/+0x16a`, stores the old root at new `+0x170`, links old `+0x160` back to the new node and writes old `+0x168 = 0`. It publishes the new root and depth 1. A second successful allocation requests `0x170` bytes and clears the new node's parent and row-count fields. With new depth 1, the selected loop skip goes directly to insertion in the new root: its count changes 0 to 1, the pending 32-byte row is copied at root offset 0, and root `+0x178` receives the new child. The new child's `+0x160/+0x168` link back to root and child index 1.

This is a selected structural boundary, not a complete split algorithm or a claim about all rows, ordering, ownership or subsequent builder steps. It assumes valid objects, the stated initial depth/parent/count, nonnull allocations, no alias changes, and the selected continuations. Allocation-failure and depth-overflow branches are boundaries. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 68 selected instruction spans. Python 3 checks target identity, indexed FDEs, branch/call displacements, corruption controls and a synthetic link projection.

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

with Path("research/work-items/RE-017-node115-replay-digest-builder-root-growth/instructions.tsv").open() as handle:
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

def short_target(address):
    raw=spans[address];return address+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x5155deb)==0x4cc0050
assert rip_target(0x4cc0343)==0x4cc0180
assert short_target(0x4cc035a)==0x4cc0370
assert rip_target(0x4cc037e)==0x64df480
assert rip_target(0x4cc0387)==0x4cc06cd
assert rip_target(0x4cc03d6)==0x64df480
assert rip_target(0x4cc03df)==0x4cc06a0
assert short_target(0x4cc0402)==0x4cc045a
assert rip_target(0x4cc0466)==0x4cc06b2
assert spans[0x4cc0379]==bytes.fromhex('bfd0010000')
assert spans[0x4cc03d1]==bytes.fromhex('bf70010000')
old={'count':11,'parent':None};root={'count':0,'parent':None,'left':old};old['parent']=root;old['index']=0
depth=1;right={'count':0,'parent':root,'index':1};key=bytes(range(32));root.update(count=1,key=key,right=right)
assert depth==1 and root['left'] is old and old['index']==0
assert root['right'] is right and right['parent'] is root and right['index']==1
assert root['count']==1 and root['key']==key
for addr in (0x4cc0379,0x4cc0498):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

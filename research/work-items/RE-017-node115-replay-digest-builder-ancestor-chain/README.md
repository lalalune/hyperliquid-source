# RE-017 · Node #115 replay digest builder multi-ancestor chain

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5905](https://github.com/lalalune/hyperliquid-source/pull/5905) traces the selected one-parent-hop path when a full digest-builder node has a parent with room. This packet examines the distinct selected case where one or more full ancestors are traversed before a nonfull ancestor is reached.

Starting from a full current node, each nonnull parent hop increments a local counter h; a parent count of at least 11 repeats the climb, while a count below 11 selects that ancestor. For h at least 2 and successful allocations, the builder allocates one `0x170` node, clears its parent and row count, then loops `h-1` times allocating `0x1d0` nodes. Each selected loop iteration clears the new node's parent/count, writes the previous chain head at new `+0x170`, and writes the previous head's parent/index fields to the new node and zero. At the selected nonfull ancestor with count k, it appends the pending 32-byte row at `+32*k`, stores the final chain head at `+0x178+8*k`, and writes the head's parent/index fields to the ancestor and `k+1`.

This is conditional local structure, not a general proof of balancing or a real replay. It assumes valid acyclic parent pointers, representable h, `0 <= k < 11`, nonnull allocations, normal helper behavior and no alias changes. Root-growth, later propagation, allocation failure and exception behavior remain outside this packet. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 51 selected instruction spans. Python 3 verifies target identity, FDEs, selected direct transfers, corruption controls and synthetic h=2/3 link-count cases.

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

with Path("research/work-items/RE-017-node115-replay-digest-builder-ancestor-chain/instructions.tsv").open() as handle:
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
assert rip_target(0x4cc0343)==0x4cc0180
assert short_target(0x4cc035a)==0x4cc0370
assert short_target(0x4cc0368)==0x4cc0350
assert short_target(0x4cc036a)==0x4cc03ce
assert rip_target(0x4cc03d6)==0x64df480
assert rip_target(0x4cc0415)==0x64df480
assert rip_target(0x4cc041e)==0x4cc0675
assert short_target(0x4cc0458)==0x4cc0410
assert short_target(0x4cc0402)==0x4cc045a
for h in (2,3):
    ancestor={'count':2};head={'type':'leaf'};allocations=0
    for i in range(h-1):
        parent={'type':'internal','child0':head};head['parent']=parent;head['index']=0;head=parent;allocations+=1
    ancestor['child']=head;head['parent']=ancestor;head['index']=3
    assert allocations==h-1 and head['parent'] is ancestor and head['index']==ancestor['count']+1
for addr in (0x4cc0415,0x4cc0458):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

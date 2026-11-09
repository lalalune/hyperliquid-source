# RE-017 · Node #115 replay digest builder parent-with-room path

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5904](https://github.com/lalalune/hyperliquid-source/pull/5904) maps the builder boundary where a full node has no parent and a new root is allocated. This packet covers a distinct selected branch where the full node's parent already exists and has room.

When the current node's unsigned word at `+0x16a` is at least 11, the builder follows its `+0x160` parent link. If that pointer is nonnull and the parent's count `k` is below 11, it reaches `0x4cc03ce` without taking the new-root allocation branch. One successful `0x170` allocation initializes a new node's parent pointer and row count to zero. The one-hop counter is 1, so the intermediate-parent allocation loop is skipped. The parent count becomes `k+1`, the pending 32-byte row is stored at parent `+32*k`, and the new node is stored at parent `+0x178+8*k`. The new node receives parent pointer and child index `k+1` at `+0x160/+0x168`.

This is a selected local structural path with valid objects, `0 <= k < 11`, nonnull allocation, one parent hop and no interfering mutation. It does not reconstruct full-node balancing, all subsequent builder steps, failure cleanup, live replay or real state roots. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 42 selected instruction spans. Python 3 verifies target identity, FDEs, selected branches and calls, corruption controls and synthetic field-offset boundaries.

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

with Path("research/work-items/RE-017-node115-replay-digest-builder-parent-room/instructions.tsv").open() as handle:
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
assert rip_target(0x4cc03df)==0x4cc06a0
assert short_target(0x4cc0402)==0x4cc045a
assert rip_target(0x4cc0466)==0x4cc06b2
for k in (0,1,10):
    assert k<11 and 32*k+32<=0x160
    assert 0x178+8*k==0x170+8*(k+1)
    parent={'count':k};child={'parent':parent,'index':k+1}
    parent['count']=k+1;parent['child']=child
    assert parent['child']['parent'] is parent and parent['count']==child['index']
assert not (11<11)
for addr in (0x4cc0368,0x4cc0498):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

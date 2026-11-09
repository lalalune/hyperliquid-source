# RE-017 · Node #115 replay digest preparation scratch sizing

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5897](https://github.com/lalalune/hyperliquid-source/pull/5897) identifies the converter's preparation call for materialized counts at least 21, while [#5899](https://github.com/lalalune/hyperliquid-source/pull/5899) conditionally relates that count to the input ring. This packet maps the selected preparation wrapper's scratch allocation and worker arguments, not the worker's algorithm.

The indirect slot `0x64e58b0` resolves to `0x4f38080`. For count N in the previously documented valid range, its arithmetic computes `B = min(250000, ceil(N/2))`. When B is at most 128 it uses its 4096-byte local stack area and passes scratch capacity 128. When B is at least 129 it requests `32*B` bytes, passes the returned pointer and capacity B, and on the selected normal return calls the release slot with `32*B`. Allocation failure reaches a separate failure slot. The wrapper passes a boolean N < 65 as R8 and the original third argument as R9 to `0x4f848d0`. In the selected converter path the scratch storage changes from stack to heap between N=256 and N=257, while the R8 boolean changes between N=64 and N=65.

This establishes wrapper arithmetic and selected calls only. It does not prove the worker sorts correctly, allocator semantics, safe operation on malformed sizes, full tree construction, real replay input count or runtime reachability. All execution observations are static; no captured binary is run.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 65 selected instruction spans. Python 3 verifies target identity, FDEs, relocation, branch and call displacements, corruption controls and synthetic threshold arithmetic.

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

with Path("research/work-items/RE-017-node115-replay-digest-sort-scratch/instructions.tsv").open() as handle:
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
assert rip_target(0x5155e7c)==0x64e58b0
assert relocations[0x64e58b0][1]==0x4f38080
assert short_target(0x4f380bd)==0x4f380c9
assert short_target(0x4f380c7)==0x4f3810c
assert rip_target(0x4f3811d)==0x4f848d0
assert short_target(0x4f38129)==0x4f3813d
for n,b,local,flag in ((21,11,True,True),(64,32,True,True),(65,33,True,False),(256,128,True,False),(257,129,False,False),(500001,250000,False,False)):
    calculated=min(min(n,250000),n-(n//2))
    assert calculated==b==min(250000,(n+1)//2)
    assert (b<=128)==local and (n<65)==flag
for addr in (0x4f380b6,0x4f3811d):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

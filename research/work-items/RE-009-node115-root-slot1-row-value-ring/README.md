# RE-009 · Node #115 circular-row value ring projection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4208](https://github.com/lalalune/hyperliquid-source/pull/4208) maps the selected circular-row value to three children and traces the first child's tree projection. This packet follows its second child `0x450eb50`, whose source is at value `+0`, into a distinct circular array of eight-byte entries. The pointer joins remain conditional on the selected dispatch.

The method reads capacity at source `+0`, array base at `+8`, index at `+0x10` and count at `+0x18`. On the selected valid nonzero-count path it subtracts capacity once if the unsigned index is at least capacity, builds a first range from the resulting index to either capacity or index plus count, and a second range beginning at zero for any wrap. It traverses the first range before the second, stepping by eight bytes, and builds a temporary 16-byte `(pointer, descriptor)` pair for each selected element. Zero count yields no selected elements. The method sends a separate count descriptor and the pair list to `0x41ae280`, then frees the temporary allocation on selected normal return.

Each element uses descriptor `0x648e2e0`, whose visitor/constructor are `0x3916030/0x3916020`. They tail-jump to the raw qword writer and constructor described in [PR #4199](https://github.com/lalalune/hyperliquid-source/pull/4199). This is a different ring from the outer `0x70`-stride representation in [PR #4205](https://github.com/lalalune/hyperliquid-source/pull/4205). Synthetic tests cover nonwrapped, wrapped and empty index sequences only; malformed ring state, actual runtime values, complete digest composition and checkpoint replay remain open.

## Reproduce

GNU and LLVM agree on the selected instruction spans; descriptor, helper and tail-call relocations are checked against the authenticated target.
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

with Path("research/work-items/RE-009-node115-root-slot1-row-value-ring/instructions.tsv").open() as handle:
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
assert rip_target(0x3917d41) == 0x646ef18
assert relocations[0x646ef30] == (8, 0x450eb50)
assert rip_target(0x450ec3e) == 0x648e2e0
assert relocations[0x648e2f8] == (8, 0x3916030)
assert relocations[0x648e300] == (8, 0x3916020)
assert relocations[rip_target(0x3916030)] == (8, 0x14199b0)
assert relocations[rip_target(0x3916020)] == (8, 0x14196d0)
assert rip_target(0x450ecde) == 0x41ae280
def indices(capacity,index,count):
    if count == 0: return []
    start = index - (capacity if index >= capacity else 0)
    available = capacity - start
    return list(range(start, min(capacity, start + count))) + list(range(max(0, count-available)))
assert indices(5,1,3) == [1,2,3]
assert indices(5,4,3) == [4,0,1]
assert indices(5,2,0) == []
assert indices(5,6,3) == [1,2,3]
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

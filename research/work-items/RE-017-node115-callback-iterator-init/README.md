# RE-017 · Node #115 replay callback iterator initialization

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4172](https://github.com/lalalune/hyperliquid-source/pull/4172) maps the collector's direct-segment iterator and [PR #4174](https://github.com/lalalune/hyperliquid-source/pull/4174) maps its tree arm. This packet identifies how the callback initializes those two variants from its locked object, allowing an offline model to select the appropriate arm without guessing from the row byte.

The callback reads object word `+0x18`. If it equals `0x8000000000000000`, object `+0x20` supplies a pointer and `+0x28` another saved word; a nonzero pointer produces iterator tag 1 and remaining count from object `+0x30`, while a zero pointer produces tag 0 and count zero. The initialized iterator's current-node field `+8` is zero, saved pointer and depth are at `+0x10/+0x18`, and count is at `+0x40`. A nonempty tag-1 iterator therefore enters the initialization and tree traversal analyzed in #4174. Tag 0 has zero count on this construction path, so it returns the no-item sentinel before the iterator's invalid-tag failure branch.

Otherwise, the callback builds tag 2 from the pointer at object `+0x20`, index at `+0x28`, capacity word at `+0x18`, and length at `+0x30`. For nonzero length, the selected arithmetic subtracts capacity once from the index if the unsigned index is at least capacity; the first interval runs from the resulting index to either capacity or index plus length, and an overflow interval begins at zero. Interval endpoints scale by `0xb0` and add the same base pointer. A zero length initializes both intervals empty. The included synthetic boundary checks show nonwrapped, wrapped and empty arithmetic; they do not establish arbitrary malformed input behavior or target execution.

The selector is a representation discriminator, not a checkpoint height or evidence that a given real checkpoint uses either variant. This is static evidence; no real replay is claimed.

## Reproduce

GNU and LLVM agree on the selected instruction spans.
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

with Path("research/work-items/RE-017-node115-callback-iterator-init/instructions.tsv").open() as handle:
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
assert rip_target(0x5a635a7) == 0x5b74af0
assert 0x338 - 0x2f0 == 0x48
assert 0x330 - 0x2f0 == 0x40
def intervals(capacity, index, length):
    if length == 0:
        return (0, 0, 0, 0)
    first = index - (capacity if index >= capacity else 0)
    remaining = length - (capacity - first)
    return (first, capacity, 0, remaining) if remaining > 0 else (first, first + length, 0, 0)
assert intervals(8, 2, 3) == (2, 5, 0, 0)
assert intervals(8, 6, 4) == (6, 8, 0, 2)
assert intervals(8, 8, 0) == (0, 0, 0, 0)
assert intervals(8, 10, 3) == (2, 5, 0, 0)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

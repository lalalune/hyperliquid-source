# RE-009 · Node #115 root value third-child alternate tree traversal

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4210](https://github.com/lalalune/hyperliquid-source/pull/4210) establishes the selected circular representation of the third child of the root-row value; the sentinel representation invokes `0x37c8e10`. This packet follows that iterator, so the two alternative representations can be distinguished when reproducing the root input projection.

The iterator checks remaining state `+0x40`; zero returns a null first pointer. Otherwise it decrements the count and requires tag 1, with an invalid tag reaching a failure call and `ud2`. If the current node is null, the saved node and depth drive descent through node `+0x9b0`; the state is initialized to the reached node and zero depth and slot. For an occupied node, a 16-bit count at `+0x9aa` bounds the current slot. When exhausted, parent `+0` and saved parent slot `+0x9a8` are used to climb; a missing parent reaches a failure call and `ud2`. Descending to the next position uses the child pointer at `+0x9b8+8*slot` and then repeated `+0x9b0` links. State fields are updated before return.

For selected node N and slot i, the returned first pointer is `N + 8 + 8*i` and the second is `N + 0x60 + 0xd8*i`. The caller appends these pointers to the descriptor arrays described in #4210; the slot formulas differ from the non-sentinel circular representation's `0xe0` stride and `+0/+8` projections. These observations do not establish runtime reachability, field names, a real checkpoint or a completed state root.

## Reproduce

GNU and LLVM agree on selected instruction spans; the caller's direct iterator target is checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-row-value-tree-e0/instructions.tsv").open() as handle:
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
assert rip_target(0x3c643e5) == 0x37c8e10
for slot in (0, 1, 7, 65535):
    assert 8 + slot * 8 == 8 + (slot << 3)
    assert 0x60 + slot * 0xd8 == 0x60 + 216 * slot
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

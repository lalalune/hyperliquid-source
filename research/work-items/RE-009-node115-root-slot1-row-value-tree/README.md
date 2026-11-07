# RE-009 · Node #115 circular-row value tree projection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4205](https://github.com/lalalune/hyperliquid-source/pull/4205) identifies the second projected pointer of a selected `0x70`-stride circular row as row `+0x18`; [PR #4206](https://github.com/lalalune/hyperliquid-source/pull/4206) describes its alternate tree-derived pointer. Both use descriptor `0x6477a48`, whose visitor `0x3917d20` is followed here. The pointer joins are conditional on the selected dispatch path.

The visitor builds three single-entry descriptor lists in source-offset order `+0x40`, `+0`, `+0x20` and passes them to `0x41adc70`; constructor `0x3917cc0` initializes three sentinel child entries. Their respective visitor/constructor bindings are `0x45103a0/0x45070a0`, `0x450eb50/0x450e0e0`, and `0x3c641b0/0x3c4d910`.

For the first projected child, `0x45103a0` reads a count at its source `+0x10`, allocates 16-byte descriptor pairs, and on the selected nonempty traversal reads a node pointer at source `+0`. It follows node links at `+0x68`, compares slots with the 16-bit field at node `+0x62`, and ascends via node `+0` with parent slot at `+0x60`. Each selected slot contributes pointer `node + 8 + 8*slot` and descriptor `0x648e3f8`, whose methods resolve to `0x457d480/0x457d470`. The method later sends a separate count entry and the pair array to `0x41ae280`. Null-parent failure and allocation branches are separate; exact container ownership and all node layouts are not claimed.

These are distinct nested child inputs, not a complete row serialization. No live checkpoint value, full root or block replay is established.

## Reproduce

GNU and LLVM agree on the selected instruction spans; descriptor methods and direct call bindings are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-slot1-row-value-tree/instructions.tsv").open() as handle:
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
assert rip_target(0x3c61a19) == 0x6477a48
assert relocations[0x6477a60] == (8, 0x3917d20)
assert relocations[0x6477a68] == (8, 0x3917cc0)
for instruction, descriptor, visitor, constructor in [(0x3917d30,0x646eef0,0x45103a0,0x45070a0),(0x3917d41,0x646ef18,0x450eb50,0x450e0e0),(0x3917d56,0x646ef40,0x3c641b0,0x3c4d910)]:
    assert rip_target(instruction) == descriptor
    assert relocations[descriptor+0x18] == (8,visitor)
    assert relocations[descriptor+0x20] == (8,constructor)
assert rip_target(0x3917da3) == 0x41adc70
assert rip_target(0x4510486) == 0x648e3f8
assert relocations[0x648e410] == (8, 0x457d480)
assert relocations[0x648e418] == (8, 0x457d470)
assert rip_target(0x45106a1) == 0x41ae280
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

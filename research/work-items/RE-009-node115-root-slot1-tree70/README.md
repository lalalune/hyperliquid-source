# RE-009 · Node #115 root slot 1 alternate tree iterator

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4205](https://github.com/lalalune/hyperliquid-source/pull/4205) covers the selected circular-segment path of the inner root-slot-1 projection and leaves its alternate iterator `0x37c8560` open. This packet follows that iterator's tag-1 tree arm. Its result pointers feed the two descriptor arrays in #4205; these are not necessarily contiguous `0x70`-byte rows.

The iterator checks the remaining count at state `+0x40`: zero returns `rax = 0`, otherwise it decrements the count and requires tag 1. An invalid nonempty tag reaches a failure call and `ud2`. A null current node follows the saved node/depth through pointers at node `+0x4b0` and initializes the iterator state. On the selected traversal, it compares slot index to the 16-bit count at node `+0x4ae`; exhausted slots ascend through the pointer at node `+0`, using the saved parent slot at `+0x4ac`. A missing parent on that path reaches a failure call and `ud2`.

For selected node `N` and slot `i`, it returns first pointer `N + 0x3d0 + 0x14*i` and second pointer `N + 8 + 0x58*i`, after writing next-node, depth and slot state. The caller puts these pointers in separate arrays with descriptors `0x6476bc0` and `0x6477a48`. The first descriptor reaches the 20-byte raw writer analyzed in [PR #4201](https://github.com/lalalune/hyperliquid-source/pull/4201); the second's full semantics remain open. The circular representation's row `+0/+0x18` and stride `0x70` must not be assumed for this tree arm. These are static layout observations, not proof of runtime reachability or a real checkpoint replay.

## Reproduce

GNU and LLVM agree on the selected instruction spans. The iterator call and descriptor bindings are checked directly against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-slot1-tree70/instructions.tsv").open() as handle:
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
assert rip_target(0x3c61aa5) == 0x37c8560
assert rip_target(0x3c61a12) == 0x6476bc0
assert rip_target(0x3c61a19) == 0x6477a48
assert relocations[0x6476bd8] == (8, 0x41f8050)
assert relocations[0x6477a60] == (8, 0x3917d20)
for slot in (0,1,7,65535):
    assert 0x3d0 + (slot + slot * 4) * 4 == 0x3d0 + 0x14 * slot
    assert 8 + slot * 0x58 == 8 + 88 * slot
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-017 · Node #115 replay callback tree iterator arm

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4172](https://github.com/lalalune/hyperliquid-source/pull/4172) traces the callback's mode-byte collector through the iterator's tag-2 direct-segment arm. This packet follows the separate tag-1 arm of the same `0x4e1a100` iterator, so a replay model need not treat every collected row as a direct `0xb0`-byte segment.

For a non-tag-2 state the iterator first tests the remaining count at `+0x40`; zero returns `rax = 0`, otherwise it decrements the count and requires tag 1, with another tag reaching the `ud2` failure path. A null current node uses the saved pointer and depth at `+0x10` and `+0x18` to follow the pointer at node `+0x7a0`, then saves the resulting node and clears those fields. A non-null node compares the current slot index with the 16-bit slot limit at `+0x79a`. When the index is exhausted, the path ascends via node `+0`, updates depth and takes the saved 16-bit parent slot at the child's `+0x798`; a null parent on this path reaches a failure call followed by `ud2`.

On the selected return path, for node `N` and slot `i` the first pointer is `N + 8 + 8*i` and the second is `N + 0x60 + 0xa8*i`. The caller's byte test at second pointer `+0xa4` therefore reads `N + 0x104 + 0xa8*i`, not the direct-segment `row + 0xac` formula. The traversal writes its next-node, depth and slot state before returning. These offsets describe an observed layout, not established domain types or an assertion that a real checkpoint reaches this arm. Neither a real replay nor complete container semantics is claimed.

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

with Path("research/work-items/RE-017-node115-replay-iterator-tree/instructions.tsv").open() as handle:
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
assert rip_target(0x5b74b13) == 0x4e1a100
assert 0x60 + 0xa4 == 0x104
for slot in (0, 1, 7, 65535):
    assert (0x60 + 0xa8 * slot) + 0xa4 == 0x104 + 0xa8 * slot
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-009 · Node #115 root qword-child digest finalization

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4185](https://github.com/lalalune/hyperliquid-source/pull/4185) follows a root visitor's qword into a buffered child owner but leaves ordinary finalization open. This packet follows the already identified reducer `0x141a250` for the child representation whose first word is `0x8000000000000000`. The [block-root packet](../RE-017-abci-block-root-115/README.md) identified the reducer and its caller; the buffer-to-finalizer handoff below is the bounded addition.

For this representation the reducer reads the owner pointer from the child at `+8`, saves the owner flag at `+0x18`, and copies `0x778` bytes of owner state beginning at `+0x20` into local storage. It reads capacity, buffer pointer and buffered length from owner `+0`, `+8` and `+0x10`. If the saved flag equals one it calls a separate error/reporting helper; the selected normal route has flag unequal to one. If the buffered length is nonzero, the reducer calls digest update `0x160b3a0` on the local state with that pointer and length; for zero length it skips the update. It then calls digest finalizer `0x160bcd0` on the local state, copies the resulting 32 bytes into the output at `+1`, and writes output tag 0. The selected normal path subsequently releases the buffer when capacity is nonzero and releases the owner.

If a newly initialized qword child has received exactly one successful inline write and no other intervening mutation, the reducer's update input is the corresponding eight little-endian bytes; for the marker 1 these are `01 00 00 00 00 00 00 00`. That conditional inference is not an observed runtime state and does not assume that two separate child writes are concatenated. The result is a child digest, not the complete state root. Other reducer representations, all compression equivalence and actual checkpoint/block replay remain outside this packet.

## Reproduce

GNU and LLVM agree on the selected instruction spans; relocation checks bind update and finalization to the authenticated target.
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

with Path("research/work-items/RE-009-node115-root-child-finalize/instructions.tsv").open() as handle:
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
assert relocations[rip_target(0x141a2d2)] == (8, 0x160b3a0)
assert relocations[rip_target(0x141a2e8)] == (8, 0x160bcd0)
assert elf_bytes('.rodata', 0x459280, 8) == (1).to_bytes(8, 'little')
assert 0x8000 > 8
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

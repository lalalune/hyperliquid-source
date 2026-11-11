# RE-009 · Node #115 alternate root payload guards and variants

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4212](https://github.com/lalalune/hyperliquid-source/pull/4212) maps the root row value's non-2 tag arm to four ordered children at source `+0xc8`, `+0xd0`, `+0`, and `+0xb8`. This packet resolves the first two shared visitor guards and the fourth child's two tag cases. Source offsets below apply to the pointer passed to that non-2 visitor.

The first two children share descriptor `0x646a9e8` and visitor `0x4513270`. Each tests its first qword: zero constructs an empty slice with sentinel data pointer 8; nonzero supplies one element at the unchanged child pointer with descriptor `0x648e760`. Both go to `0x41ae280`. The descriptor resolves to `0x3f7a840`, the two-child visitor documented in [PR #4218](https://github.com/lalalune/hyperliquid-source/pull/4218). A nonzero first qword therefore does not by itself demonstrate how every following child is serialized.

The fourth child, at source `+0xb8`, has descriptor `0x646aa38` and visitor `0x392b690`. It tests the 32-bit tag at this child. Tag 1 selects discriminant 1 and descriptor `0x646aac8`; every other tag selects discriminant 0 and descriptor `0x646f2e0`. Both pass a single child pointer at child `+8` to `0x41aed60`. The first descriptor resolves to `0x3f7a840`, the second to qword visitor thunk `0x4303b70` and its relocated slot `0x64df530` to `0x14199b0`. The tag-1 and other paths therefore have different immediate child methods despite using the same child pointer. The third outer child is the shared nine-field projection analyzed in #4213.

These are conditional static dispatch relationships, not a schema name, complete root encoding or proof of real checkpoint reachability. Guard handling for invalid or externally supplied tags is not established.

## Reproduce

GNU and LLVM agree on selected instruction spans. Direct descriptor references, dispatcher calls and relocation-backed visitor targets are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-other-tag-guards/instructions.tsv").open() as handle:
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
assert relocations[0x646aa00] == (8, 0x4513270)
assert relocations[0x646aa50] == (8, 0x392b690)
for insn,target in [(0x4513282,0x648e760),(0x45132d9,0x41ae280),(0x392b6b6,0x646aac8),(0x392b6d5,0x646f2e0),(0x392b706,0x41aed60),(0x4303b70,0x64df530)]:
    assert rip_target(insn) == target
for slot,target in [(0x648e778,0x3f7a840),(0x646aae0,0x3f7a840),(0x646f2f8,0x4303b70),(0x64df530,0x14199b0)]:
    assert relocations[slot] == (8,target)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

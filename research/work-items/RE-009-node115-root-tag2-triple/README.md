# RE-009 · Node #115 tagged root payload three-child projection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4212](https://github.com/lalalune/hyperliquid-source/pull/4212) shows that the tag-2 arm sends payload `+0xb8` through descriptor `0x648db28`, whose visitor is `0x44eb980`. This packet traces that child's ordered projections and the guarded visitor of its third projection. Offsets below are relative to this `+0xb8` child, not to the enclosing tagged source.

`0x44eb980` passes three one-item slices in order to `0x41adc70`: child `+8` with descriptor `0x64884f8`, child `+0` with `0x648d448`, and child `+9` with `0x648d470`. Relocations resolve these visitors to `0x1419d40`, `0x3f7a840`, and `0x43d1450`. The middle child itself passes two slices, source `+0` and `+8`, to `0x41ae280` via descriptors `0x64741c8` and `0x64741f0`; their visitors resolve to `0x141b3c0` and `0x3b84cf0`. The latter ignores the source pointer and returns 4 exactly when signed overflow occurs in `0 - destination[0]`, otherwise 0; it is not a write of the projected source.

For the third child, `0x43d1450` stages discriminant 1 when the source byte equals 1 and 0 for every other value. It returns status 1 if destination's first qword is `0x8000000000000000`, or status 2 if destination `+0x10` is zero. Otherwise it selects the object pointed to by destination `+8`; if its first qword is `0x8000000000000001`, the code invokes an indirect helper and `0x41c70d0` before copying three words into that object. Both the sentinel and non-sentinel object paths then call an indirect helper with the staged discriminant and object. The precise domain types, downstream bytes and actual checkpoint reachability remain unproven.

## Reproduce

GNU and LLVM agree on selected instruction spans; descriptor relocations and direct dispatcher edges are checked in the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-tag2-triple/instructions.tsv").open() as handle:
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
assert relocations[0x648db40] == (8, 0x44eb980)
for insn, target in [(0x44eb990,0x64884f8),(0x44eb9a1,0x648d448),(0x44eb9b6,0x648d470),(0x44eba03,0x41adc70),(0x3f7a84c,0x64741c8),(0x3f7a861,0x64741f0),(0x3f7a89b,0x41ae280),(0x43d149b,0x41c70d0),(0x43d14d5,0x41c70d0)]:
    assert rip_target(insn) == target
for slot,target in [(0x6488510,0x1419d40),(0x648d460,0x3f7a840),(0x648d488,0x43d1450),(0x64741e0,0x141b3c0),(0x6474208,0x3b84cf0)]:
    assert relocations[slot] == (8,target)
for value in (0, 1, 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff):
    signed = value if value < (1 << 63) else value - (1 << 64)
    assert (not (-(1 << 63) <= -signed < (1 << 63))) == (value == 0x8000000000000000)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

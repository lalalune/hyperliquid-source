# RE-009 · Node #115 root 0x110-element selected leaf widths

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [0x110-element packet](../RE-009-node115-root-110-element-variant/README.md) maps ten ordered non-2-arm projections; its [option-guard packet](../RE-009-node115-root-110-option-guards/README.md) records three option conditions. This packet resolves selected leaf widths and exact-fit fallback boundaries for six of those projections. Offsets are relative to the non-2 element pointer. Presence predicates and destination state condition every listed write.

| Child | Selected source range | Visitor | Direct-copy width |
|---|---|---|---:|
| 1, if 32-bit tag at +0 is 1 | `[0x08,0x10)` | `0x14199b0` | 8 |
| 2, if 32-bit tag at +0x10 is 1 | `[0x18,0x20)` | `0x14199b0` | 8 |
| 3 | `[0x10c,0x10d)` | `0x1419d40` | 1 |
| 6, if 32-bit tag at +0xd8 is 1 | `[0xdc,0xe0)` | `0x1419c90` | 4 |
| 7 | `[0xf8,0x10c)` | `0x141b9b0` | 20 |
| 10 | `[0xf0,0xf8)` | `0x14199b0` | 8 |

The table preserves the relative child order from the parent, not a claim that the complete parent output is the concatenation of these fields. The 20-byte slice ends exactly where child 3's byte begins. Each leaf tests the destination sentinel using signed overflow from `0 - destination[0]`. On the active branch it copies directly only when remaining unsigned capacity is strictly greater than its width; at exact fit or less it calls slot `0x64df4a8` with the staged bytes and respective width. On successful direct copying the destination length advances by that width and the low return byte becomes 4. These paths do not establish names, all helper behavior, general malformed-state semantics, or a real checkpoint/root match.

## Reproduce

GNU and LLVM agree on the selected instruction spans. The descriptor and thunk relocations link these known parent paths to four distinct authenticated leaf widths; boundary controls are synthetic arithmetic checks, not execution of the target.
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

with Path("research/work-items/RE-009-node115-root-110-leaf-widths/instructions.tsv").open() as handle:
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
for slot,target in [(0x648d190,0x4513770),(0x648e410,0x457d480),(0x64df538,0x14199b0),(0x6488510,0x1419d40),(0x648d2f8,0x45130f0),(0x648e700,0x4305830),(0x64df4e8,0x1419c90),(0x64884e8,0x41f8050),(0x64df600,0x141b9b0),(0x648d050,0x3916030),(0x64df530,0x14199b0)]:
    assert relocations[slot] == (8,target)
for insn,target in [(0x457d480,0x64df538),(0x4305830,0x64df4e8),(0x41f8050,0x64df600),(0x3916030,0x64df530)]:
    assert rip_target(insn) == target
for width in (1,4,8,20):
    for remaining in (0,width-1,width,width+1):
        assert (remaining > width) == (not remaining <= width)
assert 0xf8 + 20 == 0x10c
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

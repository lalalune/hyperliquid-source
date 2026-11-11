# RE-009 · Node #115 0x110-stride root element variant

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4223](https://github.com/lalalune/hyperliquid-source/pull/4223) identifies a `0x110`-stride vector and its element descriptor `0x647a240`. This packet resolves the element's tag selection and the ten source projections of its non-2 arm. Offsets are relative to the individual element pointer, not the enclosing `0x120`-stride element.

The descriptor resolves to `0x4305e80`. A 32-bit tag equal to 2 sets discriminant 0 and selects element `+8` with descriptor `0x6482968`, whose visitor is the qword writer `0x14199b0`. Other tag values set discriminant 1 and select the original element pointer with descriptor `0x6484920`, visitor `0x44eb3e0`. Both call `0x41aed60` with the selected child and a separate discriminant entry.

The non-2 visitor constructs ten one-element source/descriptor pairs in this order:

| Order | Offset | Descriptor | Visitor |
|---|---:|---:|---:|
| 1 | `0x00` | `0x648d178` | `0x4513770` |
| 2 | `0x10` | `0x648d178` | `0x4513770` |
| 3 | `0x10c` | `0x64884f8` | `0x1419d40` |
| 4 | `0xe0` | `0x648d2b8` | `0x4305d40` |
| 5 | `0xe8` | `0x648d2b8` | `0x4305d40` |
| 6 | `0xd8` | `0x648d2e0` | `0x45130f0` |
| 7 | `0xf8` | `0x64884d0` | `0x41f8050` |
| 8 | `0x10d` | `0x648d308` | `0x45149f0` |
| 9 | `0x20` | `0x648d330` | `0x44eb7a0` |
| 10 | `0xf0` | `0x648d038` | `0x3916030` |

Before traversing them the visitor returns status 1 for destination signed-overflow sentinel and status 3 when destination count at `+0x10` differs from 10. Its loop calls child visitors and stops on any status other than 4; a sentinel destination child invokes its descriptor constructor before the visitor. The order is dispatch order, not memory order or proven final bytes. Unknowns include source field semantics, malformed tags and real checkpoint/root behavior.

## Reproduce

GNU and LLVM agree on selected instruction spans; descriptor, dispatcher and relocation bindings are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-110-element-variant/instructions.tsv").open() as handle:
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
assert relocations[0x647a258] == (8,0x4305e80)
for insn,target in [(0x4305ea6,0x6482968),(0x4305edb,0x6484920),(0x4305f0c,0x41aed60),(0x44eb3f6,0x648d178),(0x44eb41c,0x64884f8),(0x44eb434,0x648d2b8),(0x44eb463,0x648d2e0),(0x44eb481,0x64884d0),(0x44eb49f,0x648d308),(0x44eb4ba,0x648d330),(0x44eb4d8,0x648d038)]:
    assert rip_target(insn) == target
for slot,target in [(0x6482980,0x14199b0),(0x6484938,0x44eb3e0),(0x648d190,0x4513770),(0x6488510,0x1419d40),(0x648d2d0,0x4305d40),(0x648d2f8,0x45130f0),(0x64884e8,0x41f8050),(0x648d320,0x45149f0),(0x648d348,0x44eb7a0),(0x648d050,0x3916030)]:
    assert relocations[slot] == (8,target)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

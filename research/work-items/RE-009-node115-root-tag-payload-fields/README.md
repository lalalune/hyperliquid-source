# RE-009 · Node #115 tagged root-value shared payload fields

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4212](https://github.com/lalalune/hyperliquid-source/pull/4212) identifies two selector arms with a common visitor `0x44eb7a0`: tag 2 reaches it at source `+8`, while the other arm reaches it at the original source. This packet resolves that shared visitor's nine ordered child pointers, descriptors, and relocation-backed visitor targets. The offsets are relative to the pointer passed to the common visitor, not uniformly to the enclosing tagged source.

| Order | Payload offset | Descriptor | Visitor |
|---|---:|---:|---:|
| 1 | `0x98` | `0x648cb38` | `0x14199b0` |
| 2 | `0x00` | `0x648d358` | `0x4513570` |
| 3 | `0xa0` | `0x64884f8` | `0x1419d40` |
| 4 | `0x10` | `0x648d380` | `0x44e9d30` |
| 5 | `0x48` | `0x648d3a8` | `0x44ea980` |
| 6 | `0xa1` | `0x648d3d0` | `0x45131f0` |
| 7 | `0x58` | `0x648d3f8` | `0x45133f0` |
| 8 | `0xb2` | `0x648d420` | `0x150d5b0` |
| 9 | `0x90` | `0x648d448` | `0x3f7a840` |

The visitor constructs one pointer/descriptor pair for each offset and one single-element slice per pair, then passes the nine slices in this order to `0x41ad3c0`. The order is dispatch order, not memory order. Descriptor relocations establish method addresses; they do not establish field names, all serialized byte widths or a complete state-root encoding. The link to root capture is conditional on the paths in #4210 and #4212, not a demonstration that a real checkpoint exercises either path.

## Reproduce

GNU and LLVM agree on selected instruction spans. Descriptor addresses, visitor relocations and dispatcher target are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-tag-payload-fields/instructions.tsv").open() as handle:
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
for insn, target in [(0x44eb7b6,0x648cb38),(0x44eb7c7,0x648d358),(0x44eb7df,0x64884f8),(0x44eb7f4,0x648d380),(0x44eb809,0x648d3a8),(0x44eb821,0x648d3d0),(0x44eb836,0x648d3f8),(0x44eb84e,0x648d420),(0x44eb86c,0x648d448),(0x44eb96a,0x41ad3c0)]:
    assert rip_target(insn) == target
for descriptor, visitor in [(0x648cb38,0x14199b0),(0x648d358,0x4513570),(0x64884f8,0x1419d40),(0x648d380,0x44e9d30),(0x648d3a8,0x44ea980),(0x648d3d0,0x45131f0),(0x648d3f8,0x45133f0),(0x648d420,0x150d5b0),(0x648d448,0x3f7a840)]:
    assert relocations[descriptor + 0x18] == (8, visitor)
assert relocations[0x648d348] == (8, 0x44eb7a0)
assert relocations[0x646aa28] == (8, 0x44eb7a0)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

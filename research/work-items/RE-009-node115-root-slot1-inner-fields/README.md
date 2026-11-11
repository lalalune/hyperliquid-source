# RE-009 · Node #115 root slot 1 inner element fields

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4196](https://github.com/lalalune/hyperliquid-source/pull/4196) identifies `0x120`-stride inner elements and descriptor `0x647a128`. This packet follows that descriptor's visitor `0x39176d0` and constructor `0x3917660` to the immediate child projections, and traces the first projected child one level further. Capture and pointer joins remain conditional on the recorded dispatch path.

The constructor creates eight 24-byte child entries with uninitialized sentinel `0x8000000000000001`. The visitor builds one-element descriptor lists in this observed source-offset order: `+0xa8`, `+0`, `+0x38`, `+0x80`, `+0x110`, `+0xe8`, `+0x108`, `+0x118`; these are not sorted by memory address. It dispatches to `0x41ae850`, which requires eight destination entries and has separate sentinel and wrong-count statuses. The descriptor method addresses are bound in the checks below.

The first projected visitor `0x46f4af0`, starting at inner element `+0xa8`, creates two element descriptors for its own offsets `+0` and `+0x20` and a separate count value 2, then calls `0x41ae280`. In terms of the inner element these pointers are `+0xa8` and `+0xc8`. They are child projections, not evidence of a flat concatenation. Nested field meanings, runtime values, later digest composition, all failure paths and actual checkpoint replay remain open.

## Reproduce

GNU and LLVM agree on the selected instruction spans; the method relocations and direct calls are checked against the authenticated target.
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

with Path("research/work-items/RE-009-node115-root-slot1-inner-fields/instructions.tsv").open() as handle:
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
assert rip_target(0x3d68265) == 0x647a128
assert relocations[0x647a140] == (8, 0x39176d0)
assert relocations[0x647a148] == (8, 0x3917660)
assert rip_target(0x3917866) == 0x41ae850
for instruction, descriptor, visitor, constructor in [(0x39176e6,0x646edd8,0x46f4af0,0x46f46d0),(0x39176f7,0x646ee00,0x46a55e0,0x46a1010),(0x391770c,0x646ee28,0x43ca170,0x4325510),(0x3917724,0x646ee50,0x4591a60,0x4591a00),(0x391773c,0x646aaa0,0x3916050,0x3916040),(0x3917754,0x646ee78,0x3c61870,0x3c4d910),(0x391776c,0x646aac8,0x3f7a840,0x3f7a7f0),(0x3917784,0x646eea0,0x4305d40,0x4305cf0)]:
    assert rip_target(instruction) == descriptor
    assert relocations[descriptor+0x18] == (8,visitor)
    assert relocations[descriptor+0x20] == (8,constructor)
assert rip_target(0x46f4b60) == 0x41ae280
assert 0xa8 + 0x20 == 0xc8
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-009 · Node #115 digest chunk and parent bulk dispatch

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4180](https://github.com/lalalune/hyperliquid-source/pull/4180) identifies complete-segment dispatch `0x160bf70` and [PR #4178](https://github.com/lalalune/hyperliquid-source/pull/4178) identifies parent-pair dispatch `0x160c1b0`. This packet resolves their selector-indexed tables and backend relocation slots together. The two helpers have separate entry points and relative jump tables; on the selected nonzero-selector paths they call the same backend per selector but provide different block-count constants: 16 for a complete 1024-byte segment and 1 for a 64-byte parent pair.

| Selector | Chunk arm / parent arm | Backend relocation target |
| --- | --- | --- |
| 1 | `0x160c0b8` / `0x160c2f8` | `0x633a680` |
| 2 | `0x160c021` / `0x160c261` | `0x633d500` |
| 3 | `0x160c06e` / `0x160c2ae` | `0x633fe80` |
| 4 | `0x160bfd4` / `0x160c214` | `0x6342440` |

The checked selector-0 entries instead dispatch directly to two different helpers (`0x160de30` and `0x160e0b0`); the outer root constructor's recorded selector routine produces 1–4, as described in [PR #4133](https://github.com/lalalune/hyperliquid-source/pull/4133). Each selected nonzero arm guards count multiplication by 32 against overflow, compares the required byte count to the supplied output capacity, and has separate failure continuations. This does not identify instruction-set requirements, prove backend equivalence, or establish the actual digest of a captured block.

## Reproduce

GNU and LLVM agree on the selected instruction spans. The checks bind the two signed-relative jump tables and four relative relocations directly to the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-digest-bulk-dispatch/instructions.tsv").open() as handle:
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
assert rip_target(0x160a481) == 0x160bf70
assert rip_target(0x160aac0) == 0x160c1b0
assert rip_target(0x160bf95) == 0x46abd4
assert rip_target(0x160c1d5) == 0x46abe8
def jump_targets(addr):
    return tuple(addr + offset for offset in struct.unpack('<5i', elf_bytes('.rodata', addr, 20)))
assert jump_targets(0x46abd4) == (0x160bfa5, 0x160c0b8, 0x160c021, 0x160c06e, 0x160bfd4)
assert jump_targets(0x46abe8) == (0x160c1e5, 0x160c2f8, 0x160c261, 0x160c2ae, 0x160c214)
assert rip_target(0x160bfca) == 0x160de30
assert rip_target(0x160c20a) == 0x160e0b0
for chunk, parent, target in [(0x160c0fa, 0x160c33a, 0x633a680), (0x160c063, 0x160c2a3, 0x633d500), (0x160c0b0, 0x160c2f0, 0x633fe80), (0x160c016, 0x160c256, 0x6342440)]:
    assert relocations[rip_target(chunk)] == relocations[rip_target(parent)] == (8, target)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

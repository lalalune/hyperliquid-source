# RE-009 · Node #115 root slot 1 inner circular-row projection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4197](https://github.com/lalalune/hyperliquid-source/pull/4197) maps inner-element source offset `+0xe8` to visitor `0x3c61870`. This packet follows its selected circular-segment iterator and two output projections. The capture and child pointers remain conditional on the observed dispatch chain.

The visitor uses source `+0x18` as an allocation-sizing word for two arrays of 16-byte pointer/descriptor pairs. When source word `+0` is not `0x8000000000000000`, it constructs tag 2 circular intervals using source `+8` as base, `+0x10` as index and `+0x18` as count. In the selected tag-2 iterator path each source row advances by `0x70`; when the first interval is exhausted, the saved second interval replaces it. Each selected row produces one descriptor pair with the row pointer and `0x6476bc0`, and a second with row `+0x18` and `0x6477a48`. The first descriptor binds `0x41f8050/0x43025f0`; the second binds `0x3917d20/0x3917cc0` as visitor/constructor.

The representation selected by the sentinel takes a separate iterator path through `0x37c8560`, outside this packet's row-layout claim. The two arrays and a separate count value feed `0x41adc70`; temporary arrays are freed on selected normal return. This does not assert all iterator states, source field meanings, actual checkpoint values or a complete state root.

## Reproduce

GNU and LLVM agree on the selected instruction spans; descriptor and dispatch bindings are checked directly against the authenticated target.
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

with Path("research/work-items/RE-009-node115-root-slot1-ring70/instructions.tsv").open() as handle:
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
assert rip_target(0x3917754) == 0x646ee78
assert relocations[0x646ee90] == (8, 0x3c61870)
assert rip_target(0x3c61a12) == 0x6476bc0
assert rip_target(0x3c61a19) == 0x6477a48
assert relocations[0x6476bd8] == (8, 0x41f8050)
assert relocations[0x6476be0] == (8, 0x43025f0)
assert relocations[0x6477a60] == (8, 0x3917d20)
assert relocations[0x6477a68] == (8, 0x3917cc0)
assert rip_target(0x3c61aa5) == 0x37c8560
assert rip_target(0x3c61b70) == 0x41adc70
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

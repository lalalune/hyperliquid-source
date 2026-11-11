# RE-009 · Node #115 wide-row inner map projection order

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4201](https://github.com/lalalune/hyperliquid-source/pull/4201) binds the wide-row projection at row `+0` to a two-child visitor, whose methods `0x46a3c30` and `0x46a5db0` receive sources at row `+0` and `+0x38`. This packet follows both methods and distinguishes the order of their two projected arrays. The outer row and destination joins remain conditional on the selected static path.

Each method separately reads a sizing word at its source `+0x30`, a traversal count at `+0x10`, and a row base at `+8`. For the selected normal traversal both advance source rows by `0x20` and build two arrays of 16-byte `(pointer, descriptor)` pairs. Their projections differ:

| Method | First array | Second array |
| --- | --- | --- |
| `0x46a3c30` | row `+0x18`, descriptor `0x6493318` | row `+0`, descriptor `0x6493340` |
| `0x46a5db0` | row `+0`, descriptor `0x6493340` | row `+0x18`, descriptor `0x6493318` |

Descriptor `0x6493318` binds visitor/constructor `0x3916030/0x3916020`; descriptor `0x6493340` binds `0x4302e50/0x43025f0`. Both methods pass their arrays and the separate sizing value to `0x41adc70` and release temporary arrays on selected normal return. Although the pointer sets are similar, the array positions are reversed; a reconstruction cannot interchange them without further evidence. Neither sizing/traversal equality, the semantic meaning of these words, nested visitors' complete behavior nor a real root is asserted.

## Reproduce

GNU and LLVM agree on the selected instruction spans. Descriptor and dispatch bindings are checked directly against the authenticated target.
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

with Path("research/work-items/RE-009-node115-root-wide-row-inner-order/instructions.tsv").open() as handle:
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
assert rip_target(0x43cb03c) == 0x6487d30
assert rip_target(0x43cb051) == 0x6487d58
assert relocations[0x6487d48] == (8, 0x46a3c30)
assert relocations[0x6487d70] == (8, 0x46a5db0)
assert rip_target(0x46a3d26) == rip_target(0x46a5eaf) == 0x6493318
assert rip_target(0x46a3d2d) == rip_target(0x46a5ea8) == 0x6493340
assert relocations[0x6493330] == (8, 0x3916030)
assert relocations[0x6493338] == (8, 0x3916020)
assert relocations[0x6493358] == (8, 0x4302e50)
assert relocations[0x6493360] == (8, 0x43025f0)
assert rip_target(0x46a3e1a) == rip_target(0x46a5f99) == 0x41adc70
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-009 · Node #115 row value third-child circular projection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4208](https://github.com/lalalune/hyperliquid-source/pull/4208) maps the selected root circular-row value into three children. This packet follows its third child at value `+0x20`, visitor `0x3c641b0`, through its selected circular-segment projection. The capture and child-pointer joins remain conditional on the observed dispatch.

The method reads source `+0x18` to size two temporary arrays of 16-byte pointer/descriptor pairs. For the non-sentinel representation it builds tag-2 circular intervals from source base `+8`, index `+0x10` and count `+0x18`. On the selected tag-2 traversal, rows advance by `0xe0`, with the saved second interval replacing the first when exhausted. Each row contributes its base pointer with descriptor `0x6477b88` and row `+8` with descriptor `0x6477bb0`, to separate arrays. Their visitor/constructor bindings are `0x3916030/0x3916020` and `0x3918670/0x3918610` respectively.

The sentinel representation instead uses iterator `0x37c8e10`; its slot layout is not inferred here. The two arrays and separate count are passed to `0x41adc70`, then released on selected normal return. This `0xe0` row stride and `+0/+8` projection are distinct from the `0x70` row stride and `+0/+0x18` projection in [PR #4205](https://github.com/lalalune/hyperliquid-source/pull/4205). No domain names, real checkpoint data or complete state-root behavior are asserted.

## Reproduce

GNU and LLVM agree on the selected instruction spans; descriptor method and dispatcher bindings are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-row-value-ring-e0/instructions.tsv").open() as handle:
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
assert rip_target(0x3917d56) == 0x646ef40
assert relocations[0x646ef58] == (8, 0x3c641b0)
assert rip_target(0x3c6435b) == 0x6477b88
assert rip_target(0x3c64362) == 0x6477bb0
assert relocations[0x6477ba0] == (8, 0x3916030)
assert relocations[0x6477ba8] == (8, 0x3916020)
assert relocations[0x6477bc8] == (8, 0x3918670)
assert relocations[0x6477bd0] == (8, 0x3918610)
assert rip_target(0x3c643e5) == 0x37c8e10
assert rip_target(0x3c644b0) == 0x41adc70
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

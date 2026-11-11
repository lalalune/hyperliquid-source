# RE-009 · Node #115 root slot 1 wrapped wide-row projections

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4197](https://github.com/lalalune/hyperliquid-source/pull/4197) maps the third projected child of a `0x120`-stride root-slot-1 inner element to source offset `+0x38` and visitor `0x43ca170`. This packet follows that wrapper to `0x46a1590` and its selected source-row projections. The captured-pointer and child joins remain conditional on the observed dispatch.

The wrapper requires a non-sentinel destination with one child; the two guard failures return status 1 or 3. It lazily constructs that child if uninitialized, then calls `0x46a1590`. The latter separately reads a sizing word at source `+0x30`, a traversal count at `+0x10`, and row base at `+8`. It builds two temporary arrays of 16-byte `(pointer, descriptor)` pairs. For each selected source row, one array projects `row +0x88` with descriptor `0x648f6f8`, and the other projects `row +0` with descriptor `0x64930e8`; the row base advances by `0xa0`. The respective visitor/constructor bindings are `0x41f8050/0x43025f0` and `0x43cb030/0x43cafe0`.

The two arrays and separate sizing value feed the same three-entry dispatcher `0x41adc70` used by the different `0x18`-stride pair projection in [PR #4198](https://github.com/lalalune/hyperliquid-source/pull/4198). The two row layouts and source counts are not interchangeable. Temporary arrays are released on the selected normal return. Actual field names, equality of sizing and traversal counts, full nested semantics, checkpoint input and replay remain unproven.

## Reproduce

GNU and LLVM agree on the selected instruction spans; descriptor method and direct-call bindings are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-slot1-inner-wide-rows/instructions.tsv").open() as handle:
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
assert rip_target(0x391770c) == 0x646ee28
assert relocations[0x646ee40] == (8, 0x43ca170)
assert rip_target(0x43ca1ab) == 0x46a0fb0
assert rip_target(0x43ca1ce) == 0x46a1590
assert rip_target(0x46a168a) == 0x648f6f8
assert rip_target(0x46a1691) == 0x64930e8
assert relocations[0x648f710] == (8, 0x41f8050)
assert relocations[0x648f718] == (8, 0x43025f0)
assert relocations[0x6493100] == (8, 0x43cb030)
assert relocations[0x6493108] == (8, 0x43cafe0)
assert rip_target(0x46a1783) == 0x41adc70
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

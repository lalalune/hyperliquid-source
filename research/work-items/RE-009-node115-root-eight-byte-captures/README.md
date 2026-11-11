# RE-009 · Node #115 raw eight-byte root captures

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [block-root packet](../RE-017-abci-block-root-115/README.md) enumerates descriptor/capture pairs, and [PR #4185](https://github.com/lalalune/hyperliquid-source/pull/4185) resolves the `0x14199b0` qword writer. This packet compares that writer with the other eight-byte writer `0x1419900` and identifies five selected captures that use the two paths.

| Descriptor index | State-relative capture | Visitor |
| --- | --- | --- |
| 12 | `+0x4d90` | `0x1419900` |
| 17 | `+0x4d98` | `0x14199b0` |
| 24 | `+0x4da0` | `0x14199b0` |
| 25 | `+0x4da8` | `0x1419900` |
| 55 | `+0x4de0` | `0x14199b0` |

The first visitor uses scalar 64-bit XMM loads and stores; the second uses general-purpose 64-bit loads and stores. On the selected inline path both copy the same eight bytes from input to child buffer, advance its used length by eight and return status 4. Neither selected path performs floating-point arithmetic or normalizes the bit pattern, despite one using XMM registers. Both pass the saved eight bytes to the same fallback when free space is at most eight. All five descriptors use the same constructor `0x14196d0`.

On the conditional path in which each descriptor receives its recorded captured pointer, its child starts fresh, the visit succeeds inline, and no intervening mutation occurs, the selected reducer updates that child's digest with the eight captured bytes as described in [PR #4186](https://github.com/lalalune/hyperliquid-source/pull/4186). Each descriptor has a separate child: this does not assert a contiguous 40-byte digest input. Source-level types, concrete field values, final root ordering and real checkpoint replay remain open.

## Reproduce

GNU and LLVM agree on the selected instruction spans; descriptor method relocations and fallback bindings are checked directly from the authenticated ELF. Capture-to-descriptor mapping is the previously reproduced `jobs.tsv`/`captures.tsv` join, with selected setup instructions rechecked below.
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

with Path("research/work-items/RE-009-node115-root-eight-byte-captures/instructions.tsv").open() as handle:
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
assert rip_target(0x5442506) == 0x64a8318
assert rip_target(0x544258e) == 0x64a8390
assert rip_target(0x5442659) == 0x64a8480
for descriptor, visitor in ((0x64a8318, 0x1419900), (0x64a8390, 0x14199b0), (0x64a8480, 0x14199b0)):
    assert relocations[descriptor + 0x18] == (8, visitor)
    assert relocations[descriptor + 0x20] == (8, 0x14196d0)
assert relocations[rip_target(0x141994d)] == relocations[rip_target(0x14199fa)] == (8, 0x141adb0)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

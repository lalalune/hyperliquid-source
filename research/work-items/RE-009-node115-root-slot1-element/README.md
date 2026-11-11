# RE-009 · Node #115 root slot 1 element descriptor

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4194](https://github.com/lalalune/hyperliquid-source/pull/4194) follows root capture slot 1 into a vector of `0x200`-stride elements and binds each element to descriptor `0x647a1f0`. This packet resolves that descriptor's four immediate field projections and their method targets; it does not claim complete nested semantics.

The selected element constructor `0x4307160` allocates four 24-byte child entries, each initialized with sentinel `0x8000000000000001`. Its visitor `0x43071c0` builds four single-entry descriptor lists, in this order:

| Element-relative source | Descriptor | Visitor | Constructor |
| --- | --- | --- | --- |
| `+0` | `0x64849c0` | `0x3f47000` | `0x3f46fb0` |
| `+0x18` | `0x64849e8` | `0x44e8d30` | `0x44e8cb0` |
| `+0x188` | `0x6484a10` | `0x392b710` | `0x3917cc0` |
| `+0x1e0` | `0x6484a38` | `0x3c50a40` | `0x3c4d910` |

The visitor hands these lists to `0x41ad9a0`. That helper checks a non-sentinel destination and a count of four, returning 1 or 3 on the corresponding guard failure. Its selected first-list path lazily constructs the child through descriptor `+0x20`, invokes the visitor at `+0x18`, and stops on a status other than 4. The four projected offsets and method bindings are static observations; they do not prove the fields' domain names, all nested behavior, actual runtime input or a complete root.

## Reproduce

GNU and LLVM agree on the selected instruction spans; descriptor method relocations are checked directly against the target.
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

with Path("research/work-items/RE-009-node115-root-slot1-element/instructions.tsv").open() as handle:
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
assert rip_target(0x3d68a5e) == 0x647a1f0
assert relocations[0x647a208] == (8, 0x43071c0)
assert relocations[0x647a210] == (8, 0x4307160)
assert rip_target(0x4307277) == 0x41ad9a0
for address, descriptor, visitor, constructor in [(0x43071cf,0x64849c0,0x3f47000,0x3f46fb0), (0x43071e4,0x64849e8,0x44e8d30,0x44e8cb0), (0x43071fc,0x6484a10,0x392b710,0x3917cc0), (0x4307214,0x6484a38,0x3c50a40,0x3c4d910)]:
    assert rip_target(address) == descriptor
    assert relocations[descriptor+0x18] == (8, visitor)
    assert relocations[descriptor+0x20] == (8, constructor)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

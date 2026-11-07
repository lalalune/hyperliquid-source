# RE-009 · Node #115 root slot 1 nested vector projection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4194](https://github.com/lalalune/hyperliquid-source/pull/4194) traces the `0x200`-stride outer element vector of root capture slot 1, and [PR #4195](https://github.com/lalalune/hyperliquid-source/pull/4195) binds its first child at element offset zero to visitor `0x3f47000`. This packet follows that visitor into a second, distinct vector projection.

The visitor tail-jumps to `0x3d681f0`, which reads a nested count at source `+0x10` and base pointer at `+8`. For a nonzero count, it allocates 16 bytes per temporary pair and emits pairs containing a source element pointer and descriptor `0x647a128`. Successive source pointers advance by `0x120`, while the temporary descriptor pairs advance by `0x10`. Its empty case uses a zero-count representation. It constructs a separate one-entry descriptor referencing the nested count, dispatches count and vector to `0x41ae280`, and releases the temporary allocation after the selected call. Descriptor `0x647a128` binds visitor `0x39176d0` and constructor `0x3917660`.

The inner `0x120` and outer `0x200` strides describe different levels and must not be interchanged. The captured-pointer join and selected dispatch are static; nested field semantics, malformed counts, actual restored input, complete hash input and live block replay remain open.

## Reproduce

GNU and LLVM agree on the selected instruction spans. Descriptor and tail-call bindings are checked directly from the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-slot1-nested-vector/instructions.tsv").open() as handle:
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
assert rip_target(0x43071cf) == 0x64849c0
assert relocations[0x64849d8] == (8, 0x3f47000)
assert rip_target(0x3f47000) == 0x3d681f0
assert rip_target(0x3d68265) == 0x647a128
assert relocations[0x647a140] == (8, 0x39176d0)
assert relocations[0x647a148] == (8, 0x3917660)
assert rip_target(0x3d6831f) == 0x41ae280
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

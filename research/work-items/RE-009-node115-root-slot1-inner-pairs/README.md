# RE-009 · Node #115 root slot 1 inner pair projection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4197](https://github.com/lalalune/hyperliquid-source/pull/4197) maps the eight immediate fields of a `0x120`-stride inner element. Its second projected child uses visitor `0x46a55e0` on the element base. This packet traces that visitor's two temporary projections and their source strides. The recorded capture and pointer joins are conditional on the selected dispatch path.

The visitor reads an allocation sizing word from source `+0x30`, checks multiplication by 16 for overflow, and builds two temporary arrays of 16-byte `(pointer, descriptor)` pairs. Separately, it reads traversal count from source `+0x10` and base pointer from `+8`. For each selected 24-byte source row, the first array receives a pointer to row `+8` with descriptor `0x6493318`, while the second receives row `+0x10` with descriptor `0x64934f8`; both source pointers advance by `0x18`. Allocation sizing and traversal counts are distinct reads, so this packet does not assume they are equal. The checked visitor/constructor bindings are `0x3916030/0x3916020` and `0x457d480/0x457d470` respectively.

The resulting two pair arrays and a separate value from source `+0x30` are handed to `0x41adc70`, which requires a non-sentinel destination with three entries. On the selected normal return the visitor releases both temporary arrays when their capacities are nonzero. The source row's first eight bytes are not claimed to be a key or ignored by all other paths; no domain names, concrete runtime values, complete root preimage or real checkpoint replay are inferred.

## Reproduce

GNU and LLVM agree on the selected instruction spans; descriptor and direct-call bindings are checked against the authenticated target.
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

with Path("research/work-items/RE-009-node115-root-slot1-inner-pairs/instructions.tsv").open() as handle:
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
assert rip_target(0x39176f7) == 0x646ee00
assert relocations[0x646ee18] == (8, 0x46a55e0)
assert rip_target(0x46a56de) == 0x6493318
assert rip_target(0x46a56e5) == 0x64934f8
assert relocations[0x6493330] == (8, 0x3916030)
assert relocations[0x6493338] == (8, 0x3916020)
assert relocations[0x6493510] == (8, 0x457d480)
assert relocations[0x6493518] == (8, 0x457d470)
assert rip_target(0x46a57ca) == 0x41adc70
assert 0x10 - 0x8 == 0x8
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-009 · Node #115 root capture slot 1 element projection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [block-root packet](../RE-017-abci-block-root-115/README.md) associates descriptor index 1 with state-relative capture `+0x4630`, but leaves its visitor internals open. This packet follows visitor `0x4307630` through its direct tail jump to `0x3d689f0` and its two-child dispatcher `0x41ae280`. The capture-to-descriptor pointer join is conditional on the recorded pointer array not being altered.

The selected visitor reads a count from source `+0x10` and a base pointer from `+8`. For a nonzero count it allocates a vector of 16-byte pairs. Each pair contains an element pointer and descriptor `0x647a1f0`; the element pointer advances by `0x200` per pair, and the collected count advances by one. The constructor/method fields at that descriptor bind to `0x4307160` and `0x43071c0`. Zero count instead builds an empty-vector representation. The visitor constructs a separate single entry referencing the count, then passes the count entry and the vector to `0x41ae280`; after that call, it frees the temporary vector if its capacity is nonzero.

The dispatcher requires a two-entry destination, with status 1 for its sentinel condition and 3 for a wrong count. Its selected loops use descriptor methods to lazily initialize child state and visit entries in sequence; any returned status other than 4 stops traversal. These observations establish a `0x200` input stride and the count/vector split on this static path, not the meanings of the element fields, a flat serialized block, actual checkpoint values, or an end-to-end root. Allocation failure and unwind are not claimed as normal results.

## Reproduce

GNU and LLVM agree on the selected instruction spans. The descriptor methods and the visitor jump are checked against the authenticated ELF; capture association is the prior packet's reproduced join.
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

with Path("research/work-items/RE-009-node115-root-slot1-stride/instructions.tsv").open() as handle:
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
assert relocations[0x64a81a0] == (8, 0x4307630)
assert relocations[0x64a81a8] == (8, 0x41f7be0)
assert rip_target(0x4307630) == 0x3d689f0
assert rip_target(0x3d68a5e) == 0x647a1f0
assert relocations[0x647a208] == (8, 0x43071c0)
assert relocations[0x647a210] == (8, 0x4307160)
assert rip_target(0x3d68b1f) == 0x41ae280
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

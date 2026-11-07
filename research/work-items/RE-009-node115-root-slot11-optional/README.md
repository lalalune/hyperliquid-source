# RE-009 · Node #115 root slot 11 optional packed children

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4192](https://github.com/lalalune/hyperliquid-source/pull/4192) maps the second and third child of state-root capture slot 11 to a shared 12-byte descriptor, but leaves its nested visitor open. This packet follows that visitor `0x15d1540`, including the link to the packed calendar writer studied separately in [PR #4191](https://github.com/lalalune/hyperliquid-source/pull/4191).

The visitor tests the 32-bit word at its input against zero. For zero it skips the payload child and visits the marker child with literal qword 0. For any nonzero value it initializes and visits the payload child, passing the original input pointer unchanged; only status 4 continues to marker child with literal qword 1. Both paths first require a non-sentinel two-entry destination, returning status 1 or 3 on the corresponding failed guard. Marker and payload children are lazily initialized when their first word is the uninitialized sentinel. Nonzero is the actual machine test; it is not proof that every nonzero packed calendar value is valid.

The selected payload constructor and visitor resolve through `0x156f390` and `0x156f3a0` to `0x141a020` and `0x141b1e0` respectively. The latter is the packed 8+4-byte child writer analyzed in #4191. The marker visitor resolves to qword writer `0x14199b0`, and the marker literals are verified directly in the ELF. These are two separate child nodes and are not asserted to be concatenated into one preimage. The capture join is conditional, and no real checkpoint value, end-to-end root or runtime execution is claimed.

## Reproduce

GNU and LLVM agree on the selected instruction spans; all tail-call, method and marker literal bindings are checked against the authenticated target.
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

with Path("research/work-items/RE-009-node115-root-slot11-optional/instructions.tsv").open() as handle:
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
assert rip_target(0x15b4971) == 0x6400138
assert relocations[0x6400150] == (8, 0x15d1540)
assert relocations[0x6400158] == (8, 0x15d14f0)
assert relocations[rip_target(0x15d158f)] == (8, 0x156f390)
assert relocations[rip_target(0x15d15ac)] == (8, 0x156f3a0)
assert relocations[rip_target(0x156f390)] == (8, 0x141a020)
assert relocations[rip_target(0x156f3a0)] == (8, 0x141b1e0)
assert relocations[rip_target(0x15d163e)] == (8, 0x14199b0)
assert rip_target(0x15d15c3) == 0x459280
assert rip_target(0x15d1611) == 0x459348
assert elf_bytes('.rodata', 0x459280, 8) == (1).to_bytes(8, 'little')
assert elf_bytes('.rodata', 0x459348, 8) == bytes(8)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

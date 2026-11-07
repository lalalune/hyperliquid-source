# RE-009 · Node #115 root row value tagged payload projections

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4210](https://github.com/lalalune/hyperliquid-source/pull/4210) identifies descriptor `0x6477bb0` for the second projection of the third child of a root-row value, but leaves its downstream format open. Its relocated visitor is `0x3918670`. This packet resolves both selector arms and the immediate payload descriptors, establishing an ordered set of candidate input projections for state-root reconstruction without naming the underlying domain fields.

The visitor compares the source's 32-bit tag with 2. For tag 2 it sets the payload pointer to source `+8`, uses discriminant 0 and descriptor `0x646f080`; otherwise it retains the original pointer, uses discriminant 1 and descriptor `0x646f0a8`. Both paths pass a one-item pointer/descriptor array and the discriminant to `0x41aed60`. Relocations bind the first visitor to `0x44f50b0` and the second to `0x37c27c0`.

The first payload visitor supplies the payload base with descriptor `0x648d330` and payload `+0xb8` with descriptor `0x648db28`, in that order, to `0x41ae280`. The second supplies original source `+0xc8`, `+0xd0`, base, and `+0xb8`, with descriptors `0x646a9e8`, `0x646a9e8`, `0x646aa10`, and `0x646aa38`, respectively, to `0x41ad9a0`. The corresponding relocated visitors are checked below. This describes immediate dispatch and pointer ordering, not complete encoding, runtime reachability, or state-root equivalence.

## Reproduce

GNU and LLVM agree on selected instruction spans. Descriptor relocations and direct dispatch targets are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-value-tag-two/instructions.tsv").open() as handle:
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
assert relocations[0x6477bc8] == (8, 0x3918670)
assert rip_target(0x3918696) == 0x646f080
assert rip_target(0x39186b5) == 0x646f0a8
assert rip_target(0x39186e6) == 0x41aed60
assert relocations[0x646f098] == (8, 0x44f50b0)
assert relocations[0x646f0c0] == (8, 0x37c27c0)
assert rip_target(0x44f50bc) == 0x648d330
assert rip_target(0x44f50d4) == 0x648db28
assert rip_target(0x44f510e) == 0x41ae280
assert rip_target(0x37c27d6) == 0x646a9e8
assert rip_target(0x37c27f8) == 0x646aa10
assert rip_target(0x37c2810) == 0x646aa38
assert rip_target(0x37c2873) == 0x41ad9a0
assert relocations[0x648d348] == (8, 0x44eb7a0)
assert relocations[0x648db40] == (8, 0x44eb980)
assert relocations[0x646aa00] == (8, 0x4513270)
assert relocations[0x646aa28] == (8, 0x44eb7a0)
assert relocations[0x646aa50] == (8, 0x392b690)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-009 · Node #115 root capture qword-child buffering

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4184](https://github.com/lalalune/hyperliquid-source/pull/4184) follows the selected root slot-26 nested visitor and its marker child. Both the nested first-child writer and outer marker writer use `0x14199b0` through different relocation slots. The child constructors for these selected qword writes use `0x14196d0`. This packet follows the shared write boundary into its target-bound buffer and digest update; the two writes belong to different children, so their bytes are not claimed to be concatenated directly.

The constructor allocates an owner of `0x798` bytes and a `0x8000`-byte buffer. It writes the owner pointer at destination `+8` and the sentinel `0x8000000000000000` at destination `+0`. The writer loads exactly one qword from its input. A destination whose first word is not that sentinel returns zero. For the sentinel case it calculates remaining buffer space as owner capacity minus used length. When that value is strictly greater than 8, it stores the qword at buffer pointer plus used length, increases used length by 8 and returns status 4. The target is x86-64, so the stored bytes are little endian. Equal-to-8 and smaller space take the separate `0x141adb0` fallback, rather than the inline branch.

The fallback checks the incoming length against remaining capacity and can pass buffered bytes to digest-update slot `0x64df510`, whose relocation resolves to `0x160b3a0`. Its further copy, direct-update, error and unwind paths remain bounded by the included code; this packet does not claim a full flush or final root algorithm. In the tag-1 outer marker case, the literal qword is 1, so its selected eight input bytes are `01 00 00 00 00 00 00 00`; the other marker is zero. No actual state value, runtime checkpoint, or end-to-end root is asserted.

## Reproduce

GNU and LLVM agree on the selected instruction spans; the writer, constructor, fallback and digest-update relocation edges and literal bytes are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-qword-child/instructions.tsv").open() as handle:
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
assert rip_target(0x4d3f40f) == 0x5106a90
assert relocations[rip_target(0x4d3f431)] == relocations[rip_target(0x4d3f47f)] == (8, 0x14196d0)
assert relocations[rip_target(0x5106acb)] == (8, 0x14196d0)
assert relocations[rip_target(0x4d3f4a0)] == relocations[rip_target(0x5106ae9)] == (8, 0x14199b0)
assert relocations[rip_target(0x14199fa)] == (8, 0x141adb0)
assert relocations[rip_target(0x141adf1)] == relocations[rip_target(0x141aedb)] == (8, 0x160b3a0)
assert elf_bytes('.rodata', 0x459280, 8) == bytes.fromhex('01 00 00 00 00 00 00 00')
assert elf_bytes('.rodata', 0x459348, 8) == bytes(8)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

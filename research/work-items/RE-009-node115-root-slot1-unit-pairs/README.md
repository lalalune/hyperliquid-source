# RE-009 · Node #115 inner element word-and-unit projections

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4197](https://github.com/lalalune/hyperliquid-source/pull/4197) maps inner-element source offsets `+0x108` and `+0x118` to visitors `0x3f7a840` and `0x4305d40`. This packet follows their two-child projections and resolves both second-child visitors. The captured pointer and selected destination joins remain conditional.

Each visitor constructs two one-entry descriptor lists for source offsets `+0` then `+8`, relative to its input, and calls `0x41ae280`. The first list reaches an eight-byte child writer: `0x141b3c0` for the `+0x108` projection and `0x14199b0` for the `+0x118` projection. On their selected inline paths both read a qword and store its eight raw bytes in their respective child buffer. The second list reaches `0x3b84cf0` or `0x41d6980`. Both helpers consist of the same 12 machine bytes: they ignore the source argument, test the destination first word, return status 4 exactly for sentinel `0x8000000000000000`, and return 0 otherwise; neither stores source bytes.

Thus the pointer to the second child is passed at inner offsets `+0x110` or `+0x120`, but the selected second-child helpers do not read those addresses. The static path reads the qword sources at `+0x108` or `+0x118` on its selected normal first-child visits. It is not evidence that surrounding fields are unused elsewhere, or that either composite produces one flat eight-byte root preimage. Runtime reachability, full digest composition and checkpoint replay remain open.

## Reproduce

GNU and LLVM agree on the selected instruction spans; descriptor methods, common helper bytes and direct dispatch calls are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-slot1-unit-pairs/instructions.tsv").open() as handle:
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
assert rip_target(0x391776c) == 0x646aac8
assert relocations[0x646aae0] == (8, 0x3f7a840)
assert rip_target(0x3917784) == 0x646eea0
assert relocations[0x646eeb8] == (8, 0x4305d40)
assert rip_target(0x3f7a84c) == 0x64741c8
assert rip_target(0x3f7a861) == 0x64741f0
assert relocations[0x64741e0] == (8, 0x141b3c0)
assert relocations[0x6474208] == (8, 0x3b84cf0)
assert rip_target(0x4305d4c) == 0x64828c8
assert rip_target(0x4305d61) == 0x6484b28
assert relocations[0x64828e0] == (8, 0x14199b0)
assert relocations[0x6484b40] == (8, 0x41d6980)
assert rip_target(0x3f7a89b) == rip_target(0x4305d9b) == 0x41ae280
assert elf_bytes('.text',0x3b84cf0,12) == elf_bytes('.text',0x41d6980,12) == bytes.fromhex('31 c0 48 3b 06 0f 90 c0 c0 e0 02 c3')
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

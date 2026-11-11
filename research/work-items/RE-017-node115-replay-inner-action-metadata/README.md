# RE-017 · Node #115 replay inner action metadata

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The bundle parser calls `0x38d8420` for every selected span. This packet pins the boundary between that span's fixed and optional metadata and its actual action bytes.

The helper rejects lengths at most `0x4b` with word `0x8a`. It reads 65 bytes from the start and an eight-byte word at input `+0x41`. It later stores the latter byte-swapped at result `+0x150`. The byte at input `+0x49` controls an optional 20-byte field. Value zero sets the next cursor to `+0x4a`. Value one copies 20 bytes and sets the cursor to `+0x5e`, requiring at least one byte after the copy. Other values give word `0x8d`.

At that cursor, the first byte must be below 2, otherwise the helper writes `0x8e`. The next byte selects a separate optional eight-byte field. Value zero consumes the two selector bytes and passes the rest to `0x38d96c0`. Value one requires at least ten bytes at this cursor, byte-swaps the qword at cursor `+2` and consumes ten bytes before calling the same decoder. Other values give `0x8f`. For the four combinations of these two options, the action decoder's selected input starts at offsets `0x4c`, `0x54`, `0x60` or `0x68`. The action decoder separately rejects an empty slice and reads its own leading discriminator.

On a selected successful path, the optional qword tag and value go to result `+0x08/+0x10`, the 20-byte optional field is staged at `+0x159` and its tag at `+0x158`, and the first post-field selector goes to `+0x16d`. The wrapper writes leading qword zero and the bundle parser copies its 0x168-byte payload. The inner decoder's `0xe2` error result instead makes the wrapper return leading qword 1, which makes the bundle parser reject that action. These are selected raw field offsets and codes. No semantic names for the optional fields or complete action schemas are assumed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on [instructions.tsv](instructions.tsv).

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

with Path("research/work-items/RE-017-node115-replay-inner-action-metadata/instructions.tsv").open() as handle:
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
assert rip_target(0x36abff3) == 0x38d8420
assert rip_target(0x38d8634) == 0x38d96c0
assert spans[0x38d84f3][-1] == 0x49
assert spans[0x38d853c][-1] == 0x5e
assert spans[0x38d85d3][-1] == 10
assert spans[0x38d8619][-1] == 2
assert [base + extra for base in (0x4a, 0x5e) for extra in (2, 10)] == [0x4c, 0x54, 0x60, 0x68]
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

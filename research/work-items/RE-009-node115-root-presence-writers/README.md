# RE-009 · Node #115 optional root payload writer widths

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4214](https://github.com/lalalune/hyperliquid-source/pull/4214) identifies the presence guards of shared root payload fields 2 and 6, without resolving their selected child writers. This packet follows both through relocation slots and distinguishes the payload widths and source-independent status behavior. The field offsets below are relative to the shared payload used by #4213.

When field 2 at `+0` has 32-bit tag 1, its selected child is field `+8` with descriptor `0x648e850`, whose visitor `0x4305d40` presents child `+0` and child `+8` in that order via `0x64828c8` and `0x6484b28` to `0x41ae280`. The first descriptor binds visitor `0x14199b0`: on the active output branch it copies the first eight source bytes into the destination buffer when remaining capacity is greater than eight, or invokes a fallback with length eight at the exact-fit and smaller boundaries. The second descriptor binds `0x41d6980`, which does not inspect its source pointer: it returns 4 if `0 - destination[0]` has signed overflow, and 0 otherwise. Thus the second projection should not be treated as an additional eight-byte source write merely because its pointer is field `+8`.

When field 6 at `+0xa1` has byte tag 1, the selected child is field `+1` with descriptor `0x648e738`; its visitor thunk `0x4302e50` follows slot `0x64df5d8` to `0x141ba80`. On the active destination branch this visitor copies 16 bytes from that child when remaining capacity is greater than 16; exact fit and smaller go to a length-16 fallback. Both writer methods first test the destination sentinel using signed overflow and return without the direct copy on the non-overflow branch. These observations do not establish whole-structure serialization, complete error semantics or checkpoint reachability.

## Reproduce

GNU and LLVM agree on selected instruction spans; all descriptor, thunk and indirect-slot relocations are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-presence-writers/instructions.tsv").open() as handle:
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
assert relocations[0x648e868] == (8, 0x4305d40)
assert rip_target(0x4305d4c) == 0x64828c8
assert rip_target(0x4305d61) == 0x6484b28
assert rip_target(0x4305d9b) == 0x41ae280
assert relocations[0x64828e0] == (8, 0x14199b0)
assert relocations[0x6484b40] == (8, 0x41d6980)
assert relocations[0x648e750] == (8, 0x4302e50)
assert rip_target(0x4302e50) == 0x64df5d8
assert relocations[0x64df5d8] == (8, 0x141ba80)
for width in (8,16):
    for available in (0,width-1,width,width+1):
        assert (available > width) == (not available <= width)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-009 · Node #115 wide-row nested projection widths

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4202](https://github.com/lalalune/hyperliquid-source/pull/4202) finds two nested `0x20`-stride row projections whose descriptor arrays have reversed order. This packet follows the shared row-base descriptor `0x6493340` and row-`+0x18` descriptor `0x6493318` through their method relocations to the child writers. The row and destination pointer joins remain conditional on the selected static dispatch.

The row-base descriptor's visitor `0x4302e50` tail-jumps through relocation `0x64df5d8` to `0x141ba80`. On its selected sentinel and inline-capacity path that writer copies exactly 16 source bytes unchanged into a child buffer, advances used length by 16 and returns status 4. At most 16 free bytes take fallback `0x141adb0`; a destination without the sentinel returns 0. Its constructor tail-jumps to `0x141a020`.

The row-`+0x18` descriptor reaches qword writer `0x14199b0` and constructor `0x14196d0` through `0x3916030` and `0x3916020`, as also seen in [PR #4199](https://github.com/lalalune/hyperliquid-source/pull/4199). Hence the selected projected input byte ranges are row `+0..+0xf` and `+0x18..+0x1f`; bytes `+0x10..+0x17` are outside these two projections. The two inputs feed separate children, with the array ordering differing between the two parent methods. This is not a claim that the omitted interval is unused elsewhere, or that these inputs form a flat root preimage. Actual runtime values and full state-root/replay behavior remain open.

## Reproduce

GNU and LLVM agree on the selected instruction spans; descriptor and tail-call relocations are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-wide-map-value-width/instructions.tsv").open() as handle:
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
assert rip_target(0x46a3d26) == rip_target(0x46a5eaf) == 0x6493318
assert rip_target(0x46a3d2d) == rip_target(0x46a5ea8) == 0x6493340
assert relocations[0x6493330] == (8, 0x3916030)
assert relocations[0x6493338] == (8, 0x3916020)
assert relocations[0x6493358] == (8, 0x4302e50)
assert relocations[0x6493360] == (8, 0x43025f0)
assert relocations[rip_target(0x4302e50)] == (8, 0x141ba80)
assert relocations[rip_target(0x43025f0)] == (8, 0x141a020)
assert relocations[rip_target(0x3916030)] == (8, 0x14199b0)
assert relocations[rip_target(0x3916020)] == (8, 0x14196d0)
assert relocations[rip_target(0x141bad0)] == relocations[rip_target(0x14199fa)] == (8, 0x141adb0)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

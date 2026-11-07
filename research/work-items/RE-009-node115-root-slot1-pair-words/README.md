# RE-009 · Node #115 root slot 1 inner pair word visitors

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4198](https://github.com/lalalune/hyperliquid-source/pull/4198) identifies two projected pointers per selected `0x18`-byte inner row, at row `+8` and `+0x10`, and leaves their descriptors' behavior open. This packet follows both descriptor method chains into the shared qword child writer and constructor.

The first projection's descriptor visitor `0x3916030` and constructor `0x3916020` tail-jump through relocations to `0x14199b0` and `0x14196d0`. The second projection's descriptor visitor `0x457d480` and constructor `0x457d470` reach those same two target functions through distinct relocation slots. The writer reads eight bytes from its source and, on the selected normal inline path, stores the raw qword into that child's buffer and advances its used length by eight. It returns status 4 on that path; a destination without the required sentinel returns 0, and at most eight free bytes takes the separate fallback. The constructor and writer details are independently tied to [PR #4185](https://github.com/lalalune/hyperliquid-source/pull/4185).

Thus, conditional on the selected pointer and child joins, the two projections supply row bytes `+8..+15` and `+0x10..+0x17` to two child visitors. They are distinct child buffers, not an established 16-byte flat preimage; no meaning is assigned to either word. [PR #4186](https://github.com/lalalune/hyperliquid-source/pull/4186) describes the selected subsequent child finalization. No real checkpoint value, full state-root reconstruction or block replay is claimed.

## Reproduce

GNU and LLVM agree on the selected instruction spans; both levels of descriptor and tail-call relocation are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-slot1-pair-words/instructions.tsv").open() as handle:
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
assert rip_target(0x46a56de) == 0x6493318
assert rip_target(0x46a56e5) == 0x64934f8
assert relocations[0x6493330] == (8, 0x3916030)
assert relocations[0x6493338] == (8, 0x3916020)
assert relocations[0x6493510] == (8, 0x457d480)
assert relocations[0x6493518] == (8, 0x457d470)
assert relocations[rip_target(0x3916030)] == relocations[rip_target(0x457d480)] == (8, 0x14199b0)
assert relocations[rip_target(0x3916020)] == relocations[rip_target(0x457d470)] == (8, 0x14196d0)
assert relocations[rip_target(0x14199fa)] == (8, 0x141adb0)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

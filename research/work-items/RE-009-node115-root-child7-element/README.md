# RE-009 · Node #115 root payload optional vector element widths

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4219](https://github.com/lalalune/hyperliquid-source/pull/4219) identifies the 0x20-stride vector in the present arm of shared root payload field 7 and its element descriptor `0x647a290`, but does not resolve each element. This packet follows that element into its two ordered projections and their raw writers. It reuses the 20-byte writer studied in [PR #4201](https://github.com/lalalune/hyperliquid-source/pull/4201), binding it to this different vector path rather than claiming a new implementation of that helper.

The descriptor's relocated visitor `0x37166a0` passes element `+8` with descriptor `0x646a0c0` first, then element `+0` with descriptor `0x646a200`, each as a one-item slice to `0x41ae280`. The first descriptor points to thunk `0x41f8050` and slot `0x64df600`, resolving to `0x141b9b0`; the second points to thunk `0x4303b70` and slot `0x64df530`, resolving to `0x14199b0`. On their direct-output branches, these visitors copy 20 and 8 source bytes respectively, with fallback taken at exact fit as well as less remaining capacity. Thus the selected element's projected source bytes are `[8,28)` followed by `[0,8)`; offsets `[28,32)` are not directly read by these two visitors on the described paths. This is dispatch order, not a claim about final digest or errors.

The vector path and visitors remain conditional on earlier guards and destination state. The element's type, significance of the last four bytes, full serialized representation and real checkpoint reachability remain unknown.

## Reproduce

GNU and LLVM agree on selected instruction spans; relocation and indirect thunk targets are checked in the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-child7-element/instructions.tsv").open() as handle:
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
assert relocations[0x647a2a8] == (8,0x37166a0)
for insn,target in [(0x37166b0,0x646a0c0),(0x37166c1,0x646a200),(0x37166fb,0x41ae280),(0x41f8050,0x64df600),(0x4303b70,0x64df530)]:
    assert rip_target(insn) == target
for slot,target in [(0x646a0d8,0x41f8050),(0x646a218,0x4303b70),(0x64df600,0x141b9b0),(0x64df530,0x14199b0)]:
    assert relocations[slot] == (8,target)
for width in (8,20):
    for remaining in (0,width-1,width,width+1):
        assert (remaining > width) == (not remaining <= width)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

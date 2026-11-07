# RE-009 · Node #115 root payload fourth-child vector and option projections

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4213](https://github.com/lalalune/hyperliquid-source/pull/4213) maps the fourth shared root payload child at `+0x10` to `0x44e9d30`. This packet traces the three immediate child projections and resolves the first child vector and remaining two shared tag guards. Offsets below are relative to the fourth-child pointer, itself `+0x10` from the shared payload.

`0x44e9d30` constructs three one-element slices in order: child `+0x20` with descriptor `0x648d0d8`, child `+0` with `0x648d100`, and child `+0x10` with the same `0x648d100`; it dispatches them through `0x41adc70`. Relocations bind the first to visitor `0x3d6a730` and the latter two to `0x4514af0`.

The vector visitor reads count at source `+0x10` and base at `+8`; it rejects counts with any of the top five bits set before multiplying. Nonzero count allocates `count * 16` bytes for pairs. It creates one pair per element, in ascending order, pointing to `base + 8*i` with descriptor `0x647a4c0`. It passes the pair array and separate count descriptor `0x6479f20` to `0x41ae280`, and frees the allocation on normal return. For zero count it uses a zero-length array and sentinel pointer 8. The element and count descriptor relocations resolve to the same qword visitor, via a jump thunk in the former case. Allocation failure and oversized count reach an indirect failure helper. No runtime target execution is performed.

The shared child visitor `0x4514af0` tests a 32-bit value equal to 1: that branch supplies source `+8` with descriptor `0x648e2e0` as a single element; all other values supply the empty slice. Both branches pass to `0x41ae280`. This is a static structural map, not field-name identification, a complete serialized representation, or proof of real checkpoint/root equivalence.

## Reproduce

GNU and LLVM agree on selected instruction spans; caller, descriptor and indirect jump bindings are checked in the authenticated ELF. Arithmetic controls exercise zero and the count threshold.
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

with Path("research/work-items/RE-009-node115-root-payload-child4-vector/instructions.tsv").open() as handle:
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
assert relocations[0x648d398] == (8, 0x44e9d30)
assert rip_target(0x44e9d40) == 0x648d0d8
assert rip_target(0x44e9d51) == 0x648d100
assert rip_target(0x44e9dac) == 0x41adc70
assert relocations[0x648d0f0] == (8, 0x3d6a730)
assert relocations[0x648d118] == (8, 0x4514af0)
assert rip_target(0x3d6a7b1) == 0x647a4c0
assert rip_target(0x3d6a836) == 0x6479f20
assert rip_target(0x3d6a867) == 0x41ae280
assert relocations[0x647a4d8] == (8, 0x3916030)
assert relocations[0x6479f38] == (8, 0x14199b0)
assert rip_target(0x4514b05) == 0x648e2e0
assert rip_target(0x4514b5c) == 0x41ae280
for count in (0, 1, (1 << 59)-1, 1 << 59):
    assert ((count >> 59) != 0) == (count >= (1 << 59))
    if count < (1 << 59): assert count * 16 < (1 << 64)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

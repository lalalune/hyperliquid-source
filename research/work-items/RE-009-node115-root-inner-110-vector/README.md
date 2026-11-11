# RE-009 · Node #115 root inner fourth-child vector

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4197](https://github.com/lalalune/hyperliquid-source/pull/4197) maps eight ordered projections of a root slot-1 inner element. Its fourth projection is the element `+0x80` with descriptor `0x646ee50`; this packet follows that previously unresolved projection and distinguishes its `0x110`-stride vector from the surrounding `0x120`-stride elements in #4196.

The relocated visitor `0x4591a60` presents three one-element slices to `0x41adc70`, in order: source `+0` with descriptor `0x64848e0`, source `+0x18` and `+0x20` with the shared descriptor `0x6482968`. Their relocated visitors are `0x3d68d40` and `0x14199b0` respectively. The last two pointers are relative to the fourth projection, so they correspond to inner element `+0x98` and `+0xa0`.

The first child visitor reads a count at source `+0x10` and data pointer at `+8`. For a nonzero count it allocates `count << 4` bytes of pointer/descriptor pairs and iterates the source pointer in `0x110` increments; each pair uses descriptor `0x647a240`, binding to visitor `0x4305e80`. The resulting pair list and separate count descriptor `0x6479f20` go to `0x41ae280`, with normal-return release of the temporary list. The zero-count path uses a zero-length list and sentinel pointer 8. The visible code shifts the count and multiplies it by `0x110` without a visible pre-operation range check; this packet does not claim overflow safety or malformed input reachability.

The mapping is conditional on the upstream selected root capture and visitor paths; it does not establish field names, individual `0x110` element semantics, a complete root, or checkpoint replay.

## Reproduce

GNU and LLVM agree on selected instructions; descriptor bindings and direct dispatcher targets are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-inner-110-vector/instructions.tsv").open() as handle:
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
assert relocations[0x646ee68] == (8,0x4591a60)
for insn,target in [(0x4591a6c,0x64848e0),(0x4591a81,0x6482968),(0x4591adc,0x41adc70),(0x3d68db1,0x647a240),(0x3d68e3e,0x6479f20),(0x3d68e6f,0x41ae280)]:
    assert rip_target(insn) == target
for slot,target in [(0x64848f8,0x3d68d40),(0x6482980,0x14199b0),(0x647a258,0x4305e80),(0x6479f38,0x14199b0)]:
    assert relocations[slot] == (8,target)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

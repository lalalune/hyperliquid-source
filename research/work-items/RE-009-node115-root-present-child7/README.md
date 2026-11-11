# RE-009 · Node #115 root payload optional seventh-child projection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4214](https://github.com/lalalune/hyperliquid-source/pull/4214) identifies the presence guard for the seventh shared root payload field at `+0x58`: on a non-sentinel qword it dispatches the field through descriptor `0x648e7d8`. This packet resolves the selected child visitor and its 0x20-stride vector, which must be interpreted relative to that field pointer.

Relocation binds the selected descriptor to `0x37b9710`. This visitor supplies three one-item slices to `0x41adc70` in order: field `+0x20` with descriptor `0x646a0c0`, field `+0x18` with `0x646a200`, and field `+0` with `0x646a3d0`. Their visitors resolve respectively to `0x41f8050`, thunk `0x4303b70` (indirect slot `0x64df530`, relocation to `0x14199b0`), and `0x3d69080`.

The third visitor reads count at field `+0x10` and base at `+8`. For nonzero count, it allocates 16 bytes per item, builds pointer/descriptor pairs in source order with pointer `base + 0x20*i` and descriptor `0x647a290`, and supplies the pairs and separate count descriptor `0x6479f20` to `0x41ae280`; it frees the pair allocation on normal return. The zero-count branch supplies a zero-length array and sentinel pointer 8. The element descriptor binds to `0x37166a0` and the count descriptor to `0x14199b0`. Allocation failure reaches an indirect failure helper. This visitor shows left shifts for sizes and loop span without a visible pre-shift overflow guard; this packet does not infer a safe maximum count, nor claim malformed input is reachable or safe. Child domain names, full encoding and real checkpoint reachability remain open.

## Reproduce

GNU and LLVM agree on the selected instruction spans; direct dispatcher calls and descriptor and thunk relocations are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-present-child7/instructions.tsv").open() as handle:
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
assert relocations[0x648e7f0] == (8, 0x37b9710)
for insn,target in [(0x37b9720,0x646a0c0),(0x37b9735,0x646a200),(0x37b9746,0x646a3d0),(0x37b9793,0x41adc70),(0x3d690ee,0x647a290),(0x3d69178,0x6479f20),(0x3d691a9,0x41ae280),(0x4303b70,0x64df530)]:
    assert rip_target(insn) == target
for slot,target in [(0x646a0d8,0x41f8050),(0x646a218,0x4303b70),(0x646a3e8,0x3d69080),(0x647a2a8,0x37166a0),(0x6479f38,0x14199b0),(0x64df530,0x14199b0)]:
    assert relocations[slot] == (8,target)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

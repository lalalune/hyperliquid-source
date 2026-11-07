# RE-009 · Node #115 0x110 element presence guards

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4224](https://github.com/lalalune/hyperliquid-source/pull/4224) maps ten ordered children for the non-2 arm of a `0x110`-stride root element. This packet resolves the empty/present tests of four of those children, including two applications of one shared visitor. The offsets below refer to the element pointer, contingent on the non-2 arm.

Children 1 and 2, element `+0` and `+0x10`, share visitor `0x4513770`. Each tests a 32-bit tag equal to 1: on equality it selects one child at field `+8` with descriptor `0x648e3f8`, otherwise it selects a zero-length slice. That descriptor binds thunk `0x457d480`, which follows relocation slot `0x64df538` to `0x14199b0`.

Child 6, element `+0xd8`, uses `0x45130f0`; it tests a 32-bit tag equal to 1 and selects field `+4` with descriptor `0x648e6e8` on equality, otherwise the empty slice. This descriptor binds thunk `0x4305830`, whose relocation slot `0x64df4e8` resolves to `0x1419c90`.

Child 8, element `+0x10d`, uses `0x45149f0`. It tests one byte against 5: equality chooses the empty slice; any other byte selects one child at the unchanged field pointer with descriptor `0x648eda0`, visitor `0x44e6df0`. Each of these visitors passes its selected slice to `0x41ae280`; the empty slice's data value 8 is not a source pointer. The fourth visitor is only identified here, not fully interpreted. Field meanings, malformed tags, complete encoding, runtime reachability and a real checkpoint/root match remain open.

## Reproduce

GNU and LLVM agree on selected instruction spans. Descriptor relocations, thunk slots and dispatcher calls are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-110-option-guards/instructions.tsv").open() as handle:
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
for slot,target in [(0x648d190,0x4513770),(0x648d2f8,0x45130f0),(0x648d320,0x45149f0),(0x648e410,0x457d480),(0x648e700,0x4305830),(0x648edb8,0x44e6df0),(0x64df538,0x14199b0),(0x64df4e8,0x1419c90)]:
    assert relocations[slot] == (8,target)
for insn,target in [(0x4513785,0x648e3f8),(0x45137dc,0x41ae280),(0x4513105,0x648e6e8),(0x451315c,0x41ae280),(0x4514a1c,0x648eda0),(0x4514a58,0x41ae280),(0x457d480,0x64df538),(0x4305830,0x64df4e8)]:
    assert rip_target(insn) == target
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

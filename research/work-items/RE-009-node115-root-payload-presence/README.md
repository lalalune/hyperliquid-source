# RE-009 · Node #115 shared root payload presence encodings

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4213](https://github.com/lalalune/hyperliquid-source/pull/4213) maps nine ordered projections of a shared tagged root payload. This packet resolves the selection guards for fields 2, 6 and 7, where superficial treatment as the same option encoding would be incorrect. All offsets below are relative to the shared payload pointer, whose relation to the enclosing tagged source depends on the #4212 arm.

Field 2 at `+0` uses visitor `0x4513570`. A 32-bit tag equal to 1 selects one child at field `+8` with descriptor `0x648e850`; all other values select an empty slice. Field 6 at `+0xa1` uses visitor `0x45131f0`: a byte tag equal to 1 selects one child at field `+1` with descriptor `0x648e738`; all other byte values select an empty slice. Field 7 at `+0x58` uses visitor `0x45133f0`: subtraction flags from `0 - qword` select the empty slice only for `0x8000000000000000` (signed subtraction overflow); all other qwords select one child at the original field address with descriptor `0x648e7d8`.

Each method builds either a single pair or a zero-length slice and dispatches to `0x41ae280`; the observed empty descriptor pointer uses 8 as its data value with length zero, so it must not be interpreted as a source address. This is a static branch and input-pointer map, not complete serialized bytes or proof that a real checkpoint takes each branch.

## Reproduce

GNU and LLVM agree on selected instruction spans; bindings and dispatcher targets are checked against the authenticated ELF. Synthetic flag controls cover zero, extrema and neighboring qwords without executing the target.
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

with Path("research/work-items/RE-009-node115-root-payload-presence/instructions.tsv").open() as handle:
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
assert relocations[0x648d370] == (8, 0x4513570)
assert relocations[0x648d3e8] == (8, 0x45131f0)
assert relocations[0x648d410] == (8, 0x45133f0)
for insn, target in [(0x4513585,0x648e850),(0x4513204,0x648e738),(0x451341e,0x648e7d8),(0x45135dc,0x41ae280),(0x451325b,0x41ae280),(0x451345a,0x41ae280)]:
    assert rip_target(insn) == target
for value in (0, 1, 0x7fffffffffffffff, 0x8000000000000000, 0x8000000000000001, 0xffffffffffffffff):
    signed = value if value < (1 << 63) else value - (1 << 64)
    overflow = not (-(1 << 63) <= -signed < (1 << 63))
    assert overflow == (value == 0x8000000000000000)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

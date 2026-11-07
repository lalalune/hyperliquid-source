# RE-009 · Node #115 root capture slot 26 nested visitor

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [block-root packet](../RE-017-abci-block-root-115/README.md) records that capture index 41 is state-relative `+0x1c68`, that descriptor index 26 receives that capture, and that its visitor is `0x4d3f3a0`; it only details the different index-13 visitor. This packet follows the index-26 visitor into its two-child payload visitor. The joins remain conditional on the captured pointer array reaching the descriptor without an intervening change; matching offsets alone do not prove a real restored checkpoint's pointer identity.

The index-26 visitor first compares the 32-bit word at its input to 1. It requires a non-sentinel destination and a two-entry destination count; otherwise it returns status 1 or 3. On tag 1 it initializes destination child zero if needed, then passes input `+8` to `0x5106a90`; a non-4 status returns without writing the marker. This nested visitor independently requires a two-entry destination, passes that input to its first child writer, and only after status 4 passes the second child to `0x4d3f7f0`. That helper does not read its source argument or write the child: it returns status 4 exactly when the destination first word is `0x8000000000000000`, and 0 otherwise. Its caller advances the source pointer to outer input `+0x10`, but this helper ignores it. If the nested visitor succeeds, the outer visitor writes literal qword 1 to child one. For any outer tag other than 1, it skips the nested payload and writes literal qword 0 to child one. The literal addresses and bytes are verified from the target.

Destination initialization depends on the selected sentinel `0x8000000000000001`; allocator failures and other helper internals are outside this packet. This is an observed visitor path, not a claim about source-level types, a concrete field value, complete canonical root serialization, or actual checkpoint execution.

## Reproduce

GNU and LLVM agree on the selected instruction spans; the descriptor relocation and marker literals are checked against the target ELF.
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

with Path("research/work-items/RE-009-node115-root-slot26-visitor/instructions.tsv").open() as handle:
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
assert rip_target(0x544268e) == 0x64a84a8
assert relocations[0x64a84c0] == (8, 0x4d3f3a0)
assert relocations[0x64a84c8] == (8, 0x4d3e540)
assert rip_target(0x4d3f3f3) == 0x5106a40
assert rip_target(0x4d3f40f) == 0x5106a90
assert rip_target(0x4d3f425) == rip_target(0x4d3f448) == 0x459280
assert rip_target(0x4d3f473) == rip_target(0x4d3f496) == 0x459348
assert elf_bytes('.rodata', 0x459280, 8) == (1).to_bytes(8, 'little')
assert elf_bytes('.rodata', 0x459348, 8) == (0).to_bytes(8, 'little')
assert rip_target(0x5106b25) == 0x4d3f7f0
assert elf_bytes('.text', 0x4d3f7f0, 12).hex() == '31c0483b060f90c0c0e002c3'
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-017 · Node #115 selected checkpoint flag initialization

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [loader result packet](../RE-017-loader-checkpoint-result-115/README.md) traces the checkpoint flag to a byte read at parent `+0xb20` but leaves its earlier producer unresolved. This packet identifies one conditional initialization of that location, not every writer or a proof of runtime reachability.

In parent FDE `0x2cb6500`, `0x2cb7404` forms subobject `parent + 0xae8`; `0x2cb7413` passes it as the second argument to `0x2b905a0` at `0x2cb741b`. The callee preserves that argument in RBX. On the selected dispatch, subobject byte `+0x195 == 0` indexes the first signed-relative table entry at `0x607308`, selecting `0x2b905d8`. If the subsequently read dword at `0x64f01d8` is zero, execution takes the local initialization arm; if it is nonzero, execution calls slot `0x64df9f0` and, on normal return, rejoins that same arm at `0x2b90915`. The qword store at `0x2b9062d` writes `0xb` to subobject `+0x38`, hence parent `+0xb20` through `+0xb27`; on x86-64 its first byte is `0x0b`.

On the selected parent continuation after the helper returns a tag other than 2, the initializer is **not** the final source of the read bytes. At `0x2cb74cf` the parent loads 16 bytes from `parent + 0x148`; it saves and reloads them through the stack and at `0x2cb7553` stores them at `subobject + 0x30`, i.e. `parent + 0xb18`. This 16-byte store overwrites both `parent + 0xb20` and `+0xb21`, whose selected sources are the bytes at `parent + 0x150` and `+0x151` respectively. The join assumes the selected normal continuation, the SysV callee-saved subobject pointer, and no alias writes changing the source or stack copy. It does not infer those source bytes' values or their earlier producers.

The parent reads those bytes at `0x2cb758f` and `0x2cb7596`, saving the first at `+0x2a19`. It tests the second at `0x2cb75e9`: zero branches to an indirect call and, if that returns, `ud2` at `0x2cb9ed8`. The prior packet connects the saved first byte to a checkpoint helper whose selected result is the predicate byte != 2. The earlier qword initializer alone does **not** determine either read value or the later predicate; the selected overwrite must be accounted for. Other state-table entries, aliasing, runtime reachability, checkpoint-height relationships and root equality remain open.

## Reproduce

GNU and LLVM agree on selected instruction spans. The authenticated ELF verifies the caller edge and the first relative jump-table entry; boundary/corruption checks below are static synthetic controls, not target execution.
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

with Path("research/work-items/RE-017-node115-checkpoint-flag-init/instructions.tsv").open() as handle:
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
assert rip_target(0x2cb741b) == 0x2b905a0
assert rip_target(0x2b905c3) == 0x607308
assert rip_target(0x2b9090f) == 0x64df9f0
assert rip_target(0x2b90915) == 0x2b90612
entry = elf_bytes('.rodata',0x607308,4)
assert 0x607308 + struct.unpack('<i',entry)[0] == 0x2b905d8
changed = bytearray(entry)
changed[0] ^= 1
assert 0x607308 + struct.unpack('<i',changed)[0] != 0x2b905d8
assert 0xae8 + 0x38 == 0xb20
assert 0xae8 + 0x30 + 8 == 0xb20
assert 0x148 + 8 == 0x150 and 0x148 + 9 == 0x151
assert (0x0b).to_bytes(8,'little')[:2] == bytes((11,0))
assert rip_target(0x2cb75f1) == 0x2cb9b5c
assert rip_target(0x2cb9b77) == 0x2cb9ed8
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

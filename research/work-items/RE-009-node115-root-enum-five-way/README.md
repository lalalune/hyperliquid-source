# RE-009 · Node #115 root-field five-way byte visitor

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base main `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [root 0x110-element option packet](../RE-009-node115-root-110-option-guards/README.md) identifies the child-8 visitor `0x44e6df0`, reached through descriptor `0x648eda0` when the source byte differs from 5, but leaves its behavior open. This packet resolves the five selected jump-table cases and shared destination guards. The outer selected path is a static join, not evidence that a real checkpoint exercises it.

The visitor reads its source byte, indexes signed 32-bit offsets at `0x7d0178`, adds the table base and jumps. Entries 0 through 4 lead respectively to `0x44e6e08`, `0x44e6f55`, `0x44e6eb2`, `0x44e6f07`, and `0x44e6e5d`; each stages the corresponding number as a qword. In all five paths, signed overflow on `0 - destination[0]` returns status 1; otherwise zero at destination `+0x10` returns status 2. With a nonzero destination count, the code reads the object pointer at `+8`, examines the object leading qword for `0x8000000000000001`, and on equality calls the relocated slot `0x64df560` and helper `0x41c70d0` before copying three qwords into the object. Both object arms then call slot `0x64df538` with the staged case and object; this downstream return is not assumed.

Only five table entries are authenticated. Although the caller routes byte 5 to the empty arm, these observations do not establish whether other byte values reach this visitor safely. Field meaning, complete serialization and real checkpoint/root equivalence remain open.

## Reproduce

GNU and LLVM agree on 120 instruction spans. The selected entry targets, FDE and descriptor/slot relocations below are checked against the authenticated ELF; controls mutate each table entry.
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

with Path("research/work-items/RE-009-node115-root-enum-five-way/instructions.tsv").open() as handle:
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
assert relocations[0x648edb8] == (8, 0x44e6df0)
assert rip_target(0x44e6df8) == 0x7d0178
assert relocations[0x64df560] == (8, 0x14196d0)
assert relocations[0x64df538] == (8, 0x14199b0)
table = elf_bytes('.rodata', 0x7d0178, 20)
expected = [0x44e6e08, 0x44e6f55, 0x44e6eb2, 0x44e6f07, 0x44e6e5d]
assert [0x7d0178 + d for d in struct.unpack('<5i', table)] == expected
for i in range(5):
    mutation = bytearray(table)
    mutation[4*i] ^= 1
    assert [0x7d0178 + d for d in struct.unpack('<5i', mutation)] != expected
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

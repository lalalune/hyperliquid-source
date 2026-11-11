# RE-017 · Node #115 local restore completion-marker paths

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [restore intermediate](../RE-017-restore-checkpoint-intermediate-115/README.md) identifies two tests after parsing the numeric directory component, but leaves the second path's selector unresolved. The [prune reader](../RE-015-evm-prune-policy-115/README.md) observes the shared path family in a different caller. This packet pins the exact restore-site inputs that qualify an on-disk candidate.

At `0x25d43a4`, the first format record has one argument, the original directory row's path pointer and length, then the literal suffix `/CHECKPOINT_COMPLETE`. The regular-file predicate is called at `0x25d43c6`. A true AL skips the alternate call. A false AL reaches `0x25d4416`, passing the same row path and selector 2 to `0x1696b90`. This helper scales the selector by eight. Its pointer table entry `0x6408c60` resolves to the eight bytes `EvmState`, and the length table entry at `0x47b460` is 8. The format record at `0x442eac` takes the path, suffix `/CHECKPOINT_COMPLETE_` and the typed name. This constructs the alternate `/CHECKPOINT_COMPLETE_EvmState` candidate checked at `0x25d4428`.

Both calls resolve to `0x1500d20`. On the retained metadata result path that predicate masks the mode with `0xf000` and accepts `0x8000`. A true result on either marker permits appending the 32-byte candidate with the previously parsed key at `+0x18`. A false result from both takes a separate vector path. It does not produce an accepted row. A data-only directory without a qualifying marker is therefore insufficient on this selected path. Neither marker is a statement about the integrity or provenance of the checkpoint payload.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on the retained instruction boundaries and bytes in [instructions.tsv](instructions.tsv). From repository root:

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

with Path("research/work-items/RE-017-node115-restore-marker-paths/instructions.tsv").open() as handle:
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
assert rip_target(0x25d43a4) == 0x44bb44
assert rip_target(0x1696c61) == 0x442eac
assert rip_target(0x25d4416) == 0x1696b90
assert rip_target(0x1696be7) + 16 == 0x6408c60
assert rip_target(0x1696bf2) + 16 == 0x47b460
assert relocations[0x6408c60] == (8, 0x459a58)
assert elf_bytes(".rodata", 0x459a58, 8) == b"EvmState"
assert struct.unpack("<Q", elf_bytes(".rodata", 0x47b460, 8)) == (8,)
for address, literal in ((0x44bb44, b"\xc0\x14/CHECKPOINT_COMPLETE\x00"),
                         (0x442eac, b"\xc0\x15/CHECKPOINT_COMPLETE_\xc0\x00")):
    assert elf_bytes(".rodata", address, len(literal)) == literal
assert rip_target(0x25d43c6) == rip_target(0x25d4428) == 0x64e0950
assert relocations[0x64e0950] == (8, 0x1500d20)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

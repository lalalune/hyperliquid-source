# RE-009 · Node #115 root capture slot 23 byte visitor

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [block-root packet](../RE-017-abci-block-root-115/README.md) identifies state capture index 38 at state-relative `+0x4e1c` and descriptor index 23, but leaves that descriptor's visitor body open. This packet follows its byte visitor `0x1419d40` and constructor `0x14193f0`. The address join remains conditional on the selected captured pointer array reaching its corresponding descriptor without intervening mutation; it is not a claim about a particular restored state.

The constructor allocates an owner and `0x8000`-byte buffer, sets capacity and zero used length, and publishes the same `0x8000000000000000` child sentinel used by the reducer. The visitor loads a single input byte. With that destination sentinel and more than one free buffer byte, it copies the loaded byte unchanged to buffer plus used, increments used by one, and returns status 4. It does not normalize the byte to a Boolean. A destination that does not have the sentinel returns 0; at most one free byte takes fallback `0x141adb0`, whose exact-fit and digest-update behavior is described in [PR #4187](https://github.com/lalalune/hyperliquid-source/pull/4187).

On a newly initialized child with one successful inline visit and no intervening mutation, the selected reducer path in [PR #4186](https://github.com/lalalune/hyperliquid-source/pull/4186) updates the child digest with exactly that one byte before finalization. This is a conditional input model: the real byte value, any source-level type, final state-root serialization and runtime checkpoint replay remain unproven.

## Reproduce

GNU and LLVM agree on the selected instruction spans. Descriptor and helper relocations are checked directly from the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-byte-slot23/instructions.tsv").open() as handle:
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
assert rip_target(0x544263b) == 0x64a8458
assert relocations[0x64a8470] == (8, 0x1419d40)
assert relocations[0x64a8478] == (8, 0x14193f0)
assert relocations[rip_target(0x1419d87)] == (8, 0x141adb0)
assert relocations[rip_target(0x141a2d2)] == (8, 0x160b3a0)
assert relocations[rip_target(0x141a2e8)] == (8, 0x160bcd0)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

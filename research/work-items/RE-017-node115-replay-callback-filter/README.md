# RE-017 · Node #115 replay callback mode selects an additional filter

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4169](https://github.com/lalalune/hyperliquid-source/pull/4169) connects a received record to two consecutive callbacks with third arguments 0 and 1. The earlier [override-membership packet](../RE-017-node115-replay-override-membership/README.md) maps a separate five-byte-row membership test in the callback. This packet follows the callback's mode byte beyond that test.

The callback saves its third argument at stack +0xf. It passes a pointer to that byte into a descriptor at stack +0x338 before calls 0x5b74af0 and 0x4e36fb0. The returned collection has a pointer at stack +0x120 and a count at +0x128. A zero count bypasses the selected iteration. Otherwise entries advance in 16-byte units and the callback loads an entry's second word for the following path.

At 0x5a63675 a zero mode selects a direct reference increment and continues to the common construction. A nonzero mode enters an additional search if the incoming record pointer and its count at +0x20 are nonzero. This path scans 32-byte entries from the pointer at +0x18, comparing them through a tree or a separate flat search. In the selected tree arm, equality from the 32-byte memcmp returns to the next candidate. Missing or exhausted searches reach separate continuations. The zero-mode and nonzero-mode calls thus cannot be reduced to two identical invocations in an offline model.

The helper calls and collection behavior are conditional boundaries. This trace does not assign a domain name to the 32-byte keys, prove runtime reachability, or infer that an individual callback changes checkpoint state.

## Reproduce

GNU and LLVM agree on the selected instruction spans.
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

with Path("research/work-items/RE-017-node115-replay-callback-filter/instructions.tsv").open() as handle:
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
assert rip_target(0x5a6e42d) == rip_target(0x5a6e43d) == 0x5a63100
assert rip_target(0x5a635a7) == 0x5b74af0
assert rip_target(0x5a635bc) == 0x4e36fb0
assert relocations[rip_target(0x5a63786)] == (0xc00000006, 0)
assert rip_target(0x5a637e8) == 0x57fae00
assert rip_target(0x5a6367a) == 0x5a63820
assert rip_target(0x5a637ac) == 0x5a636e0

assert elf_bytes(".text", 0x5a63820, 4) == bytes.fromhex("f0 49 ff 06")
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

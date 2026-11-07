# RE-009 · Node #115 root capture slot 11 three-child visitor

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [block-root packet](../RE-017-abci-block-root-115/README.md) maps descriptor index 11 to the 32-byte state-relative capture `+0x4d70`, with visitor `0x15b4950`. This packet resolves its three child descriptors and selected serial visitor, without assigning domain names to the fields. The pointer join is conditional on the recorded capture array reaching its descriptor unchanged.

The visitor builds three one-element descriptor lists for source offsets `+0`, `+8`, and `+0x14`, in that order, then calls `0x14bbf10`. The first field uses descriptor `0x6400110`; its visitor `0x1603ec0` tail-jumps to the raw eight-byte child writer `0x1419900`, previously compared in [PR #4189](https://github.com/lalalune/hyperliquid-source/pull/4189). The second and third fields use the same descriptor `0x6400138`, whose visitor is `0x15d1540` and whose constructor is `0x15d14f0`; its selected branch tests a 32-bit tag against zero and uses a two-child representation. Their complete nested value semantics remain open.

The serial helper requires a three-entry destination; the sentinel and wrong-count conditions return statuses 1 and 3. For each of the three field lists it lazily initializes the corresponding child through the descriptor's `+0x20` method when the child carries the uninitialized sentinel, then calls its `+0x18` visitor. Any result other than 4 stops the sequence; all three successful lists return 4. Thus the observed field order does not establish a single flat 32-byte hash input. Actual state values, pointer identity at runtime, nested tag semantics and the complete state root are not established.

## Reproduce

GNU and LLVM agree on the selected instruction spans. The target's descriptor and tail-call relocations are checked below; capture-to-descriptor association is the prior packet's reproduced join.
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

with Path("research/work-items/RE-009-node115-root-slot11-three-child/instructions.tsv").open() as handle:
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
assert relocations[0x64a8308] == (8, 0x15b4950)
assert relocations[0x64a8310] == (8, 0x15b48f0)
assert rip_target(0x15b495c) == 0x6400110
assert rip_target(0x15b4971) == 0x6400138
assert rip_target(0x15b49cc) == 0x14bbf10
assert relocations[0x6400128] == (8, 0x1603ec0)
assert relocations[0x6400130] == (8, 0x1603eb0)
assert relocations[0x6400150] == (8, 0x15d1540)
assert relocations[0x6400158] == (8, 0x15d14f0)
assert relocations[rip_target(0x1603ec0)] == (8, 0x1419900)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

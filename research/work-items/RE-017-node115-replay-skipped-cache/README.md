# RE-017 · Skipped replay records still update the gossip cache

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4135](https://github.com/lalalune/hyperliquid-source/pull/4135) describes the empty-record conversion sentinel. [PR #4149](https://github.com/lalalune/hyperliquid-source/pull/4149) tracks the separate expected identity and cutoff basis. The existing [gossip cache packet](../RE-014-gossip-cache-update-115/README.md) identifies the cache update helper. This packet joins those results on the selected skipped-record path.

For a non-null received record, the worker first checks the selected identity against its expected word. On equality it calls 0x5a63100 twice with the same selected record pair, first with third argument zero and then one. It computes the saturated successor and stores that as the next expected identity before invoking converter 0x4fad300. The converter returns the high-bit sentinel for its selected empty-input cutoff. That branch clears the local flag at stack +0x5c and reaches the call at 0x5a6e4de, whose relocation resolves to the previously analyzed cache update 0x5a5d5a0. The zero flag bypasses the later wait arm and the selected cleanup returns to the receive loop.

The two callback invocations and cache update therefore precede the next receive on this path even though the sentinel bypasses the selected block-call route. The cache helper's already documented comparison can reset its four-word cache, then insert a selected successor key. These are conditional static edges, assuming ordinary calls and preserved memory. They do not establish a successful cache write, a state transition, or the identity of any real archive record.

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

with Path("research/work-items/RE-017-node115-replay-skipped-cache/instructions.tsv").open() as handle:
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
assert relocations[rip_target(0x5a6e48d)] == (8, 0x4fad300)
assert relocations[rip_target(0x5a6e4de)] == (8, 0x5a5d5a0)
assert rip_target(0x5a5d772) == 0x4dc0950
assert rip_target(0x5a5d7b4) == 0x4ddb720
assert spans[0x5a6e4ab].endswith(bytes.fromhex("00 00 00 00"))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

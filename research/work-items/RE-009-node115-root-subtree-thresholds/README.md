# RE-009 · Node #115 digest selector-dependent subtree thresholds

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4179](https://github.com/lalalune/hyperliquid-source/pull/4179) covers the above-threshold recursive split and [PR #4180](https://github.com/lalalune/hyperliquid-source/pull/4180) the base route. This packet resolves the five threshold entries at `.rodata` `0x46ab98` and connects them to the outer root-digest selector previously identified in [PR #4133](https://github.com/lalalune/hyperliquid-source/pull/4133). The outer constructor calls the selector routine and stores its returned byte at digest context `+0x6b`; this is an implementation selector, not the base hash flags at `+0x6a`.

At `0x160a120`, `0x160a127` and `0x160a12b`, the bulk helper indexes the threshold table with its selector argument, taking the base route when the unsigned input length is less than or equal to the entry and recursion when greater. For checked indexes 0, 1, 2, 3 and 4 the thresholds are respectively 1024, 4096, 4096, 8192 and 16384 bytes. The outer selector routine's recorded non-error return paths produce 1 through 4; entry 0 is an independently checked table entry, not asserted to occur on that outer construction path. Thus 4096 bytes enter the base route for selector 1, whereas 4097 enter the recursive route; selector 4 permits 16384 bytes in the base route. The included controls verify every table value directly from the authenticated ELF and test equality and one-byte-above boundaries.

The selected thresholds explain dispatch geometry only. They do not establish output equivalence among implementations, the reachable selector for a specific host, all valid indexes or any real checkpoint replay.

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

with Path("research/work-items/RE-009-node115-root-subtree-thresholds/instructions.tsv").open() as handle:
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
assert relocations[rip_target(0x41c52d8)] == (8, 0x160bee0)
assert relocations[rip_target(0x41c5387)] == (8, 0x160b3a0)
assert rip_target(0x160b85c) == 0x160a100
assert rip_target(0x160a120) == 0x46ab98
thresholds = struct.unpack('<5Q', elf_bytes('.rodata', 0x46ab98, 40))
assert thresholds == (1024, 4096, 4096, 8192, 16384)
for t in thresholds:
    assert t <= t and not t + 1 <= t
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-017 · Node #115 compact comparison reads prior raw-root history

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4141](https://github.com/lalalune/hyperliquid-source/pull/4141) distinguishes comparison from missing-reference continuation. The [ABCI root-tree packet](../RE-017-abci-root-tree-115/README.md) recovers the selected root output and a history write. The new join follows the history member from empty initialization to selector update and comparison, including the order in which a block can read and then update it.

- At startup the slow-engine constructor stages two 16-byte halves into context +0x400 and +0x410. They hold the four words `[0, 8, 0, 0]` from stack +0x80. The count at member +0x18 is zero. The constructor then passes the staged context to the repacker and selected root selector. The [greeting packet](../RE-017-abci-greeting-115/README.md) supplies the later context copy, with offset +0x6b0 in the owner body. An empty initial descriptor can therefore acquire a digest before publication if the constructor's selector takes its root path. The empty initialization alone does not imply that the first replay comparison has no reference.
- On the selected root path 0x5a07fe5 passes context +0x400, current state height and the raw 32-byte buffer at selector stack +0x130 to 0x5a03fa0. It calls 0x4dd45c0 with that same member, key and buffer. A selected ordinary insertion builds a row from the height and both 16-byte lanes. A found-key replacement writes both lanes back to the existing digest slot. The raw source differs from the later mixed buffer at stack +0x180.
- The compact block lane preserves its input context, reads member +0x400 during the comparator loop, and queries by incoming row key. The empty ordinary descriptor sends the search to its zero-count return, and the caller's separate index-bound check prevents a comparison against it. On the selected normal block continuation the comparison precedes the call at 0x5a05fc9 to the end selector. A flag-controlled split can replace that same history before that selector call. The split takes saturated context +0x18 plus one as its cutoff input. This does not assert a particular relation between that word and the restored height.

With the same owner and no interfering writes, a block can compare against a digest saved on an earlier root path. Its later end-selector calculation cannot provide a missing reference to the earlier comparison in that same invocation. For example, a selected comparison with only raw key H already present can match key H or lack key H+1. Comparing a locally computed value to another copy from this same history does not supply the independent H+1 reference required for replay validation. The packet does not infer incoming quorum provenance or any real root value.

## Reproduce

GNU and LLVM agree on the selected [instruction spans](instructions.tsv).
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

with Path("research/work-items/RE-017-node115-raw-reference-origin/instructions.tsv").open() as handle:
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
assert rip_target(0x5a0901f) == rip_target(0x5a05fc9) == 0x5a07ec0
assert rip_target(0x5a07fe5) == 0x5a03fa0
assert rip_target(0x5a03fb8) == 0x4dd45c0
assert rip_target(0x4dd4837) == 0x57ed830
assert rip_target(0x5a05df6) == 0x57f8bb0
assert rip_target(0x5a05ee3) == 0x4de5ad0
assert rip_target(0x4fcae48) == 0x59ec200
assert rip_target(0x59ec2a8) == 0x56185e0
assert rip_target(0x5618630) == 0x5a04e40
assert 0x1640 - 0x1240 == 0x400
assert 0x1650 - 0x1240 == 0x410
sample = {1199000000: bytes(32)}
assert sample.get(1199000000) == bytes(32)
assert sample.get(1199000001) is None
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

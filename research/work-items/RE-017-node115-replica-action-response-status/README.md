# RE-017 · Node #115 replica action result status and response payloads

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4161](https://github.com/lalalune/hyperliquid-source/pull/4161) identifies the Full response's ordered arrays and leaves individual action result contents open. The selected entry writer uses an object with two keys. The `user` adapter receives entry +0x28, and the `res` adapter receives the entry base and tail-calls 0x59227c0.

That result writer compares the leading byte to 15. Equality chooses the relocated `err` status and passes result +8 to the string-valued `response` adapter. The other selected branch chooses the separate relocated `ok` status and passes the result base to an alternate `response` adapter, which tail-calls the structured writer at 0x4d8e0a0. Each branch returns early on a nonzero field-writer result before the normal object close. Non-15 is a description of this branch predicate and does not validate every alternate raw tag.

A collected Full record can thus preserve ordered per-action success and error outcomes, even when a replay fails to apply one action. The string-valued response need not have the structured success schema. These JSON outcome fields are separate from checkpoint state and the ABCI digest. The fixture still requires native replay input and independent reference data.

## Reproduce

Selected instruction spans agree between GNU and LLVM.
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

with Path("research/work-items/RE-017-node115-replica-action-response-status/instructions.tsv").open() as handle:
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
assert rip_target(0x502d1f9) == rip_target(0x502d247) == 0x54834d0
assert rip_target(0x5483541) == 0x507ac50
assert rip_target(0x507ad0a) == 0x59227c0
assert rip_target(0x5922849) == 0x509a4c0
assert rip_target(0x59228c1) == 0x5086930
assert rip_target(0x50869ea) == 0x4d8e0a0
for site, field in ((0x548350b,b"user"), (0x548352d,b"res"), (0x5922800,b"status"), (0x5922835,b"response")):
    assert elf_bytes(".rodata", rip_target(site), len(field)) == field
for site, status in ((0x5922807,b"err"),(0x592288b,b"ok")):
    slot = rip_target(site) + 16
    assert elf_bytes(".rodata", relocations[slot][1], len(status)) == status
    assert struct.unpack("<Q", elf_bytes(".data.rel.ro", slot + 8, 8))[0] == len(status)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

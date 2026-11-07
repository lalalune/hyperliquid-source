# RE-017 · Node #115 replica responses encode null, Hash or Full

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4153](https://github.com/lalalune/hyperliquid-source/pull/4153) identifies the outer `resps` field and its tag-2 null branch. The other observed response variants carry different data and must be distinguished when collecting a replay fixture.

The field serializer passes tags other than 2 to 0x4d6d170. Its tag-1 arm writes the key `Hash`, then supplies the 32 bytes at response +1 to the fixed-width quoted hex adapter. Its other arm writes `Full` and passes response +8 to 0x502d0d0. This records the serializer's dispatch and does not infer that every raw tag value denotes a valid variant.

The selected Full writer reads the pointer and count from argument +8/+0x10. It walks 0x38-byte rows. Each row emits an array with a 32-byte hex value from row base and a response array from the pointer/count at row +0x28/+0x30. The inner response writer visits 0x40-byte entries. An inner count of zero bypasses the entry writer and closes the array; a nonzero return from that writer propagates to outer serialization.

The archive's `resps.Hash` value is a distinct field from the locally emitted `abci_digest`. The selected writer does not provide the hash preimage or establish equality. A Full response's entry order can be preserved without interpreting the hex field as a state-root reference.

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

with Path("research/work-items/RE-017-node115-replica-response-json/instructions.tsv").open() as handle:
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
assert rip_target(0x506e30d) == 0x4d6d170
assert rip_target(0x4d6d2f2) == 0x502d0d0
assert rip_target(0x4d6d248) == rip_target(0x502d194) == 0x4e1c250
assert rip_target(0x502d1f9) == rip_target(0x502d247) == 0x54834d0
assert elf_bytes(".rodata", rip_target(0x4d6d1c6), 4) == b"Hash"
assert elf_bytes(".rodata", rip_target(0x4d6d299), 4) == b"Full"
assert spans[0x506e2f6].endswith(b"null")
assert spans[0x502d111].endswith(b"\x38")
assert spans[0x502d24c].endswith(b"\x40")
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

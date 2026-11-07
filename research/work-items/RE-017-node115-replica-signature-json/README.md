# RE-017 · Node #115 replica signature JSON encodes integer limbs

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4160](https://github.com/lalalune/hyperliquid-source/pull/4160) identifies the replica signed-action signature field. This packet follows its representation, which differs from the fixed-width hex encoding of the enclosing bundle key and from the native replay's raw 65-byte signature tail.

The selected field adapter tail-transfers to 0x53d6fd0. That object emits `r` from signature +0, `s` from +0x20 and `v` from +0x40. The first two fields share a writer that loads four consecutive 64-bit limbs in reverse order, byte-swaps each and writes them into a 32-byte temporary. The hex adapter then skips leading zero bytes. For a nonzero first byte it enables the optional first-nibble trim mode in 0x2eabb50. An all-zero value takes the literal `0x0` path. For example, the integer one has the JSON string `"0x1"`; a 32-byte fixture must restore the omitted leading zeroes if its destination is a fixed-width field.

The `v` writer loads one unsigned byte and emits unquoted decimal with one, two or three digits. The checked path does not establish which v values signature verification will accept or reproduce a signed preimage from archived JSON.

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

with Path("research/work-items/RE-017-node115-replica-signature-json/instructions.tsv").open() as handle:
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
assert rip_target(0x5077f5a) == 0x53d6fd0
assert rip_target(0x53d701b) == rip_target(0x53d7045) == 0x508a4f0
assert rip_target(0x53d706e) == 0x50768e0
assert rip_target(0x508a5fa) == 0x4e1c600
assert relocations[rip_target(0x4e1c690)] == (8, 0x2eabb50)
assert elf_bytes(".rodata", rip_target(0x4e1c64d), 3) == b"0x0"
for site, field in ((0x53d7007,b"r"),(0x53d7034,b"s"),(0x53d705a,b"v")):
    assert elf_bytes(".rodata", rip_target(site), 1) == field
raw = bytes(range(32))
assert b"".join(raw[index:index + 8][::-1] for index in (24, 16, 8, 0)) == raw[::-1]
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

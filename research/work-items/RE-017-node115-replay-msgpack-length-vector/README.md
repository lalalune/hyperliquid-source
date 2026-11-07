# RE-017 · Node #115 replay MessagePack length vector

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The bundle framing analysis identifies an exact byte subspan handed to `0x32679a0`. This packet recovers the ordinary MessagePack array alternative, its unsigned element representation, and the boundary between malformed lengths and the outer bundle's aggregate-length check.

The decoder's ordinary fixarray route uses the low nibble as count. Marker cells 0xdc and 0xdd reach the two- and four-byte count reads respectively. Both read big-endian, test remaining input before the load, and join the same selected collection path at `0x3267b2a`. The array visitor starts with capacity at most 0x20000 and may grow, so that constant alone does not impose an element-count limit.

The visitor consumes elements in order. Its scalar call slot resolves to `0x14b7aa0`. The selected positive fixint path zero-extends its inline value, and table markers 0xcc through 0xcf select payload widths one, two, four and eight. Multi-byte values are big-endian. The scalar returns tag 9 and writes a qword at result `+0x08`; the visitor appends that word at eight-byte stride. For a truncated uint64 the helper advances the cursor by the available count, zeros the remaining count and returns tag 1, so the visitor does not append that element.

The visitor's successful output at `+0x08/+0x10/+0x18` carries capacity, pointer and count, and leading tag 9. The top-level wrapper checks the remaining **array element count** before forwarding the descriptor. The outer bundle separately sums these words and tests the length of the following payload. Example raw length-array bytes `92 01 cd 01 00` represent lengths 1 and 256 under the selected decoder. This is a synthetic header fragment, not a valid signed bundle. String, extension and signed marker alternatives are outside this claim.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on [instructions.tsv](instructions.tsv).

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

with Path("research/work-items/RE-017-node115-replay-msgpack-length-vector/instructions.tsv").open() as handle:
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
def cell(base, index):
    return base + struct.unpack("<i", elf_bytes(".rodata", base + index * 4, 4))[0]

assert rip_target(0x3267a24) == 0x701014
assert tuple(cell(0x701014, index) for index in (0xdc, 0xdd)) == (0x3267cb8, 0x3267c6e)
assert rip_target(0x3267b5d) == 0x38a9050
assert rip_target(0x38a915c) == 0x64dfeb0
assert relocations[0x64dfeb0] == (8, 0x14b7aa0)
assert rip_target(0x14b7ab5) == 0x462eb4
assert tuple(cell(0x462eb4, index - 0xc0) for index in range(0xcc, 0xd0)) == (
    0x14b7b77, 0x14b7be9, 0x14b7b54, 0x14b7cc0,
)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

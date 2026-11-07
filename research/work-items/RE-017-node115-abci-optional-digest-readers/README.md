# RE-017 · Node #115 MessagePack optional AbciDigest readers

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Scope: two MessagePack readers that pass the `AbciDigest` type literal into the same digest decoder. These readers have distinct option tag assignments. This is separate from the `voteAbciDigest` action's JSON reader and from the digest record JSON writers.

| Reader | Explicit nil result | Present result after decode | Selected error result |
| --- | --- | --- | --- |
| `0x22a6250` | word 0 at result base | word `0x0100`, digest at `+0x02..+0x21` | tag 1 at base, payload at `+0x08` |
| `0x288a010` | word `0x0100` at result base | word 0, digest at `+0x02..+0x21` | tag 1 at base, payload at `+0x08` |

The first reader recognizes marker `0xc0` before calling `0x17c73a0`. The second first calls `0x195ee10`. Its selected tag-9/value-1 branch takes a separate path that examines the next marker and reaches the word-`0x0100` result for `0xc0`. The other selected tag-9 branch calls `0x17c73a0`. Both calls supply the same ten literal bytes `AbciDigest`. With that name the selected inner call sets a 32-byte destination extent. The inner success path expects return tag 9 and writes tag 0 and the 32 bytes at its output `+0x01`.

The inverse nil/present tags mean an offline decoder must identify which reader built an intermediate result before interpreting its second byte. This packet records selected local readers and does not claim their association with any specific checkpoint field or cover all MessagePack representations.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on the selected [instruction spans](instructions.tsv). From repository root:

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
text = next(row for row in sections if row["name"] == ".text")
path = Path("research/work-items/RE-017-node115-abci-optional-digest-readers/instructions.tsv")
with path.open() as handle:
    rows = {int(row["va"], 16): row for row in csv.DictReader(handle, delimiter="\t")}
for address, row in rows.items():
    start, end = (int(row[k], 16) for k in ("fde_start", "fde_end"))
    raw = bytes.fromhex(row["bytes"])
    offset = text["offset"] + address - text["address"]
    assert (start, end) in bounds and start <= address < address + len(raw) <= end
    assert data[offset:offset + len(raw)] == raw
rodata = next(row for row in sections if row["name"] == ".rodata")
for address in (0x22a62f2, 0x288a0a9):
    code = bytes.fromhex(rows[address]["bytes"])
    assert len(code) == 7 and code[1] == 0x8d and code[2] & 0xc7 == 5
    target = address + 7 + struct.unpack_from("<i", code, 3)[0]
    offset = rodata["offset"] + target - rodata["address"]
    assert data[offset:offset + 10] == b"AbciDigest"
for address, target in ((0x22a6303, 0x17c73a0), (0x288a0bb, 0x17c73a0), (0x17c740f, 0x1a03ff0)):
    code = bytes.fromhex(rows[address]["bytes"])
    assert code[0] == 0xe8 and address + 5 + struct.unpack_from("<i", code, 1)[0] == target
for address, raw in ((0x22a62de, "66c7030000"), (0x288a151, "66c7030001")):
    assert bytes.fromhex(rows[address]["bytes"]) == bytes.fromhex(raw)
print(f"{len(rows)} instruction spans, two type references, three calls and two nil tags match")
PY
```

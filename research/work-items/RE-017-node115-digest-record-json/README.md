# RE-017 · Node #115 ABCI digest record JSON writers

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Scope: two JSON encoders for the selected three-field digest record. The action's `abciDigest` and signature-message codecs use separate functions.

| Serialized key | First writer call | Second writer call | Value argument relative to object |
| --- | --- | --- | --- |
| `height` | `0x28b57cc` | `0x537d62c` | `+0x08` |
| `abci_digest` | `0x28b57f6` | `0x537d656` | `+0x10` |
| `exchange_abci_hash` | `0x28b581b` | `0x537d67b` | `+0x00` |

Both bodies write an opening brace, set the same initial local writer state, and invoke the three field helpers in the shown order. They test each helper's return before continuing. The closing brace has the same two writer-state guards in both copies. The `abci_digest` helpers send the field address directly to a formatter with source length 32 and scratch extent 66. The `exchange_abci_hash` helpers use a different representation. If the byte at the supplied address is 1, they tail-call a different writer with the source advanced by 8. Otherwise they send the source advanced by 1 to the same 32-byte formatter family used for `abci_digest`. These are different extraction paths even though both field names refer to digests.

The record's logical producer, the meaning of the tag-1 payload and the relationship to a persisted checkpoint root remain open. The pair of 32-byte values must be tracked as separate candidates in an offline comparison.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agreed on the selected spans in [instructions.tsv](instructions.tsv). Run from repository root.

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
path = Path("research/work-items/RE-017-node115-digest-record-json/instructions.tsv")
with path.open() as handle:
    rows = {int(row["va"], 16): row for row in csv.DictReader(handle, delimiter="\t")}
for address, row in rows.items():
    start, end = (int(row[k], 16) for k in ("fde_start", "fde_end"))
    raw = bytes.fromhex(row["bytes"])
    offset = text["offset"] + address - text["address"]
    assert (start, end) in bounds and start <= address < address + len(raw) <= end
    assert data[offset:offset + len(raw)] == raw
rodata = next(row for row in sections if row["name"] == ".rodata")
for addresses in ((0x28b57bb, 0x28b57e5, 0x28b5807), (0x537d61b, 0x537d645, 0x537d667)):
    for address, literal in zip(addresses, (b"height", b"abci_digest", b"exchange_abci_hash")):
        code = bytes.fromhex(rows[address]["bytes"])
        assert len(code) == 7 and code[1] == 0x8d and code[2] & 0xc7 == 5
        offset = rodata["offset"] + address + 7 + struct.unpack_from("<i", code, 3)[0] - rodata["address"]
        assert data[offset:offset + len(literal)] == literal
for address, target in ((0x25994f9, 0x26310e0), (0x25b0cae, 0x26310e0),
                        (0x5073bf9, 0x4e1c250), (0x506d5de, 0x4e1c250),
                        (0x25b0c79, 0x2579da0), (0x506d5a9, 0x5025a10)):
    code = bytes.fromhex(rows[address]["bytes"])
    assert code[0] in (0xe8, 0xe9) and address + 5 + struct.unpack_from("<i", code, 1)[0] == target
print(f"{len(rows)} instruction spans, six key references and six helper edges match")
PY
```

# RE-005 · Node #115 vote digest signature-message serializer

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Scope: the shared serializer and selected forwarding to the digest context. The runtime-tag packet pins the two caller contexts but leaves their serialization boundary open. The execution handoff in #4114 identifies the vote-specific callers.

The L1-hash and ABCI-digest vote handlers stage height followed by 32 digest bytes. Their selected preparation calls reach `0x38d2920` and `0x38d2b00`, respectively. At `0x38d2956` and `0x38d2b36`, both call `0x41d4610` with the same input layout.

- At `0x41d465b` the serializer passes a count of 2 to its container helper. A returned qword other than 2 exits through a result carrying the original word and its companion.
- On the selected normal branch the helper at `0x41d46a0` receives the input qword at offset zero. Its successful continuation uses the raw marker `0x8000000000000004`.
- The digest formatter at `0x41d4784` receives the input pointer advanced by 8, source width 32, and a formatting extent of 66. Its returned pair reaches the string writer at `0x41d4791`. That helper is distinct from the initial container helper. The writer result is tested before the closing operation.
- The two outer callers accept the same raw success marker and forward the buffer pointer and length to slot `0x64df510`, followed by slot `0x64df518` on the same context. Their relative relocations resolve to `0x160b3a0` and `0x160bcd0`. Both are prior runtime-tag boundaries.

This establishes the selected structured input to digesting the signature message, separate from the named action JSON. The retained body passes neither the Action tag nor the signature field into this shared serializer. It does not establish complete wire bytes, domain separation across other layers, or what generated the 32-byte vote digest in the first place. No signature was generated or checked by running the target.

## Reproduce

From repository root, the following checks the 41 selected instruction spans against the original artifact, resolves the two shared direct calls and verifies three relative slot relocations. GNU objdump 2.45 and LLVM objdump 23.1.4 agreed on the spans. Disassemble using the FDE bounds in [instructions.tsv](instructions.tsv).

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
path = Path("research/work-items/RE-005-node115-vote-digest-preimage/instructions.tsv")
with path.open() as handle:
    rows = {int(row["va"], 16): row for row in csv.DictReader(handle, delimiter="\t")}
for address, row in rows.items():
    start, end = (int(row[k], 16) for k in ("fde_start", "fde_end"))
    raw = bytes.fromhex(row["bytes"])
    offset = text["offset"] + address - text["address"]
    assert (start, end) in bounds and start <= address < address + len(raw) <= end
    assert data[offset:offset + len(raw)] == raw
for address in (0x38d2956, 0x38d2b36):
    code = bytes.fromhex(rows[address]["bytes"])
    assert code[0] == 0xe8 and address + 5 + struct.unpack_from("<i", code, 1)[0] == 0x41d4610
section = next(row for row in sections if row["name"] == ".rela.dyn")
relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
    "<QQq", data[section["offset"]:section["offset"] + section["size"]]
)}
for slot, target in ((0x64df510, 0x160b3a0), (0x64df518, 0x160bcd0), (0x64e4d08, 0x2eabb50)):
    assert relocations[slot] == (8, target)
print(f"{len(rows)} instruction spans, two direct calls and three relocations match")
PY
```

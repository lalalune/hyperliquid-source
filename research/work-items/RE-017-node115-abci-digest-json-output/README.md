# RE-017 · Node #115 ABCI digest JSON line publication

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Scope: the two digest-line wrappers and their common buffered output path. RE-017-abci-post-root-115 stops at the `0x50e5fc0` boundary. #4118 identifies the field sources of the two inner JSON encoders. RE-017-abci-context-result-115 reaches the same buffering helper through a different record and writer.

The previously documented end-root bridge stages a record at stack `+0x48`. It stores the capture pointer at record `+0x00`, copies the state qword at `+0x28` to record `+0x08`, and copies the 32 bytes from its result buffer to record `+0x10`. The normal continuation of `0x4e3a7a0` forwards this record as the third argument to `0x50e5fc0`. Its sibling path calls `0x25f19b0`.

| Line wrapper | Inner JSON call | Newline store | Buffered output call |
| --- | --- | --- | --- |
| `0x25f19b0` | `0x25f19fe → 0x28b5780` | `0x25f1aab` | `0x25f1ac0 → 0x14c37f0` |
| `0x50e5fc0` | `0x50e600e → 0x537d5e0` | `0x50e60bb` | `0x50e60d0 → 0x14c37f0` |

Both wrappers require the inner serializer to return zero for the selected success arm. Each appends one byte `0x0a`, growing the scratch buffer on equality of length and capacity. Both send the scratch pointer and incremented length to `0x14c37f0`. The nonzero serializer branches bypass the newline and buffered output calls.

The common helper obtains a writer at owner `+0x18`. If the line is strictly smaller than the available tail it copies directly and updates the buffered length. At equality or above it calls the slot resolving to `0x1533d60`. On the direct-copy arm, or after that helper returns without a nonzero error result, it checks a separate predicate for a flush. The auxiliary update callers also have an explicit downstream flush arm gated by byte `+0xaa`, a global byte and a non-sentinel current head. Both flush routes use `0x1533e80`. The latter loads the descriptor from writer `+0x1c`, passes the remaining buffered slice to the `write` import, advances on a positive return and takes a retry path for errno 4.

This connects the bridge's 32-byte result to the `abci_digest` field of a selected JSON output line and qualifies an actual output boundary for offline fixtures. It assumes intervening calls preserve the staged fields. It does not prove successful file output, a concrete path or the equality of that digest to a canonical checkpoint or replay root.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 75 selected [instruction spans](instructions.tsv). From repository root:

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
path = Path("research/work-items/RE-017-node115-abci-digest-json-output/instructions.tsv")
with path.open() as handle:
    rows = {int(row["va"], 16): row for row in csv.DictReader(handle, delimiter="\t")}
for address, row in rows.items():
    start, end = (int(row[k], 16) for k in ("fde_start", "fde_end"))
    raw = bytes.fromhex(row["bytes"])
    offset = text["offset"] + address - text["address"]
    assert (start, end) in bounds and start <= address < address + len(raw) <= end
    assert data[offset:offset + len(raw)] == raw
for address, target in ((0x548dbf9, 0x4e3a7a0), (0x4e3a8dc, 0x50e5fc0),
                        (0x2d4cb7c, 0x25f19b0), (0x25f19fe, 0x28b5780),
                        (0x50e600e, 0x537d5e0), (0x25f1ac0, 0x14c37f0),
                        (0x50e60d0, 0x14c37f0), (0x14c3854, 0x1533e80),
                        (0x4e3a91e, 0x1533e80), (0x2d4cbbe, 0x1533e80)):
    code = bytes.fromhex(rows[address]["bytes"])
    assert code[0] == 0xe8 and address + 5 + struct.unpack_from("<i", code, 1)[0] == target
section = next(row for row in sections if row["name"] == ".rela.dyn")
relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
    "<QQq", data[section["offset"]:section["offset"] + section["size"]]
)}
assert relocations[0x64e0010] == (8, 0x1533d60)
assert relocations[0x64dffc0][0] & 0xffffffff == 6
assert relocations[0x64dffc8][0] & 0xffffffff == 6
print(f"{len(rows)} instruction spans, ten direct calls and three slot relocations match")
PY
objdump -R artifacts/node/115/hl-node | grep -E '64dffc[08].*(write@|__errno_location@)'
```

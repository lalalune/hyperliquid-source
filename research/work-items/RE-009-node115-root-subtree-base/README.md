# RE-009 · Node #115 root digest subtree base case

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4179](https://github.com/lalalune/hyperliquid-source/pull/4179) covers the above-threshold recursive split in `0x160a100`. This packet covers its other, selected base route for valid input lengths up to 16384 bytes. The helper prepares one pointer for each complete 1024-byte input segment, passes their count, starting counter, key, flags and selector to `0x160bf70`, and checks a separate residual length `length & 0x3ff`. The observed full-segment pointer stride is `0x400`, not 32 or 64 bytes. No residual byte takes the direct return path.

For a nonzero residual length, the helper advances the input pointer by the full-segment byte count and adds the number of complete segments to the starting counter, with an overflow edge. It initializes a temporary chunk state from the 32-byte key and the new counter, calls the chunk update helper on the residual bytes, and constructs the final flags by ORing bit 1 and the zero-test of a temporary state byte into the existing flags. A selector-indexed call produces a 32-byte result which is appended after the complete-segment outputs after a capacity check. This describes a bounded path; the exact backend operation, valid selector range and threshold table are not established here.

The synthetic controls demonstrate segment count and residual positions for 1023, 1024, 1025, 2048 and 16384 bytes. They do not execute the target, establish a complete digest, or show a real checkpoint or block replay.

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

with Path("research/work-items/RE-009-node115-root-subtree-base/instructions.tsv").open() as handle:
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
assert rip_target(0x160a481) == 0x160bf70
for length, segments, residual in [(1023, 0, 1023), (1024, 1, 0), (1025, 1, 1), (2048, 2, 0), (16384, 16, 0)]:
    assert divmod(length, 1024) == (segments, residual)
    assert (length & 0x7c00) == segments * 1024
    assert (length & 0x3ff) == residual
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

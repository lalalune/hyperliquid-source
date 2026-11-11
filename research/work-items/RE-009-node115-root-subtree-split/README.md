# RE-009 · Node #115 root digest recursive subtree split

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4176](https://github.com/lalalune/hyperliquid-source/pull/4176) traces selection of an aligned bulk range and its call to `0x160a100`; [PR #4178](https://github.com/lalalune/hyperliquid-source/pull/4178) follows a subsequent parent-reduction loop. This packet traces the bulk helper's recursive split, including the input-pointer and counter handoff between children.

At entry `0x160a100` compares the requested length against a selector-indexed threshold. Only the greater-than branch covered here computes a split. Let `q = (length - 1) >> 11`: when `q == 0`, the left length is 1024; otherwise the machine bit-scan arithmetic yields `1024 * 2**bit_length(q)`. For lengths above 1024 this is the largest power-of-two multiple of 1024 strictly smaller than the length. The right length is `length - left`; the left child receives the original pointer and counter, while the right receives `pointer + left` and `counter + (left >> 10)`. Subtraction and counter overflow have distinct failure edges.

The helper makes separate recursive calls for both ranges and combines their returned values: a selected one-value left result takes a two-value copy path, while the other selected path checks total count before calling `0x160a860`, the parent adapter described in #4178. The threshold values, selector validity, complete recursion output and compression backend are not established here. Synthetic arithmetic controls below check 1025, 2048, 3072, 4096 and 8193 bytes and do not constitute captured execution, a real root, or block replay.

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

with Path("research/work-items/RE-009-node115-root-subtree-split/instructions.tsv").open() as handle:
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
assert rip_target(0x160b85c) == 0x160a100
assert rip_target(0x160a713) == rip_target(0x160a73a) == 0x160a100
assert rip_target(0x160a7cf) == 0x160a860
def split(length):
    assert length > 1024
    q = (length - 1) >> 11
    return 1024 if q == 0 else 1024 << q.bit_length()
for length, left in [(1025, 1024), (2048, 1024), (3072, 2048), (4096, 2048), (8193, 8192)]:
    assert split(length) == left
    assert left == 1 << ((length - 1).bit_length() - 1)
    assert left + (length - left) == length
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

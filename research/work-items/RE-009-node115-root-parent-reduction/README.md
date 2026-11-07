# RE-009 · Node #115 bulk root digest parent reduction

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4176](https://github.com/lalalune/hyperliquid-source/pull/4176) traces the large-input scheduler to the bulk compression and reduction helpers. This packet follows the reduction loop and its pair adapter `0x160a860`. In the selected bulk route, the caller supplies a buffer of `n` 32-byte values from `0x160a100`. If `n >= 3`, it calls the adapter with input length `32*n`, a separate output buffer with capacity 256 bytes, and the current key, flags and selector. After the adapter returns, the caller copies `32*returned_count` bytes back to its input buffer and repeats while the new count exceeds two. Checked failure branches guard oversized counts, output size and copies.

For this caller's admitted `n` from 3 through 16, the adapter makes one pointer per complete 64-byte input pair, calls `0x160c1b0` with flags OR 4, and advances through the output at 32 bytes per pair. If there is an odd final 32-byte value, it copies that value unchanged after the pair outputs, requiring at least 32 bytes of output capacity; a nonzero remainder other than 32 goes to a failure call. It returns the output count `ceil(n/2)`. Thus a 5-value example reduces to three values, the fifth copied as the last, then to two on the next iteration. The values themselves depend on the called implementation and are not synthesized here.

The included arithmetic checks are synthetic boundary controls over the caller's validated range. This is static control-flow and buffer-layout evidence, not proof of a BLAKE3 backend, real state-root equivalence, checkpoint restoration or block replay.

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

with Path("research/work-items/RE-009-node115-root-parent-reduction/instructions.tsv").open() as handle:
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
assert rip_target(0x160b92e) == 0x160a860
assert rip_target(0x160aac0) == 0x160c1b0
for n in range(3, 17):
    pairs, remainder = divmod(n * 32, 64)
    assert pairs + (remainder != 0) == (n + 1) // 2
    assert 32 * (pairs + (remainder != 0)) <= 256
assert [(n + 1) // 2 for n in (3, 5, 16)] == [2, 3, 8]
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

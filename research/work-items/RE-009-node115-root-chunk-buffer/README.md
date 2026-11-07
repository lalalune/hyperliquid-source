# RE-009 · Node #115 root digest chunk block buffering

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [chunk-boundary packet](../RE-009-node115-root-digest-chunk-boundary/README.md) describes the outer 1024-byte boundary; [PR #4180](https://github.com/lalalune/hyperliquid-source/pull/4180) reaches the chunk update through relocation slot `0x64e1948`, which resolves to `0x1609ab0`. This packet follows that helper's 64-byte buffering boundary.

For a valid existing buffered length at context `+0x68`, the helper copies at most `64 - buffered` bytes. If that consumes the incoming data, it returns without dispatching a compression call, even if the buffer just became exactly 64 bytes. If input remains, it dispatches the buffered 64-byte block, clears that buffer, increments the byte at `+0x69`, and proceeds. With no buffered bytes, a direct 64-byte block is dispatched only when more than 64 input bytes remain; subsequent direct blocks use the same strict `remaining > 64` condition. The last 1–64 bytes are copied into the buffer. An initial empty input leaves an empty buffer.

The first dispatch computes flags as the existing byte at `+0x6a` OR the boolean that `+0x69` equals zero; subsequent loop dispatches use the existing flags. The helper also tests for buffered length greater than 64 and byte-counter overflow before selected operations. Consequently, starting empty with 64 bytes retains 64 and dispatches zero blocks; 65 dispatches one and retains one; 128 dispatches one and retains 64. Starting with 20 buffered bytes, 44 more dispatches none and 45 dispatches one. This distinction matters for finalization and cannot be replaced by eager compression of every full block.

These are static, selected valid-path observations and synthetic length controls, not proof of a particular backend's cryptographic equivalence or a real replay/root.

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

with Path("research/work-items/RE-009-node115-root-chunk-buffer/instructions.tsv").open() as handle:
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
assert relocations[rip_target(0x160a508)] == (8, 0x1609ab0)
def model(buffered, incoming):
    assert 0 <= buffered <= 64 and 0 <= incoming <= 1024 - buffered
    total = buffered + incoming
    if incoming == 0:
        return (0, buffered)
    dispatched = (total - 1) // 64
    return dispatched, total - dispatched * 64
assert model(0, 0) == (0, 0)
assert model(0, 64) == (0, 64)
assert model(0, 65) == (1, 1)
assert model(0, 128) == (1, 64)
assert model(0, 129) == (2, 1)
assert model(20, 44) == (0, 64)
assert model(20, 45) == (1, 1)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

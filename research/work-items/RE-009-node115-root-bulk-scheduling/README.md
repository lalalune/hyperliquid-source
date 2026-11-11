# RE-009 · Node #115 root digest bulk-subtree scheduling

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The existing [partial-chunk packet](../RE-009-node115-root-digest-chunk-boundary/README.md) follows a nonempty initial chunk. This packet follows the distinct empty-chunk entry and large-input scheduling in the same update helper `0x160b3a0`, called by the ABCI root digest. On entry the helper computes `byte[+0x68] + 64*byte[+0x69]`; zero takes the bulk selector directly, while a partially filled chunk can reach it after its separately described completion. Remaining input of at most 1024 bytes bypasses bulk selection; nonzero remainder is passed to the update subroutine, then the carry helper, and zero returns.

For remaining length greater than 1024 and chunk counter below `2^54`, the selected arithmetic starts with the greatest power of two no larger than the remaining byte length. It repeatedly halves that candidate until `(candidate - 1) & (counter << 10)` is zero. This picks a power-of-two range aligned to the already-consumed byte offset. The selected 1024-byte-or-smaller path invokes the chunk update/compression path; larger selections enter `0x160a100` and a reduction loop. Under normal returns and checked stack capacity, selected values are appended to the 32-byte value stack after carry operations, the chunk counter increases by `candidate >> 10`, and the input pointer and remaining length advance by `candidate`. The loop repeats while the remainder exceeds 1024.

The checks include non-power-of-two lengths and nonzero counter alignment; they model the arithmetic only. This does not establish the compression implementation, prove a runtime root, or claim that arbitrary malformed state follows the normal path. Overflow, bounds and allocation/failure paths remain separate; no checkpoint or real block was replayed.

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

with Path("research/work-items/RE-009-node115-root-bulk-scheduling/instructions.tsv").open() as handle:
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
assert relocations[rip_target(0x41c5387)] == (8, 0x160b3a0)
assert rip_target(0x160b85c) == 0x160a100
assert rip_target(0x160b92e) == 0x160a860
assert rip_target(0x160b9ab) == rip_target(0x160ba02) == rip_target(0x160baae) == rip_target(0x160bb47) == 0x160b0e0
def select(length, counter):
    assert length > 1024 and 0 <= counter < (1 << 54)
    size = 1 << (length.bit_length() - 1)
    while (size - 1) & (counter << 10):
        size >>= 1
    return size
assert select(1025, 0) == 1024
assert select(3073, 0) == 2048
assert select(8192, 1) == 1024
assert select(8192, 2) == 2048
assert select(8192, 8) == 8192
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

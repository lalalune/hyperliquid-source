# RE-009 · Node #115 root child buffer fallback and exact fit

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4185](https://github.com/lalalune/hyperliquid-source/pull/4185) follows a qword child write and stops at fallback `0x141adb0` when the inline writer has at most eight free bytes. This packet follows that fallback on a valid, non-reentrant buffer with a normal digest helper return. The owner created for this child has capacity `0x8000`, pointer at `+8`, used length at `+0x10`, and digest context at `+0x20`.

The fallback first compares incoming length with `capacity - used`. If it fits, it skips flushing the old bytes. When incoming length is smaller than total capacity, it copies the incoming bytes to `buffer + used` and increments used. Therefore an eight-byte write at used `0x7ff8` takes the fallback because inline space is exactly eight, but still fits without flushing: the buffer becomes full. A further eight-byte write finds insufficient space, calls digest update on the existing buffer, clears the consumed buffered length on the selected non-reentrant path, and copies the new eight bytes into the now-empty buffer. With incoming length at least total capacity, the later branch calls the digest update directly instead of retaining that input in the buffer.

The flush sets owner byte `+0x18` to 1 around the update and resets it to zero on normal return. It also checks for unexpected length shrinkage and handles changed lengths separately; those paths, helper errors, unwinding and malformed owner states are not modeled as a successful flush. The examples test arithmetic and branch boundaries, not execution of the captured node or a real state root. No claim of complete hash or checkpoint replay is made.

## Reproduce

GNU and LLVM agree on the selected instruction spans; relocation checks bind the update and copy boundaries to the authenticated target.
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

with Path("research/work-items/RE-009-node115-root-buffer-fallback/instructions.tsv").open() as handle:
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
assert relocations[rip_target(0x14199fa)] == (8, 0x141adb0)
assert relocations[rip_target(0x141adf1)] == relocations[rip_target(0x141aedb)] == (8, 0x160b3a0)
def select(capacity, used, incoming):
    assert 0 <= used <= capacity and incoming >= 0
    flush = incoming > capacity - used and used != 0
    after = 0 if flush else used
    return flush, ('direct' if incoming >= capacity else 'buffer'), after + incoming if incoming < capacity else after
assert select(0x8000, 0x7ff8, 8) == (False, 'buffer', 0x8000)
assert select(0x8000, 0x8000, 8) == (True, 'buffer', 8)
assert select(0x8000, 0, 0x8000) == (False, 'direct', 0)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

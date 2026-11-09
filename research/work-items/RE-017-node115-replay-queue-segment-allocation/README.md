# RE-017 · Node #115 replay queue successor allocation

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [publication packet](../RE-017-node115-replay-queue-publish/README.md) identifies producer `0x581b0c0` and leaves segment allocation open. The [recycling packet](../RE-017-node115-replay-queue-segment-recycle/README.md) treats a separate recycling path. Here we follow this producer when the selected predecessor has a null successor.

At `0x581b134` it loads the predecessor base and rejects unsigned values above `0xffffffffffffffdf` at `0x581b13c..0x581b140`. The normal branch requests `0x220` bytes via indirect slot `0x64df480`; null reaches the separate indirect failure slot `0x64df490` and `ud2`. For a nonnull result it adds 32 to that base, stores the result at new segment `+0x200`, zeroes 16 bytes at `+0x208` and eight bytes at `+0x218`, then attempts a locked compare-and-exchange into predecessor `+0x208` with expected null. This proves initialization and publication order for that local branch, not what the indirect slots do internally.

On failed publication the returned nonnull successor becomes the next CAS target: the code recomputes the new base from that successor's `+0x200` plus 32, attempts its `+0x208`, and on another failure repeats a `pause`/recompute/CAS loop until that CAS succeeds. The initial overflow check applies to the first predecessor only; this packet does not establish bounds for later successor bases, full concurrency safety, allocator identity, runtime reachability or that the reader uses the same live queue object. The existing segment recycling packet covers later watermark and reclamation logic.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on the retained bytes; LLVM prints the lock prefix separately, so it must be concatenated with the next instruction. The verifier binds selected instruction bytes to the authenticated ELF and FDE, checks branch targets and rejects a corrupted instruction window. Python 3.14.5 was used. Synthetic unsigned arithmetic covers both sides of the first overflow boundary.

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

with Path("research/work-items/RE-017-node115-replay-queue-segment-allocation/instructions.tsv").open() as handle:
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

def target(address):
    raw=spans[address]
    if raw[0] in (0x74,0x75,0x77,0xeb):
        return address+len(raw)+struct.unpack_from("<b",raw,len(raw)-1)[0]
    return rip_target(address)
assert target(0x581b12e)==0x581b1e0
assert target(0x581b140)==0x581b27f
assert target(0x581b154)==0x581b26d
assert target(0x581b189)==0x581b1e0
assert target(0x581b1ab)==0x581b1d4
assert target(0x581b1d2)==0x581b1b0
assert target(0x581b27d)==0x581b28c
assert spans[0x581b146]==bytes.fromhex('bf20020000')
assert spans[0x581b17f]==bytes.fromhex('f0490fb1942408020000')
corrupted=bytearray(spans[0x581b17f]);corrupted[-1]^=1
assert corrupted != elf_bytes('.text',0x581b17f,len(corrupted))
limit=(1<<64)-1-32
for value,blocked in ((0,False),(limit,False),(limit+1,True),((1<<64)-1,True)):
    assert (value>limit)==blocked
    if not blocked: assert value+32 < (1<<64)
print(f"{len(spans)} authenticated instruction spans and selected branches match")
PY
```

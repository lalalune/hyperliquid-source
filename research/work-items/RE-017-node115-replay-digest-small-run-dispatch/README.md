# RE-017 · Node #115 replay digest worker small-run dispatch

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5901](https://github.com/lalalune/hyperliquid-source/pull/5901) maps the wrapper's N<65 flag and scratch storage; [#5910](https://github.com/lalalune/hyperliquid-source/pull/5910) identifies the worker's initial local threshold. This packet traces a selected smaller-than-threshold region to its dispatched helper.

For the selected converter path with `21 <= N <= 64`, the wrapper passes a nonzero flag and the worker's threshold is `M = ceil(N/2) <= 32`. When a positive remaining region R is below M, the worker computes its start as `base + 32*index` and calls relocation-resolved `0x4e7ca30` via slot `0x64eb480`. It passes `min(R,32)` as the selected row count, the wrapper scratch pointer and capacity, zeros in R8/R9, and a saved context value in its outgoing stack slot. Under `R < M <= 32`, that selected count equals R. After a normal return the worker stages `2*R+1` before the common continuation. A zero flag takes a separate calculation path rather than this call.

The resolved helper compares its incoming count with 33. In the selected path R < M <= 32, it takes the less-than-33 branch and calls `0x5408900` with the original row base, R, scratch pointer, scratch capacity, and saved stack context. The >=33 partitioning branch is unreachable under these assumptions.

The downstream helper's internal behavior, actual row order, pointer validity, complete worker semantics and live replay reachability remain unproven. The statement is conditional static dataflow, not a claim of full sorting or state-root equivalence. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 73 selected instruction spans. Python 3 verifies target identity, FDEs, selected call/branch displacements, the indirect relocation, corruption controls and synthetic arithmetic boundaries.

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

with Path("research/work-items/RE-017-node115-replay-digest-small-run-dispatch/instructions.tsv").open() as handle:
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

def short_target(address):
    raw=spans[address];return address+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x4f3811d)==0x4f848d0
assert short_target(0x4f84a27)==0x4f84a80
assert short_target(0x4f84a2e)==0x4f84a90
assert rip_target(0x4f84a62)==0x64eb480
assert relocations[0x64eb480][1]==0x4e7ca30
assert rip_target(0x4f84a76)==0x4f84bd6
assert rip_target(0x4f84a9f)==0x4f84bd1
assert short_target(0x4e7ca58)==0x4e7ca62
assert rip_target(0x4e7ca5d)==0x4e7cfa7
assert rip_target(0x4e7cfba)==0x5408900
for n in (21,22,63,64):
    m=min(64,(n+1)//2)
    assert m<=32 and n<65
    for remaining in (1,m-1):
        assert 0<remaining<m and min(remaining,32)==remaining
        assert 2*remaining+1>remaining
for addr in (0x4f84a62,0x4f84a6e):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

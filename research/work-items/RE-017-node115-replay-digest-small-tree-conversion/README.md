# RE-017 · Node #115 replay digest lookup small-tree conversion

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5884](https://github.com/lalalune/hyperliquid-source/pull/5884) connects a replay digest to lookup `0x4dc8e00`; [#5886](https://github.com/lalalune/hyperliquid-source/pull/5886) traces a selected sentinel-root comparison after this helper's initial gate. The existing [override trimming packet](../RE-017-node115-replay-override-trim/README.md) identifies a collector at `0x5b8fc50` on a different helper path. This packet maps the lookup helper's own selected pre-search conversion.

At entry the lookup loads descriptor `+0` and `+0x18`. The `neg`/overflow test is true for the word `0x8000000000000000`; it combines that predicate with unsigned `count < 32`. Only that conjunction enters the selected conversion. The code saves descriptor `+8/+0x10`, clears descriptor `+8` and `+0x18`, constructs an iterator form and calls collector `0x5b8fc50`. It saves the collector's three output qwords, then repeatedly calls `0x51e48d0` on the local iterator until its output first qword is zero. On that selected normal completion, it writes the three saved qwords to descriptor `+0/+8/+0x18`, writes zero to `+0x10`, then continues to the common sentinel check. The null original `+8` arm constructs a zero-count local iterator.

The facts above are local order and a conditional field projection; they do not prove collector contents, ownership, termination, exception behavior, concurrency safety or that this path occurs during real replay. In particular, a later common sentinel check still decides the next representation branch. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 64 selected instruction spans. Python 3 verifies the target, FDEs, selected call/branch displacements and corruption controls; synthetic predicate cases cover both sentinel and count boundaries.

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

with Path("research/work-items/RE-017-node115-replay-digest-small-tree-conversion/instructions.tsv").open() as handle:
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
assert rip_target(0x57e6785)==0x4dc8e00
assert rip_target(0x4dc8e39)==0x4dc8f26
assert short_target(0x4dc8e5a)==0x4dc8e9b
assert rip_target(0x4dc8ec7)==0x5b8fc50
assert rip_target(0x4dc8f06)==0x51e48d0
assert short_target(0x4dc8f11)==0x4dc8f00
assert rip_target(0x4dc8f33)==0x4dc909b
sentinel=1<<63
for head,count,expected in ((sentinel,0,True),(sentinel,31,True),(sentinel,32,False),(sentinel-1,1,False),(sentinel+1,1,False)):
    assert ((head==sentinel) and count<32)==expected
for addr in (0x4dc8e39,0x4dc8ec7):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

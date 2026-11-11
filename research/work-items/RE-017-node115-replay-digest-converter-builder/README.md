# RE-017 · Node #115 replay digest converter builder

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5896](https://github.com/lalalune/hyperliquid-source/pull/5896) identifies a selected descriptor snapshot and call to `0x5155d20` for a nonzero lookup result with count above 63, but leaves the converter's internals open. This packet maps the converter's selected materialization and builder dispatch, not its helpers' implementations.

The converter copies its 32-byte input snapshot to a local buffer and calls `0x5b91a70`, then reads an output count at local `+0x28`. Zero enters a separate output/cleanup arm. A count of one bypasses the two preparation calls. Counts from 2 through 20 call `0x53e5720`, while counts at least 21 call relocation-resolved `0x4f38080`; both selected normal continuations join the same allocation path. These are **materializer output** counts; this packet does not infer them from the caller's original descriptor count.

For a selected nonzero count, the converter requests `0x170` bytes. A null result enters the allocation failure slot and `ud2`; otherwise it clears a qword at allocation `+0x160` and a word at `+0x16a`. It stages a range ending at `pointer + 32*count`, calls builder `0x4cc0050`, and projects a local pair plus a third qword to its 24-byte output. The parent then uses that output as documented in #5896. Helper contents, sorting meaning, full tree construction, ownership, overflow bounds, exceptional control and live reachability remain open. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 88 selected instruction spans. Python 3 verifies target identity, FDEs, selected direct edges, the indirect relocation, predicate boundary controls and corrupted instruction bytes.

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

with Path("research/work-items/RE-017-node115-replay-digest-converter-builder/instructions.tsv").open() as handle:
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
assert rip_target(0x4dc8f92)==0x5155d20
assert rip_target(0x5155d4c)==0x5b91a70
assert rip_target(0x5155d59)==0x5155e03
assert rip_target(0x5155d72)==0x5155e3f
assert short_target(0x5155e43)==0x5155e71
assert rip_target(0x5155e55)==0x53e5720
assert rip_target(0x5155e7c)==0x64e58b0
assert relocations[0x64e58b0][1]==0x4f38080
assert rip_target(0x5155deb)==0x4cc0050
assert rip_target(0x5155d8b)==0x5155e5f
for count,route in ((0,'zero'),(1,'single'),(2,'small'),(20,'small'),(21,'large'),(64,'large')):
    assert ('zero' if count==0 else 'single' if count==1 else 'small' if count<21 else 'large')==route
for addr in (0x5155d4c,0x5155e43):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

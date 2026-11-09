# RE-017 · Node #115 replay digest materializer row count

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5897](https://github.com/lalalune/hyperliquid-source/pull/5897) records converter dispatch based on the count returned by `0x5b91a70`, without equating that count to the input descriptor. This packet traces the selected valid-ring materialization and relates its output count to the caller's threshold.

The materializer reads input capacity, pointer, head and count from offsets `+0/+8/+0x10/+0x18`. It checks the 32-byte allocation size using the count's upper bits and the shifted value's sign, rejecting counts at or above `2^58` before allocation. For valid `capacity > 0`, `head < capacity`, `0 < N <= capacity`, and successful allocation, its first loop copies `min(N, capacity-head)` rows from head to the end of the backing array. Its second loop copies any remaining rows from the beginning. Each iteration copies two 16-byte lanes and increments the output count. After the selected normal cleanup it returns `(N, output_pointer, N)` in the three output qwords. The zero-count route is separate.

Under these valid-input, successful-helper and no-alias assumptions, #5896's input count greater than 63 reaches #5897's materializer count greater than 63, and hence its at-least-21 dispatch. This is conditional static composition; neither allocation success, live descriptor validity, helper cleanup, record contents nor runtime reachability is established. It does not prove an entire tree or state root. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 117 selected instruction spans. Python 3 verifies the target, indexed FDEs, selected call/branch displacements, mutation controls and synthetic wrapped/non-wrapped row-count projections.

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

with Path("research/work-items/RE-017-node115-replay-digest-materializer-count/instructions.tsv").open() as handle:
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
assert short_target(0x5155e43)==0x5155e71
assert short_target(0x5b91a9b)==0x5b91aaa
assert rip_target(0x5b91ab0)==0x5b91bcc
assert rip_target(0x5b91ac2)==0x5b91bf1
assert short_target(0x5b91b50)==0x5b91b30
assert short_target(0x5b91b9c)==0x5b91b80
for cap,head,n in ((1,0,1),(4,0,4),(7,5,5),(9,8,2)):
    first=min(n,cap-head);second=n-first
    source=list(range(cap));copied=source[head:head+first]+source[:second]
    assert len(copied)==n and copied==[source[(head+i)%cap] for i in range(n)]
for n in (1,20,21,63,64,100):
    assert not (n>63) or (n>=21)
assert (1<<58)-1 < (1<<58) and not ((1<<58)<(1<<58))
for addr in (0x5b91a85,0x5b91bb6):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

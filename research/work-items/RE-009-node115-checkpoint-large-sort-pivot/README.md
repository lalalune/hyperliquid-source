# RE-009 · Node #115 checkpoint numeric large-sort pivot for 33–63 words

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [restore canonical-height packet](../RE-017-node115-restore-canonical-heights/README.md) links checkpoint enumeration to the shared numeric sort. The [prune path packet](../RE-017-abci-prune-path-115/README.md) identifies the mixed-input partition boundary; [#5924](https://github.com/lalalune/hyperliquid-source/pull/5924) considers a selected 21–32-word path. This packet examines the pivot selection for a different selected range, 33–63 words.

Assume a valid unsigned-word range N=33..63, nonzero incoming partition budget and the selected entry path. At `0x1550759` the code computes q=floor(N/8), then candidate word addresses at indices 0, 4q and 7q. For this range 0 < 4q < 7q < N. The three strict unsigned comparisons and conditional pointer selections at `0x155077b`–`0x15507a4` select a candidate whose value is the median of the three, including equal values. A zero budget takes a separate branch; N>=64 invokes a separate helper. The pivot's later partition, recursion, ties among equal records, runtime reachability and complete checkpoint ordering are not established here. No captured target code executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 33 selected spans. Python authenticates target bytes and FDE, selected control transfers and the comparison sequence; synthetic tests exhaust 125 candidate triples including high-bit/max unsigned values and check index bounds for N=33..63. The model is derived from selected instructions, not target execution.

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

with Path("research/work-items/RE-009-node115-checkpoint-large-sort-pivot/instructions.tsv").open() as handle:
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

import itertools
assert len(spans)==33
def target(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]
assert target(0x1550753)==0x15509d0
assert target(0x1550775)==0x1550840
assert target(0x15507b0)==0x1550859
assert spans[0x1550763][-1]==5 and spans[0x155076a][-1]==0x38
for n in range(33,64):
 q=n//8
 assert 0<4*q<7*q<n
def pivot(a,b,c,mutate=False):
 p=a<b;q=a<c;r=b<c
 index=1
 if r != p:index=2
 if (q != p) != mutate:index=0
 return (a,b,c)[index]
values=(0,1,2,2**63,2**64-1)
for a,b,c in itertools.product(values,repeat=3):
 assert pivot(a,b,c)==sorted((a,b,c))[1]
assert any(pivot(a,b,c,True)!=sorted((a,b,c))[1] for a,b,c in itertools.product(values,repeat=3))
for addr in (0x1550753,0x1550775):
 bad=bytearray(spans[addr]);bad[-1]^=1
 assert bad!=elf_bytes('.text',addr,len(bad))
print(f'{len(spans)} authenticated spans and 125 pivot triples pass')
PY
```

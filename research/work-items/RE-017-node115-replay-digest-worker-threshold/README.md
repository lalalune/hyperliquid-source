# RE-017 · Node #115 replay digest preparation worker thresholds

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5901](https://github.com/lalalune/hyperliquid-source/pull/5901) maps scratch sizing in the wrapper before its call to `0x4f848d0`. This packet identifies the selected worker's initial count gates and arithmetic without assigning a source-level purpose to the resulting values.

The worker returns via a separate path for unsigned N below 2. For N at least 2 it stores `ceil(2^62 / N)` at local `+0x80`. For N at most 4096 it stores `min(64, ceil(N/2))` at local `+0x20`. For N at least 4097 it computes `k = ceil(floor(log2(N))/2)` using `bsr(N | 1)`, then stores `floor(((N >> k) + 2^k)/2)` at that offset. It also saves wrapper arguments, including the N<65 flag and the original comparator/context argument. Subsequent worker loops and the meaning of these local thresholds are outside this packet.

Arithmetic statements assume the selected normal path and the valid unsigned N range established in #5899; they do not prove sorting, record ordering or runtime reachability. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 57 selected instruction spans. Python 3 checks the target digest, indexed FDEs, selected call/branch transfers, mutation controls and synthetic boundary arithmetic.

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

with Path("research/work-items/RE-017-node115-replay-digest-worker-threshold/instructions.tsv").open() as handle:
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
assert rip_target(0x4f848f9)==0x4f84f51
assert short_target(0x4f8492b)==0x4f8494a
assert short_target(0x4f84948)==0x4f84974
def calc(n):
    q=((1<<62)+n-1)//n
    if n<=4096: m=min(64,(n+1)//2)
    else:
        k=(n|1).bit_length()//2
        m=((n>>k)+(1<<k))//2
    return q,m
for n in (2,21,64,65,4095,4096,4097,8192,100000):
    q,m=calc(n)
    assert q*n>=(1<<62) and (q-1)*n<(1<<62)
    assert m>0
assert calc(4096)[1]==64 and calc(4097)[1]==64 and calc(8192)[1]==96
for addr in (0x4f8490e,0x4f8494e):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-017 · Node #115 replay digest wrapped-run search

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5890](https://github.com/lalalune/hyperliquid-source/pull/5890) traces one non-wrapping digest run. This packet covers the distinct wrapped-ring selection in the same helper, assuming valid non-sentinel metadata and a nonempty head and wrapped run.

Let `tail = capacity - head` and `wrapped = count - tail`, with `0 < tail < count <= capacity`. The selected branch compares physical row zero, the first row in the wrapped run, against the 32-byte key. Equality immediately returns tag 0 and logical index `tail`. If row zero is greater than the key, control selects the head-to-end tail run and its previously documented search. If row zero is less, control selects the start-of-buffer wrapped run, performs its own midpoint/length comparisons and adds `tail` to the selected local result index. The final returned RAX distinguishes equality (0) from a missing key (1).

For strictly increasing synthetic logical rows, the verifier tests equality and insertion indexes across split positions; this is a model of the selected instruction sequence, not target execution. Duplicate keys, malformed metadata, concurrent mutation, source ordering and actual replay inputs are not established. Valid bounds, the imported `memcmp` contract and normal selected control flow are assumptions. No captured binary is run.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 108 selected instruction spans. Python 3 verifies target identity, FDEs, branch/call displacements, comparator relocation/symbol, corruption controls and synthetic wrapped-run examples.

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

with Path("research/work-items/RE-017-node115-replay-digest-wrapped-search/instructions.tsv").open() as handle:
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
assert rip_target(0x57fae42)==0x64dfb50
assert rip_target(0x57fae5a)==0x57fafb9
assert rip_target(0x57fae65)==0x57faf2d
assert rip_target(0x57fae73)==0x57faf48
assert rip_target(0x57faf40)==0x57faea8
assert rip_target(0x57faf6f)==0x64dfb50
assert short_target(0x57faf86)==0x57faf50
assert rip_target(0x57faf9a)==0x64dfb50
info,addend=relocations[0x64dfb50]
assert (info&0xffffffff)==6 and addend==0
sym=next(x for x in sections if x['name']=='.dynsym')
strings=next(x for x in sections if x['name']=='.dynstr')
nameoff=struct.unpack_from('<I',data,sym['offset']+(info>>32)*24)[0]
start=strings['offset']+nameoff;end=data.index(b'\0',start)
assert data[start:end]==b'memcmp'
def run(rows,key):
    length=len(rows);base=0
    while length>1:
        old=base;half=length>>1;base+=half
        if rows[base]>key:base=old
        length-=half
    cmp=(rows[base]>key)-(rows[base]<key)
    return (0,base) if cmp==0 else (1,base+(cmp<0))
def wrapped_search(tail,wrapped,key):
    if wrapped[0]==key:return 0,len(tail)
    if wrapped[0]>key:return run(tail,key)
    tag,index=run(wrapped,key)
    return tag,len(tail)+index
for n in (2,3,7,16):
    rows=[bytes([2*i+2])*32 for i in range(n)]
    for cut in range(1,n):
        for k in range(0,2*n+3):
            key=bytes([k])*32;tag,index=wrapped_search(rows[:cut],rows[cut:],key)
            assert index==sum(row<key for row in rows) and (tag==0)==(key in rows)
for addr in (0x57fae42,0x57fafb6):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

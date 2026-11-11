# RE-017 · Node #115 replay digest contiguous-run search

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5888](https://github.com/lalalune/hyperliquid-source/pull/5888) and [#5889](https://github.com/lalalune/hyperliquid-source/pull/5889) cover selected one-row digest lookups. This packet addresses the multi-row binary-search loop in the same lookup helper when the valid logical rows form one contiguous, non-wrapping run.

For valid `head < capacity`, positive count at most `capacity - head`, the selected `0x57fae00` branch computes the first physical row as `base + 32*head` and run length as count. With run length greater than one, the loop starts index zero, takes `half = length >> 1`, compares the middle 32-byte row to the key using imported `memcmp`, retains the old index when the row is greater and the middle index otherwise, and reduces length by half until one candidate remains. The final comparison returns RAX 0 and candidate index in RDX for equality, or RAX 1 and the before/after insertion index for inequality. The enclosing lookup at `0x4dc8f41` consumes that return.

For strictly increasing synthetic keys, the verifier compares the local arithmetic projection with insertion positions; equal duplicate keys may return any matching position. This is not proof that real rows are sorted, that the complete wrapped-ring algorithm is recovered, or that live replay takes this path. It assumes valid bounds, readable rows, the imported comparator contract, selected control flow and no intervening mutation. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 64 selected instruction spans. Python 3 verifies target identity, FDEs, branch and call targets, comparator symbol relocation, corruption controls and synthetic sorted-run examples.

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

with Path("research/work-items/RE-017-node115-replay-digest-contiguous-search/instructions.tsv").open() as handle:
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
assert rip_target(0x4dc8f41)==0x57fae00
assert short_target(0x57fae34)==0x57fae89
assert rip_target(0x57faeb1)==0x64dfb50
assert short_target(0x57faef2)==0x57faec0
assert rip_target(0x57faf06)==0x64dfb50
assert short_target(0x57faf0e)==0x57faf23
info,addend=relocations[0x64dfb50]
assert (info&0xffffffff)==6 and addend==0
sym=next(x for x in sections if x['name']=='.dynsym')
strings=next(x for x in sections if x['name']=='.dynstr')
nameoff=struct.unpack_from('<I',data,sym['offset']+(info>>32)*24)[0]
start=strings['offset']+nameoff;end=data.index(b'\0',start)
assert data[start:end]==b'memcmp'
def search(rows,key):
    length=len(rows);base=0
    assert length>0
    while length>1:
        old=base;half=length>>1;base+=half
        if rows[base]>key:base=old
        length-=half
    cmp=(rows[base]>key)-(rows[base]<key)
    return (0,base) if cmp==0 else (1,base+(cmp<0))
for n in (1,2,3,7,16):
    rows=[bytes([2*i+2])*32 for i in range(n)]
    for k in range(0,2*n+3):
        key=bytes([k])*32;tag,index=search(rows,key)
        expected=sum(row<key for row in rows)
        assert index==expected and (tag==0)==(key in rows)
for addr in (0x57faedf,0x57faee7):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

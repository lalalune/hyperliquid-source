# RE-017 · Node #115 replay digest insertion around one row

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5887](https://github.com/lalalune/hyperliquid-source/pull/5887) traces an initial insertion into an empty non-sentinel descriptor; [#5888](https://github.com/lalalune/hyperliquid-source/pull/5888) covers a repeated equal key. This packet traces two different-key cases around that one existing 32-byte row.

Assume a non-sentinel descriptor with capacity C greater than one, head C−1, count one and a valid row there. The one-row lookup compares the existing row against the requested key with the imported 32-byte `memcmp`. A negative comparator result produces logical insertion index 1; a positive result produces index 0. Either non-equal path returns RAX 1, which the enclosing selected lookup turns into a tag-zero missing-key result containing the key, descriptor and index.

On the selected wrapper continuation the insertion helper receives that descriptor/index/key. With the stated nonfull metadata and normal move-helper return, index 0 takes the front branch, sets head to C−2 and inserts there; index 1 takes the back branch, keeps head C−1 and inserts at physical slot 0. Both increment descriptor count to 2, with the new row on the side selected by the comparison. The wrapper then observes index less than the new count. These are two isolated boundary cases, not proof of general sorting correctness, real replay ordering or atomicity. The comparison assumes the imported comparator's standard contract; helper behavior, aliasing, concurrency and actual digest values remain boundaries. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 130 selected instruction spans. Python 3 checks the authenticated target, FDEs, branch targets, comparator relocation and symbol, mutation controls, and synthetic front/back cases.

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

with Path("research/work-items/RE-017-node115-replay-digest-one-row-insert/instructions.tsv").open() as handle:
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
assert rip_target(0x57faf06)==0x64dfb50
assert short_target(0x57faf0e)==0x57faf23
assert rip_target(0x57faf1e)==0x57fafb9
assert rip_target(0x4dc9017)==0x4dc918f
assert rip_target(0x57e68a6)==0x57eb000
assert short_target(0x57eb040)==0x57eb089
assert rip_target(0x57eb071)==0x5812ad0
assert rip_target(0x57eb0a2)==0x5812ad0
info,addend=relocations[0x64dfb50]
assert (info&0xffffffff)==6 and addend==0
sym=next(x for x in sections if x['name']=='.dynsym')
strings=next(x for x in sections if x['name']=='.dynstr')
nameoff=struct.unpack_from('<I',data,sym['offset']+(info>>32)*24)[0]
start=strings['offset']+nameoff;end=data.index(b'\0',start)
assert data[start:end]==b'memcmp'
for cap in (2,3,32):
    old=bytes([128])*32
    for key,index in ((bytes([1])*32,0),(bytes([254])*32,1)):
        assert (0 if old>key else 1)==index
        head=cap-1;count=1
        if index==0: head=(head-1)%cap
        slot=(head+index)%cap;count+=1
        assert slot==(cap-2 if index==0 else 0) and count==2 and index<count
for addr in (0x57faf10,0x57eb040):
    changed=bytearray(spans[addr]);changed[-1]^=1
    assert changed!=elf_bytes('.text',addr,len(changed))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

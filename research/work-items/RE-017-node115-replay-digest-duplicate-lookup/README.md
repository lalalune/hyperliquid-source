# RE-017 · Node #115 repeated digest lookup in a one-row container

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5887](https://github.com/lalalune/hyperliquid-source/pull/5887) models a selected initial insertion in an empty non-sentinel container. This packet asks what the same lookup wrapper does if that inserted key is looked up again while the descriptor remains unchanged. It covers one row, not a complete duplicate-detection or concurrency contract.

Assume non-sentinel capacity `C > 0`, head `C-1`, count one and the previously inserted 32-byte row at that physical head. The non-sentinel lookup calls `0x57fae00`; its count/head arithmetic selects the one-row run. The selected final 32-byte `memcmp` compares that row with the requested key. Equal bytes take `0x57faf23`, returning RAX 0 and logical index RDX 0. The enclosing lookup's non-sentinel equal route writes tag 1, output `+8 = 0`, descriptor pointer at `+0x10` and index zero at `+0x18`.

The wrapper's tag-one path sees output `+8` zero, checks `0 < descriptor count` and reaches the existing owner count/limit gate directly. When owner count does not exceed limit, that path returns without the missing-key insertion and owner append found in #5887. This concerns the selected wrapper control flow under unchanged valid memory and normal helper returns; it does not prove callback idempotence, no other side effects, live event ordering, or equality of real replay digests. Non-equal comparisons, other layouts and concurrent mutation remain outside this claim. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 88 selected instruction spans. Python 3 verifies target identity, indexed FDEs, selected transfers, comparator symbol relocation, and mutation controls. Synthetic keys and capacities check only the selected one-row conditions.

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

with Path("research/work-items/RE-017-node115-replay-digest-duplicate-lookup/instructions.tsv").open() as handle:
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
assert rip_target(0x4dc8f41)==0x57fae00
assert rip_target(0x4dc8f49)==0x4dc8fe0
assert short_target(0x4dc8fed)==0x4dc9032
assert rip_target(0x4dc9046)==0x4dc914e
assert short_target(0x4dc9153)==0x4dc9191
assert short_target(0x57fae34)==0x57fae89
assert short_target(0x57faeaf)==0x57faef4
assert rip_target(0x57faf06)==0x64dfb50
assert short_target(0x57faf0e)==0x57faf23
assert rip_target(0x57faf28)==0x57fafb9
assert short_target(0x57e679b)==0x57e67b1
assert rip_target(0x57e67b9)==0x57e6980
info,addend=relocations[0x64dfb50]
assert (info&0xffffffff)==6 and addend==0
sym=next(x for x in sections if x['name']=='.dynsym')
strings=next(x for x in sections if x['name']=='.dynstr')
nameoff=struct.unpack_from('<I',data,sym['offset']+(info>>32)*24)[0]
start=strings['offset']+nameoff;end=data.index(b'\0',start)
assert data[start:end]==b'memcmp'
for capacity in (1,2,32):
    head=capacity-1;count=1;logical_index=0;key=bytes(range(32));rows=[None]*capacity;rows[head]=key
    physical=(head+logical_index)%capacity
    assert rows[physical]==key and logical_index<count
    assert rows[physical]!=bytes(reversed(key))
    owner_count=1;limit=1
    assert owner_count<=limit
for address in (0x57faf06,0x4dc9042):
    changed=bytearray(spans[address]);changed[-1]^=1
    assert changed!=elf_bytes('.text',address,len(changed))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

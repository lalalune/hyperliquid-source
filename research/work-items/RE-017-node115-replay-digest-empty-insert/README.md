# RE-017 · Node #115 replay digest insertion into empty containers

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5884](https://github.com/lalalune/hyperliquid-source/pull/5884) records the replay digest lookup's tag-one/trim gate, and [#5886](https://github.com/lalalune/hyperliquid-source/pull/5886) handles one sentinel-root lookup. This packet follows a different selected route: an empty non-sentinel descriptor, its missing-key result, and insertion of that 32-byte key.

For a descriptor with non-sentinel capacity greater than zero and count zero, `0x57fae00` takes its count-zero route and returns RAX 1, RDX 0. Lookup `0x4dc8e00` takes its non-sentinel path, copies the key into result `+0x20..+0x3f`, writes descriptor pointer at `+0x10`, index zero at `+0x18`, and returns tag zero. On the selected wrapper continuation, output `+8` zero invokes `0x57eb000` with that descriptor, index and copied key.

With valid allocated capacity greater than zero, head zero and count zero, the insertion helper takes its index-zero route: its selected arithmetic changes the descriptor head to `capacity - 1`, increments count to one and writes the two 16-byte key lanes to that physical slot after the move helper returns. The wrapper's index-versus-count guard then passes. If its separate owner ring also has valid nonzero capacity, head zero and count zero, it appends the original 32-byte input at owner slot zero and increments its count; limit at least one avoids the subsequent trim. This is an isolated static projection of a first insertion, not a statement that real checkpoint recovery starts with empty containers. The move helper, concurrency, allocator/grow paths, pointer validity, data provenance and actual digest are boundaries. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 128 selected instruction spans. Python 3 checks the authenticated target, FDEs, selected branch/call targets and corruption controls, and models the stated empty-container case with synthetic keys and capacities.

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

with Path("research/work-items/RE-017-node115-replay-digest-empty-insert/instructions.tsv").open() as handle:
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
assert short_target(0x57e683b)==0x57e6891
assert rip_target(0x57e68a6)==0x57eb000
assert rip_target(0x4dc8f41)==0x57fae00
assert short_target(0x57fae16)==0x57fae81
assert rip_target(0x57faea2)==0x57fafb9
assert rip_target(0x4dc8f54)==0x4dc8fe0
assert short_target(0x4dc8fed)==0x4dc9032
assert rip_target(0x57eb0a2)==0x5812ad0
assert short_target(0x57eb040)==0x57eb089
for capacity in (1,2,32):
    key=bytes(range(32));head=0;count=0;index=0
    assert index<=count and count<capacity
    head=(head-1)%capacity;slot=(index+head)%capacity
    count+=1;descriptor=[None]*capacity;descriptor[slot]=key
    assert head==capacity-1 and slot==head and count==1 and descriptor[slot]==key
    assert index<count
    owner=[None]*capacity;owner_head=owner_count=0
    owner[(owner_head+owner_count)%capacity]=key;owner_count+=1
    assert owner[0]==key and owner_count==1
for address in (0x4dc8fef,0x57eb0c2):
    changed=bytearray(spans[address]);changed[-1]^=1
    assert changed!=elf_bytes('.text',address,len(changed))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-017 · Node #115 replay digest builder rightmost resumption

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5904](https://github.com/lalalune/hyperliquid-source/pull/5904) and [#5906](https://github.com/lalalune/hyperliquid-source/pull/5906) trace selected root-growth and multi-ancestor chain attachment, ending before the builder resumes. This packet traces the subsequent selected rightmost descent and count update.

After attaching the new chain, the builder tests its hop counter h. For nonzero h it follows `node + 0x170 + 8*node_word(+0x16a)` h times: first a remainder of h modulo 8 and then an unrolled group of eight repeated until the remaining count is zero. For the newly attached chain in #5906, the ancestor's updated count selects its new right child; each intermediate new node has count zero and therefore selects child zero until the new leaf. The selected continuation increments the separate qword at the saved R13 pointer once and jumps back to `0x4cc01ae` for the next input. The zero-h continuation also increments that qword once before the same jump.

This is conditional static control flow: valid acyclic nodes, intact child links/counts, representable h, successful prior allocations and no intervening alias writes are required. The packet does not establish runtime reachability, complete balancing, key order or a state root. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 69 selected instruction spans. Python 3 verifies target identity, indexed FDEs, selected transfers and corruption controls; synthetic h=1,2,8,9 link cases test the stated projection.

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

with Path("research/work-items/RE-017-node115-replay-digest-builder-rightmost-resume/instructions.tsv").open() as handle:
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
assert rip_target(0x4cc04b7)==0x4cc0588
assert rip_target(0x4cc04c7)==0x4cc0599
assert short_target(0x4cc04e6)==0x4cc04d0
assert rip_target(0x4cc04f7)==0x4cc057f
assert short_target(0x4cc057d)==0x4cc0500
assert rip_target(0x4cc0583)==0x4cc01ae
assert rip_target(0x4cc0594)==0x4cc01ae
assert rip_target(0x4cc05a5)==0x4cc0500
for h in (1,2,8,9):
    leaf={'children':[],'count':0};head=leaf
    for _ in range(h-1):head={'children':[head],'count':0}
    parent={'count':3,'children':[None,None,None,head]};cur=parent
    for _ in range(h):cur=cur['children'][cur['count']]
    assert cur is leaf and h==(h%8)+8*(h//8)
for addr in (0x4cc04d8,0x4cc057f):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

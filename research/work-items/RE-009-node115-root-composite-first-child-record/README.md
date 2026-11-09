# RE-009 · Node #115 composite root first child record

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [block-root packet](../RE-017-abci-block-root-115/README.md) identifies reducer `0x141a250`; the [child-finalize packet](../RE-009-node115-root-child-finalize/README.md) follows its single-buffer representation. This packet examines the distinct composite representation until its first non-skipped child result is staged.

On the selected non-single-buffer path, the reducer traverses 24-byte child slots with a zero-based index. A first word of `0x8000000000000001` skips that slot. Other slots are copied to a temporary and recursively passed through relocation-resolved `0x141a250`; a returned tag byte 2 also skips the slot. For the first result whose tag is not 2, the selected normal allocation requests 0xc0 bytes and copies a 48-byte staged record to its beginning: the original child index at +0, return tag at +8, and return bytes 1..32 at +9..+0x28. Seven further bytes from the returned region occupy +0x29..+0x2f; their meaning and validity are not inferred. The original slot index advances even across skipped children.

For a child whose separately documented finalizer returns tag 0 plus 32 digest bytes, this record carries that child digest and its original slot index. This is not a proof of subsequent aggregation, child execution, a complete parent preimage or a real state root. Valid child/result buffers, normal recursive returns, successful allocation and no alias mutation are assumptions; error and unwind branches remain outside scope. No captured binary executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 80 selected spans. Python authenticates target/FDE, recursion, sentinel/tag edges and allocation; a synthetic byte model checks skipped-slot indexes and the overlapping 48-byte projection. It does not execute target bytes.

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

with Path("research/work-items/RE-009-node115-root-composite-first-child-record/instructions.tsv").open() as handle:
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

assert len(spans)==80
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x141a27b)==0x141a346
assert short(0x141a3d2)==0x141a3b0
assert rip_target(0x141a3f1)==0x64df500 and relocations[0x64df500][1]==0x141a250
assert short(0x141a407)==0x141a3b0
assert rip_target(0x141a461)==0x141a3b0
assert spans[0x141a4ab]==bytes.fromhex('bfc0000000')
assert rip_target(0x141a4b0)==0x64df480
assert spans[0x141a4da]==bytes.fromhex('0f115020')
assert spans[0x141a4de]==bytes.fromhex('0f114810')
assert spans[0x141a4e2]==bytes.fromhex('0f1100')
def first_record(children):
 for index,(sentinel,result) in enumerate(children):
  if sentinel or result[0]==2:continue
  assert len(result)==40
  return index.to_bytes(8,'little')+result
 return None
result=bytes([0])+bytes(range(1,40))
r=first_record([(True,result),(False,bytes([2])+bytes(39)),(False,result)])
assert len(r)==48 and int.from_bytes(r[:8],'little')==2
assert r[8]==0 and r[9:41]==result[1:33] and r[41:48]==result[33:40]
assert first_record([(True,result),(False,bytes([2])+bytes(39))]) is None
for a in (0x141a3f1,0x141a461):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and first-record models pass')
PY
```

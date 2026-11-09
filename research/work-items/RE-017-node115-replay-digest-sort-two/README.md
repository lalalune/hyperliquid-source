# RE-017 · Node #115 replay digest two-row small sort

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5912](https://github.com/lalalune/hyperliquid-source/pull/5912) traces a selected small-run call to `0x5408900`; [#5914](https://github.com/lalalune/hyperliquid-source/pull/5914) maps its capacity gate. This packet examines the helper for exactly two 32-byte rows, sufficient scratch capacity (at least 18), valid non-overlapping input and scratch and ordinary `memcmp` semantics. It neither assumes those inputs occur during actual replay nor covers larger counts.

The entry takes the 2..7 branch. With half count one, it copies input rows 0 and 1 into corresponding scratch rows, skips both half-insertion loops, then compares the two scratch rows through the imported `memcmp` slot using length 32. The two merge selections copy the lexicographically smaller byte sequence into input row 0 and the larger into input row 1. Equal byte sequences remain equal; no general stability claim follows. With the stated preconditions and normal comparator return, the selected two-row path reaches the normal return rather than the capacity or consistency failure branches. The packet does not establish the behavior for R>2, the comparator implementation in a running process, real input reachability, or any state-root equivalence. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 138 selected instruction spans. Python verifies target identity, FDEs, bytes, selected edges, relocation symbol, mutation controls and synthetic two-row examples derived from both comparison branches; the synthetic check is a model of the stated preconditions, not an execution of the target.

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

with Path("research/work-items/RE-017-node115-replay-digest-sort-two/instructions.tsv").open() as handle:
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

assert len(spans)==138
assert rip_target(0x5408917)==0x5408f45
assert rip_target(0x5408924)==0x5408fa3
assert rip_target(0x5408943)==0x5408b97
assert rip_target(0x5408bd8)==0x5408cd4
assert rip_target(0x5408cf6)==0x5408e19
assert rip_target(0x5408ebe)==0x64dfb50
assert rip_target(0x5408f00)==0x64dfb50
info,addend=relocations[0x64dfb50]
assert info & 0xffffffff == 6
symtab=next(s for s in sections if s['name']=='.dynsym')
strtab=next(s for s in sections if s['name']=='.dynstr')
symoff=symtab['offset']+(info>>32)*24
nameoff=struct.unpack_from('<I',data,symoff)[0]+strtab['offset']
assert data[nameoff:data.index(b'\0',nameoff)]==b'memcmp'
def compare(a,b):
    return (a>b)-(a<b)
def selected_path(left,right):
    assert len(left)==len(right)==32
    # Entry skips both half-insertion loops when n=2, so scratch is [left,right].
    scratch=[left,right]
    # 0x5408ed1..0x5408ee6 selects left only on a negative first comparison.
    first_cmp=compare(scratch[0],scratch[1])
    first=scratch[0] if first_cmp<0 else scratch[1]
    # 0x5408f00..0x5408f19 compares in reverse and chooses right on nonnegative.
    second_cmp=compare(scratch[1],scratch[0])
    second=scratch[1] if second_cmp>=0 else scratch[0]
    return first,second
values=[bytes(32),bytes([1])+bytes(31),bytes(31)+bytes([1]),bytes([255])*32]
for left in values:
    for right in values:
        assert selected_path(left,right)==tuple(sorted((left,right)))
# A reversed sign selection is detected by the deliberately reversed pair.
assert (values[3],values[0])!=selected_path(values[3],values[0])
for x in (0x5408ebe,0x5408f00):
    bad=bytearray(spans[x]);bad[-1]^=1
    assert bad!=elf_bytes('.text',x,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-017 · Node #115 replay digest builder first distinct row

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5897](https://github.com/lalalune/hyperliquid-source/pull/5897) traces a converter into builder `0x4cc0050`; [#5899](https://github.com/lalalune/hyperliquid-source/pull/5899) conditionally connects a valid input count above 63 to its preparation path. This packet examines the first selected builder insertion when the first two prepared 32-byte rows differ.

The converter allocates a `0x170`-byte initial node, clears its word at `+0x16a`, initializes a separate count to zero, and passes the builder a tagged range with byte tag 2, a row pointer and end pointer `start + 32*N`. On the selected normal path with `N > 1`, builder depth zero and valid node and range, it reads the first row, advances by 32, reads the second, and compares the two 16-byte lanes with `pcmpeqb`/`pmovmskb`. If at least one of the 32 bytes differs, it carries the first row to the insertion gate. A node word at `+0x16a` below 11 selects a direct append; with initial count zero it increments that word to 1, writes the first row into node offset 0, and increments the separate count.

On the separate selected case of exactly two equal 32-byte rows, the combined two-lane equality mask is `0xffff`. The builder advances through the equal second row, then on range exhaustion carries that row to the same direct insertion gate. With the same empty initial node and normal path, it writes one row and increments the node and separate count once. This is a two-row adjacent-equality observation, not proof of global deduplication or of the order produced by the preparation helper.

This only maps one selected step. Longer equal runs, later node splits, complete preparation order, validity of pointer/length, exceptional paths and real runtime data remain unproven. It does not establish a complete tree, actual replay acceptance or a state root. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 134 selected instruction spans. Python 3 verifies target identity, FDEs, selected edges, corruption controls and synthetic first-row mismatch and node-boundary cases.

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

with Path("research/work-items/RE-017-node115-replay-digest-builder-first-row/instructions.tsv").open() as handle:
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
assert rip_target(0x5155deb)==0x4cc0050
assert rip_target(0x4cc0071)==0x4cc013f
assert short_target(0x4cc01c0)==0x4cc01f0
assert rip_target(0x4cc01c5)==0x4cc05ad
assert rip_target(0x4cc0233)==0x4cc0300
assert rip_target(0x4cc027b)==0x4cc0317
assert rip_target(0x4cc0343)==0x4cc0180
assert (0x4cc0299+2+struct.unpack_from('<b',spans[0x4cc0299],1)[0])==0x4cc0304
assert (0x4cc0306+2+struct.unpack_from('<b',spans[0x4cc0306],1)[0])==0x4cc0312
assert spans[0x5155dd7]==bytes.fromhex('c644246002')
for n in (2,64):
    first=bytes(32);second=bytes(31)+b'\x01';node=bytearray(0x170);count=0
    assert n>1 and first!=second and count<11
    node[32*count:32*count+32]=first;count+=1
    assert node[:32]==first and count==1
assert bytes(32)==bytes(32) and not (11<11)
for addr in (0x4cc027b,0x4cc0183):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

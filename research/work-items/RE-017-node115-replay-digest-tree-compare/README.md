# RE-017 · Node #115 replay digest lookup tree comparison

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5884](https://github.com/lalalune/hyperliquid-source/pull/5884) traces a selected 32-byte digest through the call at `0x57e6785` to lookup `0x4dc8e00` but leaves lookup internals open. This packet addresses one sentinel-root, nonnull-node comparison path and the equal-result output.

The lookup saves the key pointer from RDX. After its earlier conditional storage-conversion branch, a descriptor first word equal to `0x8000000000000000` takes the tree path at `0x4dc909b`. With a nonnull root, it reads an unsigned 16-bit count at node `+0x16a`, multiplies that count by 32 and iterates node bytes in 32-byte steps. At `0x4dc90f3` it invokes the imported `memcmp` slot `0x64dfb50` on the saved key, the selected node row and length 32. The relocation is `R_X86_64_GLOB_DAT` for `memcmp`; no target machine code is executed here. A positive comparison continues to the next slot. A zero comparison follows `0x4dc9115` to `0x4dc9135`, where the result holds the selected node at output `+8`, current depth at `+0x10`, selected slot index at `+0x18`, the saved root-reference address at `+0x20`, and tag 1 at output `+0`.

On a negative comparison, or after every row compares below the key, the selected continuation uses the candidate index and decrements depth. A non-underflowing depth follows child pointer `node +0x170 + 8*index`; underflow reaches the tag-zero output at `0x4dc9158` without following a child. That output copies the 32-byte key and preserves the leaf pointer and candidate index at `+0x30/+0x40`. The distinct null-root entry zeroes the leaf pointer first before sharing this output. This selected continuation does not prove whole-tree ordering or valid metadata.

This is a local selected-node result, assuming valid memory, the indexed FDE path, the imported comparator's usual contract and no concurrent mutation. The sentinel conversion, non-sentinel layout, other conversion and insertion behavior and actual digest values are not fully reconstructed; no real state root or replay acceptance is claimed. The callback-to-key connection uses the explicit assumptions in #5884. No captured binary is run.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 89 selected instruction spans. Python 3 verifies target digest, FDEs, selected transfers, comparator relocation/symbol identity, and corruption controls. Synthetic comparison examples test only the described ordering cases.

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

with Path("research/work-items/RE-017-node115-replay-digest-tree-compare/instructions.tsv").open() as handle:
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
assert rip_target(0x4dc8f33)==0x4dc909b
assert rip_target(0x4dc90b5)==0x64dfb50
assert short_target(0x4dc910c)==0x4dc90e0
assert short_target(0x4dc9115)==0x4dc9135
assert short_target(0x4dc9153)==0x4dc9191
assert short_target(0x4dc9129)==0x4dc91a6
assert short_target(0x4dc91ab)==0x4dc9158
assert rip_target(0x4dc90a6)==0x4dc9155
assert spans[0x4dc912b]==bytes.fromhex('4f8bacfd70010000')
info,addend=relocations[0x64dfb50]
assert (info&0xffffffff)==6 and addend==0
symindex=info>>32
sym=next(x for x in sections if x['name']=='.dynsym')
strings=next(x for x in sections if x['name']=='.dynstr')
nameoff=struct.unpack_from('<I',data,sym['offset']+symindex*24)[0]
start=strings['offset']+nameoff;end=data.index(b'\0',start)
assert data[start:end]==b'memcmp'
for key,row,order in ((bytes(32),bytes(32),0),(bytes([1])*32,bytes(32),1),(bytes(32),bytes([1])*32,-1)):
    assert ((key>row)-(key<row))==order
for address in (0x4dc90e9,0x4dc9135):
    changed=bytearray(spans[address]);changed[-1]^=1
    assert changed!=elf_bytes('.text',address,len(changed))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

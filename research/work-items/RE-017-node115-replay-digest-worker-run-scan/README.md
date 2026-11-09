# RE-017 · Node #115 replay digest worker adjacent-run scan

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5901](https://github.com/lalalune/hyperliquid-source/pull/5901) identifies the preparation worker and scratch arguments. This packet maps one selected adjacent-row scan in worker `0x4f848d0`; it does not establish the complete preparation or sorting algorithm.

For a selected region with at least three readable 32-byte rows and remaining count at least the local threshold, the worker compares row 1 with row 0 using the imported 32-byte `memcmp`. If that result is nonnegative, its selected loop advances while each following row compares nonnegative to its immediate predecessor; equality remains in that run. If the first comparison is negative, the alternate selected loop advances while following comparisons remain negative; equality stops that run. Both loops stop at the selected region boundary and carry the run length to the later threshold check. The comparison slot `0x64dfb50` is an `R_X86_64_GLOB_DAT` relocation for `memcmp`.

This is local control flow under valid pointers, the comparator contract, selected gates and no concurrent mutation. It does not prove how later branches transform the rows, full sorting correctness, real input order, runtime reachability or a state root. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 60 selected instruction spans. Python 3 checks target identity, FDEs, selected branch/call targets, comparator relocation/symbol, mutation controls and synthetic adjacent-run examples.

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

with Path("research/work-items/RE-017-node115-replay-digest-worker-run-scan/instructions.tsv").open() as handle:
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
assert short_target(0x4f84a27)==0x4f84a80
assert short_target(0x4f84a84)==0x4f84ab0
assert rip_target(0x4f84ac0)==0x64dfb50
assert short_target(0x4f84ac8)==0x4f84b14
assert rip_target(0x4f84afc)==0x64dfb50
assert short_target(0x4f84b10)==0x4f84af0
assert rip_target(0x4f84b4c)==0x64dfb50
assert short_target(0x4f84b54)==0x4f84b65
assert short_target(0x4f84b60)==0x4f84b40
info,addend=relocations[0x64dfb50]
assert (info&0xffffffff)==6 and addend==0
sym=next(x for x in sections if x['name']=='.dynsym')
strings=next(x for x in sections if x['name']=='.dynstr')
nameoff=struct.unpack_from('<I',data,sym['offset']+(info>>32)*24)[0]
start=strings['offset']+nameoff;end=data.index(b'\0',start)
assert data[start:end]==b'memcmp'
def run(rows):
    descending=rows[1]<rows[0];length=2
    while length<len(rows):
        if (rows[length]<rows[length-1])!=descending:break
        length+=1
    return length
assert run([b'a'*32,b'a'*32,b'b'*32,b'a'*32])==3
assert run([b'c'*32,b'b'*32,b'b'*32,b'a'*32])==2
for addr in (0x4f84ac0,0x4f84b54):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

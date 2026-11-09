# RE-009 · Node #115 flat root-history survivor publication

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [flat cutoff packet](../RE-009-node115-root-history-flat-cutoff/README.md) identifies the strict-lower count D but leaves the subsequent copies and publication open. [#5935](https://github.com/lalalune/hyperliquid-source/pull/5935) conditionally identifies the selected cutoff as the 50th row from the logical end. This packet follows the flat copy and owner replacement.

Assume a valid non-sentinel flat ring with capacity C<2^63, start S<C, count 0<N<=C, 0<=D<N, nonwrapping addresses, disjoint newly allocated storage and normal successful helper returns. Let L=min(N,C−S), W=N−L, and M=N−D. The helper allocates 40*M bytes. If D<L it copies the tail-span suffix starting at logical D, then W rows from the wrapped span; otherwise it copies M rows starting D−L into the wrapped span. It updates the old descriptor count to D and returns a new flat descriptor with capacity M, the allocated pointer, start 0 and count M. The selected caller releases the old flat allocation and installs the returned four-word descriptor. Under those conditions the installed rows are exactly the original logical suffix D..N in order.

Combining with #5935 and the strict-lower count, a sorted unique valid ring with N>=51 installs its last 50 rows on this selected path; equal cutoff keys may retain more. This is conditional on those prior unmerged observations and normal allocation/copy/release, not evidence of actual runtime reachability, tree representation, crash consistency or checkpoint state-root equality. The zero-survivor and failure branches are not covered. No captured target code executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 134 selected spans. Python authenticates the target and FDEs, selected count/copy/publication edges, and memcpy relocation. The synthetic ring model checks wrapped and unwrapped layouts and all nonempty suffix cut positions; it is not target execution.

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

with Path("research/work-items/RE-009-node115-root-history-flat-survivor-publication/instructions.tsv").open() as handle:
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

assert len(spans)==134
assert rip_target(0x4de5af0)==0x4de5b87
assert rip_target(0x4de5b8d)==0x57f2d30
assert rip_target(0x4de5f0b)==0x64df508
assert rip_target(0x4de5f52)==0x64df508
assert rip_target(0x5a0464a)==0x4de5ad0
assert rip_target(0x5a046b4)==0x64df4a0
info,_=relocations[0x64df508]
assert info&0xffffffff==6
sym=next(s for s in sections if s['name']=='.dynsym');strings=next(s for s in sections if s['name']=='.dynstr')
name=struct.unpack_from('<I',data,sym['offset']+(info>>32)*24)[0]+strings['offset']
assert data[name:data.index(b'\0',name)]==b'memcpy'
assert spans[0x4de5f58]==bytes.fromhex('49896e18')
assert spans[0x5a046c4]==bytes.fromhex('0f114b10')
assert spans[0x5a046c8]==bytes.fromhex('0f1103')
cases=0
for n in range(1,61):
 for cap in (n,n+1,n+5):
  for start in range(cap):
   physical=[None]*cap;logical=list(range(n))
   for i,x in enumerate(logical):physical[(start+i)%cap]=x
   first=min(n,cap-start);wrapped=n-first
   for d in range(n):
    m=n-d
    if d<first:out=physical[start+d:start+first]+physical[:wrapped]
    else:out=physical[d-first:d-first+m]
    assert len(out)==m and out==logical[d:]
    cases+=1
for n in range(51,61):
 d=n-50;assert list(range(n))[d:]==list(range(n-50,n))
for a in (0x4de5f0b,0x5a0464a):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and {cases} survivor-copy models pass')
PY
```

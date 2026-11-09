# RE-009 · Node #115 byte-child digest initialization and reference inputs

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [slot-23 byte visitor packet](../RE-009-node115-root-byte-slot23/README.md) observes a raw byte write and leaves its digest initialization open. [#5941](https://github.com/lalalune/hyperliquid-source/pull/5941) reconstructs the distinct qword-child constructor's initial digest mode. This packet compares the byte child's own constructor and joins its inline raw-byte input to that mode.

The two selected constructor normal paths have 86 instruction spans each at a fixed address delta. Eighty-one pairs have identical bytes; the remaining five differ only in RIP-relative displacement and resolve to the same target addresses. Under the byte-copy and initialization interpretation in #5941, this binds the byte child to the same IV, zero counter/base flags and separate implementation selector. On a freshly initialized child with exactly one successful inline visit, the writer passes its single byte unchanged, including values other than 0 and 1, to the selected update/finalize path. Thus independent ordinary unkeyed BLAKE3 of that one byte supplies a conditional reference value, not an observed #115 digest or a complete state root. The proof assumes normal allocations, no intervening mutation and the cited finalizer contract; fallback writes and real state values are excluded.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 188 selected spans. Python authenticates target identity, indexed FDEs, paired bytes, all five qualified RIP targets and the byte load/store witnesses. No captured target code executes.

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

with Path("research/work-items/RE-009-node115-root-byte-child-digest-mode/instructions.tsv").open() as handle:
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

assert len(spans)==188
old=sorted(a for a in spans if 0x14196d0<=a<0x14198f8)
new=sorted(a for a in spans if 0x14193f0<=a<0x1419618)
assert len(old)==len(new)==86
qualified=[]
for b,a in zip(new,old):
 assert a-b==0x2e0
 x,y=spans[a],spans[b]
 assert len(x)==len(y)
 if x!=y:
  assert x[:-4]==y[:-4] and rip_target(a)==rip_target(b)
  qualified.append(a)
assert qualified==[0x14196e3,0x14196f5,0x1419700,0x141970f,0x141975b]
assert spans[0x1419d45]==bytes.fromhex('0fb60f')
assert spans[0x1419d6b]==bytes.fromhex('880c02')
assert rip_target(0x1419415)==0x64df488 and relocations[0x64df488][1]==0x160bee0
for a in (0x1419415,0x1419d6b):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans; 81 identical pairs and five qualified RIP pairs pass')
PY
```

## Independent reference values

An already-installed `@noble/hashes` 1.8.0 implementation yielded these ordinary unkeyed BLAKE3 reference digests. They are conditional reference values, not observed node outputs:

| Byte | Reference digest |
| --- | --- |
| `00` | `2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213` |
| `01` | `48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b` |
| `ff` | `99d44d377bc5936d8cb7f5df90713d84c7587739b4724d3d2f9af1ee0e4c8efd` |

With Node.js and `@noble/hashes` 1.8.0 already available in the module search path:

```sh
node - <<'JS'
const {blake3}=require('@noble/hashes/blake3');
const expected=['2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213','48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b','99d44d377bc5936d8cb7f5df90713d84c7587739b4724d3d2f9af1ee0e4c8efd'];
for(const [i,v] of [0,1,255].entries()) if(Buffer.from(blake3(Buffer.from([v]))).toString('hex')!==expected[i]) throw Error('reference mismatch');
console.log('three reference vectors match');
JS
```

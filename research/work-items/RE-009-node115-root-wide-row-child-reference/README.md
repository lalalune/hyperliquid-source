# RE-009 · Node #115 wide-row child reference inputs

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [wide-row projection packet](../RE-009-node115-root-wide-map-value-width/README.md) maps two separate child inputs, row `+0..+0xf` and `+0x18..+0x1f`, but does not establish their hash mode. [#5941](https://github.com/lalalune/hyperliquid-source/pull/5941) and [#5944](https://github.com/lalalune/hyperliquid-source/pull/5944) establish conditional initialization relations for the two constructor targets. This packet joins those targets to the two wide-row descriptors and records independent reference inputs.

For the selected fresh-child, successful inline-write path, the row-base descriptor binds to a 16-byte writer and constructor `0x141a020`; the `+0x18` descriptor binds to an eight-byte writer and constructor `0x14196d0`. With the cited constructor and finalizer contracts, both inputs use the ordinary unkeyed BLAKE3 reference mode, in separate child buffers. A synthetic row of bytes `00..1f` supplies `00..0f` and `18..1f`, respectively; bytes `10..17` are not supplied by these two projections. This says nothing about their use elsewhere or a parent concatenation/order, and does not observe an actual node digest or state root. Pointer joins, valid buffers, normal returns and no later mutation are assumptions. No captured target code executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 37 selected spans. Python checks target identity, FDEs, descriptor/constructor/writer relocations and raw-width instructions. The independent reference values below require an already-installed `@noble/hashes` 1.8.0; they are not target execution.

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

with Path("research/work-items/RE-009-node115-root-wide-row-child-reference/instructions.tsv").open() as handle:
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

assert len(spans)==37
assert rip_target(0x46a3d26)==rip_target(0x46a5eaf)==0x6493318
assert rip_target(0x46a3d2d)==rip_target(0x46a5ea8)==0x6493340
for slot,target in ((0x6493330,0x3916030),(0x6493338,0x3916020),(0x6493358,0x4302e50),(0x6493360,0x43025f0)):
 assert relocations[slot][1]==target
for site,target in ((0x4302e50,0x141ba80),(0x43025f0,0x141a020),(0x3916030,0x14199b0),(0x3916020,0x14196d0)):
 assert relocations[rip_target(site)][1]==target
assert spans[0x141baac]==bytes.fromhex('0f1007')
assert spans[0x141baaf]==bytes.fromhex('0f11040a')
assert spans[0x14199b5]==bytes.fromhex('488b0f')
assert spans[0x14199dc]==bytes.fromhex('48890c02')
row=bytes(range(32))
assert row[:16].hex()=='000102030405060708090a0b0c0d0e0f'
assert row[24:32].hex()=='18191a1b1c1d1e1f'
for a in (0x4302e50,0x3916020):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and wide-child bindings pass')
PY
```

## Independent reference values

| Projected input | Unkeyed BLAKE3 reference |
| --- | --- |
| `000102030405060708090a0b0c0d0e0f` | `a6a492965517a830cb75fdb713465aa465f2f098233896fea44c1d98268bf9e3` |
| `18191a1b1c1d1e1f` | `606e0091f8630d9c16305cb01b9a41918c5a16069399decc4bcafd81055b04ec` |

With Node.js and `@noble/hashes` 1.8.0 already available in the module search path:

```sh
node - <<'JS'
const {blake3}=require('@noble/hashes/blake3');
const rows=[['000102030405060708090a0b0c0d0e0f','a6a492965517a830cb75fdb713465aa465f2f098233896fea44c1d98268bf9e3'],['18191a1b1c1d1e1f','606e0091f8630d9c16305cb01b9a41918c5a16069399decc4bcafd81055b04ec']];
for(const [input,expected] of rows) if(Buffer.from(blake3(Buffer.from(input,'hex'))).toString('hex')!==expected) throw Error('reference mismatch');
console.log('two reference vectors match');
JS
```

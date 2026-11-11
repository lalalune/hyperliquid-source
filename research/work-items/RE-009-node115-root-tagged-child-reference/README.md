# RE-009 · Node #115 tagged root-child reference inputs

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [block-root packet](../RE-017-abci-block-root-115/README.md) identifies the selected index-13 tagged visitor and its marker writes but leaves child digest mode and values open. [#5941](https://github.com/lalalune/hyperliquid-source/pull/5941) conditionally qualifies the shared qword child's initialization. This packet connects the tag/status branches and marker constants to separate child reference inputs.

On the selected valid two-child container path, the visitor compares the low 32-bit tag with 1. Tag 1 first sends the eight-byte source payload at +8 to child zero; only a status-4 return reaches child one with the literal qword 1. A non-1 low tag bypasses that payload visit and sends literal qword 0 to child one. Both constructor slots resolve to `0x14196d0` and both writer slots to `0x14199b0`. Under #5941 and the cited child-finalizer contract, fresh children with one successful inline write have independent unkeyed BLAKE3 reference inputs. This is not proof that an unvisited child disappears from a parent, that the two child digests are concatenated, or that any reference digest was observed from the target.

The synthetic example below uses payload `0001020304050607`, and literal markers as eight little-endian bytes. It assumes valid containers and buffers, successful initialization/writes/finalization, no intervening mutation, and the cited unmerged mode contract. Other tag bits, malformed layouts, actual runtime state and complete state-root behavior remain open. No captured target code executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 70 selected spans. Python authenticates target identity, indexed FDE, tag/status edges, four constructor/writer relocations and the two literal qwords. Independent reference hashes below use an already-installed `@noble/hashes` 1.8.0; they are not target execution.

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

with Path("research/work-items/RE-009-node115-root-tagged-child-reference/instructions.tsv").open() as handle:
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

assert len(spans)==70
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x4d3ebf6)==0x4d3ec93
assert rip_target(0x4d3ec58)==0x4d3ece8
assert rip_target(0x4d3ec67)==rip_target(0x4d3ec8a)==0x459280
assert rip_target(0x4d3ecb5)==rip_target(0x4d3ecd8)==0x459348
for site,target in ((0x4d3ec33,0x14196d0),(0x4d3ec50,0x14199b0),(0x4d3ec73,0x14196d0),(0x4d3ecc1,0x14196d0),(0x4d3ece2,0x14199b0)):
 assert relocations[rip_target(site)][1]==target
assert elf_bytes('.rodata',0x459280,8)==(1).to_bytes(8,'little')
assert elf_bytes('.rodata',0x459348,8)==bytes(8)
def inputs(tag,payload,status):
 assert len(payload)==8
 if (tag&0xffffffff)==1:
  return [payload,(1).to_bytes(8,'little')] if status==4 else [payload]
 return [bytes(8)]
payload=bytes(range(8))
assert inputs(1,payload,4)==[payload,bytes.fromhex('0100000000000000')]
assert inputs(1,payload,3)==[payload]
assert inputs(0,payload,4)==[bytes(8)]
assert inputs(0x100000001,payload,4)==inputs(1,payload,4)
for a in (0x4d3ebf6,0x4d3ec58):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and tagged-child bindings pass')
PY
```

## Independent reference values

| Conditional child input | Unkeyed BLAKE3 reference |
| --- | --- |
| `0001020304050607` | `2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb` |
| `0100000000000000` | `1a0d12016999e47689dae5744d2b8c1903faf7ca2886a658150083100ef2c8ee` |
| `0000000000000000` | `71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb` |

With Node.js and `@noble/hashes` 1.8.0 already available in the module search path:

```sh
node - <<'JS'
const {blake3}=require('@noble/hashes/blake3');
const rows=[['0001020304050607','2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb'],['0100000000000000','1a0d12016999e47689dae5744d2b8c1903faf7ca2886a658150083100ef2c8ee'],['0000000000000000','71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb']];
for(const [input,expected] of rows) if(Buffer.from(blake3(Buffer.from(input,'hex'))).toString('hex')!==expected) throw Error('reference mismatch');
console.log('three reference vectors match');
JS
```

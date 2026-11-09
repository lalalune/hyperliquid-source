# RE-009 · Node #115 slot-26 nested empty-child reference

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [slot-26 visitor packet](../RE-009-node115-root-slot26-visitor/README.md) maps the outer tagged path and nested no-op visitor but leaves its child initialization and digest reference open. [#5941](https://github.com/lalalune/hyperliquid-source/pull/5941) and [#5944](https://github.com/lalalune/hyperliquid-source/pull/5944) qualify the two qword-child constructor modes. This packet joins the distinct slot-26 path to those modes.

On the selected tag-1 route with fresh children, the nested visitor first constructs `0x14196d0` and writes the source qword at outer input +8 through `0x14199b0`. After status 4, its second constructor `0x57ba3e0` resolves to `0x141a020`; the following `0x4d3f7f0` checks only the destination sentinel and does not read the advanced source pointer or append input. With successful construction and no later mutation, that second nested child has zero buffered input. If it reaches the previously documented normal child finalizer, the cited initialization contract makes the ordinary unkeyed BLAKE3 empty-input digest a conditional reference. After nested status 4, the separate outer marker child receives qword 1; a non-1 outer tag bypasses the nested payload and writes marker 0.

This does not prove that the empty child is finalized in a real run, that child digests are concatenated, or that an actual checkpoint or full state root matches any reference. Valid pointer joins, normal allocations/writes/finalization and no intervening mutation are assumptions. No captured binary executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 126 selected spans. Python authenticates the target/FDEs, selected descriptor, nested constructor/writer/no-op and marker bindings. Independent reference vectors below require an already-installed `@noble/hashes` 1.8.0 and are not target outputs.

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

with Path("research/work-items/RE-009-node115-root-slot26-empty-child-reference/instructions.tsv").open() as handle:
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

assert len(spans)==126
assert rip_target(0x544268e)==0x64a84a8
assert relocations[0x64a84c0][1]==0x4d3f3a0
assert rip_target(0x4d3f3f3)==0x5106a40
assert rip_target(0x4d3f40f)==0x5106a90
for site,target in ((0x5106acb,0x14196d0),(0x5106ae9,0x14199b0),(0x57ba3e0,0x141a020),(0x4d3f431,0x14196d0),(0x4d3f4a0,0x14199b0)):
 assert relocations[rip_target(site)][1]==target
assert rip_target(0x5106b08)==0x57ba3e0
assert rip_target(0x5106b25)==0x4d3f7f0
assert b''.join(spans[a] for a in (0x4d3f7f0,0x4d3f7f2,0x4d3f7f5,0x4d3f7f8,0x4d3f7fb)).hex()=='31c0483b060f90c0c0e002c3'
assert elf_bytes('.rodata',0x459280,8)==(1).to_bytes(8,'little')
assert elf_bytes('.rodata',0x459348,8)==bytes(8)
for a in (0x5106b08,0x5106b25):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and nested child bindings pass')
PY
```

## Independent reference values

With ordinary unkeyed BLAKE3, `@noble/hashes` 1.8.0 gives empty input `af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262`, qword marker 1 `1a0d12016999e47689dae5744d2b8c1903faf7ca2886a658150083100ef2c8ee`, and qword marker 0 `71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb`. These are conditional references, not observed node outputs.

With Node.js and `@noble/hashes` 1.8.0 already in the module search path:

```sh
node - <<'JS'
const {blake3}=require('@noble/hashes/blake3');
const rows=[['','af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262'],['0100000000000000','1a0d12016999e47689dae5744d2b8c1903faf7ca2886a658150083100ef2c8ee'],['0000000000000000','71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb']];
for(const [input,expected] of rows)if(Buffer.from(blake3(Buffer.from(input,'hex'))).toString('hex')!==expected)throw Error('reference mismatch');
console.log('three reference vectors match');
JS
```

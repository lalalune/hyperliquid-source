# RE-009 · Node #115 qword-child digest initialization mode

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [qword-child packet](../RE-009-node115-root-qword-child/README.md) identifies constructor `0x14196d0`, its buffer and the eight-byte write but leaves the embedded digest's initialization open. The [child-finalize packet](../RE-009-node115-root-child-finalize/README.md) follows buffered input into finalization. The separate [outer hash-mode packet](../RE-009-node115-abci-root-hash-mode/README.md) identifies the corresponding unkeyed BLAKE3 IV and distinguishes flags from implementation selection. This packet traces the qword constructor's own selected initialization.

On the successful owner/buffer allocation path, the constructor loads the same 32 IV bytes, initializes the working and stored IV copies, clears the initial counter, length and base-flag bytes, and writes the selector result separately. The overlapping staged vector moves place the digest context at owner `+0x20`: its working IV is at context `+0x40`, stored IV at `+0x70`, base flags at `+0x6a`, and selector at `+0x6b`. The selector slot resolves to `0x160bee0`. These initial values match ordinary unkeyed BLAKE3 mode under the cited update/finalization interpretation; a selector is not a hash flag or an assertion about the host's actual CPU.

Combined with the cited single successful qword write and finalizer path, a newly initialized child with exactly one inline write of marker 1 supplies eight bytes `01 00 00 00 00 00 00 00` to that unkeyed reference hash. This is a conditional reference input, not a digest observed from #115, an assertion about multiple writes, or a full state-root result. Allocation failure, later mutations, real checkpoint reachability and captured execution remain outside the claim.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 86 selected constructor spans. Python authenticates target identity, FDE, IV bytes, selector relocation and selected instructions; a byte-offset model checks the overlapping stack-to-owner copies and distinguishes selector from base flag. The model does not execute target bytes or compute a runtime digest.

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

with Path("research/work-items/RE-009-node115-root-qword-child-digest-mode/instructions.tsv").open() as handle:
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

assert len(spans)==86
assert rip_target(0x14196f5)==0x64df488
assert relocations[0x64df488][1]==0x160bee0
assert rip_target(0x1419700)==0x457ae0
assert rip_target(0x141970f)==0x457af0
iv=struct.pack('<8I',0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
assert elf_bytes('.rodata',0x457ae0,32)==iv
stack=bytearray([0xa5])*0x200;owner=bytearray([0x5a])*0xc0
stack[0x30:0x70]=bytes(64)
stack[0x70:0x90]=iv
stack[0xac:0xcc]=iv
stack[0x97:0x9b]=bytes(4)
stack[0x90:0x98]=bytes(8)
stack[0xd5:0x115]=stack[0x30:0x70]
stack[0x115:0x135]=stack[0x70:0x90]
stack[0x130:0x140]=stack[0x8b:0x9b]
stack[0:0x20]=stack[0xa8:0xc8]
stack[0x20:0x24]=stack[0xc8:0xcc]
owner[0x19:0x89]=stack[0xce:0x13e]
owner[0x89:0x8b]=stack[0x13e:0x140]
owner[0x8b]=4
owner[0x8c:0xac]=stack[0:0x20]
owner[0xac:0xb0]=stack[0x20:0x24]
owner[0xb0:0xb4]=bytes(4)
assert owner[0x60:0x80]==iv and owner[0x90:0xb0]==iv
assert owner[0x80:0x88]==bytes(8)
assert owner[0x88:0x8b]==bytes(3) and owner[0x8b]==4
assert (1).to_bytes(8,'little')==bytes.fromhex('0100000000000000')
for a in (0x1419700,0x1419869):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and child initialization projection pass')
PY
```

## Independent reference digests

As a separate reference calculation, the already-installed `@noble/hashes` 1.8.0 implementation produced the following ordinary unkeyed BLAKE3 outputs. These are **not** observed node outputs and depend on the conditional constructor/write/finalizer join above:

| Eight input bytes | Reference digest |
| --- | --- |
| `0000000000000000` | `71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb` |
| `0100000000000000` | `1a0d12016999e47689dae5744d2b8c1903faf7ca2886a658150083100ef2c8ee` |

With Node.js and `@noble/hashes` 1.8.0 already available in the module search path, reproduce independently with:

```sh
node - <<'JS'
const {blake3}=require('@noble/hashes/blake3');
const digest=(s)=>Buffer.from(blake3(Buffer.from(s,'hex'))).toString('hex');
if(digest('')!=='af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262') throw Error('empty reference');
if(digest('0000000000000000')!=='71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb') throw Error('zero marker');
if(digest('0100000000000000')!=='1a0d12016999e47689dae5744d2b8c1903faf7ca2886a658150083100ef2c8ee') throw Error('one marker');
console.log('three reference vectors match');
JS
```

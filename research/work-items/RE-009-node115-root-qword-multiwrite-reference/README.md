# RE-009 · Node #115 qword-child repeated writes across buffer boundary

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [qword-child packet](../RE-009-node115-root-qword-child/README.md) follows one inline write; the [buffer-fallback packet](../RE-009-node115-root-buffer-fallback/README.md) identifies exact-fit and flush boundaries; [#5941](https://github.com/lalalune/hyperliquid-source/pull/5941) qualifies the fresh child's hash mode. This packet composes repeated writes to the same child, not separate children.

Assume a newly initialized child, valid 0x8000-byte buffer, repeated successful eight-byte writes, normal non-reentrant helper returns and no intervening mutation. Each inline write appends its eight source bytes at the current used offset. The first 4,095 writes take the inline `free>8` branch; write 4,096 finds exactly eight free bytes, takes fallback and fills the buffer without flushing. Write 4,097 encounters zero free bytes, updates the existing digest with the 0x8000 buffered bytes, resets used and appends its new eight bytes. Under the cited ordinary unkeyed BLAKE3 and finalizer contracts, the reference input is the ordered concatenation of all source words regardless of this buffer split.

This is a conditional same-child data-flow model, not a claim that the paired-child visitor shares a buffer, that such repeated writes occur in a real checkpoint, or that target digests or a state root have been observed. Error, reentrancy, intervening writes and captured execution are excluded.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 68 selected spans. Python authenticates target/FDEs, selected writer, fallback, copy and digest dispatch edges, and checks the buffer boundary model. The independent BLAKE3 reference vectors below use an already-installed `@noble/hashes` 1.8.0 and do not execute the target.

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

with Path("research/work-items/RE-009-node115-root-qword-multiwrite-reference/instructions.tsv").open() as handle:
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

assert len(spans)==68
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x14199fa)==0x64df4a8 and relocations[0x64df4a8][1]==0x141adb0
assert rip_target(0x141adf1)==0x64df510 and relocations[0x64df510][1]==0x160b3a0
assert rip_target(0x141aebf)==0x64df508
assert rip_target(0x141add1)==0x141aeb0
assert short(0x14199d6)==0x14199f0
assert spans[0x14199dc]==bytes.fromhex('48890c02')
capacity=0x8000;used=0;flushed=bytearray();buf=bytearray();word=bytes(range(8))
for i in range(1,4098):
 free=capacity-used
 inline=free>8
 if not inline and free<8:
  flushed.extend(buf);buf.clear();used=0
 buf.extend(word);used+=8
 if i==4095:assert inline and used==0x7ff8 and not flushed
 if i==4096:assert not inline and used==0x8000 and not flushed
 if i==4097:assert not inline and used==8 and len(flushed)==0x8000
assert bytes(flushed+buf)==word*4097
assert bytes(word+word)!=word # dropping a write is detected
for a in (0x14199fa,0x141aebf):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and repeated-write boundary model pass')
PY
```

## Independent reference values

Each reference input consists of N repetitions of the eight-byte word `0001020304050607`. These are unkeyed BLAKE3 reference digests, not node outputs:

| N | Reference digest |
| --- | --- |
| 2 | `1c2fb43b002b0ef47235862c2d8ed6f001843a895d4212d881423651676336bf` |
| 4095 | `4474a6de9e982a85655eab06ed2ef8cbd45913f3a83ab92d8212814bb13d72a9` |
| 4096 | `b07b023478987ba410e9ece1652d27d78cad34b104b01395a3172e4d8fdd616a` |
| 4097 | `1b938f3c0d4083194d7b841773a866d131bda3a4145fc67d8bd648fbfde57d50` |

With Node.js and `@noble/hashes` 1.8.0 already available in the module search path:

```sh
node - <<'JS'
const {blake3}=require('@noble/hashes/blake3');
const word=Buffer.from('0001020304050607','hex');
const cases=[[2,'1c2fb43b002b0ef47235862c2d8ed6f001843a895d4212d881423651676336bf'],[4095,'4474a6de9e982a85655eab06ed2ef8cbd45913f3a83ab92d8212814bb13d72a9'],[4096,'b07b023478987ba410e9ece1652d27d78cad34b104b01395a3172e4d8fdd616a'],[4097,'1b938f3c0d4083194d7b841773a866d131bda3a4145fc67d8bd648fbfde57d50']];
for(const [n,expected] of cases){const h=blake3.create();for(let i=0;i<n;i++)h.update(word);if(Buffer.from(h.digest()).toString('hex')!==expected)throw Error('reference mismatch');}
console.log('four reference vectors match');
JS
```

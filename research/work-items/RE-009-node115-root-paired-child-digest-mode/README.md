# RE-009 · Node #115 paired qword-child digest initialization

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [paired-captures packet](../RE-009-node115-root-paired-captures/README.md) maps two different child constructors and visits the upper qword before the lower one, but leaves the second child's digest initialization open. [#5941](https://github.com/lalalune/hyperliquid-source/pull/5941) traces the first qword constructor's IV and initial flags. This packet compares the second constructor and qualifies the resulting pair of reference inputs.

The selected normal constructor paths at `0x14196d0` and `0x141a020` have 86 paired instruction spans. Eighty-one pairs are byte-identical; the other five differ only in RIP-relative fields which resolve to identical targets. Under #5941's initialization interpretation, both children therefore begin with the same unkeyed BLAKE3 IV, zero counter/base flag and separate selector. The paired visitor calls the first constructor/writer on source +8 and, after status 4, the second constructor/writer on source +0. For the synthetic source bytes `00..0f`, one successful inline visit supplies `08..0f` to child zero and `00..07` to child one. These are two separate child buffers; concatenation or the later parent preimage is not established.

The independent BLAKE3 values below are conditional reference values, not observed #115 digests. Successful allocations, fresh children, normal writer/finalizer paths and no later mutation are assumed. No captured target code executes, and real checkpoint state or the full state root remains unknown.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 199 selected spans. Python authenticates target/FDEs, qualified constructor pairs, paired visitor slots and gating. No captured target code executes.

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

with Path("research/work-items/RE-009-node115-root-paired-child-digest-mode/instructions.tsv").open() as handle:
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

assert len(spans)==199
first=sorted(a for a in spans if 0x14196d0<=a<0x14198f8)
second=sorted(a for a in spans if 0x141a020<=a<0x141a248)
assert len(first)==len(second)==86
qualified=[]
for a,b in zip(first,second):
 assert b-a==0x950
 x,y=spans[a],spans[b]
 assert len(x)==len(y)
 if x!=y:
  assert x[:-4]==y[:-4] and rip_target(a)==rip_target(b)
  qualified.append(a)
assert qualified==[0x14196e3,0x14196f5,0x1419700,0x141970f,0x141975b]
for site,target in ((0x46f45a3,0x14196d0),(0x46f45bf,0x14199b0),(0x46f45d8,0x141a020),(0x46f45ff,0x141b3c0)):
 assert relocations[rip_target(site)][1]==target
raw=spans[0x46f45c7]
assert 0x46f45c7+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]==0x46f4605
assert spans[0x46f4590]==bytes.fromhex('4c8d7708')
assert spans[0x46f45c9]==bytes.fromhex('4c89e7')
v=bytes(range(16))
assert v[8:16].hex()=='08090a0b0c0d0e0f' and v[:8].hex()=='0001020304050607'
for a in (0x46f45a3,0x46f45d8):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and paired-child bindings pass')
PY
```

## Independent reference values

An already-installed `@noble/hashes` 1.8.0 produced these independent unkeyed BLAKE3 values; these are conditional references, not node outputs.

| Child | Input bytes | Reference digest |
| --- | --- | --- |
| 0 | `08090a0b0c0d0e0f` | `78534dd0ab885fda45e90541b73c2dd13e919598b6c18b4232ebf7696a945fa2` |
| 1 | `0001020304050607` | `2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb` |

With Node.js and `@noble/hashes` 1.8.0 already available in the module search path:

```sh
node - <<'JS'
const {blake3}=require('@noble/hashes/blake3');
const rows=[['08090a0b0c0d0e0f','78534dd0ab885fda45e90541b73c2dd13e919598b6c18b4232ebf7696a945fa2'],['0001020304050607','2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb']];
for(const [input,expected] of rows) if(Buffer.from(blake3(Buffer.from(input,'hex'))).toString('hex')!==expected) throw Error('reference mismatch');
console.log('two reference vectors match');
JS
```

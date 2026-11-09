# RE-009 · Node #115 tree root-history survivor publication

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [tree cutoff packet](../RE-009-node115-root-history-tree-cutoff/README.md) follows the selected cutoff split, and the [partition-count packet](../RE-009-node115-root-history-partition-count/README.md) follows its counts. [#5937](https://github.com/lalalune/hyperliquid-source/pull/5937) conditionally identifies the 50th-from-end cutoff. [#5936](https://github.com/lalalune/hyperliquid-source/pull/5936) examines the different flat publication. This packet follows publication when the selected suffix has 50 keys and distinguishes whether the old side crosses the conversion threshold.

For a valid ordered tree with distinct keys, accurate N>=51 and the selected 50th-from-end cutoff, assume the cited split/count contracts and normal successful allocation and helper returns. The old strict-lower side has D=N−50 keys and the new suffix has 50. The wrapper stores D in the old tree descriptor. When N>=82, D>=32 and it bypasses conversion of the old side. When 51<=N<=81, D=1..31 and the selected path collects the old side to flat form before cleanup, as described by the [tree flatten packet](../RE-009-node115-root-history-tree-flatten/README.md). In both cases the new count 50>31 bypasses conversion of the returned suffix. The returned four words contain the tree sentinel, new root, new height and new count. The caller invokes old-tree cleanup in the first case, or releases the converted old flat storage in the second, then copies the returned descriptor over the owner. Under the cited split semantics the installed tree represents the suffix of 50 keys; this packet does not independently re-prove the split or cleanup helper.

The unique-key premise deliberately selects a 50-key returned tree. Duplicate cutoff keys, abnormal conversion, error/unwind, concurrent mutation, persistence and actual runtime checkpoint or state-root behavior remain outside this claim. No captured binary executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 105 selected spans. Python authenticates target identity, FDEs, selected split/count/threshold/cleanup/publication edges, and a synthetic count model. The model assumes the cited split semantics and does not execute target bytes.

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

with Path("research/work-items/RE-009-node115-root-history-tree-survivor-publication/instructions.tsv").open() as handle:
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

assert len(spans)==105
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x4de5af0)==0x4de5b87
assert rip_target(0x4de5b22)==0x4ca3ca0
assert rip_target(0x4de5b42)==0x4ca3a30
assert rip_target(0x4de5b7c)==0x4de5c52
assert rip_target(0x4de5c56)==0x4de5da7
assert rip_target(0x4de5dab)==0x4de5f78
assert rip_target(0x4de5ce1)==0x5b74f20
assert rip_target(0x4de5d76)==0x51e06d0
assert rip_target(0x5a0464a)==0x4de5ad0
assert short(0x5a04655)==0x5a046a1
assert rip_target(0x5a0465b)==0x5248d30
assert short(0x5a04660)==0x5a046ba
assert rip_target(0x5a046b4)==0x64df4a0
assert spans[0x5a046c4]==bytes.fromhex('0f114b10')
assert spans[0x5a046c8]==bytes.fromhex('0f1103')
for n in range(51,513):
 keys=list(range(n));cutoff=keys[n-50]
 old=[x for x in keys if x<cutoff];new=[x for x in keys if x>=cutoff]
 assert len(old)==n-50 and len(new)==50
 assert (len(old)>31)==(n>=82)
 assert new==keys[-50:]
assert len(list(range(81))[:-50])==31 # conversion boundary differs
assert len([x for x in [i//3 for i in range(90)] if x>=40//3])>50
for a in (0x4de5c56,0x5a0465b):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and selected tree-count models pass')
PY
```

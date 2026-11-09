# RE-017 · Node #115 replay digest lookup and trim gate

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [override trimming packet](../RE-017-node115-replay-override-trim/README.md) begins after a tag-one helper result. [#5882](https://github.com/lalalune/hyperliquid-source/pull/5882) conditionally connects a null-first callback's 32-byte digest buffer to this helper. This packet identifies the selected lookup and gates before the existing trim loop.

At `0x57e6750`, the helper copies both 16-byte lanes of the supplied key into its stack, then calls `0x4dc8e00` with the owner `+0x20`, the stack key, and an output buffer. If the returned low dword at output `+0` equals 1, it tests output `+8`: nonzero goes to the count/limit gate; zero first checks output `+0x18` against the qword at `[output+0x10]+0x18` and reaches `0x57e6991` when the unsigned index is at least that bound. On the selected passing continuation, unsigned owner count `+0x18` is compared with limit `+0x40`: count above the limit enters the previously documented trimming loop; count at or below it returns through `0x57e6980`. A non-one tag takes a separate path not reconstructed here.

The callback-to-key connection assumes the selected null-first, nonzero-selector path and preserved buffer across prior calls. The lookup result's domain meaning and helper internals, valid pointer lifetimes, non-one result behavior and runtime reachability remain unproven; neither a particular digest nor a state root is asserted. No captured target is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 47 selected instruction spans. Python 3 checks the target SHA-256, indexed FDEs, direct transfers and a mutation control. Synthetic gate cases are illustrative inputs, not target execution.

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

with Path("research/work-items/RE-017-node115-replay-digest-lookup-gate/instructions.tsv").open() as handle:
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
assert rip_target(0x5a6383f)==0x57e6750
assert rip_target(0x5a63688)==0x5a63832
assert rip_target(0x57e6785)==0x4dc8e00
assert rip_target(0x57e678f)==0x57e6835
assert short_target(0x57e679b)==0x57e67b1
assert rip_target(0x57e67ab)==0x57e6991
assert rip_target(0x57e67b9)==0x57e6980
assert rip_target(0x57e6821)==0x4ddd0b0
for tag,pointer,index,bound,count,limit in ((1,1,0,0,5,4),(1,0,3,4,4,4),(1,0,4,4,5,4),(0,0,0,4,5,4)):
    if tag!=1: outcome='other'
    elif pointer==0 and index>=bound: outcome='boundary'
    elif count>limit: outcome='trim'
    else: outcome='return'
    if (tag,pointer,index,bound,count,limit)==(1,0,4,4,5,4): assert outcome=='boundary'
    if (tag,pointer,index,bound,count,limit)==(1,1,0,0,5,4): assert outcome=='trim'
    if (tag,pointer,index,bound,count,limit)==(1,0,3,4,4,4): assert outcome=='return'
    if tag==0: assert outcome=='other'
for address in (0x57e6785,0x57e67ab):
    changed=bytearray(spans[address]);changed[-1]^=1
    assert changed!=elf_bytes('.text',address,len(changed))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

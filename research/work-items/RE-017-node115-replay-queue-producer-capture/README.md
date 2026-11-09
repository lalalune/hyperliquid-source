# RE-017 · Node #115 replay producer capture and consumer queue identity

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [queue publication packet](../RE-017-node115-replay-queue-publish/README.md) observes an enqueue but cannot establish that its selected caller and replay reader use the same live object. The [receive-descriptor packet](../RE-012-snapshot-replay-receive-descriptor-origin-115/README.md) and [PR #5035](https://github.com/lalalune/hyperliquid-source/pull/5035) conditionally connect the replay consumer to the stream constructor's result `+0x28`. Here a different selected producer site captures the constructor's first result word.

The stream constructor writes the same object pointer R13 at result `+0` and `+0x28` (`0x2cef83c/0x2cef84f`). The caller copies result `+0` from stack `+0x140` through `+0x13a0` and `+0xa0` to stack `+0x898`, then passes stack `+0x7d0` to the relocation-resolved target `0x5a81ed0`: this places that pointer at input `+0xc8`. On its normal path `0x5a81ed0` copies `0x118` input bytes into stack `+0x10` and copies a `0x2d80`-byte image from there to a new allocation. The pointer thus occupies allocation `+0xc8`. The routine passes that allocation and table `0x64b91a8` to the resolved tail target `0x15d6ef0`. The table entry at `+0x18` resolves to FDE `0x5a82670`.

On a selected continuation of that FDE, `0x5a88989` loads the input object's `+0xc8`; after checking and updating its `+0x1c0`, `0x5a889cc/0x5a889db` pass the loaded object's `+0x80` to queue publisher `0x581b0c0`. The pair passed in this branch has a zero first qword and a second word from R15. This provides a conditional producer/consumer object-identity chain from one constructor return, unlike a layout-only match. It assumes the documented branches, normal allocation/copy/scheduling and that dispatch invokes the table target on that allocation; intervening mutation or aliasing and real runtime reachability are not proven. No statement follows about which record is first, timing, checkpoint height, or payload semantics.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 54 selected instructions, combining LLVM's separated lock prefix with its successor. Python 3.14.5 verifies SHA-256, FDEs, direct and relocation-resolved edges, table entry, selected bytes and corruption controls. The synthetic offset projection does not execute the captured binary.

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

with Path("research/work-items/RE-017-node115-replay-queue-producer-capture/instructions.tsv").open() as handle:
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

assert rip_target(0x2cc1827)==0x2cef6e0
assert rip_target(0x2cc281f)==0x64e74d8
assert relocations[0x64e74d8][1]==0x5a81ed0
assert rip_target(0x5a81fc0)==0x64df508
assert rip_target(0x5a8200f)==0x64df508
assert rip_target(0x5a82015)==0x64b91a8
assert rip_target(0x5a82036)==0x64e1758
assert relocations[0x64e1758][1]==0x15d6ef0
assert relocations[0x64b91c0][1]==0x5a82670
assert rip_target(0x5a889db)==0x581b0c0
assert 0x898-0x7d0==0xc8
assert spans[0x2cef83c]==bytes.fromhex('4d892e')
assert spans[0x2cef84f]==bytes.fromhex('4d896e28')
q=0x12345678
result=bytearray(0x48);struct.pack_into('<Q',result,0,q);struct.pack_into('<Q',result,0x28,q)
input_=bytearray(0x118);input_[0xc8:0xd0]=result[:8]
future=bytearray(0x2d80);future[:0x118]=input_
assert struct.unpack_from('<Q',future,0xc8)[0]==struct.unpack_from('<Q',result,0x28)[0]
assert struct.unpack_from('<Q',future,0xc0)[0]!=q
for addr in (0x2cef84f,0x5a889db):
    changed=bytearray(spans[addr]);changed[-1]^=1
    assert changed!=elf_bytes('.text',addr,len(changed))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

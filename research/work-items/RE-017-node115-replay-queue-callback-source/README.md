# RE-017 · Node #115 replay receive queue callback source

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The existing [receive-descriptor packet](../RE-012-snapshot-replay-receive-descriptor-origin-115/README.md) traces callback `+0x6c0` to a queue pointer Q and the probe's reader/producer descriptor addresses, but leaves Q's origin open. The [capture-writer packet](../RE-012-snapshot-replay-callback-capture-writer-115/README.md) maps the later allocation and copy for callback `+0x708`. This packet traces the separate callback `+0x6c0` data on a selected construction path.

In parent FDE `0x2cb6500`, the selected non-2 branch copies `0x7f0` bytes from the source in R15 to stack `+0x2740`, then to stack `+0x1f50`. The latter copy makes the first 16 bytes at stack `+0x2720` correspond to source R15 `+0x7d0` because `0x2720 - 0x1f50 = 0x7d0`. The selected load/store at `0x2cb80d4/0x2cb80e4` copies those bytes to parent `+0x9b0`. Later `0x2cb97ef/0x2cb9805` copies parent `+0x9b0..+0x9bf` to stack `+0xdf0`, and `0x2cb9874` copies `0x718` bytes from stack `+0x730` to the nonnull allocation. Thus stack `+0xdf0` corresponds to allocation `+0x6c0`. The following 16 bytes take the parallel path through parent `+0x9c0` and callback `+0x6d0`.

On the prior packet's selected adapter and original-input receive arm, Q is the first qword of those 32 callback bytes, and the probe uses Q `+0x1a0` and Q `+0x80`. The join is conditional on the selected construction/dispatch arms, normal returns of the copy slots, consistent object identity, and no intervening writes or aliases. It does not determine the value of Q, concrete segment/index/slot, checkpoint-height relation, or prove that the publication caller in the separate queue packet owns this same Q. Indirect helpers and concurrency are not reconstructed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 51 selected instructions. Python 3.14.5 verifies the target digest, FDE bounds, selected bytes and branch/call targets; synthetic offset and corruption controls check the two copy projections.

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

with Path("research/work-items/RE-017-node115-replay-queue-callback-source/instructions.tsv").open() as handle:
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

assert rip_target(0x2cb7cbc)==0x64df508
assert rip_target(0x2cb804e)==0x64df508
assert rip_target(0x2cb97db)==0x64df508
assert rip_target(0x2cb9874)==0x64df508
assert rip_target(0x5ab6f81)==0x581a100
assert 0x2720-0x1f50==0x7d0
assert 0xdf0-0x730==0x6c0
assert 0xe00-0x730==0x6d0
source=bytes(i&255 for i in range(0x7f0))
stack=bytearray(0x3000);stack[0x2740:0x2f30]=source;stack[0x1f50:0x2740]=stack[0x2740:0x2f30]
parent=bytearray(0x9d0);parent[0x9b0:0x9d0]=stack[0x2720:0x2740]
stack[0xdf0:0xe10]=parent[0x9b0:0x9d0]
callback=stack[0x730:0xe48]
assert callback[0x6c0:0x6e0]==source[0x7d0:0x7f0]
assert callback[0x6c0:0x6e0]!=source[0x7cf:0x7ef]
mutated=bytearray(spans[0x2cb9805]);mutated[-1]^=1
assert mutated != elf_bytes('.text',0x2cb9805,len(mutated))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

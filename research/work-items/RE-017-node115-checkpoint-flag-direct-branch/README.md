# RE-017 · Node #115 checkpoint flag direct-branch source

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [checkpoint-result packet](../RE-017-loader-checkpoint-result-115/README.md) identifies reads at parent `+0xb20/+0xb21`; [PR #5024](https://github.com/lalalune/hyperliquid-source/pull/5024) traces their selected upstream packed pair to BPL and parent `+0x72`, under nonaliasing and no-intervening-write assumptions. This packet resolves one concrete predecessor of those two inputs, rather than assuming all control-flow paths have the same origin.

At `0x2cb6bf4`, the parent reads byte `+0x6c` into EBP. At `0x2cb6bf8`, it compares byte `+0x38` with 2; equality branches directly to `0x2cb712a`. On that branch, `0x2cb712e` reads byte `+0x72` into ECX, then `0x2cb71af/0x2cb71b6` store the low bytes BPL and CL to parent `+0xc8/+0xc9`. No calls appear on this direct branch between the byte reads and stores. Thus these local packed bytes equal the bytes read from parent `+0x6c/+0x72` on the selected path.

The existing [phase-producer evidence](../RE-005-node115-phase-producer/records.json) identifies caller tag writes for both shaping arms. The first arm stores 2 at caller `+0x248`, while the second stores 1, and both copy caller `+0xe8` into caller `+0x240` before passing caller `+0x220` as parent. At the state-zero entry (see [#5027](https://github.com/lalalune/hyperliquid-source/pull/5027)), parent `+0x28` is copied to `+0x38` and parent `+0x20` to `+0x68`. Consequently, **if that initialized state reaches the later comparison without intervening writes or aliasing**, the first arm supplies compare value 2, the second supplies 1, and the `+0x6c` byte is the byte at caller `+0xec`. This is a conditional dataflow join, not proof that either arm reaches the later comparison or that helpers preserve these fields.

Under the explicit subsequent copy and helper-preservation assumptions in #5024, the pair can be joined to later `+0xb20/+0xb21` reads. This does not prove the compare-equal branch is reached by a real checkpoint, that helper calls cannot alter the source, or that the two fields denote particular domain concepts. The non-equal branch is not reconstructed here, and no completed root or replay claim follows.

## Reproduce

GNU and LLVM agree on selected instruction spans. The direct conditional target is checked against authenticated ELF bytes, and synthetic controls distinguish the two byte inputs.
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

with Path("research/work-items/RE-017-node115-checkpoint-flag-direct-branch/instructions.tsv").open() as handle:
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
assert rip_target(0x2cb6bfc) == 0x2cb712a
assert rip_target(0x2cde6f4) == rip_target(0x2cdf58b) == 0x2cb6500
for tag in (1,2):
    caller=bytearray(0x292); caller[0xe8:0xf0]=bytes(range(8)); caller[0x248]=tag
    caller[0x240:0x248]=caller[0xe8:0xf0]
    parent=bytearray(caller[0x220:]); parent[0x38:0x48]=parent[0x28:0x38]
    parent[0x68:0x70]=parent[0x20:0x28]
    assert (parent[0x38] == 2) == (tag == 2)
    assert parent[0x6c] == caller[0xec]
    assert parent[0x6c] != caller[0xeb]
for x,y in ((0,1),(2,3),(255,0)):
    parent=bytearray(0xca);parent[0x6c]=x;parent[0x72]=y
    bpl=parent[0x6c];cl=parent[0x72]
    parent[0xc8]=bpl;parent[0xc9]=cl
    assert parent[0xc8:0xca] == bytes((x,y))
    assert (x ^ 1, y) != (x,y)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

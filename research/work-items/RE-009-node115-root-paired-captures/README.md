# RE-009 · Node #115 paired-word root captures

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [block-root packet](../RE-017-abci-block-root-115/README.md) maps six captures to the same 16-byte descriptor but does not trace its visitor `0x46f4560`. Those descriptor indexes and state-relative captures are `4/+0x4cc8`, `5/+0x4cd8`, `14/+0x4ce8`, `20/+0x4cf8`, `33/+0x4d08`, and `43/+0x4d48`. This packet follows their common two-child visitor and its writer bindings. As with the earlier capture join, the relationship is conditional on the selected pointer array reaching the descriptor unchanged.

The descriptor constructor `0x46f4510` allocates two 24-byte child entries with sentinel `0x8000000000000001`. The visitor checks the destination sentinel and requires two children, returning status 1 or 3 on those respective failed checks. On the selected normal path, it initializes child zero when needed and passes source `+8` to `0x14199b0`, which writes eight raw bytes. Only on status 4 does it initialize child one as needed and pass source `+0` to `0x141b3c0`, which also writes eight raw bytes on its selected inline path. Thus the child visitation order is the upper eight bytes first, then the lower eight bytes; they enter separate child buffers, not one proven contiguous digest stream. The second writer's fallback uses the same `0x141adb0` buffer helper as the first.

No source-level pair type, real captured value, complete root tree encoding or runtime replay is asserted. The two qword visits and child allocation are bounded observations; error and unwind semantics beyond the recorded branches remain open.

## Reproduce

GNU and LLVM agree on the selected instruction spans. Descriptor, helper and fallback relocations are checked against the authenticated ELF; the six capture/descriptor pairs come from the prior packet's reproduced tables.
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

with Path("research/work-items/RE-009-node115-root-paired-captures/instructions.tsv").open() as handle:
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
assert rip_target(0x544242c) == 0x64a8200
assert relocations[0x64a8218] == (8, 0x46f4560)
assert relocations[0x64a8220] == (8, 0x46f4510)
assert relocations[rip_target(0x46f45a3)] == (8, 0x14196d0)
assert relocations[rip_target(0x46f45bf)] == (8, 0x14199b0)
assert relocations[rip_target(0x46f45d8)] == (8, 0x141a020)
assert relocations[rip_target(0x46f45ff)] == (8, 0x141b3c0)
assert relocations[rip_target(0x14199fa)] == relocations[rip_target(0x141b40a)] == (8, 0x141adb0)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

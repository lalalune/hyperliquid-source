# RE-017 · Node #115 empty replay-record age gate

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [record identity packet](../RE-017-node115-replay-record-identity/README.md) establishes the worker's earlier record comparison and successor store. This packet follows the subsequent record conversion at `0x5a6e48d`. Its relative slot `0x64e76e8` resolves to `0x4fad300`, which can decline a record that already passed the identity comparison.

The helper reads the first record pointer from the pair. With marker `0x8000000000000001` at record `+0x28`, it takes the successor basis at record `+0x60`; otherwise it takes `+0xb0`. It increments with unsigned saturation. It then reads count at second record pointer `+0x20`.

- For input count zero, it compares the saturated successor with the third argument plus 10, also saturated. If the successor is strictly below that threshold it returns first qword `0x8000000000000000`. Equality takes the ordinary-result path. The ordinary empty result contains capacity 0, pointer 8 and count 0, and preserves the successor and supplied scalar at `+0x18/+0x20`.
- For nonzero input count, the row loop runs and bypasses this empty-input gate. Its output row count can differ from the input count because the row decoder's return tag determines whether a row is appended. A zero output count after filtering does not imply that the age check was taken.
- The worker has already stored its local expected successor before calling the converter. The sentinel branches to `0x5a6e4de` instead of the selected block-call route through `0x5a6ea10`. A normal empty result can reach that block call if its intervening branches succeed.

Use the third argument as an explicit test input until its source and units have been independently joined. Useful fixture cases are below, equal, above and saturated threshold. This does not show that any real archived block is empty or old enough to take the branch.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on the selected [instruction spans](instructions.tsv).

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

with Path("research/work-items/RE-017-node115-replay-empty-record-age/instructions.tsv").open() as handle:
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
assert rip_target(0x5a6e48d) == 0x64e76e8
assert relocations[0x64e76e8] == (8, 0x4fad300)
assert rip_target(0x5a6ea10) == 0x4f122c0
assert spans[0x4fad5f5][0] == 0x73
assert 0x4fad5f5 + 2 + struct.unpack("<b", spans[0x4fad5f5][1:])[0] == 0x4fad607
limit = (1 << 64) - 1
for basis, scalar, decline in ((8, 0, True), (9, 0, False), (10, 0, False),
                               (limit - 2, limit, True), (limit, limit, False)):
    assert (min(basis + 1, limit) < min(scalar + 10, limit)) == decline
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

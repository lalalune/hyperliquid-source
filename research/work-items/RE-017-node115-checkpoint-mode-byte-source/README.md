# RE-017 · Node #115 checkpoint neighbor byte caller source

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [loader-result packet](../RE-017-loader-checkpoint-result-115/README.md) observes parent `+0xb21` before the checkpoint path. [PR #5025](https://github.com/lalalune/hyperliquid-source/pull/5025) conditionally connects this byte through the selected packing path to parent `+0x72`. This packet resolves an upstream caller-to-parent byte transfer on two selected construction arms and the initial parent state dispatch. Previous PR joins are context, not a merged dependency.

The existing [phase-producer packet](../RE-005-node115-phase-producer/records.json) already identifies the caller +0x1e8 to +0x290 transfer and its rebuild-arm source; this packet adds the selected parent state-zero dispatch and the conditional join to +0x72.

In caller FDE `0x2cde430`, one selected arm loads byte `caller + 0x1e8` into EAX at `0x2cde692`, writes its low byte to `caller + 0x290` at `0x2cde6d8`, and calls `0x2cb6500` with pointer `caller + 0x220` at `0x2cde6f4`. A second arm does the same load/store at `0x2cdf527/0x2cdf56f` and calls the same parent at `0x2cdf58b`. Both arms initialize `caller + 0x291` to zero immediately before the call. Therefore `caller + 0x290/+0x291` correspond to parent `+0x70/+0x71`.

At parent entry, byte `+0x71` indexes the signed-relative table at `0x60bb44`; entry 0 resolves to `0x2cb656e`. That selected arm copies byte `parent+0x70` to `+0x72` at `0x2cb656e/0x2cb6572`. Combining these observations gives `parent+0x72 = caller+0x1e8` on either selected construction arm and state-zero entry, assuming the cited caller object and no intervening alias writes. The later `+0x72` read at `0x2cb712e` can be joined only when the selected continuation reaches it and the byte has not changed. Neither runtime reachability nor the meaning or allowed values of the caller byte are proven; no checkpoint root or replay equivalence is claimed.

## Reproduce

GNU and LLVM agree on selected instruction spans. Both direct parent calls and the first state-table displacement are checked against the authenticated ELF; mutation controls test the selected table entry.
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

with Path("research/work-items/RE-017-node115-checkpoint-mode-byte-source/instructions.tsv").open() as handle:
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
assert rip_target(0x2cde6f4) == 0x2cb6500
assert rip_target(0x2cdf58b) == 0x2cb6500
assert rip_target(0x2cb6559) == 0x60bb44
entry=elf_bytes('.rodata',0x60bb44,4)
assert 0x60bb44 + struct.unpack('<i',entry)[0] == 0x2cb656e
changed=bytearray(entry); changed[0]^=1
assert 0x60bb44 + struct.unpack('<i',changed)[0] != 0x2cb656e
assert 0x220 + 0x70 == 0x290 and 0x220 + 0x71 == 0x291
for value in (0,1,2,255):
    assert bytes([value])[0] == value
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

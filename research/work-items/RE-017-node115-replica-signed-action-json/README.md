# RE-017 · Node #115 replica signed-action JSON field selection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4154](https://github.com/lalalune/hyperliquid-source/pull/4154) identifies the enclosing bundle tuple and object. Here the selected `signed_actions` JSON array is joined to its per-action representation. [PR #3972](https://github.com/lalalune/hyperliquid-source/pull/3972) covers MessagePack action writers. The new path emits JSON and its optional-field predicates are taken from this JSON writer.

The field serializer 0x5090810 opens an array. Zero entries bypass the element serializer. On a nonzero count it calls 0x5923350 once at the array base, then visits subsequent elements at stride 0x168, emitting a comma before each. A nonzero element result returns without going through the successful closing-bracket path.

The selected element writes `signature` from action +0x100, optional `vaultAddress` from +0x150 only when the byte there equals 1, `action` from +0x10, optional `isFrontend` from +0x165 only when that byte equals 1, and `nonce` from +0x148. If the leading qword is nonzero, the element passes its base to 0x59d7540. That adapter selects `expiresAfter` when its leading byte is zero and a separate error boundary otherwise. A field writer error short-circuits the selected success path. This records emission predicates and offsets. It does not equate field names with signed preimage encodings or assert the validity of arbitrary raw tags.

For a replay fixture, an omitted optional field should remain distinguishable from a present JSON value. The selected writer gives no rule for restoring a native action or validating its signature from the JSON alone.

## Reproduce

Selected instruction spans agree between GNU and LLVM.
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

with Path("research/work-items/RE-017-node115-replica-signed-action-json/instructions.tsv").open() as handle:
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
assert rip_target(0x53caf5b) == 0x5090810
assert rip_target(0x50908ec) == rip_target(0x5090936) == 0x5923350
assert rip_target(0x5923480) == 0x59d7540
for site, field in ((0x592338e,b"signature"), (0x59233ca,b"vaultAddress"), (0x59233f4,b"action"), (0x5923426,b"isFrontend"), (0x5923453,b"nonce"), (0x59d7548,b"expiresAfter")):
    assert elf_bytes(".rodata", rip_target(site), len(field)) == field
assert spans[0x50908fa].endswith(struct.pack("<I", 0x168))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

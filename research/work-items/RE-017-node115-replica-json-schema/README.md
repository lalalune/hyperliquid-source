# RE-017 · Node #115 replica JSON distinguishes consensus round from height

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [ABCI context result packet](../RE-017-abci-context-result-115/README.md) traces the replica line encoder and identifies the three outer field names. This packet follows the inner block's field writes and the explicit absent-response representation, providing a way to check the type of an acquired archive record before attempting native replay.

| JSON path | Selected record operand | Writer route |
| --- | --- | --- |
| `abci_block.time` | block +0x38 | 0x4d6d60c |
| `abci_block.signed_action_bundles` | block base | 0x4d6d639 |
| `abci_block.round` | block +0x18 | 0x4d6d667 |
| `abci_block.parent_round` | block +0x20 | 0x4d6d691 |
| `abci_block.hardfork` | block +0x28 | 0x4d6d6a4, through the hardfork field adapter |
| `abci_block.proposer` | block +0x44 | 0x4d6d6ba, through the proposer field adapter |
| `resps` | outer +0x58 | tag 2 writes JSON `null`; another arm calls a response value writer |
| `height` | outer +0x80 | 0x4d6d7de |

The outer first-field call passes the record base. The generic field emitter inserts the supplied field label and tail-transfers to the block serializer. The two round words use the same value writer with distinct member addresses. This supports the [preflight packet's](../RE-017-abci-preflight-result-115/README.md) field names and provides an independent interpretation of archived parent and current round values. An archive reader should retain all three scalars independently. The selected tag-2 response arm emits a present key with a null value, so null alone does not identify an empty signed-action list.

The selected file encoder appends one newline after the object. A raw exporter record matching this shape is a better provenance check than the public explorer's block-level `txs` envelope. The structural check supplies no schema mapping from those exported bundles to the native queue bytes, no state-root field in this record, and no proof of a captured artifact or replay.

## Reproduce

GNU and LLVM agree on the selected [instruction spans](instructions.tsv).
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

with Path("research/work-items/RE-017-node115-replica-json-schema/instructions.tsv").open() as handle:
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
assert rip_target(0x595ab43) == 0x50e2f80
assert rip_target(0x50e2fce) == 0x4d6d740
assert rip_target(0x4d6d78b) == 0x50818f0
assert rip_target(0x50819aa) == 0x4d6d5c0
assert rip_target(0x4d6d667) == rip_target(0x4d6d691) == 0x50783d0
for site, field in (
    (0x4d6d777, b"abci_block"), (0x4d6d7a4, b"resps"), (0x4d6d7ca, b"height"),
    (0x4d6d5fb, b"time"), (0x4d6d625, b"signed_action_bundles"), (0x4d6d656, b"round"),
    (0x4d6d680, b"parent_round"), (0x4e0b078, b"hardfork"), (0x4e0a658, b"proposer"),
):
    assert elf_bytes(".rodata", rip_target(site), len(field)) == field
assert spans[0x506e2f6].endswith(b"null")
assert spans[0x50e307b].endswith(b"\n")
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

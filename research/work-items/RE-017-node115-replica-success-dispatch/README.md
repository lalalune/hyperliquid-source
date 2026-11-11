# RE-017 · Node #115 replica structured success response dispatch

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4162](https://github.com/lalalune/hyperliquid-source/pull/4162) identifies the outer per-action result status and separate error path. This packet recovers the structured success response types selected within the native replica archive.

The writer reads one byte from the result, indexes a relative 32-bit table and jumps to the table base plus the selected signed displacement. The predecessor handles byte 15 as the string error. The following rows cover the 0–14 table domain. Each listed type label comes from a relocated pointer and explicit length in its descriptor.

| Tag | Target | Type label | Selected data writer |
| ---: | --- | --- | --- |
| 0 | `0x4d8e0bf` | `order` | `0x5086350` |
| 1 | `0x4d8e51d` | `cancel` | `0x5088bf0` |
| 2 | `0x4d8e3a5` | `createVault` | `0x506d150` |
| 3 | `0x4d8e422` | `liquidation` | `0x507bf10` |
| 4 | `0x4d8e22b` | `twapOrder` | `0x509e1f0` |
| 5 | `0x4d8e59b` | `twapCancel` | `0x5098c90` |
| 6 | `0x4d8e697` | `trailingStop` | `0x5072ad0` |
| 7 | `0x4d8e4a0` | `createSubAccount` | `0x506d150` |
| 8 | `0x4d8e78f` | `token` | `0x5079ee0` |
| 9 | `0x4d8e327` | `spot` | `0x5079ee0` |
| 10 | `0x4d8e715` | `validatorVote` | `0x5079cc0` |
| 11 | `0x4d8e1ae` | `governanceProposal` | `0x5073b20` |
| 12 | `0x4d8e2a9` | `setGlobal` | `0x5073790` |
| 13 | `0x4d8e619` | `delayed` | `0x5084940` |
| 14 | `0x4d8e13d` | `default` | No data call |

The default arm returns through the object close without calling a data writer. Sharing a data writer does not collapse the type labels, as seen for createVault/createSubAccount and token/spot. The result envelope can preserve these distinctions as replay outcome metadata. The packet does not establish the internals of the data writers or the behavior of out-of-domain tags.

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

with Path("research/work-items/RE-017-node115-replica-success-dispatch/instructions.tsv").open() as handle:
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
rows = (
    (0x4d8e0bf, 0x4d8e0f1, b"order", 0x4d8e133, 0x5086350),
    (0x4d8e51d, 0x4d8e54f, b"cancel", 0x4d8e591, 0x5088bf0),
    (0x4d8e3a5, 0x4d8e3d7, b"createVault", 0x4d8e418, 0x506d150),
    (0x4d8e422, 0x4d8e454, b"liquidation", 0x4d8e496, 0x507bf10),
    (0x4d8e22b, 0x4d8e25d, b"twapOrder", 0x4d8e29f, 0x509e1f0),
    (0x4d8e59b, 0x4d8e5cd, b"twapCancel", 0x4d8e60f, 0x5098c90),
    (0x4d8e697, 0x4d8e6c9, b"trailingStop", 0x4d8e70b, 0x5072ad0),
    (0x4d8e4a0, 0x4d8e4d2, b"createSubAccount", 0x4d8e513, 0x506d150),
    (0x4d8e78f, 0x4d8e7c1, b"token", 0x4d8e7fb, 0x5079ee0),
    (0x4d8e327, 0x4d8e359, b"spot", 0x4d8e39b, 0x5079ee0),
    (0x4d8e715, 0x4d8e747, b"validatorVote", 0x4d8e788, 0x5079cc0),
    (0x4d8e1ae, 0x4d8e1e0, b"governanceProposal", 0x4d8e221, 0x5073b20),
    (0x4d8e2a9, 0x4d8e2db, b"setGlobal", 0x4d8e31d, 0x5073790),
    (0x4d8e619, 0x4d8e64b, b"delayed", 0x4d8e68d, 0x5084940),
    (0x4d8e13d, 0x4d8e16f, b"default", 0x0, 0x0),
)
base = rip_target(0x4d8e0af)
for index, (entry, descriptor_site, name, call, target) in enumerate(rows):
    assert base + struct.unpack("<i", elf_bytes(".rodata", base + index * 4, 4))[0] == entry
    label_slot = rip_target(descriptor_site) + 16
    assert struct.unpack("<Q", elf_bytes(".data.rel.ro", label_slot + 8, 8))[0] == len(name)
    assert elf_bytes(".rodata", relocations[label_slot][1], len(name)) == name
    if call:
        assert rip_target(call) == target
assert rip_target(0x50869ea) == 0x4d8e0a0
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

# RE-017 · Node #115 exchange ABCI hash tree JSON representation

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[#4118](https://github.com/lalalune/hyperliquid-source/pull/4118) identifies the two JSON writers for `exchange_abci_hash` and leaves their tag-1 payload open. The [ABCI root tree packet](../RE-017-abci-root-tree-115/README.md) recovers a MessagePack representation with ordered pairs and a 0x30 stride. This packet closes the separate JSON shape at `0x2579da0` and `0x5025a10` so an offline checker can identify the tree-valued alternative in a digest line.

Both tag-1 field writers pass the input advanced by 8. The callee reads a row pointer at its input `+0x08` and count at `+0x10`, then writes an opening bracket. Zero count closes that bracket. For nonzero count it writes each row as an inner array. The first element comes from the row's base qword, passed to its integer formatter. A comma precedes the second element. If row byte `+0x08` equals 1, the writer recursively passes row `+0x10`; otherwise it passes row `+0x09` and width 32 to its hex-string formatter. It closes the pair and uses comma separation for following rows. The repeated loop advances by 0x30 in both copies and preserves the stored row order. Nonzero recursive or leaf-writer results bypass the selected successful closure.

For example, the selected shape for two synthetic rows is `[[3,"0x…"],[8,[]]]` when row 3 is a leaf and row 8 is an empty nested branch. This describes the observed output shape, not an observed digest line. A tag-1 field can therefore contain ordered nested pairs while the other local tag branch emits a single digest string. Preserve the pair order and recursive structure when building a reference input. This is not a proof that the tree came from a particular checkpoint, or that re-encoding an arbitrary JSON tree will reproduce an accepted root.

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

with Path("research/work-items/RE-017-node115-exchange-abci-hash-tree-json/instructions.tsv").open() as handle:
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
for address, target in ((0x25b0c79, 0x2579da0), (0x506d5a9, 0x5025a10),
                        (0x2579e02, 0x25fba40), (0x5025a72, 0x50fc010),
                        (0x2579e6d, 0x2579da0), (0x5025c81, 0x5025a10),
                        (0x2579ed2, 0x26310e0), (0x5025b42, 0x4e1c250)):
    assert spans[address][0] in (0xe8, 0xe9)
    assert rip_target(address) == target
for address in (0x257a086, 0x257a08a, 0x5025cf6, 0x5025cfa):
    assert spans[address][-1] == 0x30
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

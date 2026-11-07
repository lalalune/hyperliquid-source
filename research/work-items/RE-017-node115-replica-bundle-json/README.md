# RE-017 · Node #115 replica JSON bundle entries preserve a tuple

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4153](https://github.com/lalalune/hyperliquid-source/pull/4153) identifies `abci_block.signed_action_bundles` and its position in the replica line. [PR #4136](https://github.com/lalalune/hyperliquid-source/pull/4136) identifies the native replay bundle's signed byte interval and 65-byte tail. The new scope here is the different nested JSON representation an archive reader must preserve.

The selected field writer at 0x5075db0 starts the outer array and skips the tuple writer when its entry count is zero. For each present entry it opens another array and calls a string formatter with source at the 40-byte entry's base, length 32, and output capacity 66. The adapter clears R8 before calling 0x2eabb50, which writes the literal prefix `0x` and the selected nibble table's characters. This mode preserves both digits of each input byte, including leading zeroes. It supplies 66 text bytes before JSON quotes. The trace identifies a fixed-size byte field and its representation. It does not identify the producer or prove this value is the block hash, the signer's address, or a signed preimage.

The second element dereferences entry +0x20 and advances by 0x10 before entering the object writer. That writer emits `signed_actions`, `broadcaster`, and `broadcaster_nonce`, using object offsets 0, 0x20 and 0x18 respectively. It exits on a field writer's error. The multi-entry loop applies the same two writers, advances by 0x28 and preserves entry order. Thus a fixture must distinguish an empty outer array from a one-element array of two-element tuples and preserve the nonce as a separate field.

The JSON object does not by itself supply the original native framing or signed preimage. No real bundle was decoded or replayed by this packet.

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

with Path("research/work-items/RE-017-node115-replica-bundle-json/instructions.tsv").open() as handle:
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
assert rip_target(0x4d6d639) == 0x5075db0
assert rip_target(0x5075ed1) == rip_target(0x5075ff6) == 0x4e1c250
assert rip_target(0x5075f05) == rip_target(0x5076032) == 0x53caf10
assert relocations[rip_target(0x4e1c260)] == (8, 0x2eabb50)
assert spans[0x2eabb62].endswith(b"0x")
assert elf_bytes(".rodata", rip_target(0x2eabb89), 16) == b"0123456789abcdef"
for site, field in ((0x53caf47, b"signed_actions"), (0x53caf74, b"broadcaster"), (0x53caf9a, b"broadcaster_nonce")):
    assert elf_bytes(".rodata", rip_target(site), len(field)) == field
assert len(b"0x" + bytes(32).hex().encode()) == 66
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

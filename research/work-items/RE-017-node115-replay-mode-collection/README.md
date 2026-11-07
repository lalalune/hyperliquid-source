# RE-017 · Node #115 callback mode selects iterator rows

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4171](https://github.com/lalalune/hyperliquid-source/pull/4171) identifies the callback mode and its later membership filter. Here the collector at `0x5b74af0` also uses that mode earlier: the callback passes a descriptor at stack `+0x2f0` with the address of the mode byte at stack `+0x338`, making the pointer descriptor offset `+0x48`. The collector repeatedly calls `0x4e1a100` and compares the byte at the returned second pointer `+0xa4` to the byte addressed by descriptor `+0x48`. Unequal rows are skipped, while equal rows become a pair of returned pointers in a 16-byte vector. The first match allocates capacity four; subsequent matches append, growing as needed. No matches return the empty triple `(0, 8, 0)`.

In the iterator's selected direct-segment arm each row advances by `0xb0`, and the second returned pointer is row base `+8`: the compared byte is therefore row base `+0xac` for that arm. Other iterator arms remain outside this packet. The collector appends matching pairs in encounter order, but the callback subsequently passes the vector through `0x4e36fb0`, which calls another helper; no ordering claim is made about its eventual consumer. The mode is a literal byte comparison, not proof of a particular runtime row or checkpoint state. No live replay or real checkpoint is established here.

## Reproduce

GNU and LLVM agree on the selected instruction spans.
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

with Path("research/work-items/RE-017-node115-replay-mode-collection/instructions.tsv").open() as handle:
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
assert rip_target(0x5a6e42d) == rip_target(0x5a6e43d) == 0x5a63100
assert rip_target(0x5a635a7) == 0x5b74af0
assert rip_target(0x5a635bc) == 0x4e36fb0
assert rip_target(0x5b74b13) == rip_target(0x5b74bb3) == 0x4e1a100
assert rip_target(0x4e36ff6) == 0x5a8a610
assert 0x338 - 0x2f0 == 0x48
assert 8 + 0xa4 == 0xac
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

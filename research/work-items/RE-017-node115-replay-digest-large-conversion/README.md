# RE-017 · Node #115 replay digest lookup large-container conversion

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5895](https://github.com/lalalune/hyperliquid-source/pull/5895) traces the lookup helper's sentinel and `count < 32` conversion. This packet examines its separate non-sentinel, nonzero-search-result and `count > 63` route before the tree path described in [#5886](https://github.com/lalalune/hyperliquid-source/pull/5886).

After the descriptor is found non-sentinel, `0x4dc8f41` calls the 32-byte lookup. A zero RAX or unsigned descriptor count at most 63 bypasses this conversion. Otherwise the helper copies 32 descriptor bytes to stack `+0x30`, writes descriptor fields `+0 = 0`, `+8 = 1` and `+0x10..+0x1f = 0`, then calls `0x5155d20` with output stack `+0x18` and the snapshot. On the selected continuation where descriptor `+0` remains zero, it skips the conditional cleanup call. It writes the sentinel `0x8000000000000000` to descriptor `+0`, copies the helper's first two output qwords to `+8/+0x10` and its third qword to `+0x18`, and falls through to the existing tree path.

This establishes gates, write order and a selected field projection, not the internal behavior of `0x5155d20`, general ownership, exception cleanup or actual data migration. The unchanged-zero continuation requires normal returns and no intervening descriptor mutation or aliases; the alternate post-helper paths are not reconstructed. No claim is made about real replay reaching the threshold or about a state root. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 49 selected instruction spans. Python 3 verifies the target digest, FDE, selected transfers and corrupted instruction controls; synthetic gates test the 63/64 boundary.

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

with Path("research/work-items/RE-017-node115-replay-digest-large-conversion/instructions.tsv").open() as handle:
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

def short_target(address):
    raw=spans[address];return address+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x4dc8f33)==0x4dc909b
assert rip_target(0x4dc8f41)==0x57fae00
assert rip_target(0x4dc8f49)==0x4dc8fe0
assert rip_target(0x4dc8f54)==0x4dc8fe0
assert rip_target(0x4dc8f92)==0x5155d20
assert short_target(0x4dc8f9d)==0x4dc901c
assert short_target(0x4dc901f)==0x4dc9086
for result,count,convert in ((0,64,False),(1,63,False),(1,64,True),(1,65,True)):
    assert (result!=0 and count>63)==convert
for addr in (0x4dc8f4f,0x4dc8f92):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

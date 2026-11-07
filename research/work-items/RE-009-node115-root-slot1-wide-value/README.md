# RE-009 · Node #115 root wide-row projected visitors

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4200](https://github.com/lalalune/hyperliquid-source/pull/4200) traces two projections from each selected `0xa0`-byte row of root slot 1's wrapped inner child. This packet follows both projected descriptors into their next visitor boundaries. The source and descriptor joins remain conditional on the selected static path.

For the first projected source at row `+0x88`, descriptor visitor `0x41f8050` tail-jumps through a relocation to `0x141b9b0`. The selected inline path loads 16 bytes at source `+0` and four more at `+0x10`, stores those exact 20 bytes into the child buffer, advances used length by 20 and returns status 4. A non-sentinel destination returns 0, and free space of at most 20 takes fallback `0x141adb0`. Thus, on this bounded path the source byte interval is row `+0x88..+0x9b`; no interpretation of the 20 bytes is required. Its constructor tail-jumps to `0x141a020`.

For the other projection at row `+0`, descriptor visitor `0x43cb030` builds two one-entry descriptor lists for source offsets `+0` and `+0x38`, then calls the two-child dispatcher `0x41ae280`. Their visitor/constructor bindings are `0x46a3c30/0x46a1010` and `0x46a5db0/0x46a0fb0`. The two projected row sides feed separate child structures; this packet does not infer a flat row preimage, domain types or actual runtime values. Complete nested behavior, state root and checkpoint replay remain open.

## Reproduce

GNU and LLVM agree on the selected instruction spans; relocation slots, descriptor methods and direct calls are checked against the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-slot1-wide-value/instructions.tsv").open() as handle:
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
assert rip_target(0x46a168a) == 0x648f6f8
assert rip_target(0x46a1691) == 0x64930e8
assert relocations[0x648f710] == (8, 0x41f8050)
assert relocations[0x648f718] == (8, 0x43025f0)
assert relocations[0x6493100] == (8, 0x43cb030)
assert relocations[0x6493108] == (8, 0x43cafe0)
assert relocations[rip_target(0x41f8050)] == (8, 0x141b9b0)
assert relocations[rip_target(0x43025f0)] == (8, 0x141a020)
assert relocations[rip_target(0x141ba0e)] == (8, 0x141adb0)
assert rip_target(0x43cb03c) == 0x6487d30
assert rip_target(0x43cb051) == 0x6487d58
assert relocations[0x6487d48] == (8, 0x46a3c30)
assert relocations[0x6487d50] == (8, 0x46a1010)
assert relocations[0x6487d70] == (8, 0x46a5db0)
assert relocations[0x6487d78] == (8, 0x46a0fb0)
assert rip_target(0x43cb08b) == 0x41ae280
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

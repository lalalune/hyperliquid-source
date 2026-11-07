# RE-009 · Node #115 root packed-12-byte captures

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [block-root packet](../RE-017-abci-block-root-115/README.md) maps descriptor indexes 15 and 16 to state-relative captures `+0x4df8` and `+0x4e04`, using the same 12-byte descriptor. This packet resolves its tail-call visitor and the selected output representation. The capture-to-descriptor relationship is conditional on the recorded pointer array remaining unchanged.

Descriptor visitor `0x3d5e950` jumps through relocation slot `0x64df5a0` to `0x141b1e0`. The latter first checks for child sentinel `0x8000000000000000`; another destination returns status 0. It reads the first eight input bytes as a qword and the following four bytes at `+8` as a dword. It does not copy that qword directly: it takes the upper 32 bits, combines bit fields and signed arithmetic derived from the lower 32 bits, multiplies an intermediate by `0x15180`, and adds the upper word. On the selected inline path it appends the resulting eight-byte word followed by the original four-byte dword, in x86 little-endian memory order, then returns status 4. The two buffer writes have independent capacity tests and may individually enter fallback `0x141adb0`; a failure after the first write is not assumed to roll it back.

Constructor `0x3d5e820` installs a fresh digest/buffer owner and publishes the same sentinel. A successful first inline visit with no intervening mutation therefore supplies the derived 12 bytes to the selected reducer finalization described in [PR #4186](https://github.com/lalalune/hyperliquid-source/pull/4186). These observations do not prove the source-level type, all valid packed values, a complete arithmetic specification for invalid inputs, or an observed real root. No checkpoint or block was executed.

## Reproduce

GNU and LLVM agree on the selected instruction spans. Descriptor, tail-call and fallback relocations are checked directly from the authenticated target; capture joins are bounded by the prior packet's tables.
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

with Path("research/work-items/RE-009-node115-root-packed12-captures/instructions.tsv").open() as handle:
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
assert rip_target(0x5442559) == 0x64a8368
assert relocations[0x64a8380] == (8, 0x3d5e950)
assert relocations[0x64a8388] == (8, 0x3d5e820)
assert relocations[rip_target(0x3d5e950)] == (8, 0x141b1e0)
assert rip_target(0x3d5e8e5) == 0x141ad30
assert relocations[rip_target(0x141b2db)] == (8, 0x141adb0)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

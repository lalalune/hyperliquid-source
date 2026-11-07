# RE-017 · Node #115 startup replay discovery uses byte-ordered names

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [startup sampling packet](../RE-012-node115-startup-end-height-window/README.md) proves a five-entry reverse structural budget but leaves input order open. The [entry checkpoint packet](../RE-017-entry-checkpoint-115/README.md) and [prune-path packet](../RE-017-abci-prune-path-115/README.md) analyze related helpers on a different caller. Here the startup locator and the per-file search both resolve to the same directory adapter. The selected small-input path gives a concrete naming constraint for constructing a replay fixture.

1. Startup call 0x595b21f passes the rendered replica path and Location data naming `node/src/startup.rs`; the per-file call at 0x595b553 resolves to the same adapter. The adapter calls 0x5c9ca30, whose short-path arm checks C-string termination and calls the `opendir` import. A failed open on that arm packs errno and sets tag 2. The adapter converts that tag to output discriminant 1 before either collector. A missing directory therefore differs from a successful open with no eligible rows.
2. On a selected successful open, the adapter invokes a 32-byte entry pipeline and then a 24-byte pipeline. The 32-byte collector's shared metadata helper writes its directory-mode test into byte +0x18 on the selected metadata-success branch. The 24-byte collector drops unflagged rows and forwards the three-word name record from each selected flagged row. This is evidence of directory eligibility on the selected path. It does not assert symlink handling or all metadata-failure cases.
3. For 2–20 eligible 24-byte names, 0x14c6d40 compares the common prefix through `memcmp`, uses the length difference when the prefix compares equal, and moves a row left only on a negative comparison. The builder 0x1539de0 hands the resulting range to 0x149bab0. The selected leaf insertion appends and advances its entry count. For a small single-leaf case, this ties the reverse structural scan to reverse byte order. The 32-byte feeder has a separate flag tie-break. The at-least-21 route goes through a different sort entry and is outside the ordering claim here.

A bounded fixture with three eligible directory names `1`, `2`, and `10` enters the small-path name order `1`, `10`, `2`, and the reverse cursor visits `2`, `10`, `1`. Fixed-width YYYYMMDD labels preserve calendar ordering under this comparator. Arbitrary decimal names can differ from numerical order. The previously established final maximum among successful sampled file results still applies.

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

with Path("research/work-items/RE-017-node115-replica-discovery-order/instructions.tsv").open() as handle:
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
assert rip_target(0x595b21f) == rip_target(0x595b553) == 0x64e0968
assert relocations[0x64e0968] == (8, 0x1501290)
assert relocations[rip_target(0x15012a5)] == (8, 0x5c9ca30)
assert rip_target(0x5c9cb83) == 0x64ec5f8
assert relocations[0x64ec5f8] == (0x7c00000006, 0)
assert rip_target(0x14c6dcf) == 0x64dfb50
assert relocations[0x64dfb50] == (0xc00000006, 0)
assert rip_target(0x15b599d) == 0x14c6d40
assert rip_target(0x1539e66) == 0x149bab0
assert elf_bytes(".rodata", relocations[rip_target(0x595b210)][1], 19) == b"node/src/startup.rs"
assert list(reversed(sorted((b"1", b"2", b"10")))) == [b"2", b"10", b"1"]
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

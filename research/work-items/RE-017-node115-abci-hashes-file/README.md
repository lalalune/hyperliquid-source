# RE-017 · Node #115 routes a selected raw ABCI digest to the hourly hash sink

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4117](https://github.com/lalalune/hyperliquid-source/pull/4117) identifies two named writer descriptors and their owner offsets. [PR #4124](https://github.com/lalalune/hyperliquid-source/pull/4124) follows the selected digest to its JSON line. The new join here identifies the name of the selected sink, connects its initial and rotated paths, and explains why the path's date is a separate provenance field from the record's height.

The slow-engine constructor sends the `abci_hashes` descriptor through staging offset +0x330. The context repacker copies input bytes 0..0x41f on the non-2 route and passes a copy of that prefix to selector 0x5a07ec0. The selector keeps its argument in R14, computes R14+0x330, and passes that address to the digest bridge. The bridge saves the pointer and reloads it as the first argument to 0x4e3a7a0. This selects the constructor's `abci_hashes` descriptor on the traced route. The separate `abci_digest_quorum` descriptor lives at +0x280 and is not the argument to this call.

The name builder at 0x1546700 combines the configured base, the `/data/` literal and the supplied name. On the selected normal uncached path the next helper copies that composed path into its returned name triple. The hourly initializer at 0x1546000 uses the name at +0x8/+0x10, reads the current date word, derives a separate hour byte and renders `<base>/data/abci_hashes/hourly/<YYYYMMDD>/<decimal hour>`. The date callback's six-byte format is `%Y%m%d`. The hour callback's digit-table path uses unsigned decimal and produces a single digit for an hour under ten on the selected format path.

At write time the digest bridge supplies a fresh wall-clock tuple and separately copies state +0x28 into the JSON record. The path selector at 0x1546570 takes the date from the tuple. With hourly mode set it returns the path-reuse sentinel only if date and hour both match the stored words. Otherwise the same hourly format is rendered and its result reaches the writer. The day-only arm uses a different template. A fixture should use the JSON record height for matching and preserve the actual capture path, since the filename's time fields come from the clock tuple. Neither the named writer nor a nonempty file proves a separately computed quorum root, successful flush, or a specific remote archive.

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

with Path("research/work-items/RE-017-node115-abci-hashes-file/instructions.tsv").open() as handle:
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
assert elf_bytes(".rodata", rip_target(0x5a6c448), 11) == b"abci_hashes"
assert relocations[rip_target(0x5a08fbc)] == (8, 0x38c6590)
assert rip_target(0x5a0901f) == 0x5a07ec0
assert rip_target(0x5a07fce) == 0x548dad0
assert rip_target(0x548dbf9) == 0x4e3a7a0
assert relocations[rip_target(0x4e3a7e0)] == (8, 0x1546570)
assert elf_bytes(".rodata", rip_target(0x1546799), 10) == bytes.fromhex("c0 06 2f 64 61 74 61 2f c0 00")
hourly_template = bytes.fromhex("c0 08 2f 68 6f 75 72 6c 79 2f c0 01 2f c0 00")
assert all(elf_bytes(".rodata", rip_target(site), len(hourly_template)) == hourly_template for site in (0x1546110, 0x1546606))
assert elf_bytes(".rodata", rip_target(0x150ceb2), 6) == b"%Y%m%d"
assert elf_bytes(".rodata", rip_target(0x150cfa0), 20) == b"00010203040506070809"
assert relocations[rip_target(0x1546101)] == (8, 0x150cf50)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

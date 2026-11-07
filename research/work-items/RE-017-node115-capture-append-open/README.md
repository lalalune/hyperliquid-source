# RE-017 · Node #115 capture writer opens files for append

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

[PR #4155](https://github.com/lalalune/hyperliquid-source/pull/4155) recovers the hourly ABCI digest path. This packet maps the first open of that capture path and the initialized buffer. It provides a restart-fixture constraint: a reused path can retain prior lines.

The digest's optional flush invokes the same lazy writer initializer used by the replica buffered-output helper. A non-sentinel existing writer returns its member address without opening again on this path. On a sentinel the initializer stages options with bytes +8/+9 zero, byte +0xa one, +0xb zero, +0xc one and +0xd zero. It copies the stored name slice into the path adapter. The selected short-name branch appends a NUL, checks conversion, and calls 0x5c97060.

That helper selects base flags 0x401, adds 0x40 for create, and adds 0x80000. The caller provides no extra flags and supplies mode 0666, before the process umask. The resulting 0x80441 is write-only, append, create and close-on-exec for the bound Linux x86-64 `open64` import. On errno 4 the helper retries with the same flags and mode. Success passes the fd to the writer initializer, which allocates a 0x4000-byte buffer, starts its used length at zero, and stores the fd separately. A path or open error takes a distinct result path.

A zero used length describes the new buffer and does not say that the opened file is empty. The selected open path establishes neither successful application-level writes nor persistence across crashes.

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

with Path("research/work-items/RE-017-node115-capture-append-open/instructions.tsv").open() as handle:
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
assert rip_target(0x4e3a916) == rip_target(0x14c3807) == 0x14c3950
assert rip_target(0x14c39f5) == 0x15b6b70
assert rip_target(0x15b6bfc) == 0x5c97060
assert relocations[rip_target(0x5c97140)] == (0xb400000006, 0)
assert int.from_bytes(spans[0x14c3976][-8:], "little") >> 32 == 0o666
assert (0x401 | 0x40 | 0x80000) == 0x80441
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

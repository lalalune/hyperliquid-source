# RE-017 · Node #115 checkpoint flag packed-source chain

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [loader checkpoint result packet](../RE-017-loader-checkpoint-result-115/README.md) reads two parent bytes at `+0xb20/+0xb21`. [PR #5009](https://github.com/lalalune/hyperliquid-source/pull/5009) identifies a later 16-byte overwrite sourced from parent `+0x148`; this packet follows one earlier selected packing path that constructs that source. The join is conditional on the listed path and ordinary nonaliasing/no-intervening-write assumptions; the prior packet is context, not a merged dependency.

At `0x2cb712e`, byte `parent+0x72` is zero-extended into ECX. At `0x2cb715f`, R13 is set to `parent+0x90`. The code stores BPL into `parent+0xc8` at `0x2cb71af` and CL into `parent+0xc9` at `0x2cb71b6`. The low byte BPL is an input to this selected local path; this packet does not infer its upstream producer. With R13 unchanged, `0x2cb71e0` loads 16 bytes from `r13+0x30`, corresponding to parent `+0xc0..+0xcf`, and `0x2cb71e5` writes them to `parent+0x108..+0x117`. Consequently the two packed bytes land at `parent+0x110/+0x111`.

The next selected 64-byte copy reads `parent+0xd8..+0x117` and writes `parent+0x118..+0x157`. Its last 16-byte load/store at `0x2cb7238/0x2cb7255` carry the two bytes to `parent+0x150/+0x151`. On the later selected continuation, the source pair is copied by `0x2cb74cf/0x2cb7553` to the subobject and reaches reads `+0xb20/+0xb21`. Thus, if the intermediate helper calls preserve these parent bytes and the saved stack copy, the read pair equals the BPL value staged at `0x2cb71af` and the byte read from `parent+0x72` at `0x2cb712e`. The second byte is also tested before the checkpoint continuation. The two bytes are not identified as height, round, or protocol flags; values and reachability on a real checkpoint remain open.

## Reproduce

GNU and LLVM agree on the selected instruction spans. The source and destination offsets, exact-copy arithmetic and mutation controls are validated below against the authenticated ELF; no target execution is performed.
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

with Path("research/work-items/RE-017-node115-checkpoint-flag-packing/instructions.tsv").open() as handle:
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
assert 0x90 + 0x38 == 0xc8 and 0x90 + 0x39 == 0xc9
assert 0x108 + 8 == 0x110 and 0x108 + 9 == 0x111
assert 0x118 + (0x110 - 0xd8) == 0x150
assert 0x118 + (0x111 - 0xd8) == 0x151
assert 0xae8 + 0x30 + 8 == 0xb20 and 0xae8 + 0x30 + 9 == 0xb21
for a,b in ((0,0),(1,2),(0xff,0x80)):
    source=bytearray(16); source[8:10]=bytes((a,b))
    copied=bytes(source)
    assert copied[8:10] == bytes((a,b))
    source[8] ^= 1
    assert bytes(source)[8:10] != copied[8:10]
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

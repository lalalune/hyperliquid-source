# RE-017 · Node #115 local restore canonical height paths

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [restore intermediate](../RE-017-restore-checkpoint-intermediate-115/README.md) proves reversal relative to an unknown provider order. The [prune path packet](../RE-017-abci-prune-path-115/README.md) analyses the shared numeric collector and sort in the pruning context, and leaves the rendered text unknown. This packet joins the restore call site to that provider and resolves the numeric callback that reconstructs the directory name.

- The restore call at `0x25d410d` passes the formatted checkpoint base and zero R8 to the slot resolving to `0x15623e0`. The provider uses that zero to select an empty suffix and adds the slash prefix via the format record at `0x449b0f`.
- Its collector carries the accepted numeric value in RDX and stores that word in an eight-byte vector. The input name pointer is absent from the vector. For counts 2 through 20 the selected insertion loop orders the words by unsigned value. The provider calls the formatter loop with that order. At 21 or more it instead calls the separately studied large-sort boundary.
- The formatter at `0x1532490` reads one word per iteration. It resolves its numeric callback through slot `0x64e0a98` to `0x1689420`, which emits decimal digit pairs using the table at `0x46ea12`, emits one zero for zero, and passes only the written suffix of its scratch array to the formatting sink. With the default formatting context, the selected records therefore use a rendered decimal component, with no original leading plus or zero padding. For example, a source component `+00042` accepted by the numeric parser supplies the same numeric argument as `42`. This does not assert that duplicate numbers are impossible.
- Restore reverses the returned 24-byte records in place. For the verified small-sort branch it consequently visits descending numeric paths when testing completion markers, before the separate exact-key scan. A restore fixture should use the rendered numeric directory name even if testing an original enumeration entry with alternate spelling.

The claim assumes the observed callbacks and selected normal returns. It does not imply selection of a nearby height, successful filesystem reads, or full large-sort closure.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on the [instruction spans](instructions.tsv).

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

with Path("research/work-items/RE-017-node115-restore-canonical-heights/instructions.tsv").open() as handle:
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
for address, target in ((0x25d410d, 0x64e1208), (0x15624fc, 0x1532810),
                        (0x156254d, 0x15331c0), (0x1533256, 0x1532490),
                        (0x1532503, 0x64e0a98), (0x1689431, 0x46ea12)):
    assert rip_target(address) == target
assert relocations[0x64e1208] == (8, 0x15623e0)
assert relocations[0x64e0a98] == (8, 0x1689420)
assert elf_bytes(".rodata", rip_target(0x1562440), 4) == b"\xc0\x01/\x00"
assert elf_bytes(".rodata", rip_target(0x1532525), 4) == b"\xc0\xc0\xc0\x00"
assert elf_bytes(".rodata", 0x46ea12, 200) == b"".join(f"{i:02}".encode() for i in range(100))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

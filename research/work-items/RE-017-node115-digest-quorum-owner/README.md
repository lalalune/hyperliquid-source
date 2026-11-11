# RE-017 · Node #115 ABCI digest quorum owner handoff

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Scope: named descriptor construction through the selected normal owner publication. The existing ABCI greeting packet follows the loaded state pointer. This packet follows two separately constructed descriptors.

| Descriptor | Name reference | Constructor staging | Body offset | Returned allocation offset |
| --- | --- | --- | --- | --- |
| `abci_digest_quorum` | `0x5a6c418` | `+0x280` | `+0x930` | `+0x940` |
| `abci_hashes` | `0x5a6c448` | `+0x330` | `+0x9e0` | `+0x9f0` |

1. At the two name references the constructor supplies lengths 18 and 11. Each name reaches slots `0x64e0f98` and `0x64e0fa0`, which resolve to `0x1546700` and `0x1546000`. Separate 0xb0-byte copies carry the resulting descriptors through stack temporaries into a record at `rsp+0x1240`.
2. The constructor writes zero to that record's leading word, copies 0x438 bytes, and calls `0x5a08f80`. Its initial repacker `0x38c6590` selects the input's first 0x420 bytes when the leading dword differs from 2. Both descriptors fit within those bytes. On the selected normal branch the wrapper copies 0x470 bytes to its output after its contextual helper returns.
3. At `0x5a6c619`, the owner builder at `0x5649680` receives that output and the name `node_slow_abci_engine`. The relevant copy starts at `rsp+0x3f8`, eight bytes before the copied input, and lands at body offset `+0x6a8`. The net translation is `+0x6b0`. The constructor then prepends two qwords to the body and copies 0xb80 bytes into the non-null allocation it returns in RDX.

The separate call using the literal `vote_abci_digest` reaches `0x1548bb0`. The evidence identifies the selected descriptor locations, assuming normal returns and no aliasing writes by intervening helpers. It does not identify their contents at runtime, their consumers or the digest used as a reference root.

## Reproduce

The 73 selected instruction spans agree between GNU objdump 2.45 and LLVM objdump 23.1.4. Use the FDE ranges in [instructions.tsv](instructions.tsv). From repository root, check the recorded spans, named RIP-relative operands, and the relevant slots as follows.

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
text = next(row for row in sections if row["name"] == ".text")
path = Path("research/work-items/RE-017-node115-digest-quorum-owner/instructions.tsv")
with path.open() as handle:
    rows = {int(row["va"], 16): row for row in csv.DictReader(handle, delimiter="\t")}
for address, row in rows.items():
    start, end = (int(row[k], 16) for k in ("fde_start", "fde_end"))
    raw = bytes.fromhex(row["bytes"])
    offset = text["offset"] + address - text["address"]
    assert (start, end) in bounds and start <= address < address + len(raw) <= end
    assert data[offset:offset + len(raw)] == raw
rodata = next(row for row in sections if row["name"] == ".rodata")
for address, literal in ((0x5a6c418, b"abci_digest_quorum"), (0x5a6c448, b"abci_hashes"),
                         (0x5a6c478, b"vote_abci_digest")):
    code = bytes.fromhex(rows[address]["bytes"])
    assert len(code) == 7 and code[1] == 0x8d and code[2] & 0xc7 == 5
    target = address + 7 + struct.unpack_from("<i", code, 3)[0]
    assert rodata["address"] <= target <= target + len(literal) <= rodata["address"] + rodata["size"]
    offset = rodata["offset"] + target - rodata["address"]
    assert data[offset:offset + len(literal)] == literal
section = next(row for row in sections if row["name"] == ".rela.dyn")
relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
    "<QQq", data[section["offset"]:section["offset"] + section["size"]]
)}
for slot, target in ((0x64e0f98, 0x1546700), (0x64e0fa0, 0x1546000), (0x64e1020, 0x1548bb0),
                     (0x64e80e8, 0x38c6590), (0x64ebc98, 0x5649680)):
    assert relocations[slot] == (8, target)
print(f"{len(rows)} instruction spans, three literal references and five relocations match")
PY
```

# RE-005 · Node #115 recovered signer result construction

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Scope: the signer identity output at `0x1536a90` after the two checked backend operations. RE-010-gov-vote-path-115 already covers normalization and the backend failure branches. RE-009-node115-restart-validation-row-walk observes tag 1 at a different caller. This packet traces the source of the 20 bytes compared by the digest-vote core in #4114.

Both backend calls must return 1 to reach the selected output builder. At `0x1536db4` it provides a 65-byte zero-initialized scratch span, a pointer to length 65, the previous backend's staged output and selector 2. The serializer slot resolves to `0x632b480`. The caller copies all 65 scratch bytes and hashes bytes 1 through 64. It skips byte zero via the source LEA at `0x1536dfa`. There is no intervening branch on the serializer return or output length in this wrapper.

The sponge input uses a zeroed 200-byte state, rate 136, domain byte 1, and a requested output length of 32. Its selected absorb and squeeze slots are the same implementations documented in RE-017-abci-result-digest-115. The final two stores read the last 20 bytes of the 32-byte output, beginning at scratch `+0xac` relative to squeeze output `+0xa0` after the copies. The wrapper writes them to result offsets `+0x01..+0x14`, then sets tag 0. The backend failure branches join the existing error path, which stores a qword at result `+0x08` and sets tag 1.

This resolves the selected output layout and hash slice for offline signer comparison. The sponge parameters and output slice are consistent with an Ethereum-style signer address. The binary was not executed, and this analysis does not establish complete backend equivalence or the reachability of a serialization failure after successful recovery.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agreed on [instructions.tsv](instructions.tsv). The following pins the ELF and checks the retained spans and selected slots.

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
path = Path("research/work-items/RE-005-node115-signer-result/instructions.tsv")
with path.open() as handle:
    rows = {int(row["va"], 16): row for row in csv.DictReader(handle, delimiter="\t")}
for address, row in rows.items():
    start, end = (int(row[k], 16) for k in ("fde_start", "fde_end"))
    raw = bytes.fromhex(row["bytes"])
    offset = text["offset"] + address - text["address"]
    assert (start, end) in bounds and start <= address < address + len(raw) <= end
    assert data[offset:offset + len(raw)] == raw
section = next(row for row in sections if row["name"] == ".rela.dyn")
relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
    "<QQq", data[section["offset"]:section["offset"] + section["size"]]
)}
for address, slot, target in ((0x1536ba4, 0x64df9d8, 0x632b660),
                              (0x1536cba, 0x64df9e0, 0x632b7b0),
                              (0x1536db4, 0x64df9e8, 0x632b480),
                              (0x1536e9a, 0x64e0148, 0x5cda910),
                              (0x1536ec6, 0x64e0150, 0x5cdad40)):
    code = bytes.fromhex(rows[address]["bytes"])
    assert code[:2] == b"\xff\x15" and address + 6 + struct.unpack_from("<i", code, 2)[0] == slot
    assert relocations[slot] == (8, target)
print(f"{len(rows)} instruction spans and five slot-backed call targets match")
PY
```

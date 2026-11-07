# RE-017 · Node #115 compact ABCI digest reference lookup

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [loader result packet](../RE-017-loader-checkpoint-result-115/README.md) identifies the compact 32-byte equality test and the mismatch writer. The [two-run search packet](../RE-001-two-run-search-57f8bb0-115/README.md) studies the search helper and marks the compact call site as a boundary. This packet closes the selected reference lookup from the compact comparator's perspective.

The loop advances the incoming comparison rows by `0x68`. Its search key is the qword at row base, and the incoming 32-byte candidate occupies row `+0x48..+0x67`. The code separately loads the current state `+0x28` into a diagnostic local. Those loads do not establish equality between the incoming row key and the current height. Earlier code feeds the incoming bytes to helper `0x4e3a020` using context `+0x280`, while the reference search below uses context `+0x400`.

- If the word at context `+0x400` is ordinary, `0x57f8bb0` searches by row key. A set low return bit, or returned index at least context `+0x418`, advances to the next input row without comparison. Otherwise the caller adds context `+0x410` to the returned index and subtracts the capacity once if the sum is at least that capacity. It then takes 32 bytes at context `[+0x408]` plus 40 times the projected index plus 8.
- If the word is `0x8000000000000000`, context `+0x408` supplies the initial node. The selected node uses count `+0x1c2`, keys at `+0x168 + 8*i` and children at `+0x1c8 + 8*i`. An exact key match uses the 32-byte node lane at `+0x20*i`. An absent initial node or exhausted child depth advances without comparison.
- Both found-reference arms join the two 16-byte equality operations. A mismatch takes `0x5a060ec`, which references the two bad-digest path literals and calls the previously studied writer. No-found and matched-equal can both continue to the next row, so lack of a mismatch by itself is insufficient evidence of alignment.

This applies to the selected compact context and valid container invariants. It supplies an offline comparison rule for reporting matched, mismatched and missing-reference cases. It does not establish where a live comparator's reference history came from, successful writes to the diagnostic paths, or the canonical digest of a real block.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on [instructions.tsv](instructions.tsv).

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

with Path("research/work-items/RE-017-node115-compact-digest-reference-lookup/instructions.tsv").open() as handle:
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
assert rip_target(0x5a05df6) == 0x57f8bb0
assert rip_target(0x5a05e3c) == 0x5a05ce7
assert rip_target(0x5a05d28) == 0x5a060ec
assert rip_target(0x5a06150) == 0x4e4a740
for address, literal in ((0x5a060f4, b"/tmp/evm_db_bad_abci_digest"),
                         (0x5a06129, b"/tmp/abci_state_bad_abci_digest.rmp")):
    assert elf_bytes(".rodata", rip_target(address), len(literal)) == literal

for capacity in (1, 2, 8, 33):
    for start in range(capacity):
        for index in range(capacity):
            combined = start + index
            projected = combined - capacity if combined >= capacity else combined
            assert projected == combined % capacity
digest = bytes(range(32))
for index in range(32):
    different = bytearray(digest)
    different[index] ^= 1
    mask = sum((different[i] == digest[i] and different[i+16] == digest[i+16]) << i
               for i in range(16))
    assert mask == 0xffff ^ (1 << (index % 16))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

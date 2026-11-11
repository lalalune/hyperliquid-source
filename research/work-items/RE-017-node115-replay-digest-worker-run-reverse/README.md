# RE-017 · Node #115 replay digest descending-run reversal

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

[#5909](https://github.com/lalalune/hyperliquid-source/pull/5909) traces selected nondecreasing and strictly descending 32-byte adjacent-run scans in preparation worker `0x4f848d0`. This packet maps the selected reversal after a strictly descending run meets the worker's local threshold.

For a selected run of at least three valid rows, the negative first comparator result is retained, and the scan yields length L. If L meets the local threshold, the selected negative-result path computes `floor(L/2)` swaps. Its two pointers begin at the first and last 32-byte rows; each iteration exchanges both 16-byte lanes, moves the first pointer forward 32 bytes and the last backward 32 bytes. It then continues to the common run continuation. The nonnegative first-comparison route bypasses this reversal. A distinct two-row shortcut is outside the main claim.

For a valid strictly descending synthetic run, this local operation reverses its rows; this is not proof that the worker sorts the full input or that real replay data is ordered. Valid readable/writable storage, comparator behavior, selected threshold and no concurrent mutation are assumptions. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 66 selected instruction spans. Python 3 verifies target identity, indexed FDEs, selected edges, corruption controls and synthetic odd/even reversal cases.

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

with Path("research/work-items/RE-017-node115-replay-digest-worker-run-reverse/instructions.tsv").open() as handle:
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

def short_target(address):
    raw=spans[address];return address+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x4f84ac0)==0x64dfb50
assert short_target(0x4f84ac8)==0x4f84b14
assert rip_target(0x4f84b4c)==0x64dfb50
assert short_target(0x4f84b54)==0x4f84b65
assert short_target(0x4f84b86)==0x4f84bc9
assert short_target(0x4f84bc7)==0x4f84ba0
for n in (3,4,5,8):
    rows=[bytes([n-i])*32 for i in range(n)];expected=list(reversed(rows))
    for i in range(n//2): rows[i],rows[n-1-i]=rows[n-1-i],rows[i]
    assert rows==expected
for addr in (0x4f84b7e,0x4f84bc7):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

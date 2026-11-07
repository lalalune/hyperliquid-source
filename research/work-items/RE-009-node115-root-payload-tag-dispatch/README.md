# RE-009 · Node #115 shared root payload field-5 jump table

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[PR #4213](https://github.com/lalalune/hyperliquid-source/pull/4213) binds the fifth ordered child at shared payload `+0x48` to visitor `0x44ea980`, without resolving its cases. This packet resolves the eleven observed jump-table entries and distinguishes the special entry 9 from ten paths which stage a case number and then inspect the destination state. The offsets are relative to the shared pointer, whose relation to the parent tagged source depends on the branch described in #4212.

The visitor reads a qword index from the field, loads a signed 32-bit relative displacement at `0x7d01b4 + 4*index`, adds table base `0x7d01b4`, and jumps there. The eleven table entries indexed 0 through 10 lead, respectively, to `0x44ea998`, `0x44eabbf`, `0x44eaab2`, `0x44eab09`, `0x44ea9f7`, `0x44eac1e`, `0x44eac7d`, `0x44eab60`, `0x44ead38`, `0x44eaa56`, and `0x44eacdc`. The ten non-9 entries stage the same number as their index at stack `+8`; entry 9 instead constructs a one-element payload descriptor at source `+8` and calls `0x41aed60`.

For the other ten cases, a signed-overflow check on `0 - destination[0]` returns status 1 on overflow, and destination `+0x10 < 2` returns status 2. Otherwise the code examines the qword at the object pointed to by destination `+8`, offset `+0x18`, against `0x8000000000000001`; equality invokes an indirect helper and `0x41c70d0`, writes three words of result state, then rejoins the indirect dispatch also reached by inequality. The visitor itself has no visible bound check before indexing this table: eleven entries are authenticated here, not a claim that arbitrary indices are safe or reachable. The output's domain meaning and full root encoding remain unknown.

## Reproduce

GNU and LLVM agree on selected instruction spans. Signed jump-table displacements and descriptor bindings are read directly from the authenticated ELF.
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

with Path("research/work-items/RE-009-node115-root-payload-tag-dispatch/instructions.tsv").open() as handle:
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
assert relocations[0x648d3c0] == (8, 0x44ea980)
assert rip_target(0x44ea988) == 0x7d01b4
assert rip_target(0x44eaaa7) == 0x41aed60
expected = [0x44ea998,0x44eabbf,0x44eaab2,0x44eab09,0x44ea9f7,0x44eac1e,0x44eac7d,0x44eab60,0x44ead38,0x44eaa56,0x44eacdc]
table = struct.unpack('<11i', elf_bytes('.rodata', 0x7d01b4, 44))
assert [0x7d01b4 + x for x in table] == expected
for value in (0, 1, 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff):
    signed = value if value < (1 << 63) else value - (1 << 64)
    assert (not (-(1 << 63) <= -signed < (1 << 63))) == (value == 0x8000000000000000)
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

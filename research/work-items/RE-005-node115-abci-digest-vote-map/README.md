# RE-005 · Node #115 ABCI digest vote map admission

- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Scope: selected map admission and output projection at `0x2017280..0x201855e`. #4111 describes writer-side projections; this packet concerns the reader. Other visitor routes, key parsing and the inner decode helpers are boundaries.

## Observations

The selected input discriminator `0x15` leads to iteration over 0x40-byte records. A field classifier result tag 9 reaches the index branch at `0x201781a`; other classifier results take a separate error path.

| Selected field | Branch and present storage | Duplicate path | Missing path |
| --- | --- | --- | --- |
| `height` | Index zero reaches `0x20178c0` and the selected value helper call at `0x2017939`. Result tag 9 permits staging the qword at `rsp+0xe8`. | `0x20178c9` to literal at `0x2018391`. | `0x2017b9c` to a named formatter. Its tag-9 continuation can supply a value; another result is carried to the error arm. |
| `abciDigest` | Index one reaches `0x2017838`. After `0x2017884`, a result byte equal to 1 goes to an error continuation. The selected other arm stages two 16-byte lanes at `rsp+0x240` and `+0x250`, then sets the low present byte at `rsp+0x24` to 1. | `0x201783d` to literal at `0x2018329`. | `0x2017bbc` to literal at `0x2017de1` on the selected normal completion path. |
| `signature` | The third observed dispatch arm reaches `0x2017960`. After `0x20179b0`, a result dword of 1 goes to a separate error. The selected other arm copies four 16-byte lanes and one trailing qword. | `0x2017969` to literal at `0x20182c1`. | `0x2017bc5` reaches the named formatter at `0x2017d94`. |

The duplicate arms reference the same length-prefixed duplicate template. The missing-digest and missing-signature arms reference the missing template and join a leading qword 1 store. The normal complete map copies digest to result `+0x8..+0x27`, height to `+0x28`, signature storage to `+0x30..+0x77`, then sets the leading qword to zero. Relative to the start of the payload after the leading qword, these are the same offsets observed independently in the writer. The success projection is subject to the following helper's tag-9 result.

The record establishes selected field ownership and error ordering. It does not authenticate a signature, prove a full wire schema, or identify the reference digest producer. No component gate is requested.

## Reproduce

From the repository root, use the authenticated artifact and either disassembler:

```sh
shasum -a 256 artifacts/node/115/hl-node
objdump -d -M intel --insn-width=16 --start-address=0x2017280 --stop-address=0x201855e artifacts/node/115/hl-node
llvm-objdump -d --x86-asm-syntax=intel --start-address=0x2017280 --stop-address=0x201855e artifacts/node/115/hl-node
```

The TSV preserves selected instruction bytes, ELF virtual addresses and file offsets. GNU 2.45 and LLVM 23.1.4 agreed on the recorded instruction spans. This command independently verifies the mapped file offsets, indexed unwind interval and named references using the repository parsers:

```sh
PYTHONPATH=tools python3 -B - <<'PY'
import csv
import hashlib
from pathlib import Path
from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, index = unwind_index(data)
_, fdes = eh_frame_records(data, sections)
fde, = [row for row in fdes if row["start"] == 0x2017280]
assert fde["end"] == 0x201855e
assert any(row["start"] == fde["start"] and row["fde"] == fde["fde"] for row in index)
text = next(section for section in sections if section["name"] == ".text")
rodata = next(section for section in sections if section["name"] == ".rodata")
with Path("research/work-items/RE-005-node115-abci-digest-vote-map/instructions.tsv").open() as handle:
    rows = {int(row["va"], 16): row for row in csv.DictReader(handle, delimiter="\t")}
for address, row in rows.items():
    raw = bytes.fromhex(row["bytes"])
    offset = text["offset"] + address - text["address"]
    assert fde["start"] <= address < address + len(raw) <= fde["end"]
    assert offset == int(row["file_offset"], 16)
    assert data[offset:offset + len(raw)] == raw
for address, name in {
    0x2017cdd: b"height", 0x2017d51: b"signature", 0x2017de1: b"abciDigest",
    0x20182c1: b"signature", 0x2018329: b"abciDigest", 0x2018391: b"height",
    0x2017e12: b"\x0fmissing field", 0x201835d: b"\x11duplicate field",
}.items():
    raw = bytes.fromhex(rows[address]["bytes"])
    target = address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)
    offset = rodata["offset"] + target - rodata["address"]
    assert data[offset:offset + len(name)] == name
print(f"{len(rows)} instruction spans and 8 references checked")
PY
```

No captured code was executed.

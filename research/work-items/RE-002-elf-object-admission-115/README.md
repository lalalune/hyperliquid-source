# RE-002 node115 ELF Object admission and Build ID handoff

This packet maps the borrowed file and section view constructed by
0x5c93da0 and consumed by the GNU Build ID reader. It builds on the
reader contract in PR #2859. Target Linux x86-64 node #115 has SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base is 05bc2de303c05525b71e7e257426e741bc66a390.

## Admission and handoff

- The constructor rejects input shorter than 64 bytes. Its identification
  checks require ELF magic, class 2, data encoding 1 and version 1.
  The early failure stores 0x8000000000000000 at output +0.
- A zero section-table offset reaches the empty section view. For a nonzero
  offset the record width must be 64. A nonzero count comes from header
  +0x3c. A zero count first requires a complete section-zero record, then
  reads its qword +0x20. A zero extended count reaches the empty view.
  A nonzero extended count with any of its top six bits set is rejected
  before multiplication by 64. The table must fit within the input.
- When the table is nonempty, name-table index 0xffff takes its replacement
  from section zero +0x28. The resulting index must be nonzero and below
  the count. Type 8 takes the empty name-span path. Otherwise the constructor
  records the name span after checking addition overflow at 0x5c93eb9.
  This particular check does not compare the span end against file length.
- The success stores at 0x5c94119 publish file pointer and length at +0x18
  and +0x20, then section pointer and count at +0x28 and +0x30. The empty
  section view has a sentinel pointer of one and count zero.
- The retained consumer calls the constructor at 0x5c83e79, checks the
  failure marker and passes the same stack object to 0x5c948e0 at
  0x5c83ea9. The reader checks count before dereferencing the section view.

The constructor also has symbol table selection, allocation and sorting
paths. Header admission alone does not establish constructor success.
Those paths are outside the selected contract, as are native ABI
equivalence and behavior under target execution.

## Reproduce

From the repository root, use authenticated artifacts, Python with Capstone
5.0.7, GNU objdump/readelf 2.45 and LLVM objdump 23.1.4.

```sh
python3 -B research/work-items/RE-002-elf-object-admission-115/collect.py --out work/elf-object-static-fresh
python3 -B research/work-items/RE-002-elf-object-admission-115/verify.py --out work/elf-object-check-fresh.json
```

Three complete FDEs contain 5,496 bytes and 1,214 instructions. The new
constructor body is 1,845 bytes. The reader and consumer are retained
context. GNU and LLVM instruction bytes agree with Capstone and GNU
readelf confirms the FDE extents. The verifier reproduced every retained
export and detected 17 byte-window corruptions and two identity controls.
The scaffold is reused from the MIT Build ID packet. The analysis uses
file bytes and does not execute or emulate the capture.

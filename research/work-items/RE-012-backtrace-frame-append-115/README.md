# RE-012: map node115 backtrace frame append and marker index

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The callback distinguishes pre-populated frame records from
unwind-context input. The latter reads IP and CFA and
finds the enclosing function. It packages those values with
the frame marker and initializes the remaining local fields.

The destination grows on capacity equality and appends a
56-byte record. After incrementing length, it compares the
selected function with the saved marker. A match stores
the new length only when the marker slot is still empty.
This is frame storage and marker selection, separate from
unwinder traversal.

The retained 1 full FDEs cover 334 bytes and 90 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 1 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-backtrace-frame-append-115/collect.py --out work/backtrace-frame-append-fresh
python3 -B research/work-items/RE-012-backtrace-frame-append-115/verify.py --out work/backtrace-frame-append-check-fresh.json
```

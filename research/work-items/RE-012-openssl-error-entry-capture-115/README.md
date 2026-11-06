# RE-012: map node115 OpenSSL error entry flags and owned fields

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The routine supplies five output pointers to ERR_get_error_all.
A zero return writes the high-bit-plus-two empty marker.
Otherwise data flag 0x2 controls whether the data pointer
is measured and passed to text validation. With that bit
set, flag 0x1 selects an owned copy of the span. The
other route retains the returned pointer and length.

The file string is copied with its terminator. A nonnull
function string is also copied with its terminator; the
null arm stores a zero pointer. The output includes the
error code at +0x28 and line at +0x40. This packet follows
one captured entry and its memory ownership, leaving
error queue collection across entries outside scope.

The retained 1 full FDEs cover 789 bytes and 188 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-openssl-error-entry-capture-115/collect.py --out work/openssl-error-entry-capture-fresh
python3 -B research/work-items/RE-012-openssl-error-entry-capture-115/verify.py --out work/openssl-error-entry-capture-check-fresh.json
```

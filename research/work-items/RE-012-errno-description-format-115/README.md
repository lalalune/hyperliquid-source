# RE-012: map node115 errno description buffer and text projection

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected formatting branch supplies the errno dword and
a zeroed 128-byte stack buffer to __xpg_strerror_r. A
negative status takes the diagnostic at 0x5ca832e. The other
branch gets the byte count using strlen and passes the
buffer and length to the bound text conversion helper.

The conversion result has two ownership routes. One moves
the result's three words forward directly. The other reads
the returned span and allocates and copies its bytes when
nonempty, preserving the separate empty branch. The common
formatter continuation receives the resulting text record.
This packet covers the errno description path and excludes
the other encoded error variants and locale internals.

The retained 1 full FDEs cover 1237 bytes and 285 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-errno-description-format-115/collect.py --out work/errno-description-format-fresh
python3 -B research/work-items/RE-012-errno-description-format-115/verify.py --out work/errno-description-format-check-fresh.json
```

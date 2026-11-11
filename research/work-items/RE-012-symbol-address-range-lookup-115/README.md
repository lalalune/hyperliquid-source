# RE-012: map node115 symbol address range selection and bounds

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected symbol path reads the source discriminator
and returns the pre-populated pair for tag three. The
range-backed arm admits the selected source descriptor
and reads an ordered table of 24-byte entries.

It performs the visible halving search on entry starts,
then requires the query to lie in the half-open candidate
interval. It checks the chosen index against the range
count and the mapped index against the record count.
The accepted record uses a 72-byte stride. This packet
scopes the range selector, separate from symbol formatting
and the other resolver branches.

The retained 1 full FDEs cover 809 bytes and 214 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-symbol-address-range-lookup-115/collect.py --out work/symbol-address-range-lookup-fresh
python3 -B research/work-items/RE-012-symbol-address-range-lookup-115/verify.py --out work/symbol-address-range-lookup-check-fresh.json
```

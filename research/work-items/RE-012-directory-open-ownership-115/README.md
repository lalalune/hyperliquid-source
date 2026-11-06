# RE-012: map node115 directory stream construction and error tags

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The stack path calls opendir only after the scanned zero
matches the original path length. An embedded zero sends the
static error pointer to the output, with byte tag two. The
long path calls the separate adapter and converges on the
same stream/error dispatch.

A null stream returns packed errno with byte tag two. For a
nonnull stream the routine copies the source path bytes into
owned storage, using pointer one for length zero. It allocates
a 48-byte record whose first two words are one, stores the
length, copy pointer, repeated length and stream pointer, and
publishes byte tag zero. The next-entry iterator is a separate
operation. No live filesystem path was opened.

The retained 1 full FDEs cover 683 bytes and 168 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 1 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-directory-open-ownership-115/collect.py --out work/directory-open-ownership-fresh
python3 -B research/work-items/RE-012-directory-open-ownership-115/verify.py --out work/directory-open-ownership-check-fresh.json
```

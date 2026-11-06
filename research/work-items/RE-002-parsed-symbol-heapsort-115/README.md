# RE-002: map node115 parsed-symbol heapsort fallback

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The std census attributes the complete leaf 0x5c7f2c0 to the
ParsedSym specialization of heapsort. This packet resolves the
key, tie handling, record moves and fallback edge. The partition
routine at 0x5c7f3c0 tail-calls it at 0x5c7f7c5 through RELATIVE
slot 0x64ec628, forwarding the current pointer and element count.
The partition and small-sort policies are context.

Records have stride 24. The first qword is compared unsigned.
The cursor begins at n + floor(n/2) and decrements. While its
value is at least n, cursor minus n is the root of a sift using
all n records. Otherwise it exchanges the full root and cursor
records and sifts root zero within the prefix of length cursor.
Zero length returns immediately. The final cursor-zero exchange
is with the root itself and the empty sift exits.

Each sift starts with child 2*root+1 and stops if that child
is outside the active prefix. The next child is chosen only
when it exists and its key is strictly greater than the first
child's key. Equal children select the first child. A parent
key at least the chosen child's key stops the sift. Otherwise
the stores exchange all 24 bytes and descend. The root extraction
swaps can reorder equal keys, so the output is ascending by key
with no stability guarantee. This is a bounded static algorithm
contract. Neither compiler identity nor captured execution is claimed.

The retained 2 full FDEs cover 1279 bytes and 332 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 9 instruction/data windows, 1 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-002-parsed-symbol-heapsort-115/collect.py --out work/parsed-symbol-heapsort-fresh
python3 -B research/work-items/RE-002-parsed-symbol-heapsort-115/verify.py --out work/parsed-symbol-heapsort-check-fresh.json
```

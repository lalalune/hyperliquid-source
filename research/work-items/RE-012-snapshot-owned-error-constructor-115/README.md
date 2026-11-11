# RE-012: recover node #115 owned error construction and partial cleanup

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The selector error path uses this constructor to transfer a three-qword record into a tagged owned value. The first 24-byte allocation receives the original qwords. The second 24-byte allocation receives the inner pointer at +0, the table at +8, and the low byte of the selector at +16. The return increments the wrapper pointer by one. The table's first entry is RELATIVE-bound to 0x5cf5990.

The two allocation failures have distinct unwind paths. Failure before the transfer conditionally releases the original buffer using its saved pointer and size. Failure after the first copy passes the allocated inner record and the same table to the cleanup helper before resuming unwind. This maps ownership transfer and its rollback for partial construction.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-owned-error-constructor-115/collect.py --out work/node115-snapshot-owned-error-constructor-fresh
python3 -B research/work-items/RE-012-snapshot-owned-error-constructor-115/verify.py --out work/node115-snapshot-owned-error-constructor-check-fresh.json
```

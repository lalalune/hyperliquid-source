# RE-012: recover node #115 bounded stack read and append publication

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The helper reads at most 32 bytes into stack storage and checks for a count of 33 or higher before copying. It calculates spare capacity as destination capacity minus logical length. A count above the spare capacity branches to the growth path. The normal copy uses destination base plus the prior logical length, skips memcpy for zero bytes, and publishes the new length after the copy.

The successful return places zero in RAX and the read count in RDX. A read result of -1 enters errno handling, and errno four drops the temporary error before reissuing the 32-byte read. This maps the bounded append operation, separate from the outer file wrapper's initial allocation estimate.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-bounded-read-append-115/collect.py --out work/node115-snapshot-bounded-read-append-fresh
python3 -B research/work-items/RE-012-snapshot-bounded-read-append-115/verify.py --out work/node115-snapshot-bounded-read-append-check-fresh.json
```

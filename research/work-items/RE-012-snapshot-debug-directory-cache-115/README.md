# RE-012: map node #115 debug-directory predicate and cache

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The debug-directory predicate reads the byte at 0x650008a before allocating a stack frame. Any nonzero byte returns immediately, with one interpreted as true. The zero-byte path constructs the NUL-terminated string `/usr/lib/debug` and calls 0x5c9f780 with a result pointer, -100, the pathname and zero.

Result tag three reaches the fallback call at 0x5ca0cad with the pathname and a cleared result area. The successful fallback and the ordinary non-error result read mode words from different offsets, then share the mask-and-compare sequence at 0x5ca0cd4. The predicate tests `(mode & 0xf000) == 0x4000` and publishes byte one on a match and two otherwise. The tag-two arm and fallback error arm both reach the error handler at 0x5ca0d03 and publish two if it returns. Publication is a plain byte store and this window supplies no synchronization guarantee.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-debug-directory-cache-115/collect.py --out work/node115-snapshot-debug-directory-cache-fresh
python3 -B research/work-items/RE-012-snapshot-debug-directory-cache-115/verify.py --out work/node115-snapshot-debug-directory-cache-check-fresh.json
```

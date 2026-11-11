# RE-012: recover node #115 realpath allocation ownership conversion

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The canonical-path adapter calls realpath with a null destination. A null result captures errno and writes the signed-minimum sentinel and packed errno. On success the returned C allocation is measured with strlen, and a separate allocation is made for exactly that many bytes. The memcpy count excludes the terminating NUL.

The empty branch substitutes pointer one and skips the byte allocation. Both successful branches release the original realpath allocation through the free slot before publishing the owned byte triple, with the measured length in both capacity and length fields. A failed second allocation instead reaches the allocation-error helper. This documents conversion across allocator ownership, separate from readlink's capacity retry.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-realpath-owned-bytes-115/collect.py --out work/node115-snapshot-realpath-owned-bytes-fresh
python3 -B research/work-items/RE-012-snapshot-realpath-owned-bytes-115/verify.py --out work/node115-snapshot-realpath-owned-bytes-check-fresh.json
```

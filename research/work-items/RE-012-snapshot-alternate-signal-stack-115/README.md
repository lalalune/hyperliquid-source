# RE-012: recover node #115 alternate signal stack installation

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The alternate-stack path queries sigaltstack with a null new-stack pointer. It inspects bit 1 of the returned flags and leaves the return pointer zero when that bit is clear. When set, the path obtains getauxval(0x33), chooses the larger of that value and 0x2000, and adds the global length at 0x6500048 to obtain the mmap64 length.

On successful mapping it calls mprotect with protection zero over the leading global-length span. The installed stack starts immediately after that span. The worker passes the adjusted address, flags zero and the usable size to sigaltstack, and returns the adjusted address. The mmap64 and mprotect failures branch away before installation. The earlier pthread attribute probe is retained in the function evidence as context for reaching this path.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-alternate-signal-stack-115/collect.py --out work/node115-snapshot-alternate-signal-stack-fresh
python3 -B research/work-items/RE-012-snapshot-alternate-signal-stack-115/verify.py --out work/node115-snapshot-alternate-signal-stack-check-fresh.json
```

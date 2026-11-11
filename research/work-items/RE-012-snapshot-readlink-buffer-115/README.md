# RE-012: recover node #115 readlink growth and result ownership

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The readlink wrapper begins with a 256-byte allocation. A return exactly equal to the capacity calls the growth helper, reloads the buffer pointer and capacity, and retries. A shorter nonzero result uses the resize slot with the returned size. Zero releases the buffer and substitutes pointer one with zero capacity. The successful output contains capacity, pointer, and byte length at +0/+8/+16.

Return -1 instead captures errno, writes (errno << 32)|2 at +8 and the signed-minimum sentinel at +0. That path releases the current buffer when its capacity is nonzero. This recovers the buffer lifecycle and capacity-equality retry condition without assuming a terminating NUL in the returned bytes.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-readlink-buffer-115/collect.py --out work/node115-snapshot-readlink-buffer-fresh
python3 -B research/work-items/RE-012-snapshot-readlink-buffer-115/verify.py --out work/node115-snapshot-readlink-buffer-check-fresh.json
```

# RE-012: recover node #115 build-ID debug pathname construction

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The builder at 0x5ca08c0 publishes a signed-minimum sentinel at output offset zero if the input length is below two or the directory predicate returns false. Otherwise it constructs an owned byte sequence. Two overlapping vector copies reproduce the 25-byte prefix `/usr/lib/debug/.build-id/` from the bytes at 0x949e81.

The first input byte becomes two lowercase hexadecimal digits, followed by a slash. Starting at input index one, the loop emits two lowercase hexadecimal digits per byte until the supplied length is reached. Both nibble conversions choose between ASCII offsets 0x30 and 0x57. The builder appends six bytes spelling `.debug` and publishes the byte length at result offset 0x10 alongside the capacity and pointer. The recorded window covers pathname construction, including capacity checks, without relying on a file being present at the resulting path.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-build-id-debug-path-115/collect.py --out work/node115-snapshot-build-id-debug-path-fresh
python3 -B research/work-items/RE-012-snapshot-build-id-debug-path-115/verify.py --out work/node115-snapshot-build-id-debug-path-check-fresh.json
```

# RE-012: recover node #115 Unix error-kind dispatch table

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The classifier subtracts one in 32-bit arithmetic and performs an unsigned comparison against 121. Original inputs 1 through 122 index the 122 signed little-endian dwords at 0x948920. All other 32-bit inputs return byte 0x29. Each table entry is relative to the common table base, and each resolved leaf returns a byte constant or clears EAX to return zero. Multiple inputs share leaves. This packet retains the numeric mapping without assigning source-level names to the byte tags.

The rows below are indexed by the original input. Each full row lists ten consecutive output bytes in hex. The extractor checked the full table and required every destination to decode as a complete constant-return leaf.

```text
  1  01 00 29 23 29 29 22 29 29 29
 11  0d 26 01 29 29 1c 0c 1f 29 0e
 21  0f 14 29 29 29 1d 1b 18 19 11
 31  20 0b 29 29 1e 21 29 24 10 12
 41  29 29 29 29 29 29 29 29 29 29
 51  29 29 29 29 29 29 29 29 29 29
 61  29 29 29 29 29 29 29 29 29 29
 71  29 29 29 29 29 29 29 29 29 29
 81  29 29 29 29 29 29 29 29 29 29
 91  29 29 29 29 24 29 29 08 09 0a
101  05 29 06 03 29 29 07 29 29 16
111  02 29 04 29 27 13 29 29 29 29
121  29 1a
```

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-unix-error-kind-dispatch-115/collect.py --out work/node115-snapshot-unix-error-kind-dispatch-fresh
python3 -B research/work-items/RE-012-snapshot-unix-error-kind-dispatch-115/verify.py --out work/node115-snapshot-unix-error-kind-dispatch-check-fresh.json
```

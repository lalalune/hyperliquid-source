# RE-001: map node115 command byte join allocation and separator placement

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The command renderer calls 0x150d100 with a count and 24-byte records. This helper sums each length at +0x10 with a carry check, then sizes the buffer with one byte per gap. Count zero returns a zero capacity, pointer one, and zero length. For a nonempty input the first entry is copied separately, then each subsequent entry is preceded by one byte loaded from the supplied separator pointer. A zero-length subsequent entry still consumes its separator.

The append loop checks available capacity before copying, and the unwind landing path frees the owned buffer when its capacity is nonzero. The evidence distinguishes this byte layout from upstream rendering and does not execute a shell.

The retained 1 full FDEs cover 555 bytes and 141 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-command-byte-join-115/collect.py --out work/startup-command-byte-join-fresh
python3 -B research/work-items/RE-001-startup-command-byte-join-115/verify.py --out work/startup-command-byte-join-check-fresh.json
```

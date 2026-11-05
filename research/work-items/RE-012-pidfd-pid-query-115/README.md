# RE-012: map node115 pidfd PID ioctl and optional libc fallback

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The wrapper initializes the query buffer with mask one and
calls ioctl request 0xc040ff0b. Non--1 returns tag zero and
the buffer dword read from offset 0x10.

Failure captures errno. Only errno 0x16 or 0x19 consults
the optional pidfd_getpid slot. With a nonzero slot the
fallback uses the same descriptor. Its -1 result packs
the new errno, while success publishes the returned PID.
If the fallback is skipped, the original ioctl error is
preserved. This packet covers PID lookup, separate from
process wait and status collection.

The retained 1 full FDEs cover 209 bytes and 62 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-pidfd-pid-query-115/collect.py --out work/pidfd-pid-query-fresh
python3 -B research/work-items/RE-012-pidfd-pid-query-115/verify.py --out work/pidfd-pid-query-check-fresh.json
```

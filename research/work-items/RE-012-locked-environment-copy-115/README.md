# RE-012: map node115 locked environment lookup and owned copy

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The third argument enters getenv under the read lock at 0x64ffff0.
The fast path compares the unsigned state with 0x3ffffffd and
CAS-increments it. An out-of-range or failed CAS calls the reader
slow path, then rejoins before getenv.

A null result writes the marker 0x8000000000000000 at output +0.
An empty string writes length and capacity zero with pointer one.
A nonempty string allocates strlen bytes and copies that many bytes
while the read guard remains held. The output stores capacity,
pointer and length at +0, +8 and +16. The function returns the
output address.

Normal release subtracts one atomically. It clears bit 30 in the
post-decrement state and calls the wake helper if that masked state
equals 0x80000000. The unwind landing path repeats the same release
test before resuming the exception. Allocation failure calls the
failure helper with alignment one and the requested length, followed
by ud2. This packet follows the ownership transition, independent
of the lock slow-path internals.

The retained 1 full FDEs cover 303 bytes and 80 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 7 instruction/data windows, 4 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-locked-environment-copy-115/collect.py --out work/locked-environment-copy-fresh
python3 -B research/work-items/RE-012-locked-environment-copy-115/verify.py --out work/locked-environment-copy-check-fresh.json
```

# RE-012: map node115 thread join result take and reference release

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

Join reads the thread handle at owner +0x10 and calls
pthread_join with null return storage. Nonzero status is
packed and passed to the diagnostic. After a successful
join, the result packet must pass a CAS from one to all
ones and a separate strong-count check. It restores the
CAS word to one after a successful exchange.

The result words at +0x20/+0x28 are read and the presence
word at +0x18 is cleared. The missing-presence arm goes to
a diagnostic. The ordinary return decrements the owner
and packet references, calling their release boundaries
on zero, then returns the extracted pair.

The paired detach path calls pthread_detach without testing
its status, then releases the same two reference fields.
Its unwind path releases the packet reference before
resuming. These paths consume an existing thread handle,
separate from thread creation and naming.

The retained 2 full FDEs cover 463 bytes and 119 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 7 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-pthread-join-result-take-115/collect.py --out work/pthread-join-result-take-fresh
python3 -B research/work-items/RE-012-pthread-join-result-take-115/verify.py --out work/pthread-join-result-take-check-fresh.json
```

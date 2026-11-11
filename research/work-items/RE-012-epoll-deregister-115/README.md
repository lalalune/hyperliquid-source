# RE-012: map node115 epoll deregistration and deferred reference handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The wrapper calls epoll_ctl operation two with a null event
pointer. A negative result is saved as packed errno; the
nonnegative route saves zero. Both routes then acquire the
state lock and increment the referenced object's count.

If the queue length equals capacity, it calls the growth
boundary. It appends the object pointer, increments length,
publishes it and releases the lock. Length exactly 16
takes the additional helper at 0x475aea0 after release;
other lengths skip it. The ordinary return yields the
saved kernel result. This deregistration queue is separate
from registration rollback and the event dispatch loop.

The retained 1 full FDEs cover 384 bytes and 110 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 1 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-epoll-deregister-115/collect.py --out work/epoll-deregister-fresh
python3 -B research/work-items/RE-012-epoll-deregister-115/verify.py --out work/epoll-deregister-check-fresh.json
```

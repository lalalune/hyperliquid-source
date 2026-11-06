# RE-012: map node115 thread creation stack sizing and ownership

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The thread constructor initializes pthread attributes and
selects an unsigned maximum of the requested size and a
minimum. The minimum defaults to 0x4000. A nonzero cached
function can supply it and the cache sentinel one resolves
the function through dlsym.

The first stack-size call uses the selected size. Status 22
alone enters the retry that uses sysconf selector 0x1e and
rounds with (size + page - 1) & -page. A successful stack
setup calls pthread_create with entry 0x5ca44a0. Creation
failure disposes of the argument and returns tag one with
(status << 32) | 2; success returns tag zero and thread
handle. Both ordinary completion paths destroy attributes.
The stack setter and attribute destruction diagnostics are
retained. This scope precedes the thread-entry callback.

The retained 1 full FDEs cover 507 bytes and 131 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 6 instruction/data windows, 0 RELATIVE addends, 6 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-pthread-create-stack-policy-115/collect.py --out work/pthread-create-stack-policy-fresh
python3 -B research/work-items/RE-012-pthread-create-stack-policy-115/verify.py --out work/pthread-create-stack-policy-check-fresh.json
```

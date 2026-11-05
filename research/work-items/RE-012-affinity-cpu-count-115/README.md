# RE-012: map node115 CPU affinity count and sysconf fallback

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected routine checks the initialization state and returns
the cached qword when nonzero. A zero cache falls through to a
128-byte zeroed mask and sched_getaffinity(pid=0,size=128).

A successful query counts set bits over exactly 1024 positions.
The loop handles two adjacent positions per iteration using a
qword index and even shift, increments only for set bits and
retains the overflow checks. It returns the zero-extended count.
A nonzero status calls sysconf with selector 0x54 and returns
that signed value if it is at least two, otherwise one. This
packet separates the query fallback from initialization and
does not infer the provenance of the cache value.

The retained 1 full FDEs cover 312 bytes and 79 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-affinity-cpu-count-115/collect.py --out work/affinity-cpu-count-fresh
python3 -B research/work-items/RE-012-affinity-cpu-count-115/verify.py --out work/affinity-cpu-count-check-fresh.json
```

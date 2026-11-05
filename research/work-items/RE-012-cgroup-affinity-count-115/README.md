# RE-012: map node115 vector affinity count and CPU cap selection

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This path intersects an upstream cap with the OS CPU count.
It calls sched_getaffinity with pid zero and a zeroed 128-byte
mask. Success counts bits using packed shift/mask/add steps,
byte sums and a final lane reduction. An all-zero count and a
failed affinity call both select sysconf selector 0x54.

A usable count returns tag zero and the unsigned minimum of
the count and cap. Sysconf -1 captures errno with low tag two;
zero uses a distinct static error payload. Both use tag one.
The fallback cap is all ones and the join adjusts a zero cap
to one. This differs from the separately mapped scalar mask
counter by the explicit cap and result/error protocol. The
upstream quota parser is outside this packet.

The retained 1 full FDEs cover 7007 bytes and 1584 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 7 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-cgroup-affinity-count-115/collect.py --out work/cgroup-affinity-count-fresh
python3 -B research/work-items/RE-012-cgroup-affinity-count-115/verify.py --out work/cgroup-affinity-count-check-fresh.json
```

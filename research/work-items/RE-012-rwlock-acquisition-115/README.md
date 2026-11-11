# RE-012: map node115 rwlock reader and writer acquisition

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

PR #2960 maps release and wake selection. This packet resolves
the distinct acquisition side at 0x5c844a0 and 0x5c84640. It binds
selected caller sites 0x5c81a1b and 0x5c80c0b via their actual
RELATIVE slots. Caller bodies are context for the selected edges.

The low 30 bits encode the observed ownership count or writer
marker, with bit 30 for reader waiters and bit 31 for writer waiters.
Reader acquisition uses compare-exchange to add one. The ordinary
gate requires both waiter bits clear and a low count below
0x3ffffffe. After returning from the wait path it also admits low
counts 1 through 0x3ffffffd with bit 30 clear, even with bit 31 set.
Count 0x3ffffffe reaches the diagnostic arm when acquisition is
not admitted. A blocked reader sets bit 30 and waits on the state
word, rechecking the full expected word first.

The writer path attempts compare-exchange only when the low 30
bits are zero. It ORs in 0x3fffffff initially. After the generation
snapshot/recheck arm, the acquisition mask becomes 0xbfffffff.
When blocked it sets bit 31 if absent, samples the word at +4,
then rechecks ownership and writer-wait status. The wait uses the
sampled generation on +4, with an additional reload before the
imported call. This is the same writer-generation address that
the selected release packet increments before waking one writer.

Both waits use syscall number 202, operation 0x89 and mask
0xffffffff. Negative results with errno 4 repeat the respective
pre-wait word checks. The proof stops at the imported calls.
No scheduling, fairness or concurrency equivalence is inferred
from these static predicates. Qualification reads bytes only.

The retained 4 full FDEs cover 1351 bytes and 374 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 13 instruction/data windows, 2 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-rwlock-acquisition-115/collect.py --out work/rwlock-acquisition-fresh
python3 -B research/work-items/RE-012-rwlock-acquisition-115/verify.py --out work/rwlock-acquisition-check-fresh.json
```

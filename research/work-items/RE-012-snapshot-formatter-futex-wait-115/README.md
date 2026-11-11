# RE-012: recover node #115 contended formatter futex acquisition

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The owner-recursive formatter dispatches contended acquisition through RELATIVE slot 0x64e06a8 to this helper. It reads the 32-bit lock word, performs a bounded PAUSE loop only while the value is one, and tries locked 0-to-1 compare-exchange if it observes zero. The contention arm exchanges in two unless already observing two. An exchange that observes zero acquires the lock with the contention marker still present.

With the word still equal to two the helper issues the Linux x86-64 futex syscall (0xca) with operation 0x89, expected value two and a 0xffffffff bitset. The initialized timeout-selection byte is zero, selecting a null timeout on this path. A negative return triggers an errno lookup. Errno four returns to the wait predicate, while other outcomes reload the word and retry contention handling. The state-two distinction explains the caller's conditional wake on final unlock. This packet describes the 32-bit blocking acquire state machine.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-formatter-futex-wait-115/collect.py --out work/node115-snapshot-formatter-futex-wait-fresh
python3 -B research/work-items/RE-012-snapshot-formatter-futex-wait-115/verify.py --out work/node115-snapshot-formatter-futex-wait-check-fresh.json
```

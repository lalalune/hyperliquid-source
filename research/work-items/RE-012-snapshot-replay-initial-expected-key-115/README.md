# RE-017: trace node #115 initial replay expected key from callback

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The existing entry-checkpoint and expanded-result packets identify callback adapter 0x2a92960 and its worker binding. PR #3813 covers the selected receive probe, and #3815 covers the worker's expected-word comparison and successor. This packet connects their boundary: the adapter loads callback +0x708 into R8 at 0x2a929ab before calling slot 0x64e71d0 at 0x2a929ba. The unique RELATIVE relocation names 0x5a6e1e0. On the selected initial path the worker moves R8 to RBP at 0x5a6e1f1 and stores it at stack +0x168 at 0x5a6e2d6.

The receive call at 0x5a6e328 takes the staged receive inputs and has a tag-one gate. The expected word is a later acceptance check, not a seek argument at this call. A non-one tag branches to 0x5a70087. For the selected tag-one nonnull payload, the worker selects record +0x60 if +0x28 has the marker, +0x58 if only +0xb8 has the marker, otherwise +0xe8. The comparison at 0x5a6e3e2 is exact equality against the staged expected word. Mismatch reaches 0x5a700f8 before the selected reference increments.

The cross-function pins record the consumer and failure boundaries as context. This establishes where the initial expected value enters the worker. The writer of callback +0x708, its relationship to checkpoint height, and the initial physical position of the queue are unresolved. No runtime replay or root equality is claimed.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-replay-initial-expected-key-115/collect.py --out work/node115-snapshot-replay-initial-expected-key-fresh
python3 -B research/work-items/RE-012-snapshot-replay-initial-expected-key-115/verify.py --out work/node115-snapshot-replay-initial-expected-key-check-fresh.json
```
